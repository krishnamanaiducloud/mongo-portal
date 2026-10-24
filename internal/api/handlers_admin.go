package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/krishnamanaiducloud/mongo-portal/internal/audit"
	"github.com/krishnamanaiducloud/mongo-portal/internal/rbac"
	"github.com/krishnamanaiducloud/mongo-portal/internal/session"
	"github.com/krishnamanaiducloud/mongo-portal/internal/store"
)

// SessionRegistry is the shared session registry (store.Registry).
type SessionRegistry interface {
	Upsert(ctx context.Context, metas []store.SessionMeta) error
	Remove(ctx context.Context, handles []string) error
	List(ctx context.Context, owner string, limit int64) ([]store.SessionMeta, error)
	Revoke(ctx context.Context, handle, owner, by string) (int64, error)
	RevokedOn(ctx context.Context, pod string) ([]string, error)
}

func (s *Server) meta(x *session.Session) store.SessionMeta {
	m := store.SessionMeta{Handle: x.Handle, Owner: x.Owner, Profile: x.Profile, MongoUser: x.MongoUser, AuthSource: x.AuthSource,
		Mechanism: x.Mechanism, Pod: s.Pod, ClientIP: x.ClientIP, UserAgent: x.UserAgent, TLS: x.TLS,
		CreatedAt: x.CreatedAt.UTC(), LastSeen: x.LastSeen().UTC(), ExpiresAt: x.ExpiresAt.UTC()}
	if x.Principal != nil {
		m.User, m.Identity, m.Provider = x.Principal.User, string(x.Principal.Source), x.Principal.Provider
	}
	return m
}

// registerSession publishes a new session to the registry (best effort).
func (s *Server) registerSession(x *session.Session) {
	x.Pod = s.Pod
	if s.Registry == nil {
		return
	}
	m := s.meta(x)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Registry.Upsert(ctx, []store.SessionMeta{m}); err != nil {
			s.Logger.Debug("session registry upsert failed", "error", err.Error())
		}
	}()
}

// RunRegistry syncs this replica's sessions with the registry until ctx
// ends: it publishes activity and closes sessions revoked elsewhere.
func (s *Server) RunRegistry(ctx context.Context, every time.Duration) {
	if s.Registry == nil {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.syncRegistry(ctx)
		}
	}
}

func (s *Server) syncRegistry(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	local := s.Store.All()
	metas := make([]store.SessionMeta, 0, len(local))
	for _, x := range local {
		metas = append(metas, s.meta(x))
	}
	if err := s.Registry.Upsert(ctx, metas); err != nil {
		s.Logger.Debug("session registry sync failed", "error", err.Error())
		return
	}
	revoked, err := s.Registry.RevokedOn(ctx, s.Pod)
	if err != nil {
		return
	}
	for _, h := range revoked {
		s.Store.DeleteHandle(h, "revoked")
	}
}

// unregister removes a closed session from the registry (best effort).
func (s *Server) unregister(handle string) {
	if s.Registry == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Registry.Remove(ctx, []string{handle})
	}()
}

type sessionRow struct {
	store.SessionMeta
	Current bool `json:"current"`
	Local   bool `json:"local"`
}

// listSessions returns sessions from the registry when available, else
// this replica's sessions. owner "" lists everyone's.
func (s *Server) listSessions(ctx context.Context, rc *reqCtx, owner string) ([]sessionRow, string) {
	current := ""
	if sess, err := s.Store.Get(rc.secret, rc.owner); err == nil {
		current = sess.Handle
	}
	localHandles := map[string]bool{}
	var rows []sessionRow
	for _, x := range s.Store.All() {
		if owner == "" || x.Owner == owner {
			localHandles[x.Handle] = true
			rows = append(rows, sessionRow{SessionMeta: s.meta(x), Current: x.Handle == current, Local: true})
		}
	}
	if s.Registry == nil {
		return rows, "local"
	}
	all, err := s.Registry.List(ctx, owner, 1000)
	if err != nil {
		return rows, "local"
	}
	for _, m := range all {
		if !localHandles[m.Handle] {
			rows = append(rows, sessionRow{SessionMeta: m, Current: m.Handle == current})
		}
	}
	slices.SortFunc(rows, func(a, b sessionRow) int { return b.LastSeen.Compare(a.LastSeen) })
	return rows, "registry"
}

func sessionNote(source string) string {
	if source == "registry" {
		return "Sessions of every portal replica (shared session registry)."
	}
	return "Sessions held by the portal replica serving this request. Enable session.registry to see every replica."
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	rows, src := s.listSessions(r.Context(), rc, rc.owner)
	out := make([]map[string]any, 0, len(rows))
	for _, x := range rows {
		out = append(out, map[string]any{
			"handle": x.Handle, "profile": x.Profile, "mongoUser": x.MongoUser, "authSource": x.AuthSource, "mechanism": x.Mechanism,
			"createdAt": x.CreatedAt, "lastSeen": x.LastSeen, "expiresAt": x.ExpiresAt, "userAgent": x.UserAgent, "clientIP": x.ClientIP,
			"current": x.Current, "tls": x.TLS, "pod": x.Pod,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out, "source": src, "note": sessionNote(src)})
}

func (s *Server) handleTerminateSession(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	h := r.PathValue("handle")
	ok := s.Store.DeleteByHandle(rc.owner, h, "terminated")
	if !ok && s.Registry != nil {
		// Held by another replica: revoke it there (owner must match).
		if rows, _ := s.listSessions(r.Context(), rc, rc.owner); slices.ContainsFunc(rows, func(x sessionRow) bool { return x.Handle == h }) {
			n, err := s.Registry.Revoke(r.Context(), h, "", rc.owner)
			ok = err == nil && n > 0
		}
	}
	if !ok {
		writeError(w, r, http.StatusNotFound, "not_found", "Session not found")
		return
	}
	s.Metrics.ActiveSessions.Set(float64(s.Store.Count()))
	e := s.baseEvent(rc, "session_terminate", audit.Success, "")
	e.Target = h
	s.Audit.Record(r.Context(), e)
	writeJSON(w, http.StatusOK, map[string]any{"terminated": true})
}

// handleAdminSessions lists every session (sessions get all).
func (s *Server) handleAdminSessions(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !s.authorize(w, r, rc, rbac.Sessions, rbac.Get, "all") {
		return
	}
	rows, src := s.listSessions(r.Context(), rc, r.URL.Query().Get("owner"))
	if u := strings.ToLower(r.URL.Query().Get("user")); u != "" {
		rows = slices.DeleteFunc(rows, func(x sessionRow) bool {
			return !strings.Contains(strings.ToLower(x.User), u) && !strings.Contains(strings.ToLower(x.MongoUser), u)
		})
	}
	if rows == nil {
		rows = []sessionRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": rows, "source": src, "note": sessionNote(src),
		"canRevoke": s.allowed(rc, rbac.Sessions, rbac.Delete, "all")})
}

// handleAdminRevoke revokes one session or every session of a principal.
func (s *Server) handleAdminRevoke(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !s.authorize(w, r, rc, rbac.Sessions, rbac.Delete, "all") {
		return
	}
	var req struct {
		Handle string `json:"handle"`
		Owner  string `json:"owner"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if (req.Handle == "") == (req.Owner == "") || len(req.Handle) > 64 || len(req.Owner) > 600 {
		writeError(w, r, http.StatusBadRequest, "invalid_input", "Give either handle or owner")
		return
	}
	n := int64(0)
	if req.Handle != "" {
		if s.Store.DeleteHandle(req.Handle, "revoked") {
			n++
		}
	} else {
		n += int64(s.Store.DeleteOwner(req.Owner, "revoked"))
	}
	if s.Registry != nil {
		if m, err := s.Registry.Revoke(r.Context(), req.Handle, req.Owner, rc.owner); err == nil {
			n = max(n, m)
		}
	}
	s.Metrics.ActiveSessions.Set(float64(s.Store.Count()))
	e := s.baseEvent(rc, "session_revoke", audit.Success, "")
	e.Target, e.Count = req.Handle+req.Owner, n
	s.Audit.Record(r.Context(), e)
	writeJSON(w, http.StatusOK, map[string]any{"revoked": n})
}

// auditFilter parses the audit query parameters.
func auditFilter(r *http.Request) (audit.Filter, error) {
	q := r.URL.Query()
	f := audit.Filter{User: q.Get("user"), Action: q.Get("action"), Outcome: q.Get("outcome"), Profile: q.Get("profile"),
		Database: q.Get("database"), Collection: q.Get("collection"), Text: q.Get("q"), BeforeID: q.Get("beforeId")}
	for _, v := range []string{f.User, f.Action, f.Outcome, f.Profile, f.Database, f.Collection, f.Text, f.BeforeID} {
		if len(v) > 256 {
			return f, errInvalid("filter values must be at most 256 characters")
		}
	}
	parse := func(k string, into *time.Time) error {
		if v := q.Get(k); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				return errInvalid(k + " must be an RFC 3339 time")
			}
			*into = t.UTC()
		}
		return nil
	}
	if err := parse("from", &f.From); err != nil {
		return f, err
	}
	if err := parse("to", &f.To); err != nil {
		return f, err
	}
	if err := parse("before", &f.Before); err != nil {
		return f, err
	}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	return f, nil
}

type invalidErr string

func (e invalidErr) Error() string { return string(e) }
func errInvalid(m string) error    { return invalidErr(m) }

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	f, err := auditFilter(r)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_input", err.Error())
		return
	}
	all := r.URL.Query().Get("scope") == "all"
	if all && !s.authorize(w, r, rc, rbac.Audit, rbac.Get, "all") {
		return
	}
	if !all {
		f.Owner = rc.owner
	}
	format := r.URL.Query().Get("format")
	if format != "" {
		// Exports page through the whole selection, bounded.
		f.Limit = 1000
	}
	events, durable, err := s.Audit.Query(r.Context(), f)
	if err != nil {
		// The durable store is unavailable: fall back to this replica.
		events, durable = s.Audit.Local(f), false
	}
	switch format {
	case "":
	case "ndjson", "csv":
		s.exportAudit(w, r, rc, f, events, format)
		return
	default:
		writeError(w, r, http.StatusBadRequest, "invalid_input", "format must be ndjson or csv")
		return
	}
	resp := map[string]any{
		"events":  events,
		"scope":   map[bool]string{true: "all", false: "self"}[all],
		"durable": durable,
	}
	if len(events) == f.Limit && f.Limit > 0 {
		last := events[len(events)-1]
		resp["next"] = map[string]any{"before": last.Time.Format(time.RFC3339Nano), "beforeId": last.ID}
	}
	if durable {
		resp["note"] = "Events of every portal replica from the durable audit store. The structured log stream receives the same events."
	} else {
		resp["note"] = "Recent events recorded by this portal replica. The durable trail is the structured log stream" +
			map[bool]string{true: " (the audit store is unavailable).", false: "; enable audit.persist for a searchable trail of every replica."}[s.Audit.Persistent()]
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) exportAudit(w http.ResponseWriter, r *http.Request, rc *reqCtx, f audit.Filter, first []audit.Event, format string) {
	const maxExport = 100000
	name := "audit-" + time.Now().UTC().Format("20060102T150405Z")
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.csv"`)
	} else {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.ndjson"`)
	}
	cw := csv.NewWriter(w)
	enc := json.NewEncoder(w)
	cols := []string{"time", "id", "outcome", "action", "ssoUser", "identity", "provider", "mongoUser", "profile", "database", "collection", "target", "reason", "errorClass", "durationMs", "count", "client", "requestId", "traceId", "pod", "seq", "hash"}
	if format == "csv" {
		_ = cw.Write(cols)
	}
	n := 0
	page := first
	for len(page) > 0 && n < maxExport {
		for _, e := range page {
			if format == "csv" {
				_ = cw.Write([]string{e.Time.Format(time.RFC3339Nano), e.ID, e.Outcome, e.Action, csvSafe(e.SSOUser), e.Identity, e.Provider, csvSafe(e.MongoUser),
					e.Profile, csvSafe(e.Database), csvSafe(e.Collection), csvSafe(e.Target), csvSafe(e.Reason), e.ErrorClass,
					strconv.FormatInt(e.DurationMS, 10), strconv.FormatInt(e.Count, 10), e.Client, e.RequestID, e.TraceID, e.Pod, strconv.FormatInt(e.Seq, 10), e.Hash})
			} else {
				_ = enc.Encode(e)
			}
			n++
		}
		if len(page) < f.Limit {
			break
		}
		last := page[len(page)-1]
		f.Before, f.BeforeID = last.Time, last.ID
		var err error
		if page, _, err = s.Audit.Query(r.Context(), f); err != nil {
			break
		}
	}
	cw.Flush()
	e := s.baseEvent(rc, "audit_export", audit.Success, format)
	e.Count = int64(n)
	s.Audit.Record(r.Context(), e)
}

// csvSafe prevents spreadsheet formula injection in exported values.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

// handleAuditVerify checks the hash chain of one replica's stored events.
func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !s.authorize(w, r, rc, rbac.Audit, rbac.Get, "all") {
		return
	}
	if s.AuditChain == nil {
		writeError(w, r, http.StatusConflict, "not_durable", "Chain verification needs the durable audit store (audit.persist)")
		return
	}
	pod := r.URL.Query().Get("pod")
	from, _ := strconv.ParseInt(r.URL.Query().Get("from"), 10, 64)
	if pod == "" || len(pod) > 253 {
		writeError(w, r, http.StatusBadRequest, "invalid_input", "pod is required")
		return
	}
	events, err := s.AuditChain(r.Context(), pod, max(from, 1), 5000)
	if err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "store_unavailable", "The audit store is unavailable")
		return
	}
	broken := audit.VerifyChain(events)
	resp := map[string]any{"pod": pod, "checked": len(events), "intact": broken < 0}
	if len(events) > 0 {
		resp["firstSeq"], resp["lastSeq"] = events[0].Seq, events[len(events)-1].Seq
	}
	if broken >= 0 {
		resp["brokenAtSeq"] = events[broken].Seq
	}
	writeJSON(w, http.StatusOK, resp)
}
