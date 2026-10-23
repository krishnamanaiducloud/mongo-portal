package api

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/krishnamanaiducloud/mongo-portal/internal/audit"
	"github.com/krishnamanaiducloud/mongo-portal/internal/config"
	"github.com/krishnamanaiducloud/mongo-portal/internal/identity"
	"github.com/krishnamanaiducloud/mongo-portal/internal/mongoconn"
	"github.com/krishnamanaiducloud/mongo-portal/internal/rbac"
	"github.com/krishnamanaiducloud/mongo-portal/internal/session"
)

// authOptions tells the UI which sign-in methods are available right now.
func (s *Server) authOptions() map[string]any {
	src := s.Identity.Sources()
	return map[string]any{
		"openshift":    src.OpenShift,
		"openshiftURL": oauthStartPath,
		"header":       src.Header,
		"dev":          src.Dev,
		"requireSSO":   src.RequireSSO,
		// MongoDB-only login is possible unless SSO is required.
		"mongodbLogin": !src.RequireSSO,
	}
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	binding := s.ensurePreCookie(w, r, rc)
	hasSession := false
	if rc.p != nil {
		_, err := s.Store.Get(rc.secret, rc.owner)
		hasSession = err == nil
	}
	resp := map[string]any{
		"authenticated": rc.p != nil,
		"user":          rc.user(),
		"source":        rc.source(),
		"sso":           rc.p.SSO(),
		"groups":        []string{},
		"roles":         []string{},
		"permissions":   s.globalPermissions(rc),
		"csrfToken":     s.preauthToken(binding, time.Now()),
		"hasSession":    hasSession,
		"ssoLogoutURL":  s.Config.Identity.SSOLogoutURL,
		"environment":   s.Config.Environment,
		"build":         s.Build,
		"auth":          s.authOptions(),
	}
	if rc.p != nil {
		if rc.p.Groups != nil {
			resp["groups"] = rc.p.Groups
		}
		if roles := s.roles(rc); roles != nil {
			resp["roles"] = roles
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// globalPermissions are UI hints for controls that are not tied to one
// namespace. Every request is still checked against its concrete object.
func (s *Server) globalPermissions(rc *reqCtx) map[string]bool {
	out := map[string]bool{}
	if rc.p == nil {
		return out
	}
	pol, subj := s.RBAC.Policy(), rc.p.Subjects()
	for res, acts := range rbac.Actions {
		for _, a := range acts {
			out[string(res)+":"+string(a)] = pol.Possible(subj, res, a)
		}
	}
	out["audit:all"] = pol.Allowed(subj, rbac.Audit, rbac.Get, "all")
	return out
}

// handlePermissions explains the principal's RBAC roles and rules.
func (s *Server) handlePermissions(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	pol := s.RBAC.Policy()
	subj := rc.p.Subjects()
	rules := pol.RulesFor(subj)
	if rules == nil {
		rules = []rbac.Rule{}
	}
	direct := pol.DirectRoles(subj)
	if direct == nil {
		direct = []string{}
	}
	resp := map[string]any{
		"user": rc.p.User, "source": rc.p.Source, "subjects": subj,
		"roles": pol.Roles(subj), "directRoles": direct, "defaultRole": pol.DefaultRole(),
		"rules": rules, "policy": s.RBAC.Status(),
	}
	// Optional access check: ?resource=documents&action=update&object=app/orders
	if q := r.URL.Query(); q.Get("resource") != "" {
		res, act, obj := rbac.Resource(q.Get("resource")), rbac.Action(q.Get("action")), q.Get("object")
		acts, ok := rbac.Actions[res]
		if !ok || !slices.Contains(acts, act) || obj == "" || len(obj) > 512 {
			writeError(w, r, http.StatusBadRequest, "invalid_input", "resource, action and object must name a valid permission")
			return
		}
		resp["check"] = map[string]any{"resource": res, "action": act, "object": obj, "allowed": pol.Allowed(subj, res, act, obj)}
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleStatus reports the state of optional integrations. Everything here
// is informational: an unavailable integration is a state, not an error.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	profiles := make([]map[string]any, 0, len(s.Config.Profiles))
	for i := range s.Config.Profiles {
		p := &s.Config.Profiles[i]
		profiles = append(profiles, map[string]any{"name": p.Name, "displayName": p.DisplayName, "health": s.healthFor(rc, p.Name)})
	}
	resp := map[string]any{
		"auth":     s.authOptions(),
		"profiles": profiles,
		"build":    s.Build,
	}
	if rc.p != nil {
		// Operational details only for signed-in users.
		resp["rbac"] = s.RBAC.Status()
		resp["tracing"] = s.TracingEnabled
		resp["shell"] = s.Config.ShellEnabled()
		resp["sessions"] = map[string]any{"active": s.Store.Count(), "max": s.Config.Session.MaxTotal}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) profileHealth(name string) mongoconn.Health {
	if s.Monitor == nil {
		return mongoconn.Health{State: mongoconn.HealthDisabled}
	}
	return s.Monitor.Health(name)
}

// healthFor returns profile health; anonymous callers see only the state and
// latency (no replica set names or error details).
func (s *Server) healthFor(rc *reqCtx, name string) mongoconn.Health {
	h := s.profileHealth(name)
	if rc.p == nil {
		h.Reason, h.SetName = "", ""
	}
	return h
}

type profileView struct {
	Name              string           `json:"name"`
	DisplayName       string           `json:"displayName"`
	Description       string           `json:"description,omitempty"`
	DefaultAuthSource string           `json:"defaultAuthSource"`
	AuthMechanisms    []string         `json:"authMechanisms"`
	TLSMode           string           `json:"tlsMode"`
	ClientCertificate bool             `json:"clientCertificate"`
	PlaintextWarning  bool             `json:"plaintextWarning"`
	ReplicaSet        string           `json:"replicaSet,omitempty"`
	Health            mongoconn.Health `json:"health"`
}

func (s *Server) viewProfile(rc *reqCtx, p *config.Profile) profileView {
	return profileView{
		Name: p.Name, DisplayName: p.DisplayName, Description: p.Description,
		DefaultAuthSource: p.DefaultAuthSource, AuthMechanisms: p.AuthMechanisms,
		TLSMode: p.TLS.Mode, ClientCertificate: p.TLS.ClientCertFile != "",
		PlaintextWarning: p.TLS.Mode == config.TLSDisabled, ReplicaSet: p.ReplicaSet,
		Health: s.healthFor(rc, p.Name),
	}
}

func (s *Server) handleProfiles(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if s.Config.Identity.RequireSSO && !rc.p.SSO() {
		writeError(w, r, http.StatusUnauthorized, "sso_required", "Sign in with single sign-on to continue")
		return
	}
	out := make([]profileView, 0, len(s.Config.Profiles))
	for i := range s.Config.Profiles {
		out = append(out, s.viewProfile(rc, &s.Config.Profiles[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": out})
}

type loginRequest struct {
	Profile    string `json:"profile"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	AuthSource string `json:"authSource"`
	Mechanism  string `json:"mechanism"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if s.Config.Identity.RequireSSO && !rc.p.SSO() {
		writeError(w, r, http.StatusUnauthorized, "sso_required", "Sign in with single sign-on before connecting to MongoDB")
		return
	}
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	p, ok := s.Config.Profile(req.Profile)
	if !ok {
		writeError(w, r, http.StatusBadRequest, "unknown_profile", "Unknown connection profile")
		return
	}
	if req.AuthSource == "" {
		req.AuthSource = p.DefaultAuthSource
	}
	cred := mongoconn.Credentials{Username: req.Username, Password: req.Password, AuthSource: req.AuthSource, Mechanism: req.Mechanism}
	req.Password = ""
	if err := cred.Validate(p); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_input", err.Error())
		return
	}

	// Without SSO the MongoDB user is the principal (and RBAC subject).
	principal, limiterKey := rc.p, "sso\x00"+rc.owner
	if !rc.p.SSO() {
		principal, limiterKey = identity.MongoDBPrincipal(cred.Username, cred.AuthSource), "ip\x00"+clientIP(r)
	}
	ev := audit.Event{RequestID: rc.requestID, SSOUser: principal.User, Identity: string(principal.Source), Owner: principal.Key(),
		PortalRole: strings.Join(s.RBAC.Policy().Roles(principal.Subjects()), " "),
		MongoUser:  cred.Username + "@" + cred.AuthSource, Profile: p.Name, Action: "mongodb_login"}
	target := p.Name + "\x00" + cred.AuthSource + "\x00" + cred.Username
	if ok, wait := s.limiter.Allow(limiterKey, target); !ok {
		s.Metrics.AuthAttempts.WithLabelValues("mongodb", "rate_limited").Inc()
		ev.Outcome, ev.Reason = audit.Denied, "rate limited"
		s.Audit.Record(r.Context(), ev)
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeError(w, r, http.StatusTooManyRequests, "rate_limited", "Too many login attempts; try again later")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.Config.Login.Timeout)
	defer cancel()
	select {
	case s.loginSem <- struct{}{}:
		defer func() { <-s.loginSem }()
	case <-ctx.Done():
		writeError(w, r, http.StatusServiceUnavailable, "busy", "The portal is handling too many logins; try again")
		return
	}

	pool := &mongoconn.PoolStats{}
	res, err := s.Connect(ctx, p, cred, mongoconn.PoolHooks{
		Stats: pool,
		Created: func() {
			s.Metrics.MongoConns.Inc()
			s.Metrics.MongoConnEvents.WithLabelValues("created").Inc()
		},
		Closed: func() {
			s.Metrics.MongoConns.Dec()
			s.Metrics.MongoConnEvents.WithLabelValues("closed").Inc()
		},
	})
	cred.Password = ""
	if err != nil {
		me := mongoconn.Classify(err)
		ev.Outcome, ev.Reason = audit.Failure, string(me.Kind)
		s.Audit.Record(r.Context(), ev)
		s.Metrics.AuthAttempts.WithLabelValues("mongodb", string(me.Kind)).Inc()
		s.Logger.Warn("mongodb login failed", "request_id", rc.requestID, "profile", p.Name, "kind", me.Kind, "error", safeErr(me))
		if me.Kind == mongoconn.KindAuthFailed {
			s.limiter.Failure(target)
			writeError(w, r, http.StatusUnauthorized, string(me.Kind), "Authentication failed. Check the username, password and authentication database.")
			return
		}
		writeError(w, r, me.HTTPStatus(), string(me.Kind), me.Msg)
		return
	}
	s.limiter.Success(target)

	sess := &session.Session{
		Owner: principal.Key(), Principal: principal, Profile: p.Name,
		MongoUser: cred.Username, AuthSource: cred.AuthSource, Mechanism: res.Mechanism,
		TLS: res.TLSEnabled, Client: res.Client, Status: res.Status, Pool: pool, UserAgent: truncateUA(r.UserAgent()),
	}
	secret, err := s.Store.Create(sess, rc.secret)
	if err != nil {
		dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = res.Client.Disconnect(dctx)
		dcancel()
		ev.Outcome, ev.Reason = audit.Failure, "session capacity"
		s.Audit.Record(r.Context(), ev)
		writeError(w, r, http.StatusServiceUnavailable, "capacity", "The portal has reached its session limit; try again later")
		return
	}
	s.setCookie(w, secret)
	s.Metrics.ActiveSessions.Set(float64(s.Store.Count()))
	s.Metrics.AuthAttempts.WithLabelValues("mongodb", "success").Inc()
	ev.Outcome = audit.Success
	s.Audit.Record(r.Context(), ev)
	if !res.TLSEnabled {
		s.Logger.Warn("mongodb session established without TLS", "profile", p.Name, "request_id", rc.requestID)
	}
	rc.p, rc.owner, rc.sess = principal, principal.Key(), sess
	writeJSON(w, http.StatusOK, s.sessionView(rc))
}

func truncateUA(ua string) string {
	if len(ua) > 200 {
		return ua[:200]
	}
	return ua
}

func safeErr(e *mongoconn.Error) string {
	if e.Err == nil {
		return e.Msg
	}
	s := e.Err.Error()
	if len(s) > 500 {
		s = s[:500]
	}
	return s
}

func (s *Server) sessionView(rc *reqCtx) map[string]any {
	sess := rc.sess
	idle := s.Config.Session.IdleTimeout
	var roles any = []any{}
	if sess.Status != nil {
		roles = sess.Status.AuthInfo.AuthenticatedRoles
	}
	view := map[string]any{
		"handle":             sess.Handle,
		"profile":            sess.Profile,
		"mongoUser":          sess.MongoUser,
		"authSource":         sess.AuthSource,
		"mechanism":          sess.Mechanism,
		"tls":                sess.TLS,
		"identity":           rc.p,
		"portalRoles":        s.roles(rc),
		"permissions":        s.globalPermissions(rc),
		"mongoRoles":         roles,
		"createdAt":          sess.CreatedAt.UTC(),
		"expiresAt":          sess.ExpiresAt.UTC(),
		"idleExpiresAt":      sess.IdleExpiry(idle).UTC(),
		"idleTimeoutSeconds": int(idle.Seconds()),
		"csrfToken":          sess.CSRFToken,
	}
	if p, ok := s.Config.Profile(sess.Profile); ok {
		view["profileInfo"] = s.viewProfile(rc, p)
	}
	return view
}

func (s *Server) handleSessionInfo(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	writeJSON(w, http.StatusOK, s.sessionView(rc))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	s.Store.Delete(rc.secret, "logout")
	s.clearCookie(w)
	s.Metrics.ActiveSessions.Set(float64(s.Store.Count()))
	s.auditEvent(r, rc, "mongodb_logout", audit.Success, "")
	writeJSON(w, http.StatusOK, map[string]any{"loggedOut": true, "ssoLogoutURL": s.Config.Identity.SSOLogoutURL})
}

// handleSignOut ends the portal sign-in completely: the MongoDB session of
// this browser and the OpenShift sign-in.
func (s *Server) handleSignOut(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if rc.secret != "" {
		s.Store.Delete(rc.secret, "logout")
		s.clearCookie(w)
		s.Metrics.ActiveSessions.Set(float64(s.Store.Count()))
	}
	if rc.p != nil {
		s.Audit.Record(r.Context(), s.baseEvent(rc, "sign_out", audit.Success, ""))
	}
	s.Identity.SignOut(w)
	writeJSON(w, http.StatusOK, map[string]any{"signedOut": true, "ssoLogoutURL": s.Config.Identity.SSOLogoutURL})
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	current := ""
	if sess, err := s.Store.Get(rc.secret, rc.owner); err == nil {
		current = sess.Handle
	}
	list := s.Store.ListByOwner(rc.owner)
	out := make([]map[string]any, 0, len(list))
	for _, x := range list {
		out = append(out, map[string]any{
			"handle": x.Handle, "profile": x.Profile, "mongoUser": x.MongoUser, "authSource": x.AuthSource,
			"createdAt": x.CreatedAt.UTC(), "lastSeen": x.LastSeen().UTC(), "expiresAt": x.ExpiresAt.UTC(),
			"userAgent": x.UserAgent, "current": x.Handle == current, "tls": x.TLS,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out, "note": "Sessions are held by the portal instance serving this request."})
}

func (s *Server) handleTerminateSession(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	h := r.PathValue("handle")
	if !s.Store.DeleteByHandle(rc.owner, h, "terminated") {
		writeError(w, r, http.StatusNotFound, "not_found", "Session not found")
		return
	}
	s.Metrics.ActiveSessions.Set(float64(s.Store.Count()))
	s.Audit.Record(r.Context(), s.baseEvent(rc, "session_terminate", audit.Success, ""))
	writeJSON(w, http.StatusOK, map[string]any{"terminated": true})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	scope := rc.owner
	if r.URL.Query().Get("scope") == "all" && s.allowed(rc, rbac.Audit, rbac.Get, "all") {
		scope = ""
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"events": s.Audit.Recent(scope, limit),
		"scope":  map[bool]string{true: "all", false: "self"}[scope == ""],
		"note":   "Recent events recorded by this portal instance. The durable audit trail is the structured log stream.",
	})
}

// OnSessionClosed is wired into the session store.
func (s *Server) OnSessionClosed(sess *session.Session, reason string) {
	s.Metrics.SessionsClosed.WithLabelValues(reason).Inc()
	s.Metrics.ActiveSessions.Set(float64(s.Store.Count()))
	if reason != "logout" {
		e := audit.Event{Owner: sess.Owner, MongoUser: sess.MongoUser + "@" + sess.AuthSource, Profile: sess.Profile, Action: "session_closed", Outcome: audit.Success, Reason: reason}
		if sess.Principal != nil {
			e.SSOUser, e.Identity = sess.Principal.User, string(sess.Principal.Source)
		}
		s.Audit.Record(context.Background(), e)
	}
}
