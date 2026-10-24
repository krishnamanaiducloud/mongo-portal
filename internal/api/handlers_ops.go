package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/krishnamanaiducloud/mongo-portal/internal/audit"
	"github.com/krishnamanaiducloud/mongo-portal/internal/mongoconn"
	"github.com/krishnamanaiducloud/mongo-portal/internal/rbac"
)

// Running operations come from $currentOp with the user's own session. Only
// metadata is read (never command or query documents). Ending an operation
// uses killOp, which MongoDB authorizes: users may always end their own
// operations, other users' operations need the killop privilege. killOp
// ends an operation, not a client connection.

type operation struct {
	OpID         any     `json:"opid"`
	Type         string  `json:"type"`
	Op           string  `json:"op"`
	NS           string  `json:"ns"`
	Active       bool    `json:"active"`
	SecsRunning  float64 `json:"secsRunning"`
	Client       string  `json:"client"`
	AppName      string  `json:"appName"`
	User         string  `json:"user"`
	Desc         string  `json:"desc"`
	ConnectionID any     `json:"connectionId,omitempty"`
	WaitingLock  bool    `json:"waitingForLock"`
	PlanSummary  string  `json:"planSummary,omitempty"`
	KillPending  bool    `json:"killPending"`
	Slow         bool    `json:"slow"`
	// ExpectedWait explains an operation that waits by design (awaitable
	// hello, tailable cursors, change streams, oplog tailing); it is never
	// reported as slow.
	ExpectedWait string `json:"expectedWait,omitempty"`
	Portal       bool   `json:"portal"`
	Internal     bool   `json:"internal"`
}

var opIDRe = regexp.MustCompile(`^(-?\d{1,19}|[A-Za-z0-9_.-]{1,64}:\d{1,19})$`)

// currentOps runs $currentOp; without the inprog privilege it falls back to
// the user's own operations (allUsers: false) and reports that.
func (s *Server) currentOps(ctx context.Context, rc *reqCtx, idle bool, match bson.D) ([]bson.M, bool, error) {
	run := func(all bool) ([]bson.M, error) {
		pipe := bson.A{
			bson.D{{Key: "$currentOp", Value: bson.D{{Key: "allUsers", Value: all}, {Key: "idleConnections", Value: idle}, {Key: "idleSessions", Value: false}}}},
		}
		if len(match) > 0 {
			pipe = append(pipe, bson.D{{Key: "$match", Value: match}})
		}
		pipe = append(pipe,
			bson.D{{Key: "$project", Value: projectWith(bson.D{
				{Key: "opid", Value: 1}, {Key: "type", Value: 1}, {Key: "op", Value: 1}, {Key: "ns", Value: 1}, {Key: "active", Value: 1},
				{Key: "secs_running", Value: 1}, {Key: "microsecs_running", Value: 1}, {Key: "client", Value: 1}, {Key: "appName", Value: 1},
				{Key: "desc", Value: 1}, {Key: "connectionId", Value: 1}, {Key: "waitingForLock", Value: 1}, {Key: "planSummary", Value: 1},
				{Key: "killPending", Value: 1}, {Key: "user", Value: bson.D{{Key: "$arrayElemAt", Value: bson.A{"$effectiveUsers.user", 0}}}},
			})}},
			bson.D{{Key: "$limit", Value: 5000}},
		)
		cur, err := rc.sess.Client.Database("admin").Aggregate(ctx, pipe)
		if err != nil {
			return nil, err
		}
		var out []bson.M
		err = cur.All(ctx, &out)
		return out, err
	}
	docs, err := run(true)
	if err != nil && mongoconn.Classify(err).Kind == mongoconn.KindUnauthorized {
		docs, err = run(false)
		return docs, false, err
	}
	return docs, true, err
}

func (s *Server) toOperation(d bson.M) operation {
	o := operation{OpID: d["opid"], Type: mstr(d, "type"), Op: mstr(d, "op"), NS: mstr(d, "ns"), Active: mbool(d, "active"),
		Client: mstr(d, "client"), AppName: mstr(d, "appName"), User: mstr(d, "user"), Desc: mstr(d, "desc"), ConnectionID: d["connectionId"],
		WaitingLock: mbool(d, "waitingForLock"), PlanSummary: mstr(d, "planSummary"), KillPending: mbool(d, "killPending")}
	if us := mnum(d, "microsecs_running"); us > 0 {
		o.SecsRunning = us / 1e6
	} else {
		o.SecsRunning = mnum(d, "secs_running")
	}
	o.Internal = o.Client == ""
	o.Portal = strings.HasPrefix(o.AppName, "mongo-portal")
	o.ExpectedWait = expectedWait(d, s.Config.Monitoring.SlowOperationIgnoreApps)
	o.Slow = o.Active && o.ExpectedWait == "" && o.SecsRunning >= s.Config.Monitoring.SlowOperation.Seconds()
	return o
}

func (s *Server) handleListOperations(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !s.authorize(w, r, rc, rbac.Operations, rbac.Get, rc.sess.Profile) {
		return
	}
	q := r.URL.Query()
	state := q.Get("state") // active (default), idle, all
	idle := state == "idle" || state == "all"
	match := bson.D{}
	switch state {
	case "", "active":
		match = append(match, bson.E{Key: "active", Value: true})
	case "idle":
		match = append(match, bson.E{Key: "active", Value: false})
	case "all":
	default:
		writeError(w, r, http.StatusBadRequest, "invalid_input", "state must be active, idle or all")
		return
	}
	if q.Get("internal") != "true" {
		match = append(match, bson.E{Key: "client", Value: bson.D{{Key: "$exists", Value: true}}})
	}
	for k, field := range map[string]string{"client": "client", "app": "appName", "ns": "ns", "op": "op"} {
		if v := q.Get(k); v != "" {
			if len(v) > 200 {
				writeError(w, r, http.StatusBadRequest, "invalid_input", "filters must be at most 200 characters")
				return
			}
			match = append(match, bson.E{Key: field, Value: bson.Regex{Pattern: regexp.QuoteMeta(v), Options: "i"}})
		}
	}
	if v := q.Get("minSecs"); v != "" {
		n, err := strconv.ParseFloat(v, 64)
		if err != nil || n < 0 {
			writeError(w, r, http.StatusBadRequest, "invalid_input", "minSecs must be a number")
			return
		}
		match = append(match, bson.E{Key: "secs_running", Value: bson.D{{Key: "$gte", Value: int64(n)}}})
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	offset, _ := strconv.Atoi(q.Get("offset"))
	offset = max(offset, 0)

	var docs []bson.M
	var all bool
	err := s.op(r.Context(), "currentOp", s.defaultTimeout(), func(ctx context.Context) error {
		var err error
		docs, all, err = s.currentOps(ctx, rc, idle, match)
		return err
	})
	if err != nil {
		s.mongoError(w, r, rc, "currentOp", err)
		return
	}
	ops := make([]operation, 0, len(docs))
	user := strings.ToLower(q.Get("user"))
	for _, d := range docs {
		o := s.toOperation(d)
		if user != "" && !strings.Contains(strings.ToLower(o.User), user) {
			continue
		}
		ops = append(ops, o)
	}
	slices.SortStableFunc(ops, func(a, b operation) int {
		switch {
		case a.SecsRunning > b.SecsRunning:
			return -1
		case a.SecsRunning < b.SecsRunning:
			return 1
		}
		return 0
	})
	total := len(ops)
	page := ops[min(offset, total):min(offset+limit, total)]
	writeJSON(w, http.StatusOK, map[string]any{
		"operations": page, "total": total, "offset": offset, "limit": limit, "allUsers": all,
		"slowSeconds": s.Config.Monitoring.SlowOperation.Seconds(),
		"canKill":     s.allowed(rc, rbac.Operations, rbac.Kill, rc.sess.Profile),
		"note":        map[bool]string{true: "", false: "Your MongoDB user may only see its own operations (the inprog privilege, part of clusterMonitor, shows all)."}[all],
	})
}

type killRequest struct {
	OpID    json.RawMessage `json:"opid"`
	Confirm string          `json:"confirm"`
}

// handleKillOperation ends one running operation with killOp after checking
// that it exists, is a client operation and is still running.
func (s *Server) handleKillOperation(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !s.authorize(w, r, rc, rbac.Operations, rbac.Kill, rc.sess.Profile) {
		return
	}
	var req killRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	idText := strings.Trim(string(req.OpID), `"`)
	if !opIDRe.MatchString(idText) {
		writeError(w, r, http.StatusBadRequest, "invalid_input", "opid must be an operation id from the operations list")
		return
	}
	if req.Confirm != idText {
		writeError(w, r, http.StatusPreconditionRequired, "confirmation_required", "Confirm by sending confirm equal to the operation id")
		return
	}
	var opid any = idText
	if n, err := strconv.ParseInt(idText, 10, 64); err == nil {
		opid = n
	}
	var target *operation
	err := s.op(r.Context(), "currentOp", s.defaultTimeout(), func(ctx context.Context) error {
		docs, _, err := s.currentOps(ctx, rc, false, bson.D{{Key: "opid", Value: opid}})
		if err == nil && len(docs) > 0 {
			o := s.toOperation(docs[0])
			target = &o
		}
		return err
	})
	if err != nil {
		s.mongoError(w, r, rc, "currentOp", err)
		return
	}
	reason := ""
	switch {
	case target == nil:
		reason = "The operation is no longer running (or is not visible to your MongoDB user)."
	case target.Internal:
		reason = "Internal server operations (replication, TTL, ...) cannot be ended from the portal."
	case !target.Active:
		reason = "Only running operations can be ended; idle connections are not operations."
	case target.KillPending:
		reason = "The operation is already being ended."
	}
	if reason != "" {
		s.auditEvent(r, rc, "operation_kill", audit.Denied, idText+": "+reason)
		writeError(w, r, http.StatusConflict, "not_killable", reason)
		return
	}
	start := time.Now()
	err = s.op(r.Context(), "killOp", s.defaultTimeout(), func(ctx context.Context) error {
		return rc.sess.Client.Database("admin").RunCommand(ctx, bson.D{{Key: "killOp", Value: 1}, {Key: "op", Value: opid}}).Err()
	})
	e := s.baseEvent(rc, "operation_kill", audit.Success, "")
	e.Target = idText + " " + target.Op + " " + target.NS + " client " + clientHost(target.Client) + " app " + target.AppName + " user " + target.User
	e.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		me := mongoconn.Classify(err)
		e.Outcome, e.ErrorClass, e.Reason = audit.Failure, string(me.Kind), me.Msg
		s.Audit.Record(r.Context(), e)
		if me.Kind == mongoconn.KindUnauthorized {
			writeError(w, r, http.StatusForbidden, string(me.Kind), "MongoDB refused killOp: ending other users' operations needs the killop privilege (for example clusterManager or hostManager).")
			return
		}
		s.mongoError(w, r, rc, "killOp", err)
		return
	}
	s.Audit.Record(r.Context(), e)
	s.Metrics.OpsKilled.Inc()
	writeJSON(w, http.StatusOK, map[string]any{"killed": true, "opid": target.OpID,
		"note": "killOp marks the operation for termination; MongoDB ends it at its next interruption point."})
}

func clientHost(c string) string {
	if h, _, err := net.SplitHostPort(c); err == nil {
		return h
	}
	return c
}
