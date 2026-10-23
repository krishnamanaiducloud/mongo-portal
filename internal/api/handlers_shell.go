package api

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/krishnamanaiducloud/mongo-portal/internal/audit"
	"github.com/krishnamanaiducloud/mongo-portal/internal/mongoconn"
	"github.com/krishnamanaiducloud/mongo-portal/internal/query"
	"github.com/krishnamanaiducloud/mongo-portal/internal/rbac"
	"github.com/krishnamanaiducloud/mongo-portal/internal/session"
)

// The shell API backs the in-browser mongosh. The mongosh runtime runs in a
// sandboxed iframe; every driver operation it issues arrives here as a typed
// operation. Nothing here evaluates JavaScript: each operation maps to one
// driver call, is validated like the rest of the API, runs as the user's
// own MongoDB identity and is subject to the portal role.

type shellRequest struct {
	Op   string `json:"op"`
	Args string `json:"args"` // Extended JSON document
}

type shellFn func(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error)

type shellOp struct {
	// checks are the RBAC permissions the operation needs on its namespace
	// (see shellChecks).
	checks      []shellCheck
	destructive bool // requires X-Confirm: <op>
	fn          shellFn
}

// shellCheck is one RBAC permission; db says the object is the database
// (otherwise the "db/coll" namespace, or the database for database-level
// operations without a collection).
type shellCheck struct {
	res rbac.Resource
	act rbac.Action
	db  bool
}

func need(res rbac.Resource, act rbac.Action) []shellCheck { return []shellCheck{{res: res, act: act}} }

// policyError is a portal policy refusal (HTTP 403).
type policyError struct{ msg string }

func (e *policyError) Error() string { return e.msg }

func deny(format string, a ...any) error { return &policyError{msg: fmt.Sprintf(format, a...)} }

var shellOps map[string]shellOp

func init() {
	shellOps = map[string]shellOp{
		"connectionInfo":         {fn: shConnectionInfo},
		"listDatabases":          {fn: shListDatabases},
		"listCollections":        {checks: []shellCheck{{res: rbac.Databases, act: rbac.Get, db: true}}, fn: shListCollections},
		"getIndexes":             {checks: need(rbac.Indexes, rbac.Get), fn: shGetIndexes},
		"find":                   {checks: need(rbac.Documents, rbac.Get), fn: shFind},
		"aggregate":              {checks: need(rbac.Documents, rbac.Get), fn: shAggregate},
		"getMore":                {fn: shGetMore},
		"killCursor":             {fn: shKillCursor},
		"countDocuments":         {checks: need(rbac.Documents, rbac.Get), fn: shCountDocuments},
		"estimatedDocumentCount": {checks: need(rbac.Documents, rbac.Get), fn: shEstimatedCount},
		"distinct":               {checks: need(rbac.Documents, rbac.Get), fn: shDistinct},
		"explain":                {checks: need(rbac.Documents, rbac.Get), fn: shExplain},
		"runCommand":             {checks: []shellCheck{{res: rbac.Databases, act: rbac.Get, db: true}}, fn: shRunCommand},
		"insertOne":              {checks: need(rbac.Documents, rbac.Create), fn: shInsertOne},
		"insertMany":             {checks: need(rbac.Documents, rbac.Create), fn: shInsertMany},
		"updateOne":              {checks: need(rbac.Documents, rbac.Update), fn: shUpdate(false)},
		"updateMany":             {checks: need(rbac.Documents, rbac.Update), destructive: true, fn: shUpdate(true)},
		"replaceOne":             {checks: need(rbac.Documents, rbac.Update), fn: shReplaceOne},
		"deleteOne":              {checks: need(rbac.Documents, rbac.Delete), fn: shDelete(false)},
		"deleteMany":             {checks: need(rbac.Documents, rbac.Delete), destructive: true, fn: shDelete(true)},
		"findOneAndDelete":       {checks: need(rbac.Documents, rbac.Delete), fn: shFindOneAndDelete},
		"findOneAndReplace":      {checks: need(rbac.Documents, rbac.Update), fn: shFindOneAndReplace},
		"findOneAndUpdate":       {checks: need(rbac.Documents, rbac.Update), fn: shFindOneAndUpdate},
		"bulkWrite":              {checks: []shellCheck{{res: rbac.Documents, act: rbac.Create}, {res: rbac.Documents, act: rbac.Update}, {res: rbac.Documents, act: rbac.Delete}}, destructive: true, fn: shBulkWrite},
		"createIndexes":          {checks: need(rbac.Indexes, rbac.Create), fn: shCreateIndexes},
		"dropIndexes":            {checks: need(rbac.Indexes, rbac.Delete), destructive: true, fn: shDropIndexes},
		"createCollection":       {checks: need(rbac.Collections, rbac.Create), fn: shCreateCollection},
		"dropCollection":         {checks: need(rbac.Collections, rbac.Delete), destructive: true, fn: shDropCollection},
		"dropDatabase":           {checks: []shellCheck{{res: rbac.Databases, act: rbac.Delete, db: true}}, destructive: true, fn: shDropDatabase},
		"renameCollection":       {checks: need(rbac.Collections, rbac.Update), destructive: true, fn: shRenameCollection},
	}
}

// destructiveCommands require confirmation when sent through runCommand.
var destructiveCommands = map[string]bool{"dropIndexes": true, "renameCollection": true, "killOp": true}

func (s *Server) handleShell(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !s.Config.ShellEnabled() {
		writeError(w, r, http.StatusNotFound, "shell_disabled", "The shell is disabled on this portal")
		return
	}
	var req shellRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	op, ok := shellOps[req.Op]
	if !ok {
		writeError(w, r, http.StatusBadRequest, "unsupported_operation", fmt.Sprintf("Operation %q is not supported by the portal shell", req.Op))
		return
	}
	if !s.authorize(w, r, rc, rbac.Shell, rbac.Use, "*") {
		return
	}
	for _, c := range shellChecks(req.Op, op, req.Args) {
		if !s.allowed(rc, c.res, c.act, c.object) {
			s.Metrics.AuthzDenials.WithLabelValues("portal", "rbac").Inc()
			reason := fmt.Sprintf("%s %s %s", c.res, c.act, c.object)
			s.Audit.Record(r.Context(), s.shellEvent(rc, req.Op, "", "", audit.Denied, reason))
			writeError(w, r, http.StatusForbidden, "portal_role_forbidden",
				fmt.Sprintf("Your portal role does not allow %s (%s %s on %q)", req.Op, c.act, c.res, c.object))
			return
		}
	}
	if op.destructive && r.Header.Get("X-Confirm") != req.Op {
		writeError(w, r, http.StatusPreconditionRequired, "confirmation_required", req.Op+" requires confirmation")
		return
	}
	select {
	case rc.sess.Shell <- struct{}{}:
		defer func() { <-rc.sess.Shell }()
	case <-time.After(10 * time.Second):
		writeError(w, r, http.StatusTooManyRequests, "busy", "Too many concurrent shell operations")
		return
	}

	ctx := withConfirm(r.Context(), r.Header.Get("X-Confirm"))
	res, err := op.fn(s, ctx, rc, req.Args)
	if err != nil {
		s.shellError(w, r, rc, req.Op, err)
		return
	}
	out, err := bson.MarshalExtJSON(res, true, false)
	if err != nil {
		s.shellError(w, r, rc, req.Op, err)
		return
	}
	if len(out) > s.Config.Query.MaxResponseBytes {
		writeError(w, r, http.StatusRequestEntityTooLarge, "response_too_large", "The result exceeds the response size limit; use a projection, a filter or a smaller batch")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"result": string(out)})
}

type resolvedCheck struct {
	res    rbac.Resource
	act    rbac.Action
	object string
}

// shellChecks resolves the RBAC objects of an operation from its arguments.
// Arguments that cannot be read are left to the operation, which rejects
// them; namespace names are validated there as well.
func shellChecks(name string, op shellOp, args string) []resolvedCheck {
	if len(op.checks) == 0 {
		return nil
	}
	var a struct {
		DB   string `bson:"db"`
		Coll string `bson:"coll"`
		From string `bson:"from"`
		To   string `bson:"to"`
	}
	var m bson.M
	if strings.TrimSpace(args) != "" && bson.UnmarshalExtJSON([]byte(args), false, &m) == nil {
		a.DB, _ = m["db"].(string)
		a.Coll, _ = m["coll"].(string)
		a.From, _ = m["from"].(string)
		a.To, _ = m["to"].(string)
	}
	var out []resolvedCheck
	if name == "renameCollection" {
		return []resolvedCheck{
			{rbac.Collections, rbac.Update, rbac.Namespace(a.DB, a.From)},
			{rbac.Collections, rbac.Create, rbac.Namespace(a.DB, a.To)},
		}
	}
	for _, c := range op.checks {
		obj := rbac.Namespace(a.DB, a.Coll)
		switch {
		case c.db:
			obj = a.DB
		case a.Coll == "":
			// Database-level operation (for example db.aggregate).
			out = append(out, resolvedCheck{rbac.Databases, rbac.Get, a.DB})
			obj = rbac.Namespace(a.DB, "*")
		}
		out = append(out, resolvedCheck{c.res, c.act, obj})
	}
	return out
}

type confirmKey struct{}

func withConfirm(ctx context.Context, v string) context.Context {
	return context.WithValue(ctx, confirmKey{}, v)
}

func confirmed(ctx context.Context, op string) bool {
	v, _ := ctx.Value(confirmKey{}).(string)
	return v == op
}

func (s *Server) shellEvent(rc *reqCtx, op, db, coll, outcome, reason string) audit.Event {
	e := s.baseEvent(rc, "shell_"+op, outcome, reason)
	e.Database, e.Collection = db, coll
	return e
}

// shellError reports an error. MongoDB's own message is returned to the
// requesting user (it describes their own operation); logs carry codes only.
func (s *Server) shellError(w http.ResponseWriter, r *http.Request, rc *reqCtx, op string, err error) {
	var pe *policyError
	if errors.As(err, &pe) {
		s.Metrics.AuthzDenials.WithLabelValues("portal", "shell_policy").Inc()
		s.Audit.Record(r.Context(), s.shellEvent(rc, op, "", "", audit.Denied, pe.msg))
		writeError(w, r, http.StatusForbidden, "operation_not_permitted", pe.msg)
		return
	}
	var qe *query.Error
	if errors.As(err, &qe) {
		writeError(w, r, http.StatusBadRequest, "invalid_query", qe.Msg)
		return
	}
	if errors.Is(err, session.ErrTooManyCursors) {
		writeError(w, r, http.StatusTooManyRequests, "too_many_cursors", err.Error())
		return
	}
	if errors.Is(err, errBadArgs) {
		writeError(w, r, http.StatusBadRequest, "invalid_arguments", err.Error())
		return
	}
	me := mongoconn.Classify(err)
	if me.Kind == mongoconn.KindAuthFailed {
		s.mongoError(w, r, rc, "shell_"+op, err)
		return
	}
	if me.Kind == mongoconn.KindUnauthorized {
		s.Metrics.AuthzDenials.WithLabelValues("mongodb", "unauthorized").Inc()
		s.Audit.Record(r.Context(), s.shellEvent(rc, op, "", "", audit.Denied, "mongodb unauthorized"))
	}
	msg, code, name := me.Msg, me.Code, me.CodeName
	var ce mongo.CommandError
	var we mongo.WriteException
	var bwe mongo.BulkWriteException
	switch {
	case errors.As(err, &ce):
		msg, code, name = ce.Message, ce.Code, ce.Name
	case errors.As(err, &we) && len(we.WriteErrors) > 0:
		msg, code = we.WriteErrors[0].Message, int32(we.WriteErrors[0].Code) // #nosec G115 -- MongoDB error codes are int32
	case errors.As(err, &bwe) && len(bwe.WriteErrors) > 0:
		msg, code = fmt.Sprintf("write %d: %s", bwe.WriteErrors[0].Index, bwe.WriteErrors[0].Message), int32(bwe.WriteErrors[0].Code) // #nosec G115 -- MongoDB error codes are int32
	}
	if len(msg) > 1000 {
		msg = msg[:1000]
	}
	s.Logger.Warn("shell operation failed", "request_id", rc.requestID, "op", op, "kind", me.Kind, "code", code, "code_name", name)
	writeJSON(w, me.HTTPStatus(), map[string]any{"error": map[string]any{
		"code": string(me.Kind), "message": msg, "mongoCode": code, "codeName": name, "requestId": rc.requestID,
	}})
}

var errBadArgs = errors.New("invalid shell operation arguments")

func badArgs(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errBadArgs, fmt.Sprintf(format, a...))
}

func parseArgs(args string, into any) error {
	if strings.TrimSpace(args) == "" {
		args = "{}"
	}
	if err := bson.UnmarshalExtJSON([]byte(args), false, into); err != nil {
		return badArgs("%v", err)
	}
	return nil
}

func checkNS(db, coll string, needColl bool) error {
	if !query.ValidDatabaseName(db) {
		return badArgs("invalid database name %q", db)
	}
	if needColl && !query.ValidCollectionName(coll) {
		return badArgs("invalid collection name %q", coll)
	}
	return nil
}

func checkWritableNS(db, coll string) error {
	if err := checkNS(db, coll, coll != ""); err != nil {
		return err
	}
	if db == "local" || db == "config" {
		return deny("writes to the %q database are not permitted through the portal", db)
	}
	if coll != "" && query.SystemCollection(coll) {
		return deny("system collections cannot be modified through the portal")
	}
	return nil
}

func num(v any) (int64, bool) {
	switch n := v.(type) {
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		if n != math.Trunc(n) || math.IsInf(n, 0) || math.IsNaN(n) {
			return 0, false
		}
		return int64(n), true
	}
	return 0, false
}

func get(d bson.D, key string) (any, bool) {
	for _, e := range d {
		if e.Key == key {
			return e.Value, true
		}
	}
	return nil, false
}

func asDoc(v any) (bson.D, bool) {
	d, ok := v.(bson.D)
	return d, ok
}

func collation(v any) (*options.Collation, error) {
	d, ok := v.(bson.D)
	if !ok {
		return nil, badArgs("collation must be a document")
	}
	raw, err := bson.Marshal(d)
	if err != nil {
		return nil, badArgs("collation: %v", err)
	}
	c := &options.Collation{}
	if err := bson.Unmarshal(raw, c); err != nil {
		return nil, badArgs("collation: %v", err)
	}
	return c, nil
}

func (s *Server) opTimeout(opts bson.D) time.Duration {
	if v, ok := get(opts, "maxTimeMS"); ok {
		if n, ok := num(v); ok {
			return s.maxTime(n)
		}
	}
	return s.Config.Query.DefaultMaxTime
}

func (s *Server) writeTimeout(rc *reqCtx) time.Duration {
	if p, ok := s.Config.Profile(rc.sess.Profile); ok {
		return p.OperationTimeout
	}
	return s.Config.Query.MaxMaxTime
}

// ---- metadata ----

func shConnectionInfo(s *Server, ctx context.Context, rc *reqCtx, _ string) (any, error) {
	var build, hello bson.M
	admin := rc.sess.Client.Database("admin")
	err := s.op(ctx, "buildInfo", s.defaultTimeout(), func(ctx context.Context) error {
		if err := admin.RunCommand(ctx, bson.D{{Key: "buildInfo", Value: 1}}).Decode(&build); err != nil {
			return err
		}
		return admin.RunCommand(ctx, bson.D{{Key: "hello", Value: 1}}).Decode(&hello)
	})
	if err != nil {
		return nil, err
	}
	for _, k := range []string{"$clusterTime", "operationTime", "signature", "storageEngines", "openssl", "buildEnvironment", "allocator", "javascriptEngine"} {
		delete(build, k)
		delete(hello, k)
	}
	return bson.M{"buildInfo": build, "hello": hello, "profile": rc.sess.Profile, "tls": rc.sess.TLS,
		"user": rc.sess.MongoUser, "authSource": rc.sess.AuthSource}, nil
}

func shListDatabases(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error) {
	var a struct {
		Filter   bson.D `bson:"filter"`
		NameOnly bool   `bson:"nameOnly"`
	}
	if err := parseArgs(args, &a); err != nil {
		return nil, err
	}
	if err := query.Filter(a.Filter); err != nil {
		return nil, err
	}
	var res mongo.ListDatabasesResult
	err := s.op(ctx, "listDatabases", s.defaultTimeout(), func(ctx context.Context) error {
		var err error
		f := a.Filter
		if f == nil {
			f = bson.D{}
		}
		res, err = rc.sess.Client.ListDatabases(ctx, f, options.ListDatabases().SetAuthorizedDatabases(true).SetNameOnly(a.NameOnly))
		return err
	})
	if err != nil {
		if mongoconn.Classify(err).Kind != mongoconn.KindUnauthorized {
			return nil, err
		}
		dbs := bson.A{}
		for _, n := range rc.sess.Status.Databases() {
			if !s.allowed(rc, rbac.Databases, rbac.Get, n) {
				continue
			}
			dbs = append(dbs, bson.M{"name": n, "sizeOnDisk": 0, "empty": false})
		}
		return bson.M{"databases": dbs, "ok": 1}, nil
	}
	dbs := bson.A{}
	for _, d := range res.Databases {
		if !s.allowed(rc, rbac.Databases, rbac.Get, d.Name) {
			continue
		}
		dbs = append(dbs, bson.M{"name": d.Name, "sizeOnDisk": d.SizeOnDisk, "empty": d.Empty})
	}
	return bson.M{"databases": dbs, "totalSize": res.TotalSize, "ok": 1}, nil
}

func shListCollections(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error) {
	var a struct {
		DB       string `bson:"db"`
		Filter   bson.D `bson:"filter"`
		NameOnly bool   `bson:"nameOnly"`
	}
	if err := parseArgs(args, &a); err != nil {
		return nil, err
	}
	if err := checkNS(a.DB, "", false); err != nil {
		return nil, err
	}
	if err := query.Filter(a.Filter); err != nil {
		return nil, err
	}
	f := a.Filter
	if f == nil {
		f = bson.D{}
	}
	var out []bson.Raw
	db := rc.sess.Client.Database(a.DB)
	err := s.op(ctx, "listCollections", s.defaultTimeout(), func(ctx context.Context) error {
		cur, err := db.ListCollections(ctx, f, options.ListCollections().SetAuthorizedCollections(true).SetNameOnly(a.NameOnly))
		if err != nil && mongoconn.Classify(err).Kind == mongoconn.KindUnauthorized && !a.NameOnly {
			cur, err = db.ListCollections(ctx, f, options.ListCollections().SetAuthorizedCollections(true).SetNameOnly(true))
		}
		if err != nil {
			return err
		}
		return cur.All(ctx, &out)
	})
	if err != nil {
		return nil, err
	}
	out = slices.DeleteFunc(out, func(c bson.Raw) bool {
		name, _ := c.Lookup("name").StringValueOK()
		return !s.allowed(rc, rbac.Collections, rbac.Get, rbac.Namespace(a.DB, name))
	})
	if out == nil {
		out = []bson.Raw{}
	}
	return bson.M{"collections": out}, nil
}

func shGetIndexes(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error) {
	var a struct {
		DB   string `bson:"db"`
		Coll string `bson:"coll"`
	}
	if err := parseArgs(args, &a); err != nil {
		return nil, err
	}
	if err := checkNS(a.DB, a.Coll, true); err != nil {
		return nil, err
	}
	var out []bson.Raw
	err := s.op(ctx, "listIndexes", s.defaultTimeout(), func(ctx context.Context) error {
		cur, err := rc.sess.Client.Database(a.DB).Collection(a.Coll).Indexes().List(ctx)
		if err != nil {
			return err
		}
		return cur.All(ctx, &out)
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []bson.Raw{}
	}
	return bson.M{"indexes": out}, nil
}

// ---- cursors ----

type cursorReply struct {
	ID        string     `bson:"id"`
	Batch     []bson.Raw `bson:"batch"`
	Exhausted bool       `bson:"exhausted"`
}

func (s *Server) batchSize(v any) int {
	n, ok := num(v)
	if !ok || n <= 0 {
		return 100
	}
	return int(min(n, int64(s.Config.Shell.MaxBatchDocuments)))
}

// readBatch reads up to n documents, bounded by half the response cap.
func (s *Server) readBatch(ctx context.Context, cur *mongo.Cursor, n int) ([]bson.Raw, bool, error) {
	docs := make([]bson.Raw, 0, min(n, 128))
	size := 0
	limit := s.Config.Query.MaxResponseBytes / 2
	for len(docs) < n && size < limit {
		if !cur.Next(ctx) {
			if err := cur.Err(); err != nil {
				return nil, false, err
			}
			return docs, true, nil
		}
		d := make(bson.Raw, len(cur.Current))
		copy(d, cur.Current)
		docs = append(docs, d)
		size += len(d)
	}
	return docs, cur.ID() == 0 && cur.RemainingBatchLength() == 0, nil
}

// openCursor reads the first batch and registers the cursor if more remain.
func (s *Server) openCursor(ctx context.Context, rc *reqCtx, cur *mongo.Cursor, n int) (*cursorReply, error) {
	docs, exhausted, err := s.readBatch(ctx, cur, n)
	if err != nil {
		_ = cur.Close(context.Background())
		return nil, err
	}
	reply := &cursorReply{Batch: docs, Exhausted: exhausted}
	if exhausted {
		_ = cur.Close(context.Background())
		return reply, nil
	}
	c, err := rc.sess.AddCursor(cur, s.Config.Shell.MaxCursors, s.Config.Shell.CursorIdleTimeout)
	if err != nil {
		_ = cur.Close(context.Background())
		return nil, err
	}
	c.Returned = int64(len(docs))
	reply.ID = c.ID
	return reply, nil
}

func shFind(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error) {
	var a struct {
		DB      string `bson:"db"`
		Coll    string `bson:"coll"`
		Filter  bson.D `bson:"filter"`
		Options bson.D `bson:"options"`
	}
	if err := parseArgs(args, &a); err != nil {
		return nil, err
	}
	if err := checkNS(a.DB, a.Coll, true); err != nil {
		return nil, err
	}
	if err := query.Filter(a.Filter); err != nil {
		return nil, err
	}
	fo := options.Find()
	batch := 100
	for _, e := range a.Options {
		switch e.Key {
		case "projection":
			d, ok := asDoc(e.Value)
			if !ok {
				return nil, badArgs("projection must be a document")
			}
			if err := query.Projection(d); err != nil {
				return nil, err
			}
			fo.SetProjection(d)
		case "sort":
			d, ok := asDoc(e.Value)
			if !ok {
				return nil, badArgs("sort must be a document")
			}
			if err := query.Sort(d); err != nil {
				return nil, err
			}
			fo.SetSort(d)
		case "skip":
			n, ok := num(e.Value)
			if !ok || n < 0 {
				return nil, badArgs("skip must be a non-negative integer")
			}
			fo.SetSkip(n)
		case "limit":
			n, ok := num(e.Value)
			if !ok {
				return nil, badArgs("limit must be an integer")
			}
			if n < 0 {
				n = -n
			}
			if n > 0 {
				fo.SetLimit(n)
			}
		case "hint":
			if err := query.Value(e.Value); err != nil {
				return nil, err
			}
			fo.SetHint(e.Value)
		case "collation":
			c, err := collation(e.Value)
			if err != nil {
				return nil, err
			}
			fo.SetCollation(c)
		case "comment":
			fo.SetComment(e.Value)
		case "min", "max":
			d, ok := asDoc(e.Value)
			if !ok {
				return nil, badArgs("%s must be a document", e.Key)
			}
			if e.Key == "min" {
				fo.SetMin(d)
			} else {
				fo.SetMax(d)
			}
		case "returnKey":
			b, _ := e.Value.(bool)
			fo.SetReturnKey(b)
		case "showRecordId":
			b, _ := e.Value.(bool)
			fo.SetShowRecordID(b)
		case "allowDiskUse":
			b, _ := e.Value.(bool)
			fo.SetAllowDiskUse(b)
		case "batchSize":
			batch = s.batchSize(e.Value)
		case "noCursorTimeout", "tailable", "awaitData", "oplogReplay", "exhaust":
			return nil, deny("cursor option %q is not permitted", e.Key)
		}
	}
	fo.SetBatchSize(int32(batch)) // #nosec G115 -- bounded by shell.maxBatchDocuments
	var reply *cursorReply
	err := s.op(ctx, "find", s.opTimeout(a.Options), func(ctx context.Context) error {
		cur, err := rc.sess.Client.Database(a.DB).Collection(a.Coll).Find(ctx, a.Filter, fo)
		if err != nil {
			return err
		}
		reply, err = s.openCursor(ctx, rc, cur, batch)
		return err
	})
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func toStages(a bson.A) ([]bson.D, error) {
	out := make([]bson.D, 0, len(a))
	for _, v := range a {
		d, ok := v.(bson.D)
		if !ok {
			return nil, badArgs("pipeline stages must be documents")
		}
		out = append(out, d)
	}
	return out, nil
}

func shAggregate(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error) {
	var a struct {
		DB       string `bson:"db"`
		Coll     string `bson:"coll"`
		Pipeline bson.A `bson:"pipeline"`
		Options  bson.D `bson:"options"`
	}
	if err := parseArgs(args, &a); err != nil {
		return nil, err
	}
	if err := checkNS(a.DB, a.Coll, a.Coll != ""); err != nil {
		return nil, err
	}
	stages, err := toStages(a.Pipeline)
	if err != nil {
		return nil, err
	}
	if reason, ok := s.pipelineAccess(rc, a.DB, stages); !ok {
		return nil, deny("%s", reason)
	}
	policy := query.Policy{AllowWriteStages: s.Config.Query.AllowWriteStages}
	if err := query.Pipeline(stages, policy); err != nil {
		if query.HasWriteStage(stages) {
			s.Metrics.AuthzDenials.WithLabelValues("portal", "write_stage").Inc()
		}
		return nil, err
	}
	write := query.HasWriteStage(stages)
	ao := options.Aggregate()
	batch := 100
	for _, e := range a.Options {
		switch e.Key {
		case "allowDiskUse":
			b, _ := e.Value.(bool)
			ao.SetAllowDiskUse(b)
		case "batchSize":
			batch = s.batchSize(e.Value)
		case "collation":
			c, err := collation(e.Value)
			if err != nil {
				return nil, err
			}
			ao.SetCollation(c)
		case "hint":
			if err := query.Value(e.Value); err != nil {
				return nil, err
			}
			ao.SetHint(e.Value)
		case "comment":
			ao.SetComment(e.Value)
		case "let":
			d, ok := asDoc(e.Value)
			if !ok {
				return nil, badArgs("let must be a document")
			}
			if err := query.Value(d); err != nil {
				return nil, err
			}
			ao.SetLet(d)
		}
	}
	ao.SetBatchSize(int32(batch)) // #nosec G115 -- bounded by shell.maxBatchDocuments
	pipe := make(bson.A, 0, len(stages))
	for _, st := range stages {
		pipe = append(pipe, st)
	}
	var reply *cursorReply
	err = s.op(ctx, "aggregate", s.opTimeout(a.Options), func(ctx context.Context) error {
		var cur *mongo.Cursor
		var err error
		if a.Coll == "" {
			cur, err = rc.sess.Client.Database(a.DB).Aggregate(ctx, pipe, ao)
		} else {
			cur, err = rc.sess.Client.Database(a.DB).Collection(a.Coll).Aggregate(ctx, pipe, ao)
		}
		if err != nil {
			return err
		}
		reply, err = s.openCursor(ctx, rc, cur, batch)
		return err
	})
	if err != nil {
		return nil, err
	}
	if write {
		s.Audit.Record(ctx, s.shellEvent(rc, "aggregate_write_stage", a.DB, a.Coll, audit.Success, ""))
	}
	return reply, nil
}

func shGetMore(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error) {
	var a struct {
		ID        string `bson:"id"`
		BatchSize any    `bson:"batchSize"`
	}
	if err := parseArgs(args, &a); err != nil {
		return nil, err
	}
	c, ok := rc.sess.GetCursor(a.ID, s.Config.Shell.CursorIdleTimeout)
	if !ok {
		return nil, badArgs("cursor not found (it may have expired or belong to another portal instance)")
	}
	cur, ok := c.Cursor.(*mongo.Cursor)
	if !ok {
		return nil, badArgs("invalid cursor")
	}
	c.Lock()
	defer c.Unlock()
	n := s.batchSize(a.BatchSize)
	if remaining := s.Config.Shell.MaxCursorDocuments - c.Returned; int64(n) > remaining {
		if remaining <= 0 {
			rc.sess.CloseCursor(a.ID)
			return nil, deny("cursor reached the limit of %d documents; refine the query", s.Config.Shell.MaxCursorDocuments)
		}
		n = int(remaining)
	}
	var docs []bson.Raw
	var exhausted bool
	err := s.op(ctx, "getMore", s.Config.Query.MaxMaxTime, func(ctx context.Context) error {
		var err error
		docs, exhausted, err = s.readBatch(ctx, cur, n)
		return err
	})
	if err != nil {
		rc.sess.CloseCursor(a.ID)
		return nil, err
	}
	c.Returned += int64(len(docs))
	if exhausted {
		rc.sess.CloseCursor(a.ID)
	}
	return &cursorReply{ID: a.ID, Batch: docs, Exhausted: exhausted}, nil
}

func shKillCursor(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error) {
	var a struct {
		ID string `bson:"id"`
	}
	if err := parseArgs(args, &a); err != nil {
		return nil, err
	}
	rc.sess.CloseCursor(a.ID)
	return bson.M{"ok": 1}, nil
}

// ---- counts and distinct ----

func shCountDocuments(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error) {
	var a struct {
		DB      string `bson:"db"`
		Coll    string `bson:"coll"`
		Filter  bson.D `bson:"filter"`
		Options bson.D `bson:"options"`
	}
	if err := parseArgs(args, &a); err != nil {
		return nil, err
	}
	if err := checkNS(a.DB, a.Coll, true); err != nil {
		return nil, err
	}
	if a.Filter == nil {
		a.Filter = bson.D{}
	}
	if err := query.Filter(a.Filter); err != nil {
		return nil, err
	}
	co := options.Count().SetLimit(s.Config.Query.MaxCount)
	for _, e := range a.Options {
		switch e.Key {
		case "limit":
			if n, ok := num(e.Value); ok && n > 0 {
				co.SetLimit(min(n, s.Config.Query.MaxCount))
			}
		case "skip":
			if n, ok := num(e.Value); ok && n >= 0 {
				co.SetSkip(n)
			}
		case "hint":
			if err := query.Value(e.Value); err != nil {
				return nil, err
			}
			co.SetHint(e.Value)
		case "collation":
			c, err := collation(e.Value)
			if err != nil {
				return nil, err
			}
			co.SetCollation(c)
		}
	}
	var n int64
	err := s.op(ctx, "countDocuments", s.opTimeout(a.Options), func(ctx context.Context) error {
		var err error
		n, err = rc.sess.Client.Database(a.DB).Collection(a.Coll).CountDocuments(ctx, a.Filter, co)
		return err
	})
	if err != nil {
		return nil, err
	}
	return bson.M{"n": n}, nil
}

func shEstimatedCount(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error) {
	var a struct {
		DB   string `bson:"db"`
		Coll string `bson:"coll"`
	}
	if err := parseArgs(args, &a); err != nil {
		return nil, err
	}
	if err := checkNS(a.DB, a.Coll, true); err != nil {
		return nil, err
	}
	var n int64
	err := s.op(ctx, "estimatedDocumentCount", s.defaultTimeout(), func(ctx context.Context) error {
		var err error
		n, err = rc.sess.Client.Database(a.DB).Collection(a.Coll).EstimatedDocumentCount(ctx)
		return err
	})
	if err != nil {
		return nil, err
	}
	return bson.M{"n": n}, nil
}

func shDistinct(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error) {
	var a struct {
		DB      string `bson:"db"`
		Coll    string `bson:"coll"`
		Key     string `bson:"key"`
		Filter  bson.D `bson:"filter"`
		Options bson.D `bson:"options"`
	}
	if err := parseArgs(args, &a); err != nil {
		return nil, err
	}
	if err := checkNS(a.DB, a.Coll, true); err != nil {
		return nil, err
	}
	if a.Key == "" {
		return nil, badArgs("distinct requires a field name")
	}
	if a.Filter == nil {
		a.Filter = bson.D{}
	}
	if err := query.Filter(a.Filter); err != nil {
		return nil, err
	}
	do := options.Distinct()
	if v, ok := get(a.Options, "collation"); ok {
		c, err := collation(v)
		if err != nil {
			return nil, err
		}
		do.SetCollation(c)
	}
	// Decode into bson.A: a bson.RawArray is a []byte and would be
	// serialised as Binary rather than as an array.
	values := bson.A{}
	err := s.op(ctx, "distinct", s.opTimeout(a.Options), func(ctx context.Context) error {
		res := rc.sess.Client.Database(a.DB).Collection(a.Coll).Distinct(ctx, a.Key, a.Filter, do)
		if err := res.Err(); err != nil {
			return err
		}
		return res.Decode(&values)
	})
	if err != nil {
		return nil, err
	}
	return bson.D{{Key: "values", Value: values}}, nil
}

// ---- explain and commands ----

func shExplain(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error) {
	var a struct {
		DB        string `bson:"db"`
		Coll      string `bson:"coll"`
		Kind      string `bson:"kind"`
		Filter    bson.D `bson:"filter"`
		Pipeline  bson.A `bson:"pipeline"`
		Options   bson.D `bson:"options"`
		Verbosity string `bson:"verbosity"`
	}
	if err := parseArgs(args, &a); err != nil {
		return nil, err
	}
	if err := checkNS(a.DB, a.Coll, true); err != nil {
		return nil, err
	}
	switch a.Verbosity {
	case "", "queryPlanner", "executionStats", "allPlansExecution":
	default:
		return nil, badArgs("invalid explain verbosity %q", a.Verbosity)
	}
	if a.Verbosity == "" {
		a.Verbosity = "queryPlanner"
	}
	var inner bson.D
	switch a.Kind {
	case "find":
		if a.Filter == nil {
			a.Filter = bson.D{}
		}
		inner = bson.D{{Key: "find", Value: a.Coll}, {Key: "filter", Value: a.Filter}}
		for _, k := range []string{"projection", "sort", "skip", "limit", "hint", "collation", "min", "max"} {
			if v, ok := get(a.Options, k); ok {
				inner = append(inner, bson.E{Key: k, Value: v})
			}
		}
	case "aggregate":
		inner = bson.D{{Key: "aggregate", Value: a.Coll}, {Key: "pipeline", Value: a.Pipeline}, {Key: "cursor", Value: bson.D{}}}
	default:
		return nil, badArgs("explain kind must be find or aggregate")
	}
	cmd := bson.D{{Key: "explain", Value: inner}, {Key: "verbosity", Value: a.Verbosity}}
	if err := query.Command(cmd, query.Policy{}); err != nil {
		return nil, err
	}
	if a.Kind == "find" {
		if err := query.Filter(a.Filter); err != nil {
			return nil, err
		}
	}
	return s.runCmd(ctx, rc, a.DB, cmd, s.opTimeout(a.Options))
}

func (s *Server) runCmd(ctx context.Context, rc *reqCtx, db string, cmd bson.D, timeout time.Duration) (any, error) {
	var raw bson.Raw
	err := s.op(ctx, "runCommand", timeout, func(ctx context.Context) error {
		var err error
		raw, err = rc.sess.Client.Database(db).RunCommand(ctx, cmd).Raw()
		return err
	})
	if err != nil {
		return nil, err
	}
	elems, err := raw.Elements()
	if err != nil {
		return nil, err
	}
	out := bson.D{}
	for _, e := range elems {
		switch e.Key() {
		case "$clusterTime", "operationTime", "signature", "$configTime", "$topologyTime":
			continue
		}
		out = append(out, bson.E{Key: e.Key(), Value: e.Value()})
	}
	return bson.D{{Key: "result", Value: out}}, nil
}

func shRunCommand(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error) {
	var a struct {
		DB      string `bson:"db"`
		Command bson.D `bson:"command"`
	}
	if err := parseArgs(args, &a); err != nil {
		return nil, err
	}
	if err := checkNS(a.DB, "", false); err != nil {
		return nil, err
	}
	name, class := query.ClassifyCommand(a.Command)
	switch class {
	case query.CommandDenied:
		return nil, deny("the %q command is not permitted through the portal shell", name)
	case query.CommandAdmin:
		if !s.allowed(rc, rbac.Shell, rbac.Admin, a.DB) {
			return nil, deny("the %q command requires the shell admin permission (shell, admin, %s)", name, a.DB)
		}
		if destructiveCommands[name] && !confirmed(ctx, "runCommand") {
			return nil, deny("the %q command requires confirmation", name)
		}
	}
	if err := query.Command(a.Command, query.Policy{}); err != nil {
		return nil, err
	}
	res, err := s.runCmd(ctx, rc, a.DB, a.Command, s.opTimeout(a.Command))
	if err != nil {
		return nil, err
	}
	if class == query.CommandAdmin {
		s.Audit.Record(ctx, s.shellEvent(rc, "runCommand", a.DB, "", audit.Success, name))
	}
	return res, nil
}

// ---- writes ----

func (s *Server) auditWrite(ctx context.Context, rc *reqCtx, op, db, coll string) {
	s.Audit.Record(ctx, s.shellEvent(rc, op, db, coll, audit.Success, ""))
}

func validateDocs(docs ...bson.D) error {
	for _, d := range docs {
		for _, e := range d {
			if strings.HasPrefix(e.Key, "$") {
				return query.Replacement(d)
			}
		}
		if err := query.Value(d); err != nil {
			return err
		}
	}
	return nil
}

func shInsertOne(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error) {
	var a struct {
		DB       string `bson:"db"`
		Coll     string `bson:"coll"`
		Document bson.D `bson:"document"`
	}
	if err := parseArgs(args, &a); err != nil {
		return nil, err
	}
	if err := checkWritableNS(a.DB, a.Coll); err != nil {
		return nil, err
	}
	if err := validateDocs(a.Document); err != nil {
		return nil, err
	}
	var res *mongo.InsertOneResult
	err := s.op(ctx, "insertOne", s.writeTimeout(rc), func(ctx context.Context) error {
		var err error
		res, err = rc.sess.Client.Database(a.DB).Collection(a.Coll).InsertOne(ctx, a.Document)
		return err
	})
	if err != nil {
		return nil, err
	}
	s.auditWrite(ctx, rc, "insertOne", a.DB, a.Coll)
	return bson.D{{Key: "insertedId", Value: res.InsertedID}}, nil
}

func shInsertMany(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error) {
	var a struct {
		DB        string   `bson:"db"`
		Coll      string   `bson:"coll"`
		Documents []bson.D `bson:"documents"`
		Ordered   *bool    `bson:"ordered"`
	}
	if err := parseArgs(args, &a); err != nil {
		return nil, err
	}
	if err := checkWritableNS(a.DB, a.Coll); err != nil {
		return nil, err
	}
	if len(a.Documents) == 0 || len(a.Documents) > s.Config.Shell.MaxInsertDocuments {
		return nil, badArgs("insertMany accepts between 1 and %d documents", s.Config.Shell.MaxInsertDocuments)
	}
	if err := validateDocs(a.Documents...); err != nil {
		return nil, err
	}
	docs := make([]any, len(a.Documents))
	for i := range a.Documents {
		docs[i] = a.Documents[i]
	}
	io := options.InsertMany()
	if a.Ordered != nil {
		io.SetOrdered(*a.Ordered)
	}
	var res *mongo.InsertManyResult
	err := s.op(ctx, "insertMany", s.writeTimeout(rc), func(ctx context.Context) error {
		var err error
		res, err = rc.sess.Client.Database(a.DB).Collection(a.Coll).InsertMany(ctx, docs, io)
		return err
	})
	if err != nil {
		return nil, err
	}
	s.auditWrite(ctx, rc, "insertMany", a.DB, a.Coll)
	ids := bson.A{}
	for _, id := range res.InsertedIDs {
		ids = append(ids, id)
	}
	return bson.D{{Key: "insertedIds", Value: ids}}, nil
}

type writeOpts struct {
	upsert       *bool
	arrayFilters []any
	hint         any
	collation    *options.Collation
}

func parseWriteOpts(d bson.D) (*writeOpts, error) {
	w := &writeOpts{}
	for _, e := range d {
		switch e.Key {
		case "upsert":
			b, _ := e.Value.(bool)
			w.upsert = &b
		case "arrayFilters":
			arr, ok := e.Value.(bson.A)
			if !ok {
				return nil, badArgs("arrayFilters must be an array")
			}
			for _, f := range arr {
				fd, ok := f.(bson.D)
				if !ok {
					return nil, badArgs("arrayFilters entries must be documents")
				}
				if err := query.Filter(fd); err != nil {
					return nil, err
				}
				w.arrayFilters = append(w.arrayFilters, fd)
			}
		case "hint":
			if err := query.Value(e.Value); err != nil {
				return nil, err
			}
			w.hint = e.Value
		case "collation":
			c, err := collation(e.Value)
			if err != nil {
				return nil, err
			}
			w.collation = c
		}
	}
	return w, nil
}

func updateResult(r *mongo.UpdateResult) bson.D {
	return bson.D{{Key: "matchedCount", Value: r.MatchedCount}, {Key: "modifiedCount", Value: r.ModifiedCount},
		{Key: "upsertedCount", Value: r.UpsertedCount}, {Key: "upsertedId", Value: r.UpsertedID}}
}

func shUpdate(many bool) shellFn {
	op := "updateOne"
	if many {
		op = "updateMany"
	}
	return func(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error) {
		var a struct {
			DB      string `bson:"db"`
			Coll    string `bson:"coll"`
			Filter  bson.D `bson:"filter"`
			Update  any    `bson:"update"`
			Options bson.D `bson:"options"`
		}
		if err := parseArgs(args, &a); err != nil {
			return nil, err
		}
		if err := checkWritableNS(a.DB, a.Coll); err != nil {
			return nil, err
		}
		if a.Filter == nil {
			a.Filter = bson.D{}
		}
		if err := query.Filter(a.Filter); err != nil {
			return nil, err
		}
		if err := query.Update(a.Update); err != nil {
			return nil, err
		}
		wo, err := parseWriteOpts(a.Options)
		if err != nil {
			return nil, err
		}
		c := rc.sess.Client.Database(a.DB).Collection(a.Coll)
		var res *mongo.UpdateResult
		err = s.op(ctx, op, s.writeTimeout(rc), func(ctx context.Context) error {
			var err error
			if many {
				uo := options.UpdateMany()
				if wo.upsert != nil {
					uo.SetUpsert(*wo.upsert)
				}
				if wo.arrayFilters != nil {
					uo.SetArrayFilters(wo.arrayFilters)
				}
				if wo.hint != nil {
					uo.SetHint(wo.hint)
				}
				if wo.collation != nil {
					uo.SetCollation(wo.collation)
				}
				res, err = c.UpdateMany(ctx, a.Filter, a.Update, uo)
			} else {
				uo := options.UpdateOne()
				if wo.upsert != nil {
					uo.SetUpsert(*wo.upsert)
				}
				if wo.arrayFilters != nil {
					uo.SetArrayFilters(wo.arrayFilters)
				}
				if wo.hint != nil {
					uo.SetHint(wo.hint)
				}
				if wo.collation != nil {
					uo.SetCollation(wo.collation)
				}
				res, err = c.UpdateOne(ctx, a.Filter, a.Update, uo)
			}
			return err
		})
		if err != nil {
			return nil, err
		}
		s.auditWrite(ctx, rc, op, a.DB, a.Coll)
		return updateResult(res), nil
	}
}

func shReplaceOne(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error) {
	var a struct {
		DB          string `bson:"db"`
		Coll        string `bson:"coll"`
		Filter      bson.D `bson:"filter"`
		Replacement bson.D `bson:"replacement"`
		Options     bson.D `bson:"options"`
	}
	if err := parseArgs(args, &a); err != nil {
		return nil, err
	}
	if err := checkWritableNS(a.DB, a.Coll); err != nil {
		return nil, err
	}
	if a.Filter == nil {
		a.Filter = bson.D{}
	}
	if err := query.Filter(a.Filter); err != nil {
		return nil, err
	}
	if a.Replacement == nil {
		a.Replacement = bson.D{}
	}
	if err := query.Replacement(a.Replacement); err != nil {
		return nil, err
	}
	wo, err := parseWriteOpts(a.Options)
	if err != nil {
		return nil, err
	}
	ro := options.Replace()
	if wo.upsert != nil {
		ro.SetUpsert(*wo.upsert)
	}
	if wo.hint != nil {
		ro.SetHint(wo.hint)
	}
	if wo.collation != nil {
		ro.SetCollation(wo.collation)
	}
	var res *mongo.UpdateResult
	err = s.op(ctx, "replaceOne", s.writeTimeout(rc), func(ctx context.Context) error {
		var err error
		res, err = rc.sess.Client.Database(a.DB).Collection(a.Coll).ReplaceOne(ctx, a.Filter, a.Replacement, ro)
		return err
	})
	if err != nil {
		return nil, err
	}
	s.auditWrite(ctx, rc, "replaceOne", a.DB, a.Coll)
	return updateResult(res), nil
}

func shDelete(many bool) shellFn {
	op := "deleteOne"
	if many {
		op = "deleteMany"
	}
	return func(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error) {
		var a struct {
			DB      string `bson:"db"`
			Coll    string `bson:"coll"`
			Filter  bson.D `bson:"filter"`
			Options bson.D `bson:"options"`
		}
		if err := parseArgs(args, &a); err != nil {
			return nil, err
		}
		if err := checkWritableNS(a.DB, a.Coll); err != nil {
			return nil, err
		}
		if a.Filter == nil {
			a.Filter = bson.D{}
		}
		if err := query.Filter(a.Filter); err != nil {
			return nil, err
		}
		wo, err := parseWriteOpts(a.Options)
		if err != nil {
			return nil, err
		}
		c := rc.sess.Client.Database(a.DB).Collection(a.Coll)
		var res *mongo.DeleteResult
		err = s.op(ctx, op, s.writeTimeout(rc), func(ctx context.Context) error {
			var err error
			if many {
				do := options.DeleteMany()
				if wo.hint != nil {
					do.SetHint(wo.hint)
				}
				if wo.collation != nil {
					do.SetCollation(wo.collation)
				}
				res, err = c.DeleteMany(ctx, a.Filter, do)
			} else {
				do := options.DeleteOne()
				if wo.hint != nil {
					do.SetHint(wo.hint)
				}
				if wo.collation != nil {
					do.SetCollation(wo.collation)
				}
				res, err = c.DeleteOne(ctx, a.Filter, do)
			}
			return err
		})
		if err != nil {
			return nil, err
		}
		s.auditWrite(ctx, rc, op, a.DB, a.Coll)
		return bson.D{{Key: "deletedCount", Value: res.DeletedCount}}, nil
	}
}

type famArgs struct {
	DB          string `bson:"db"`
	Coll        string `bson:"coll"`
	Filter      bson.D `bson:"filter"`
	Update      any    `bson:"update"`
	Replacement bson.D `bson:"replacement"`
	Options     bson.D `bson:"options"`
}

type famOpts struct {
	projection, sort bson.D
	after            bool
	write            *writeOpts
}

func parseFamArgs(args string) (*famArgs, *famOpts, error) {
	a := &famArgs{}
	if err := parseArgs(args, a); err != nil {
		return nil, nil, err
	}
	if err := checkWritableNS(a.DB, a.Coll); err != nil {
		return nil, nil, err
	}
	if a.Filter == nil {
		a.Filter = bson.D{}
	}
	if err := query.Filter(a.Filter); err != nil {
		return nil, nil, err
	}
	o := &famOpts{}
	for _, e := range a.Options {
		switch e.Key {
		case "projection":
			d, ok := asDoc(e.Value)
			if !ok {
				return nil, nil, badArgs("projection must be a document")
			}
			if err := query.Projection(d); err != nil {
				return nil, nil, err
			}
			o.projection = d
		case "sort":
			d, ok := asDoc(e.Value)
			if !ok {
				return nil, nil, badArgs("sort must be a document")
			}
			if err := query.Sort(d); err != nil {
				return nil, nil, err
			}
			o.sort = d
		case "returnDocument":
			o.after = e.Value == "after"
		case "returnNewDocument", "returnOriginal":
			b, _ := e.Value.(bool)
			if e.Key == "returnNewDocument" {
				o.after = b
			} else {
				o.after = !b
			}
		}
	}
	w, err := parseWriteOpts(a.Options)
	if err != nil {
		return nil, nil, err
	}
	o.write = w
	return a, o, nil
}

func famResult(sr *mongo.SingleResult) (any, error) {
	raw, err := sr.Raw()
	if errors.Is(err, mongo.ErrNoDocuments) {
		return bson.D{{Key: "value", Value: nil}}, nil
	}
	if err != nil {
		return nil, err
	}
	return bson.D{{Key: "value", Value: raw}}, nil
}

func returnDoc(after bool) options.ReturnDocument {
	if after {
		return options.After
	}
	return options.Before
}

func shFindOneAndDelete(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error) {
	a, o, err := parseFamArgs(args)
	if err != nil {
		return nil, err
	}
	fo := options.FindOneAndDelete()
	if o.projection != nil {
		fo.SetProjection(o.projection)
	}
	if o.sort != nil {
		fo.SetSort(o.sort)
	}
	if o.write.hint != nil {
		fo.SetHint(o.write.hint)
	}
	if o.write.collation != nil {
		fo.SetCollation(o.write.collation)
	}
	var res any
	err = s.op(ctx, "findOneAndDelete", s.writeTimeout(rc), func(ctx context.Context) error {
		var err error
		res, err = famResult(rc.sess.Client.Database(a.DB).Collection(a.Coll).FindOneAndDelete(ctx, a.Filter, fo))
		return err
	})
	if err != nil {
		return nil, err
	}
	s.auditWrite(ctx, rc, "findOneAndDelete", a.DB, a.Coll)
	return res, nil
}

func shFindOneAndReplace(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error) {
	a, o, err := parseFamArgs(args)
	if err != nil {
		return nil, err
	}
	if a.Replacement == nil {
		a.Replacement = bson.D{}
	}
	if err := query.Replacement(a.Replacement); err != nil {
		return nil, err
	}
	fo := options.FindOneAndReplace().SetReturnDocument(returnDoc(o.after))
	if o.projection != nil {
		fo.SetProjection(o.projection)
	}
	if o.sort != nil {
		fo.SetSort(o.sort)
	}
	if o.write.upsert != nil {
		fo.SetUpsert(*o.write.upsert)
	}
	if o.write.hint != nil {
		fo.SetHint(o.write.hint)
	}
	if o.write.collation != nil {
		fo.SetCollation(o.write.collation)
	}
	var res any
	err = s.op(ctx, "findOneAndReplace", s.writeTimeout(rc), func(ctx context.Context) error {
		var err error
		res, err = famResult(rc.sess.Client.Database(a.DB).Collection(a.Coll).FindOneAndReplace(ctx, a.Filter, a.Replacement, fo))
		return err
	})
	if err != nil {
		return nil, err
	}
	s.auditWrite(ctx, rc, "findOneAndReplace", a.DB, a.Coll)
	return res, nil
}

func shFindOneAndUpdate(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error) {
	a, o, err := parseFamArgs(args)
	if err != nil {
		return nil, err
	}
	if err := query.Update(a.Update); err != nil {
		return nil, err
	}
	fo := options.FindOneAndUpdate().SetReturnDocument(returnDoc(o.after))
	if o.projection != nil {
		fo.SetProjection(o.projection)
	}
	if o.sort != nil {
		fo.SetSort(o.sort)
	}
	if o.write.upsert != nil {
		fo.SetUpsert(*o.write.upsert)
	}
	if o.write.arrayFilters != nil {
		fo.SetArrayFilters(o.write.arrayFilters)
	}
	if o.write.hint != nil {
		fo.SetHint(o.write.hint)
	}
	if o.write.collation != nil {
		fo.SetCollation(o.write.collation)
	}
	var res any
	err = s.op(ctx, "findOneAndUpdate", s.writeTimeout(rc), func(ctx context.Context) error {
		var err error
		res, err = famResult(rc.sess.Client.Database(a.DB).Collection(a.Coll).FindOneAndUpdate(ctx, a.Filter, a.Update, fo))
		return err
	})
	if err != nil {
		return nil, err
	}
	s.auditWrite(ctx, rc, "findOneAndUpdate", a.DB, a.Coll)
	return res, nil
}

func shBulkWrite(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error) {
	var a struct {
		DB         string   `bson:"db"`
		Coll       string   `bson:"coll"`
		Operations []bson.D `bson:"operations"`
		Ordered    *bool    `bson:"ordered"`
	}
	if err := parseArgs(args, &a); err != nil {
		return nil, err
	}
	if err := checkWritableNS(a.DB, a.Coll); err != nil {
		return nil, err
	}
	if len(a.Operations) == 0 || len(a.Operations) > s.Config.Shell.MaxInsertDocuments {
		return nil, badArgs("bulkWrite accepts between 1 and %d operations", s.Config.Shell.MaxInsertDocuments)
	}
	models := make([]mongo.WriteModel, 0, len(a.Operations))
	for i, op := range a.Operations {
		if len(op) != 1 {
			return nil, badArgs("operation %d must have exactly one key", i)
		}
		body, ok := op[0].Value.(bson.D)
		if !ok {
			return nil, badArgs("operation %d must be a document", i)
		}
		filter, _ := get(body, "filter")
		f, _ := filter.(bson.D)
		if f == nil {
			f = bson.D{}
		}
		upsert := false
		if v, ok := get(body, "upsert"); ok {
			upsert, _ = v.(bool)
		}
		switch op[0].Key {
		case "insertOne":
			doc, _ := get(body, "document")
			d, ok := doc.(bson.D)
			if !ok {
				return nil, badArgs("insertOne %d requires a document", i)
			}
			if err := validateDocs(d); err != nil {
				return nil, err
			}
			models = append(models, mongo.NewInsertOneModel().SetDocument(d))
			continue
		case "updateOne", "updateMany", "replaceOne", "deleteOne", "deleteMany":
		default:
			return nil, badArgs("bulkWrite operation %q is not supported", op[0].Key)
		}
		if err := query.Filter(f); err != nil {
			return nil, err
		}
		switch op[0].Key {
		case "updateOne", "updateMany":
			u, _ := get(body, "update")
			if err := query.Update(u); err != nil {
				return nil, err
			}
			if op[0].Key == "updateOne" {
				models = append(models, mongo.NewUpdateOneModel().SetFilter(f).SetUpdate(u).SetUpsert(upsert))
			} else {
				models = append(models, mongo.NewUpdateManyModel().SetFilter(f).SetUpdate(u).SetUpsert(upsert))
			}
		case "replaceOne":
			r, _ := get(body, "replacement")
			rd, ok := r.(bson.D)
			if !ok {
				return nil, badArgs("replaceOne %d requires a replacement document", i)
			}
			if err := query.Replacement(rd); err != nil {
				return nil, err
			}
			models = append(models, mongo.NewReplaceOneModel().SetFilter(f).SetReplacement(rd).SetUpsert(upsert))
		case "deleteOne":
			models = append(models, mongo.NewDeleteOneModel().SetFilter(f))
		case "deleteMany":
			models = append(models, mongo.NewDeleteManyModel().SetFilter(f))
		}
	}
	bo := options.BulkWrite()
	if a.Ordered != nil {
		bo.SetOrdered(*a.Ordered)
	}
	var res *mongo.BulkWriteResult
	err := s.op(ctx, "bulkWrite", s.writeTimeout(rc), func(ctx context.Context) error {
		var err error
		res, err = rc.sess.Client.Database(a.DB).Collection(a.Coll).BulkWrite(ctx, models, bo)
		return err
	})
	if err != nil {
		return nil, err
	}
	s.auditWrite(ctx, rc, "bulkWrite", a.DB, a.Coll)
	ups := bson.D{}
	for k, v := range res.UpsertedIDs {
		ups = append(ups, bson.E{Key: fmt.Sprint(k), Value: v})
	}
	return bson.D{{Key: "insertedCount", Value: res.InsertedCount}, {Key: "matchedCount", Value: res.MatchedCount},
		{Key: "modifiedCount", Value: res.ModifiedCount}, {Key: "deletedCount", Value: res.DeletedCount},
		{Key: "upsertedCount", Value: res.UpsertedCount}, {Key: "upsertedIds", Value: ups}}, nil
}

// indexOptionKeys are index options accepted from the shell.
var indexOptionKeys = map[string]bool{
	"name": true, "unique": true, "sparse": true, "hidden": true, "expireAfterSeconds": true,
	"partialFilterExpression": true, "collation": true, "weights": true, "default_language": true,
	"language_override": true, "textIndexVersion": true, "2dsphereIndexVersion": true, "bits": true,
	"min": true, "max": true, "wildcardProjection": true, "background": true, "v": true,
}

func shCreateIndexes(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error) {
	var a struct {
		DB    string   `bson:"db"`
		Coll  string   `bson:"coll"`
		Specs []bson.D `bson:"specs"`
	}
	if err := parseArgs(args, &a); err != nil {
		return nil, err
	}
	if err := checkWritableNS(a.DB, a.Coll); err != nil {
		return nil, err
	}
	if len(a.Specs) == 0 || len(a.Specs) > 64 {
		return nil, badArgs("createIndexes accepts between 1 and 64 index specifications")
	}
	specs := bson.A{}
	for _, sp := range a.Specs {
		key, _ := get(sp, "key")
		kd, ok := key.(bson.D)
		if !ok {
			return nil, badArgs("index specification requires a key document")
		}
		if _, err := query.Index(kd, nil); err != nil {
			return nil, err
		}
		for _, e := range sp {
			if e.Key == "key" {
				continue
			}
			if !indexOptionKeys[e.Key] {
				return nil, badArgs("index option %q is not supported", e.Key)
			}
			if e.Key == "partialFilterExpression" {
				d, ok := e.Value.(bson.D)
				if !ok {
					return nil, badArgs("partialFilterExpression must be a document")
				}
				if err := query.Filter(d); err != nil {
					return nil, err
				}
			}
		}
		if err := query.Value(sp); err != nil {
			return nil, err
		}
		specs = append(specs, sp)
	}
	cmd := bson.D{{Key: "createIndexes", Value: a.Coll}, {Key: "indexes", Value: specs}}
	res, err := s.runCmd(ctx, rc, a.DB, cmd, s.writeTimeout(rc))
	if err != nil {
		return nil, err
	}
	s.auditWrite(ctx, rc, "createIndexes", a.DB, a.Coll)
	return res, nil
}

func shDropIndexes(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error) {
	var a struct {
		DB    string `bson:"db"`
		Coll  string `bson:"coll"`
		Index any    `bson:"index"`
	}
	if err := parseArgs(args, &a); err != nil {
		return nil, err
	}
	if err := checkWritableNS(a.DB, a.Coll); err != nil {
		return nil, err
	}
	switch v := a.Index.(type) {
	case string:
		if v == "_id_" {
			return nil, badArgs("the _id index cannot be dropped")
		}
	case bson.A:
		for _, x := range v {
			if n, _ := x.(string); n == "_id_" {
				return nil, badArgs("the _id index cannot be dropped")
			}
		}
	case bson.D:
	default:
		return nil, badArgs("dropIndexes requires an index name, key document or list of names")
	}
	cmd := bson.D{{Key: "dropIndexes", Value: a.Coll}, {Key: "index", Value: a.Index}}
	res, err := s.runCmd(ctx, rc, a.DB, cmd, s.writeTimeout(rc))
	if err != nil {
		return nil, err
	}
	s.auditWrite(ctx, rc, "dropIndexes", a.DB, a.Coll)
	return res, nil
}

var createCollectionKeys = map[string]bool{
	"capped": true, "size": true, "max": true, "validator": true, "validationLevel": true,
	"validationAction": true, "collation": true, "expireAfterSeconds": true, "timeseries": true,
	"clusteredIndex": true, "changeStreamPreAndPostImages": true, "viewOn": true, "pipeline": true,
	"storageEngine": false, "indexOptionDefaults": false,
}

func shCreateCollection(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error) {
	var a struct {
		DB      string `bson:"db"`
		Coll    string `bson:"coll"`
		Options bson.D `bson:"options"`
	}
	if err := parseArgs(args, &a); err != nil {
		return nil, err
	}
	if err := checkWritableNS(a.DB, a.Coll); err != nil {
		return nil, err
	}
	cmd := bson.D{{Key: "create", Value: a.Coll}}
	for _, e := range a.Options {
		if !createCollectionKeys[e.Key] {
			return nil, badArgs("createCollection option %q is not supported", e.Key)
		}
		cmd = append(cmd, e)
	}
	if err := query.Command(cmd, query.Policy{}); err != nil {
		return nil, err
	}
	res, err := s.runCmd(ctx, rc, a.DB, cmd, s.writeTimeout(rc))
	if err != nil {
		return nil, err
	}
	s.auditWrite(ctx, rc, "createCollection", a.DB, a.Coll)
	return res, nil
}

func shDropCollection(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error) {
	var a struct {
		DB   string `bson:"db"`
		Coll string `bson:"coll"`
	}
	if err := parseArgs(args, &a); err != nil {
		return nil, err
	}
	if err := checkWritableNS(a.DB, a.Coll); err != nil {
		return nil, err
	}
	err := s.op(ctx, "dropCollection", s.writeTimeout(rc), func(ctx context.Context) error {
		return rc.sess.Client.Database(a.DB).Collection(a.Coll).Drop(ctx)
	})
	if err != nil {
		return nil, err
	}
	s.auditWrite(ctx, rc, "dropCollection", a.DB, a.Coll)
	return bson.D{{Key: "dropped", Value: true}}, nil
}

func shDropDatabase(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error) {
	var a struct {
		DB string `bson:"db"`
	}
	if err := parseArgs(args, &a); err != nil {
		return nil, err
	}
	if !s.Config.Shell.AllowDropDatabase {
		return nil, deny("dropDatabase is disabled on this portal (shell.allowDropDatabase)")
	}
	if err := checkWritableNS(a.DB, ""); err != nil {
		return nil, err
	}
	if a.DB == "admin" {
		return nil, deny("the admin database cannot be dropped through the portal")
	}
	err := s.op(ctx, "dropDatabase", s.writeTimeout(rc), func(ctx context.Context) error {
		return rc.sess.Client.Database(a.DB).Drop(ctx)
	})
	if err != nil {
		return nil, err
	}
	s.auditWrite(ctx, rc, "dropDatabase", a.DB, "")
	return bson.D{{Key: "dropped", Value: a.DB}, {Key: "ok", Value: 1}}, nil
}

func shRenameCollection(s *Server, ctx context.Context, rc *reqCtx, args string) (any, error) {
	var a struct {
		DB         string `bson:"db"`
		From       string `bson:"from"`
		To         string `bson:"to"`
		DropTarget bool   `bson:"dropTarget"`
	}
	if err := parseArgs(args, &a); err != nil {
		return nil, err
	}
	if err := checkWritableNS(a.DB, a.From); err != nil {
		return nil, err
	}
	if err := checkWritableNS(a.DB, a.To); err != nil {
		return nil, err
	}
	cmd := bson.D{{Key: "renameCollection", Value: a.DB + "." + a.From}, {Key: "to", Value: a.DB + "." + a.To}, {Key: "dropTarget", Value: a.DropTarget}}
	res, err := s.runCmd(ctx, rc, "admin", cmd, s.writeTimeout(rc))
	if err != nil {
		return nil, err
	}
	s.auditWrite(ctx, rc, "renameCollection", a.DB, a.From)
	return res, nil
}
