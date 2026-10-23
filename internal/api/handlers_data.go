package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/krishnamanaiducloud/mongo-portal/internal/audit"
	"github.com/krishnamanaiducloud/mongo-portal/internal/mongoconn"
	"github.com/krishnamanaiducloud/mongo-portal/internal/query"
	"github.com/krishnamanaiducloud/mongo-portal/internal/rbac"
	"github.com/krishnamanaiducloud/mongo-portal/internal/telemetry"
)

// op runs a MongoDB operation with a deadline, metrics and a span. Span and
// metric attributes contain only the operation name, never data.
func (s *Server) op(ctx context.Context, name string, timeout time.Duration, fn func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ctx, span := telemetry.Start(ctx, "mongodb."+name)
	defer span.End()
	start := time.Now()
	err := fn(ctx)
	outcome := "success"
	if err != nil {
		outcome = string(mongoconn.Classify(err).Kind)
	}
	s.Metrics.MongoOps.WithLabelValues(name, outcome).Observe(time.Since(start).Seconds())
	return err
}

// mongoError writes a classified MongoDB error.
func (s *Server) mongoError(w http.ResponseWriter, r *http.Request, rc *reqCtx, action string, err error) {
	me := mongoconn.Classify(err)
	if me.Kind == mongoconn.KindUnauthorized {
		s.Metrics.AuthzDenials.WithLabelValues("mongodb", "unauthorized").Inc()
		s.auditEvent(r, rc, action, audit.Denied, "mongodb unauthorized")
	}
	if me.Kind == mongoconn.KindAuthFailed {
		// Credentials stopped working (password changed, user dropped):
		// end the session so the user re-authenticates.
		s.Store.Delete(rc.secret, "reauth_required")
		s.clearCookie(w)
		writeError(w, r, http.StatusUnauthorized, "mongo_session_required", "MongoDB rejected the session credentials; sign in again")
		return
	}
	s.Logger.Warn("mongodb operation failed", "request_id", rc.requestID, "action", action, "kind", me.Kind, "code", me.Code, "code_name", me.CodeName)
	writeJSON(w, me.HTTPStatus(), map[string]any{"error": apiError{Code: string(me.Kind), Message: me.Msg, RequestID: rc.requestID, MongoCode: me.Code}})
}

func (s *Server) defaultTimeout() time.Duration { return s.Config.Query.DefaultMaxTime }

// nsParams validates {db} and {coll} path values.
func nsParams(w http.ResponseWriter, r *http.Request, needColl bool) (string, string, bool) {
	db := r.PathValue("db")
	if !query.ValidDatabaseName(db) {
		writeError(w, r, http.StatusBadRequest, "invalid_name", "Invalid database name")
		return "", "", false
	}
	if !needColl {
		return db, "", true
	}
	coll := r.PathValue("coll")
	if !query.ValidCollectionName(coll) {
		writeError(w, r, http.StatusBadRequest, "invalid_name", "Invalid collection name")
		return "", "", false
	}
	return db, coll, true
}

func requireConfirm(w http.ResponseWriter, r *http.Request, expected string) bool {
	if r.Header.Get("X-Confirm") != expected {
		writeError(w, r, http.StatusPreconditionRequired, "confirmation_required",
			"Destructive operation requires the X-Confirm header to equal "+strconv.Quote(expected))
		return false
	}
	return true
}

func extJSON(v any, canonical bool) (json.RawMessage, error) {
	b, err := bson.MarshalExtJSON(v, canonical, false)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

// access describes what the user may do on a database (coll == "") or a
// collection: "portal" is the RBAC decision, "mongo" the MongoDB privileges
// of the session. The UI offers an action only when both allow it.
func (s *Server) access(rc *reqCtx, db, coll string) map[string]any {
	caps := rc.sess.Status.CapabilitiesFor(db, coll)
	ns := rbac.Namespace(db, coll)
	if coll == "" {
		ns = rbac.Namespace(db, "*")
	}
	portal := map[string]bool{
		"find":             s.allowed(rc, rbac.Documents, rbac.Get, ns),
		"insert":           s.allowed(rc, rbac.Documents, rbac.Create, ns),
		"update":           s.allowed(rc, rbac.Documents, rbac.Update, ns),
		"remove":           s.allowed(rc, rbac.Documents, rbac.Delete, ns),
		"createIndex":      s.allowed(rc, rbac.Indexes, rbac.Create, ns),
		"dropIndex":        s.allowed(rc, rbac.Indexes, rbac.Delete, ns),
		"createCollection": s.allowed(rc, rbac.Collections, rbac.Create, ns),
		"dropCollection":   s.allowed(rc, rbac.Collections, rbac.Delete, ns),
		"dropDatabase":     s.allowed(rc, rbac.Databases, rbac.Delete, db),
	}
	return map[string]any{
		"portalWrite": portal["insert"] || portal["update"] || portal["remove"],
		"portal":      portal,
		"mongo":       caps,
	}
}

// ---- server and databases ----

func (s *Server) handleServerInfo(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !s.authorize(w, r, rc, rbac.Server, rbac.Get, rc.sess.Profile) {
		return
	}
	var build, hello bson.M
	admin := rc.sess.Client.Database("admin")
	err := s.op(r.Context(), "buildInfo", s.defaultTimeout(), func(ctx context.Context) error {
		if err := admin.RunCommand(ctx, bson.D{{Key: "buildInfo", Value: 1}}).Decode(&build); err != nil {
			return err
		}
		return admin.RunCommand(ctx, bson.D{{Key: "hello", Value: 1}}).Decode(&hello)
	})
	if err != nil {
		s.mongoError(w, r, rc, "server_info", err)
		return
	}
	pick := func(m bson.M, keys ...string) bson.M {
		out := bson.M{}
		for _, k := range keys {
			if v, ok := m[k]; ok {
				out[k] = v
			}
		}
		return out
	}
	info, err := extJSON(bson.M{
		"build": pick(build, "version", "gitVersion", "modules", "bits", "maxBsonObjectSize"),
		"hello": pick(hello, "setName", "hosts", "passives", "arbiters", "primary", "me", "isWritablePrimary", "secondary", "maxWireVersion", "electionId", "msg"),
	}, false)
	if err != nil {
		s.mongoError(w, r, rc, "server_info", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"server": info, "tls": rc.sess.TLS, "profile": rc.sess.Profile})
}

func (s *Server) handleListDatabases(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	type dbView struct {
		Name       string `json:"name"`
		SizeOnDisk int64  `json:"sizeOnDisk"`
		Empty      bool   `json:"empty"`
	}
	var res mongo.ListDatabasesResult
	err := s.op(r.Context(), "listDatabases", s.defaultTimeout(), func(ctx context.Context) error {
		var err error
		res, err = rc.sess.Client.ListDatabases(ctx, bson.D{}, options.ListDatabases().SetAuthorizedDatabases(true))
		return err
	})
	source := "listDatabases"
	var out []dbView
	if err != nil {
		if mongoconn.Classify(err).Kind != mongoconn.KindUnauthorized {
			s.mongoError(w, r, rc, "list_databases", err)
			return
		}
		source = "privileges"
		for _, n := range rc.sess.Status.Databases() {
			out = append(out, dbView{Name: n})
		}
	} else {
		for _, d := range res.Databases {
			out = append(out, dbView{Name: d.Name, SizeOnDisk: d.SizeOnDisk, Empty: d.Empty})
		}
	}
	out = slices.DeleteFunc(out, func(d dbView) bool { return !s.allowed(rc, rbac.Databases, rbac.Get, d.Name) })
	slices.SortFunc(out, func(a, b dbView) int { return strings.Compare(a.Name, b.Name) })
	if out == nil {
		out = []dbView{}
	}
	resp := map[string]any{"databases": out, "source": source}
	if source == "listDatabases" {
		// Size of the whole deployment as reported by MongoDB, and of the
		// databases this user may see.
		var visible int64
		for _, d := range out {
			visible += d.SizeOnDisk
		}
		resp["totalSize"], resp["visibleSize"] = res.TotalSize, visible
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleDatabaseStats(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	db, _, ok := nsParams(w, r, false)
	if !ok {
		return
	}
	if !s.authorize(w, r, rc, rbac.Databases, rbac.Get, db) {
		return
	}
	var stats bson.M
	err := s.op(r.Context(), "dbStats", s.defaultTimeout(), func(ctx context.Context) error {
		return rc.sess.Client.Database(db).RunCommand(ctx, bson.D{{Key: "dbStats", Value: 1}}).Decode(&stats)
	})
	if err != nil {
		s.mongoError(w, r, rc, "database_stats", err)
		return
	}
	delete(stats, "$clusterTime")
	delete(stats, "operationTime")
	raw, err := extJSON(stats, false)
	if err != nil {
		s.mongoError(w, r, rc, "database_stats", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"database": db, "stats": raw, "access": s.access(rc, db, "")})
}

func (s *Server) handleListCollections(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	db, _, ok := nsParams(w, r, false)
	if !ok {
		return
	}
	if !s.authorize(w, r, rc, rbac.Databases, rbac.Get, db) {
		return
	}
	type collView struct {
		Name     string          `json:"name"`
		Type     string          `json:"type"`
		ReadOnly bool            `json:"readOnly"`
		Options  json.RawMessage `json:"options,omitempty"`
		Access   map[string]any  `json:"access"`
	}
	var specs []mongo.CollectionSpecification
	database := rc.sess.Client.Database(db)
	err := s.op(r.Context(), "listCollections", s.defaultTimeout(), func(ctx context.Context) error {
		var err error
		specs, err = database.ListCollectionSpecifications(ctx, bson.D{}, options.ListCollections().SetAuthorizedCollections(true))
		if err != nil && mongoconn.Classify(err).Kind == mongoconn.KindUnauthorized {
			// Without listCollections, MongoDB permits nameOnly+authorizedCollections.
			specs, err = database.ListCollectionSpecifications(ctx, bson.D{}, options.ListCollections().SetAuthorizedCollections(true).SetNameOnly(true))
		}
		return err
	})
	if err != nil {
		s.mongoError(w, r, rc, "list_collections", err)
		return
	}
	out := make([]collView, 0, len(specs))
	for _, sp := range specs {
		if !s.allowed(rc, rbac.Collections, rbac.Get, rbac.Namespace(db, sp.Name)) {
			continue
		}
		v := collView{Name: sp.Name, Type: sp.Type, ReadOnly: sp.ReadOnly, Access: s.access(rc, db, sp.Name)}
		if len(sp.Options) > 0 {
			v.Options, _ = extJSON(sp.Options, false)
		}
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b collView) int { return strings.Compare(a.Name, b.Name) })
	writeJSON(w, http.StatusOK, map[string]any{"database": db, "collections": out, "access": s.access(rc, db, "")})
}

func (s *Server) handleCreateCollection(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	db, _, ok := nsParams(w, r, false)
	if !ok {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if !query.ValidCollectionName(req.Name) || query.SystemCollection(req.Name) {
		writeError(w, r, http.StatusBadRequest, "invalid_name", "Invalid collection name")
		return
	}
	if !s.authorize(w, r, rc, rbac.Collections, rbac.Create, rbac.Namespace(db, req.Name)) {
		return
	}
	err := s.op(r.Context(), "createCollection", s.defaultTimeout(), func(ctx context.Context) error {
		return rc.sess.Client.Database(db).CreateCollection(ctx, req.Name)
	})
	if err != nil {
		s.mongoError(w, r, rc, "create_collection", err)
		return
	}
	s.Audit.Record(r.Context(), s.dataEvent(rc, "create_collection", db, req.Name, ""))
	writeJSON(w, http.StatusCreated, map[string]any{"database": db, "name": req.Name})
}

func (s *Server) handleDropCollection(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	db, coll, ok := nsParams(w, r, true)
	if !ok {
		return
	}
	if !s.authorize(w, r, rc, rbac.Collections, rbac.Delete, rbac.Namespace(db, coll)) {
		return
	}
	if query.SystemCollection(coll) {
		writeError(w, r, http.StatusForbidden, "system_collection", "System collections cannot be dropped through the portal")
		return
	}
	if !requireConfirm(w, r, coll) {
		return
	}
	err := s.op(r.Context(), "dropCollection", s.defaultTimeout(), func(ctx context.Context) error {
		return rc.sess.Client.Database(db).Collection(coll).Drop(ctx)
	})
	if err != nil {
		s.mongoError(w, r, rc, "drop_collection", err)
		return
	}
	s.Audit.Record(r.Context(), s.dataEvent(rc, "drop_collection", db, coll, ""))
	writeJSON(w, http.StatusOK, map[string]any{"dropped": coll})
}

func (s *Server) dataEvent(rc *reqCtx, action, db, coll, target string) audit.Event {
	e := s.baseEvent(rc, action, audit.Success, "")
	e.Database, e.Collection, e.Target = db, coll, target
	return e
}

func (s *Server) handleCollectionStats(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	db, coll, ok := nsParams(w, r, true)
	if !ok {
		return
	}
	if !s.authorize(w, r, rc, rbac.Collections, rbac.Get, rbac.Namespace(db, coll)) {
		return
	}
	c := rc.sess.Client.Database(db).Collection(coll)
	resp := map[string]any{"database": db, "collection": coll, "access": s.access(rc, db, coll)}
	var stats bson.M
	err := s.op(r.Context(), "collStats", s.defaultTimeout(), func(ctx context.Context) error {
		cur, err := c.Aggregate(ctx, bson.A{bson.D{{Key: "$collStats", Value: bson.D{{Key: "storageStats", Value: bson.D{}}}}}})
		if err != nil {
			return err
		}
		defer cur.Close(ctx)
		if cur.Next(ctx) {
			var doc struct {
				StorageStats bson.M `bson:"storageStats"`
			}
			if err := cur.Decode(&doc); err != nil {
				return err
			}
			stats = bson.M{}
			for _, k := range []string{"count", "size", "avgObjSize", "storageSize", "totalIndexSize", "totalSize", "nindexes", "indexSizes", "capped", "max", "maxSize"} {
				if v, ok := doc.StorageStats[k]; ok {
					stats[k] = v
				}
			}
		}
		return cur.Err()
	})
	if err == nil && stats != nil {
		resp["stats"], _ = extJSON(stats, false)
	} else {
		// collStats not permitted: fall back to an estimated count.
		var n int64
		cerr := s.op(r.Context(), "estimatedDocumentCount", s.defaultTimeout(), func(ctx context.Context) error {
			var err error
			n, err = c.EstimatedDocumentCount(ctx)
			return err
		})
		if cerr != nil {
			s.mongoError(w, r, rc, "collection_stats", cerr)
			return
		}
		resp["stats"], _ = extJSON(bson.M{"count": n}, false)
		resp["limited"] = true
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---- documents ----

func (s *Server) parseLimits(r *http.Request, limitStr, skipStr string) (int64, int64, error) {
	q := s.Config.Query
	limit, skip := q.DefaultLimit, int64(0)
	if limitStr != "" {
		n, err := strconv.ParseInt(limitStr, 10, 64)
		if err != nil || n < 1 {
			return 0, 0, errors.New("limit must be a positive integer")
		}
		limit = min(n, q.MaxLimit)
	}
	if skipStr != "" {
		n, err := strconv.ParseInt(skipStr, 10, 64)
		if err != nil || n < 0 || n > q.MaxSkip {
			return 0, 0, errors.New("skip must be between 0 and " + strconv.FormatInt(q.MaxSkip, 10))
		}
		skip = n
	}
	return limit, skip, nil
}

func (s *Server) maxTime(ms int64) time.Duration {
	q := s.Config.Query
	if ms <= 0 {
		return q.DefaultMaxTime
	}
	return min(time.Duration(ms)*time.Millisecond, q.MaxMaxTime)
}

type findSpec struct {
	filter, projection, sort bson.D
	limit, skip              int64
	maxTime                  time.Duration
}

func (s *Server) buildFind(filter, projection, sort string) (*findSpec, error) {
	f, err := query.ParseDocument(filter)
	if err != nil {
		return nil, err
	}
	if err := query.Filter(f); err != nil {
		return nil, err
	}
	p, err := query.ParseDocument(projection)
	if err != nil {
		return nil, err
	}
	if err := query.Projection(p); err != nil {
		return nil, err
	}
	so, err := query.ParseDocument(sort)
	if err != nil {
		return nil, err
	}
	if err := query.Sort(so); err != nil {
		return nil, err
	}
	return &findSpec{filter: f, projection: p, sort: so}, nil
}

type docPage struct {
	Documents []json.RawMessage `json:"documents"`
	IDs       []string          `json:"ids"`
	HasMore   bool              `json:"hasMore"`
	Truncated bool              `json:"truncated"`
	Skip      int64             `json:"skip"`
	Limit     int64             `json:"limit"`
	ElapsedMS int64             `json:"elapsedMs"`
}

// collect reads up to limit documents from cur, bounded by response bytes.
func (s *Server) collect(ctx context.Context, cur *mongo.Cursor, limit int64) (*docPage, error) {
	page := &docPage{Documents: []json.RawMessage{}, IDs: []string{}}
	total := 0
	for cur.Next(ctx) {
		if int64(len(page.Documents)) >= limit {
			page.HasMore = true
			break
		}
		raw, err := extJSON(cur.Current, true)
		if err != nil {
			return nil, err
		}
		total += len(raw)
		if total > s.Config.Query.MaxResponseBytes {
			page.Truncated, page.HasMore = true, true
			break
		}
		page.Documents = append(page.Documents, raw)
		page.IDs = append(page.IDs, encodeID(cur.Current))
	}
	return page, cur.Err()
}

// encodeID returns a URL-safe token for the document's _id, or "".
func encodeID(doc bson.Raw) string {
	v, err := doc.LookupErr("_id")
	if err != nil {
		return ""
	}
	b, err := bson.MarshalExtJSON(bson.D{{Key: "_id", Value: v}}, true, false)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeID parses an id token produced by encodeID. Operator documents are
// rejected so an id can never widen into a query (e.g. {"$gt": ""}).
func decodeID(tok string) (any, error) {
	if tok == "" || len(tok) > 4096 {
		return nil, errors.New("invalid document id")
	}
	b, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		return nil, errors.New("invalid document id")
	}
	var d bson.D
	if err := bson.UnmarshalExtJSON(b, false, &d); err != nil || len(d) != 1 || d[0].Key != "_id" {
		return nil, errors.New("invalid document id")
	}
	if containsOperator(d[0].Value) {
		return nil, errors.New("invalid document id")
	}
	return d[0].Value, nil
}

func containsOperator(v any) bool {
	switch t := v.(type) {
	case bson.D:
		for _, e := range t {
			if strings.HasPrefix(e.Key, "$") || containsOperator(e.Value) {
				return true
			}
		}
	case bson.A:
		for _, x := range t {
			if containsOperator(x) {
				return true
			}
		}
	}
	return false
}

func (s *Server) handleFindDocuments(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	db, coll, ok := nsParams(w, r, true)
	if !ok {
		return
	}
	if !s.authorize(w, r, rc, rbac.Documents, rbac.Get, rbac.Namespace(db, coll)) {
		return
	}
	q := r.URL.Query()
	spec, err := s.buildFind(q.Get("filter"), q.Get("projection"), q.Get("sort"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_query", err.Error())
		return
	}
	spec.limit, spec.skip, err = s.parseLimits(r, q.Get("limit"), q.Get("skip"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_query", err.Error())
		return
	}
	ms, _ := strconv.ParseInt(q.Get("maxTimeMS"), 10, 64)
	spec.maxTime = s.maxTime(ms)
	s.runFind(w, r, rc, db, coll, spec, q.Get("count") == "true")
}

func (s *Server) runFind(w http.ResponseWriter, r *http.Request, rc *reqCtx, db, coll string, spec *findSpec, withCount bool) {
	c := rc.sess.Client.Database(db).Collection(coll)
	batch := min(spec.limit+1, 1000)                                                            // limit is clamped to query.maxLimit, so batch is in [2, 1000]
	fo := options.Find().SetLimit(spec.limit + 1).SetSkip(spec.skip).SetBatchSize(int32(batch)) // #nosec G115 -- bounded above
	if len(spec.projection) > 0 {
		fo.SetProjection(spec.projection)
	}
	if len(spec.sort) > 0 {
		fo.SetSort(spec.sort)
	}
	var page *docPage
	start := time.Now()
	err := s.op(r.Context(), "find", spec.maxTime, func(ctx context.Context) error {
		cur, err := c.Find(ctx, spec.filter, fo)
		if err != nil {
			return err
		}
		defer cur.Close(ctx)
		page, err = s.collect(ctx, cur, spec.limit)
		return err
	})
	if err != nil {
		s.mongoError(w, r, rc, "find", err)
		return
	}
	page.Skip, page.Limit, page.ElapsedMS = spec.skip, spec.limit, time.Since(start).Milliseconds()
	resp := map[string]any{"page": page, "access": s.access(rc, db, coll)}
	if withCount {
		var n int64
		cerr := s.op(r.Context(), "countDocuments", spec.maxTime, func(ctx context.Context) error {
			var err error
			n, err = c.CountDocuments(ctx, spec.filter, options.Count().SetLimit(s.Config.Query.MaxCount))
			return err
		})
		if cerr == nil {
			resp["count"] = n
			resp["countCapped"] = n >= s.Config.Query.MaxCount
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleGetDocument(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	db, coll, ok := nsParams(w, r, true)
	if !ok {
		return
	}
	if !s.authorize(w, r, rc, rbac.Documents, rbac.Get, rbac.Namespace(db, coll)) {
		return
	}
	id, err := decodeID(r.PathValue("id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_id", err.Error())
		return
	}
	canonical := r.URL.Query().Get("format") != "relaxed"
	var raw bson.Raw
	err = s.op(r.Context(), "findOne", s.defaultTimeout(), func(ctx context.Context) error {
		var err error
		raw, err = rc.sess.Client.Database(db).Collection(coll).FindOne(ctx, bson.D{{Key: "_id", Value: id}}).Raw()
		return err
	})
	if err != nil {
		s.mongoError(w, r, rc, "get_document", err)
		return
	}
	doc, err := extJSON(raw, canonical)
	if err != nil {
		s.mongoError(w, r, rc, "get_document", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"document": doc, "id": r.PathValue("id"), "access": s.access(rc, db, coll)})
}

type documentBody struct {
	Document string `json:"document"`
}

func (s *Server) parseDocumentBody(w http.ResponseWriter, r *http.Request) (bson.D, bool) {
	var body documentBody
	if !decodeJSON(w, r, &body) {
		return nil, false
	}
	if int64(len(body.Document)) > s.Config.Query.MaxDocumentBytes {
		writeError(w, r, http.StatusRequestEntityTooLarge, "document_too_large", "Document exceeds the configured size limit")
		return nil, false
	}
	text := strings.TrimSpace(body.Document)
	if text == "" || text[0] != '{' {
		writeError(w, r, http.StatusBadRequest, "invalid_document", "Document must be a JSON object")
		return nil, false
	}
	var d bson.D
	if err := bson.UnmarshalExtJSON([]byte(text), false, &d); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_document", "Invalid Extended JSON document")
		return nil, false
	}
	for _, e := range d {
		if strings.HasPrefix(e.Key, "$") {
			writeError(w, r, http.StatusBadRequest, "invalid_document", "Top-level field names must not start with '$'")
			return nil, false
		}
	}
	return d, true
}

func (s *Server) handleInsertDocument(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	db, coll, ok := nsParams(w, r, true)
	if !ok {
		return
	}
	if !s.authorize(w, r, rc, rbac.Documents, rbac.Create, rbac.Namespace(db, coll)) {
		return
	}
	if query.SystemCollection(coll) {
		writeError(w, r, http.StatusForbidden, "system_collection", "System collections cannot be modified through the portal")
		return
	}
	doc, ok := s.parseDocumentBody(w, r)
	if !ok {
		return
	}
	var res *mongo.InsertOneResult
	err := s.op(r.Context(), "insertOne", s.defaultTimeout(), func(ctx context.Context) error {
		var err error
		res, err = rc.sess.Client.Database(db).Collection(coll).InsertOne(ctx, doc)
		return err
	})
	if err != nil {
		s.mongoError(w, r, rc, "insert_document", err)
		return
	}
	raw, _ := bson.Marshal(bson.D{{Key: "_id", Value: res.InsertedID}})
	tok := encodeID(raw)
	s.Audit.Record(r.Context(), s.dataEvent(rc, "insert_document", db, coll, ""))
	idJSON, _ := extJSON(bson.D{{Key: "_id", Value: res.InsertedID}}, true)
	writeJSON(w, http.StatusCreated, map[string]any{"id": tok, "insertedId": idJSON})
}

func (s *Server) handleReplaceDocument(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	db, coll, ok := nsParams(w, r, true)
	if !ok {
		return
	}
	if !s.authorize(w, r, rc, rbac.Documents, rbac.Update, rbac.Namespace(db, coll)) {
		return
	}
	if query.SystemCollection(coll) {
		writeError(w, r, http.StatusForbidden, "system_collection", "System collections cannot be modified through the portal")
		return
	}
	id, err := decodeID(r.PathValue("id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_id", err.Error())
		return
	}
	doc, ok := s.parseDocumentBody(w, r)
	if !ok {
		return
	}
	// The _id of a document is immutable: reject a body that changes it.
	for i, e := range doc {
		if e.Key == "_id" {
			a, _ := bson.Marshal(bson.D{{Key: "v", Value: e.Value}})
			b, _ := bson.Marshal(bson.D{{Key: "v", Value: id}})
			if !bytes.Equal(a, b) {
				writeError(w, r, http.StatusBadRequest, "id_mismatch", "The document _id cannot be changed")
				return
			}
			doc = slices.Delete(doc, i, i+1)
			break
		}
	}
	var res *mongo.UpdateResult
	err = s.op(r.Context(), "replaceOne", s.defaultTimeout(), func(ctx context.Context) error {
		var err error
		res, err = rc.sess.Client.Database(db).Collection(coll).ReplaceOne(ctx, bson.D{{Key: "_id", Value: id}}, doc)
		return err
	})
	if err != nil {
		s.mongoError(w, r, rc, "replace_document", err)
		return
	}
	if res.MatchedCount == 0 {
		writeError(w, r, http.StatusNotFound, "not_found", "Document not found")
		return
	}
	s.Audit.Record(r.Context(), s.dataEvent(rc, "replace_document", db, coll, ""))
	writeJSON(w, http.StatusOK, map[string]any{"matched": res.MatchedCount, "modified": res.ModifiedCount})
}

func (s *Server) handleDeleteDocument(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	db, coll, ok := nsParams(w, r, true)
	if !ok {
		return
	}
	if !s.authorize(w, r, rc, rbac.Documents, rbac.Delete, rbac.Namespace(db, coll)) {
		return
	}
	if query.SystemCollection(coll) {
		writeError(w, r, http.StatusForbidden, "system_collection", "System collections cannot be modified through the portal")
		return
	}
	id, err := decodeID(r.PathValue("id"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_id", err.Error())
		return
	}
	if !requireConfirm(w, r, "delete") {
		return
	}
	var res *mongo.DeleteResult
	err = s.op(r.Context(), "deleteOne", s.defaultTimeout(), func(ctx context.Context) error {
		var err error
		res, err = rc.sess.Client.Database(db).Collection(coll).DeleteOne(ctx, bson.D{{Key: "_id", Value: id}})
		return err
	})
	if err != nil {
		s.mongoError(w, r, rc, "delete_document", err)
		return
	}
	if res.DeletedCount == 0 {
		writeError(w, r, http.StatusNotFound, "not_found", "Document not found")
		return
	}
	s.Audit.Record(r.Context(), s.dataEvent(rc, "delete_document", db, coll, ""))
	writeJSON(w, http.StatusOK, map[string]any{"deleted": res.DeletedCount})
}

// ---- query console ----

type queryRequest struct {
	Operation  string `json:"operation"`
	Filter     string `json:"filter"`
	Projection string `json:"projection"`
	Sort       string `json:"sort"`
	Pipeline   string `json:"pipeline"`
	Limit      int64  `json:"limit"`
	Skip       int64  `json:"skip"`
	MaxTimeMS  int64  `json:"maxTimeMS"`
}

func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	db, coll, ok := nsParams(w, r, true)
	if !ok {
		return
	}
	if !s.authorize(w, r, rc, rbac.Documents, rbac.Get, rbac.Namespace(db, coll)) {
		return
	}
	var req queryRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	bad := func(err error) { writeError(w, r, http.StatusBadRequest, "invalid_query", err.Error()) }
	limit, skip, err := s.parseLimits(r, itoa(req.Limit), itoa(req.Skip))
	if err != nil {
		bad(err)
		return
	}
	maxTime := s.maxTime(req.MaxTimeMS)

	switch req.Operation {
	case "find", "findOne":
		spec, err := s.buildFind(req.Filter, req.Projection, req.Sort)
		if err != nil {
			bad(err)
			return
		}
		spec.limit, spec.skip, spec.maxTime = limit, skip, maxTime
		if req.Operation == "findOne" {
			spec.limit = 1
		}
		s.runFind(w, r, rc, db, coll, spec, false)

	case "countDocuments":
		f, err := query.ParseDocument(req.Filter)
		if err == nil {
			err = query.Filter(f)
		}
		if err != nil {
			bad(err)
			return
		}
		var n int64
		err = s.op(r.Context(), "countDocuments", maxTime, func(ctx context.Context) error {
			var err error
			n, err = rc.sess.Client.Database(db).Collection(coll).CountDocuments(ctx, f, options.Count().SetLimit(s.Config.Query.MaxCount))
			return err
		})
		if err != nil {
			s.mongoError(w, r, rc, "count_documents", err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"count": n, "countCapped": n >= s.Config.Query.MaxCount})

	case "aggregate":
		stages, err := query.ParseArray(req.Pipeline)
		if err != nil {
			bad(err)
			return
		}
		if !s.authorizePipeline(w, r, rc, db, stages) {
			return
		}
		policy := query.Policy{AllowWriteStages: s.Config.Query.AllowWriteStages}
		if err := query.Pipeline(stages, policy); err != nil {
			if query.HasWriteStage(stages) {
				s.Metrics.AuthzDenials.WithLabelValues("portal", "write_stage").Inc()
				s.auditEvent(r, rc, "aggregate_write_stage", audit.Denied, err.Error())
			}
			bad(err)
			return
		}
		write := query.HasWriteStage(stages)
		pipe := make(bson.A, 0, len(stages)+1)
		for _, st := range stages {
			pipe = append(pipe, st)
		}
		if !write {
			pipe = append(pipe, bson.D{{Key: "$limit", Value: limit + 1}})
		}
		var page *docPage
		start := time.Now()
		err = s.op(r.Context(), "aggregate", maxTime, func(ctx context.Context) error {
			cur, err := rc.sess.Client.Database(db).Collection(coll).Aggregate(ctx, pipe)
			if err != nil {
				return err
			}
			defer cur.Close(ctx)
			page, err = s.collect(ctx, cur, limit)
			return err
		})
		if err != nil {
			s.mongoError(w, r, rc, "aggregate", err)
			return
		}
		if write {
			s.Audit.Record(r.Context(), s.dataEvent(rc, "aggregate_write_stage", db, coll, ""))
		}
		page.Limit, page.ElapsedMS = limit, time.Since(start).Milliseconds()
		writeJSON(w, http.StatusOK, map[string]any{"page": page})

	default:
		bad(errors.New("operation must be one of find, findOne, countDocuments, aggregate"))
	}
}

func itoa(n int64) string {
	if n == 0 {
		return ""
	}
	return strconv.FormatInt(n, 10)
}

// ---- indexes ----

func (s *Server) handleListIndexes(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	db, coll, ok := nsParams(w, r, true)
	if !ok {
		return
	}
	if !s.authorize(w, r, rc, rbac.Indexes, rbac.Get, rbac.Namespace(db, coll)) {
		return
	}
	var out []json.RawMessage
	err := s.op(r.Context(), "listIndexes", s.defaultTimeout(), func(ctx context.Context) error {
		cur, err := rc.sess.Client.Database(db).Collection(coll).Indexes().List(ctx)
		if err != nil {
			return err
		}
		defer cur.Close(ctx)
		for cur.Next(ctx) {
			raw, err := extJSON(cur.Current, false)
			if err != nil {
				return err
			}
			out = append(out, raw)
		}
		return cur.Err()
	})
	if err != nil {
		s.mongoError(w, r, rc, "list_indexes", err)
		return
	}
	if out == nil {
		out = []json.RawMessage{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"indexes": out, "access": s.access(rc, db, coll)})
}

func (s *Server) handleCreateIndex(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	db, coll, ok := nsParams(w, r, true)
	if !ok {
		return
	}
	if !s.authorize(w, r, rc, rbac.Indexes, rbac.Create, rbac.Namespace(db, coll)) {
		return
	}
	var req struct {
		Keys    string `json:"keys"`
		Options string `json:"options"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	keys, err := query.ParseDocument(req.Keys)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_index", err.Error())
		return
	}
	opts, err := query.ParseDocument(req.Options)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_index", err.Error())
		return
	}
	spec, err := query.Index(keys, opts)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_index", err.Error())
		return
	}
	io := options.Index()
	if spec.Name != "" {
		io.SetName(spec.Name)
	}
	if spec.Unique {
		io.SetUnique(true)
	}
	if spec.Sparse {
		io.SetSparse(true)
	}
	if spec.Hidden {
		io.SetHidden(true)
	}
	if spec.TTL != nil {
		io.SetExpireAfterSeconds(*spec.TTL)
	}
	if spec.Partial != nil {
		io.SetPartialFilterExpression(spec.Partial)
	}
	var name string
	timeout := s.Config.Query.MaxMaxTime
	if p, ok := s.Config.Profile(rc.sess.Profile); ok {
		timeout = p.OperationTimeout
	}
	err = s.op(r.Context(), "createIndex", timeout, func(ctx context.Context) error {
		var err error
		name, err = rc.sess.Client.Database(db).Collection(coll).Indexes().CreateOne(ctx, mongo.IndexModel{Keys: spec.Keys, Options: io})
		return err
	})
	if err != nil {
		s.mongoError(w, r, rc, "create_index", err)
		return
	}
	s.Audit.Record(r.Context(), s.dataEvent(rc, "create_index", db, coll, name))
	writeJSON(w, http.StatusCreated, map[string]any{"name": name})
}

func (s *Server) handleDropIndex(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	db, coll, ok := nsParams(w, r, true)
	if !ok {
		return
	}
	if !s.authorize(w, r, rc, rbac.Indexes, rbac.Delete, rbac.Namespace(db, coll)) {
		return
	}
	name := r.PathValue("name")
	if !query.ValidIndexName(name) {
		writeError(w, r, http.StatusBadRequest, "invalid_name", "Invalid index name")
		return
	}
	if name == "_id_" {
		writeError(w, r, http.StatusBadRequest, "invalid_index", query.ErrIDIndex.Error())
		return
	}
	if !requireConfirm(w, r, name) {
		return
	}
	err := s.op(r.Context(), "dropIndex", s.defaultTimeout(), func(ctx context.Context) error {
		return rc.sess.Client.Database(db).Collection(coll).Indexes().DropOne(ctx, name)
	})
	if err != nil {
		s.mongoError(w, r, rc, "drop_index", err)
		return
	}
	s.Audit.Record(r.Context(), s.dataEvent(rc, "drop_index", db, coll, name))
	writeJSON(w, http.StatusOK, map[string]any{"dropped": name})
}

// pipelineAccess checks the collections an aggregation reads through
// $lookup/$graphLookup/$unionWith and writes through $out/$merge against the
// RBAC policy. It returns a reason when access is denied.
func (s *Server) pipelineAccess(rc *reqCtx, db string, stages []bson.D) (string, bool) {
	reads, ok := query.ReadNamespaces(stages, db)
	if !ok {
		return "the pipeline references a collection that cannot be determined", false
	}
	for _, n := range reads {
		if !s.allowed(rc, rbac.Documents, rbac.Get, rbac.Namespace(n.DB, n.Coll)) {
			return "your portal role does not allow reading " + rbac.Namespace(n.DB, n.Coll), false
		}
	}
	if query.HasWriteStage(stages) {
		t, ok := query.WriteTarget(stages, db)
		if !ok {
			return "the output collection of the pipeline cannot be determined", false
		}
		ns := rbac.Namespace(t.DB, t.Coll)
		if !s.allowed(rc, rbac.Documents, rbac.Create, ns) || !s.allowed(rc, rbac.Documents, rbac.Update, ns) || !s.allowed(rc, rbac.Documents, rbac.Delete, ns) {
			return "your portal role does not allow writing to " + ns, false
		}
	}
	return "", true
}

func (s *Server) authorizePipeline(w http.ResponseWriter, r *http.Request, rc *reqCtx, db string, stages []bson.D) bool {
	reason, ok := s.pipelineAccess(rc, db, stages)
	if ok {
		return true
	}
	s.Metrics.AuthzDenials.WithLabelValues("portal", "rbac").Inc()
	s.auditEvent(r, rc, "aggregate_denied", audit.Denied, reason)
	writeError(w, r, http.StatusForbidden, "portal_role_forbidden", reason)
	return false
}
