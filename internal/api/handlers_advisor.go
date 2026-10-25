package api

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/krishnamanaiducloud/mongo-portal/internal/advisor"
	"github.com/krishnamanaiducloud/mongo-portal/internal/audit"
	"github.com/krishnamanaiducloud/mongo-portal/internal/mongoconn"
	"github.com/krishnamanaiducloud/mongo-portal/internal/query"
	"github.com/krishnamanaiducloud/mongo-portal/internal/rbac"
)

// The performance advisor reads, with the user's own MongoDB session, index
// definitions and usage, collection statistics, profiler entries and the
// slow-query log, and reports findings. It runs only read commands, never
// returns data values (queries are reduced to their shape) and never
// executes a suggestion. MongoDB authorizes every read; the portal RBAC
// limits it to namespaces the user may see.

const (
	advisorMaxDatabases   = 50
	advisorMaxCollections = 300
	advisorProfileEntries = 300
	advisorWindow         = 24 * time.Hour
)

// advisorSem bounds concurrent advisor runs per replica.
var advisorSem = make(chan struct{}, 2)

type advisorSource struct {
	Name   string `json:"name"`
	State  string `json:"state"` // available, partial, unavailable, off
	Detail string `json:"detail,omitempty"`
}

type advisorReport struct {
	Profile     string            `json:"profile"`
	GeneratedAt time.Time         `json:"generatedAt"`
	Duration    string            `json:"duration"`
	Sources     []advisorSource   `json:"sources"`
	Findings    []advisor.Finding `json:"findings"`
	Scanned     map[string]int    `json:"scanned"`
	Truncated   bool              `json:"truncated"`
}

var internalDBs = []string{"admin", "local", "config"}

func (s *Server) handleAdvisor(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !s.authorize(w, r, rc, rbac.Monitoring, rbac.Get, rc.sess.Profile) {
		return
	}
	only := r.URL.Query().Get("db")
	if only != "" && (!query.ValidDatabaseName(only) || slices.Contains(internalDBs, only)) {
		writeError(w, r, http.StatusBadRequest, "invalid_name", "Invalid database name")
		return
	}
	select {
	case advisorSem <- struct{}{}:
		defer func() { <-advisorSem }()
	default:
		writeError(w, r, http.StatusTooManyRequests, "rate_limited", "The advisor is already running; try again in a moment")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	start := time.Now()
	rep := s.runAdvisor(ctx, rc, only)
	rep.Duration = time.Since(start).Round(time.Millisecond).String()
	e := s.baseEvent(rc, "performance_advisor", audit.Success, "")
	e.Database, e.Count = only, int64(len(rep.Findings))
	s.Audit.Record(r.Context(), e)
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) runAdvisor(ctx context.Context, rc *reqCtx, only string) advisorReport {
	c := rc.sess.Client
	rep := advisorReport{Profile: rc.sess.Profile, GeneratedAt: time.Now().UTC(), Findings: []advisor.Finding{}, Scanned: map[string]int{}}
	timeout := s.defaultTimeout()

	dbs := []string{}
	if only != "" {
		if s.allowed(rc, rbac.Databases, rbac.Get, only) {
			dbs = append(dbs, only)
		}
	} else {
		var names []string
		err := s.op(ctx, "listDatabases", timeout, func(ctx context.Context) error {
			var err error
			names, err = c.ListDatabaseNames(ctx, bson.D{}, options.ListDatabases().SetAuthorizedDatabases(true))
			return err
		})
		if err != nil {
			names = rc.sess.Status.Databases()
		}
		for _, n := range names {
			if !slices.Contains(internalDBs, n) && s.allowed(rc, rbac.Databases, rbac.Get, n) {
				dbs = append(dbs, n)
			}
		}
	}
	if len(dbs) > advisorMaxDatabases {
		dbs, rep.Truncated = dbs[:advisorMaxDatabases], true
	}

	var colls []advisor.Collection
	visible := map[string]bool{}
	idx := advisorSource{Name: "Indexes and collection statistics", State: "available"}
	usage := advisorSource{Name: "Index usage ($indexStats)", State: "available"}
	var noUsage []string
	for _, db := range dbs {
		if ctx.Err() != nil {
			rep.Truncated = true
			break
		}
		var specs []bson.Raw
		err := s.op(ctx, "listCollections", timeout, func(ctx context.Context) error {
			cur, err := c.Database(db).ListCollections(ctx, bson.D{{Key: "type", Value: "collection"}})
			if err != nil {
				return err
			}
			return cur.All(ctx, &specs)
		})
		if err != nil {
			idx.State, idx.Detail = "partial", "some databases could not be listed: "+mongoconn.Classify(err).Msg
			continue
		}
		for _, spec := range specs {
			name, _ := spec.Lookup("name").StringValueOK()
			if name == "" || strings.HasPrefix(name, "system.") || !s.allowed(rc, rbac.Indexes, rbac.Get, db+"/"+name) {
				continue
			}
			if len(colls) >= advisorMaxCollections || ctx.Err() != nil {
				rep.Truncated = true
				break
			}
			_, hasValidator := spec.Lookup("options", "validator").DocumentOK()
			col, ok := s.advisorCollection(ctx, c.Database(db).Collection(name), timeout)
			if !ok {
				// Without its index definitions a collection would produce
				// wrong findings; leave it out.
				idx.State, idx.Detail = "partial", "the indexes of some collections could not be read"
				continue
			}
			col.DB, col.Name, col.HasValidator = db, name, hasValidator
			if !col.IndexStats {
				noUsage = appendUnique(noUsage, db)
			}
			colls = append(colls, col)
			visible[db+"."+name] = true
		}
	}
	if len(noUsage) > 0 {
		usage.State, usage.Detail = "partial", "not readable in "+strings.Join(noUsage, ", ")+" (needs the indexStats privilege, part of clusterMonitor or dbAdmin); unused indexes are not reported there"
		if len(noUsage) == len(dbs) {
			usage.State = "unavailable"
		}
	}
	rep.Sources = append(rep.Sources, idx, usage)

	queries, prof := s.advisorProfiler(ctx, c, dbs, visible, timeout)
	logQueries, slowLog := s.advisorSlowLog(ctx, c, visible, timeout)
	queries = append(queries, logQueries...)
	rep.Sources = append(rep.Sources, prof, slowLog)

	rep.Scanned["databases"], rep.Scanned["collections"], rep.Scanned["queries"] = len(dbs), len(colls), len(queries)
	rep.Findings = advisor.Analyze(colls, queries, time.Now())
	if rep.Findings == nil {
		rep.Findings = []advisor.Finding{}
	}
	return rep
}

func (s *Server) advisorCollection(ctx context.Context, coll *mongo.Collection, timeout time.Duration) (advisor.Collection, bool) {
	var out advisor.Collection
	var specs []bson.D
	if err := s.op(ctx, "listIndexes", timeout, func(ctx context.Context) error {
		cur, err := coll.Indexes().List(ctx)
		if err != nil {
			return err
		}
		return cur.All(ctx, &specs)
	}); err != nil {
		return out, false
	}
	for _, sp := range specs {
		ix := advisor.Index{Name: getString(sp, "name"), Keys: advisor.KeysOf(getValue(sp, "key")), Ops: -1}
		ix.Unique = getValue(sp, "unique") == true
		ix.Sparse = getValue(sp, "sparse") == true
		ix.Hidden = getValue(sp, "hidden") == true
		ix.Partial = getValue(sp, "partialFilterExpression") != nil
		ix.TTL = getValue(sp, "expireAfterSeconds") != nil
		ix.Special = getValue(sp, "collation") != nil || getValue(sp, "wildcardProjection") != nil
		out.Indexes = append(out.Indexes, ix)
	}
	type stat struct {
		Name     string `bson:"name"`
		Accesses struct {
			Ops   int64     `bson:"ops"`
			Since time.Time `bson:"since"`
		} `bson:"accesses"`
	}
	var stats []stat
	err := s.op(ctx, "indexStats", timeout, func(ctx context.Context) error {
		cur, err := coll.Aggregate(ctx, mongo.Pipeline{{{Key: "$indexStats", Value: bson.D{}}}})
		if err != nil {
			return err
		}
		return cur.All(ctx, &stats)
	})
	if err == nil {
		out.IndexStats = true
		for i := range out.Indexes {
			for _, st := range stats {
				if st.Name == out.Indexes[i].Name {
					out.Indexes[i].Ops, out.Indexes[i].Since = st.Accesses.Ops, st.Accesses.Since
				}
			}
		}
	}
	var cs []struct {
		StorageStats struct {
			Count      int64 `bson:"count"`
			AvgObjSize int64 `bson:"avgObjSize"`
		} `bson:"storageStats"`
	}
	err = s.op(ctx, "collStats", timeout, func(ctx context.Context) error {
		cur, err := coll.Aggregate(ctx, mongo.Pipeline{{{Key: "$collStats", Value: bson.D{{Key: "storageStats", Value: bson.D{}}}}}})
		if err != nil {
			return err
		}
		return cur.All(ctx, &cs)
	})
	if err == nil && len(cs) > 0 {
		out.Count, out.AvgObjSize = cs[0].StorageStats.Count, cs[0].StorageStats.AvgObjSize
	} else {
		_ = s.op(ctx, "estimatedDocumentCount", timeout, func(ctx context.Context) error {
			n, err := coll.EstimatedDocumentCount(ctx)
			out.Count = n
			return err
		})
	}
	return out, true
}

// advisorProfiler reads recent profiler entries (written only where a
// database administrator enabled profiling) of visible namespaces.
func (s *Server) advisorProfiler(ctx context.Context, c *mongo.Client, dbs []string, visible map[string]bool, timeout time.Duration) ([]advisor.Query, advisorSource) {
	src := advisorSource{Name: "Profiler (system.profile)", State: "off"}
	var on, denied []string
	var out []advisor.Query
	for _, db := range dbs {
		if ctx.Err() != nil {
			break
		}
		var level struct {
			Was    int32 `bson:"was"`
			SlowMS int32 `bson:"slowms"`
		}
		// profile: -1 reads the current level without changing it.
		levelErr := s.op(ctx, "profileLevel", timeout, func(ctx context.Context) error {
			return c.Database(db).RunCommand(ctx, bson.D{{Key: "profile", Value: -1}}).Decode(&level)
		})
		if levelErr == nil && level.Was == 0 {
			continue
		}
		var docs []bson.D
		err := s.op(ctx, "profilerRead", timeout, func(ctx context.Context) error {
			filter := bson.D{{Key: "ts", Value: bson.D{{Key: "$gte", Value: time.Now().Add(-advisorWindow)}}},
				{Key: "op", Value: bson.D{{Key: "$in", Value: bson.A{"query", "command", "getmore", "update", "remove"}}}}}
			proj := bson.D{{Key: "ns", Value: 1}, {Key: "op", Value: 1}, {Key: "command", Value: 1}, {Key: "originatingCommand", Value: 1}, {Key: "millis", Value: 1},
				{Key: "planSummary", Value: 1}, {Key: "keysExamined", Value: 1}, {Key: "docsExamined", Value: 1}, {Key: "nreturned", Value: 1}, {Key: "hasSortStage", Value: 1}}
			cur, err := c.Database(db).Collection("system.profile").Find(ctx, filter,
				options.Find().SetProjection(proj).SetSort(bson.D{{Key: "ts", Value: -1}}).SetLimit(advisorProfileEntries))
			if err != nil {
				return err
			}
			return cur.All(ctx, &docs)
		})
		if err != nil {
			denied = append(denied, db)
			continue
		}
		on = append(on, db)
		for _, d := range docs {
			// Shapes are taken at once; the documents with values are dropped.
			if q, ok := advisor.FromProfile(d); ok && visible[q.NS] {
				out = append(out, q)
			}
		}
	}
	switch {
	case len(on) > 0:
		src.State, src.Detail = "available", "last 24 hours in "+strings.Join(on, ", ")
	case len(denied) > 0:
		src.State, src.Detail = "unavailable", "not readable in "+strings.Join(denied, ", ")+" (needs find on system.profile, part of dbAdmin)"
	default:
		src.Detail = "profiling is off; a database administrator can enable it for slow operations (db.setProfilingLevel(1, { slowms: 100 }))"
	}
	return out, src
}

// advisorSlowLog reads the server's recent slow-query log lines.
func (s *Server) advisorSlowLog(ctx context.Context, c *mongo.Client, visible map[string]bool, timeout time.Duration) ([]advisor.Query, advisorSource) {
	src := advisorSource{Name: "Slow query log (getLog)", State: "available"}
	var res struct {
		Log []string `bson:"log"`
	}
	err := s.op(ctx, "getLog", timeout, func(ctx context.Context) error {
		return c.Database("admin").RunCommand(ctx, bson.D{{Key: "getLog", Value: "global"}}).Decode(&res)
	})
	if err != nil {
		src.State, src.Detail = "unavailable", "needs the getLog privilege (part of clusterMonitor): "+mongoconn.Classify(err).Msg
		return nil, src
	}
	var out []advisor.Query
	for _, line := range res.Log {
		if !strings.Contains(line, `"id":51803`) {
			continue
		}
		if q, ok := advisor.FromLogLine(line); ok && visible[q.NS] {
			out = append(out, q)
		}
	}
	src.Detail = "recent lines kept in memory by the member that answered"
	return out, src
}

func getValue(d bson.D, key string) any {
	for _, e := range d {
		if e.Key == key {
			return e.Value
		}
	}
	return nil
}

func getString(d bson.D, key string) string {
	v, _ := getValue(d, key).(string)
	return v
}

func appendUnique(list []string, s string) []string {
	if slices.Contains(list, s) {
		return list
	}
	return append(list, s)
}
