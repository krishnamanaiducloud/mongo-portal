package api

import (
	"context"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/krishnamanaiducloud/mongo-portal/internal/mongoconn"
	"github.com/krishnamanaiducloud/mongo-portal/internal/rbac"
)

// Monitoring collects deployment health with the user's own MongoDB
// session. Every section is independent: a section the user's MongoDB roles
// do not allow (most need clusterMonitor) reports why instead of failing the
// page. Only metadata is returned: no query texts, documents or commands.

type monSection struct {
	Data  any    `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
	Code  string `json:"code,omitempty"`
}

const (
	monMaxClients = 100
	monMaxOps     = 50
)

func (s *Server) handleMonitoring(w http.ResponseWriter, r *http.Request, rc *reqCtx) {
	if !s.authorize(w, r, rc, rbac.Server, rbac.Get, rc.sess.Profile) {
		return
	}
	type job struct {
		name string
		cmd  string // for the privilege hint
		fn   func(context.Context) (any, error)
	}
	jobs := []job{
		{"server", "serverStatus", func(ctx context.Context) (any, error) { return s.monServer(ctx, rc) }},
		{"host", "hostInfo", func(ctx context.Context) (any, error) { return s.monHost(ctx, rc) }},
		{"replicaSet", "replSetGetStatus", func(ctx context.Context) (any, error) { return s.monReplicaSet(ctx, rc) }},
		{"databases", "listDatabases", func(ctx context.Context) (any, error) { return s.monDatabases(ctx, rc) }},
		{"connections", "$currentOp", func(ctx context.Context) (any, error) { return s.monConnections(ctx, rc) }},
	}
	out := map[string]monSection{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var data any
			err := s.op(r.Context(), "monitoring."+j.name, s.defaultTimeout(), func(ctx context.Context) error {
				var err error
				data, err = j.fn(ctx)
				return err
			})
			sec := monSection{Data: data}
			if err != nil {
				me := mongoconn.Classify(err)
				sec = monSection{Code: string(me.Kind), Error: me.Msg}
				if me.Kind == mongoconn.KindUnauthorized {
					sec.Error = "Your MongoDB user may not run " + j.cmd + ". The built-in clusterMonitor role grants it."
				}
			}
			mu.Lock()
			out[j.name] = sec
			mu.Unlock()
		}()
	}
	wg.Wait()

	pool := rc.sess.Pool.Snapshot()
	maxPool := uint64(0)
	if p, ok := s.Config.Profile(rc.sess.Profile); ok {
		maxPool = p.MaxPoolSize
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"collectedAt": time.Now().UTC(),
		"profile":     rc.sess.Profile,
		"tls":         rc.sess.TLS,
		"session":     map[string]any{"pool": pool, "maxPoolSize": maxPool},
		"sections":    out,
	})
}

func (s *Server) adminCmd(ctx context.Context, rc *reqCtx, cmd bson.D) (bson.M, error) {
	var res bson.M
	err := rc.sess.Client.Database("admin").RunCommand(ctx, cmd).Decode(&res)
	return res, err
}

func (s *Server) monServer(ctx context.Context, rc *reqCtx) (any, error) {
	st, err := s.adminCmd(ctx, rc, bson.D{{Key: "serverStatus", Value: 1}, {Key: "metrics", Value: 0}, {Key: "locks", Value: 0}, {Key: "tcmalloc", Value: 0}})
	if err != nil {
		return nil, err
	}
	conn := msub(st, "connections")
	wt := msub(st, "wiredTiger")
	cache := msub(wt, "cache")
	netw := msub(st, "network")
	mem := msub(st, "mem")
	return map[string]any{
		"host":          mstr(st, "host"),
		"version":       mstr(st, "version"),
		"process":       mstr(st, "process"),
		"uptimeSeconds": mnum(st, "uptime"),
		"storageEngine": mstr(msub(st, "storageEngine"), "name"),
		"connections": map[string]any{
			"current": mnum(conn, "current"), "available": mnum(conn, "available"),
			"active": mnum(conn, "active"), "totalCreated": mnum(conn, "totalCreated"),
			"rejected": mnum(conn, "rejected"), "exhaustHello": mnum(conn, "exhaustHello"),
			"awaitingTopologyChanges": mnum(conn, "awaitingTopologyChanges"),
		},
		"network": map[string]any{
			"bytesIn": mnum(netw, "bytesIn"), "bytesOut": mnum(netw, "bytesOut"), "numRequests": mnum(netw, "numRequests"),
		},
		"opcounters": mnumbers(msub(st, "opcounters"), "insert", "query", "update", "delete", "getmore", "command"),
		"memoryMB":   mnumbers(mem, "resident", "virtual"),
		"cache": map[string]any{
			"bytesInCache": mnum(cache, "bytes currently in the cache"),
			"maxBytes":     mnum(cache, "maximum bytes configured"),
			"dirtyBytes":   mnum(cache, "tracked dirty bytes in the cache"),
		},
		"activeClients": mnumbers(msub(msub(st, "globalLock"), "activeClients"), "readers", "writers", "total"),
		"queue":         mnumbers(msub(msub(st, "globalLock"), "currentQueue"), "readers", "writers", "total"),
		"asserts":       mnumbers(msub(st, "asserts"), "regular", "warning", "msg", "user", "rollovers"),
		"transactions":  mnumbers(msub(st, "transactions"), "currentActive", "currentOpen", "totalCommitted", "totalAborted"),
	}, nil
}

func (s *Server) monHost(ctx context.Context, rc *reqCtx) (any, error) {
	h, err := s.adminCmd(ctx, rc, bson.D{{Key: "hostInfo", Value: 1}})
	if err != nil {
		return nil, err
	}
	sys, osInfo := msub(h, "system"), msub(h, "os")
	return map[string]any{
		"hostname": mstr(sys, "hostname"), "cpuArch": mstr(sys, "cpuArch"), "numCores": mnum(sys, "numCores"),
		"memSizeMB": mnum(sys, "memSizeMB"), "memLimitMB": mnum(sys, "memLimitMB"),
		"os": strings.TrimSpace(mstr(osInfo, "name") + " " + mstr(osInfo, "version")),
	}, nil
}

func (s *Server) monReplicaSet(ctx context.Context, rc *reqCtx) (any, error) {
	st, err := s.adminCmd(ctx, rc, bson.D{{Key: "replSetGetStatus", Value: 1}})
	if err != nil {
		if me := mongoconn.Classify(err); me.Code == 76 { // NoReplicationEnabled: standalone
			return map[string]any{"standalone": true}, nil
		}
		return nil, err
	}
	// Member configuration (priority, votes, hidden) is optional extra detail.
	cfgByID := map[int64]bson.M{}
	if c, err := s.adminCmd(ctx, rc, bson.D{{Key: "replSetGetConfig", Value: 1}}); err == nil {
		for _, m := range marr(msub(c, "config"), "members") {
			if mm, ok := mdoc(m); ok {
				cfgByID[int64(mnum(mm, "_id"))] = mm
			}
		}
	}
	var primaryOptime time.Time
	members := marr(st, "members")
	for _, m := range members {
		if mm, ok := mdoc(m); ok && mstr(mm, "stateStr") == "PRIMARY" {
			primaryOptime = mdate(mm, "optimeDate")
		}
	}
	out := make([]map[string]any, 0, len(members))
	for _, m := range members {
		mm, ok := mdoc(m)
		if !ok {
			continue
		}
		v := map[string]any{
			"name": mstr(mm, "name"), "state": mstr(mm, "stateStr"), "health": mnum(mm, "health"),
			"uptimeSeconds": mnum(mm, "uptime"), "pingMs": mnum(mm, "pingMs"), "self": mbool(mm, "self"),
			"syncSource": mstr(mm, "syncSourceHost"), "lastHeartbeatMessage": mstr(mm, "lastHeartbeatMessage"),
		}
		if t := mdate(mm, "optimeDate"); !t.IsZero() {
			v["optimeDate"] = t.UTC()
			if !primaryOptime.IsZero() {
				v["lagSeconds"] = max(primaryOptime.Sub(t).Seconds(), 0)
			}
		}
		if c, ok := cfgByID[int64(mnum(mm, "_id"))]; ok {
			v["priority"], v["votes"] = mnum(c, "priority"), mnum(c, "votes")
			v["hidden"], v["arbiterOnly"] = mbool(c, "hidden"), mbool(c, "arbiterOnly")
		}
		out = append(out, v)
	}
	return map[string]any{"set": mstr(st, "set"), "members": out, "term": mnum(st, "term")}, nil
}

func (s *Server) monDatabases(ctx context.Context, rc *reqCtx) (any, error) {
	res, err := rc.sess.Client.ListDatabases(ctx, bson.D{}, options.ListDatabases().SetAuthorizedDatabases(true))
	if err != nil {
		return nil, err
	}
	type dbv struct {
		Name       string `json:"name"`
		SizeOnDisk int64  `json:"sizeOnDisk"`
		Empty      bool   `json:"empty"`
	}
	var list []dbv
	for _, d := range res.Databases {
		if s.allowed(rc, rbac.Databases, rbac.Get, d.Name) {
			list = append(list, dbv{d.Name, d.SizeOnDisk, d.Empty})
		}
	}
	slices.SortFunc(list, func(a, b dbv) int { return int(b.SizeOnDisk - a.SizeOnDisk) })
	var visible int64
	for _, d := range list {
		visible += d.SizeOnDisk
	}
	return map[string]any{"totalSize": res.TotalSize, "visibleSize": visible, "databases": list}, nil
}

// monConnections summarizes every client connection (active and idle) with
// $currentOp. Command and query documents are never read into the result.
func (s *Server) monConnections(ctx context.Context, rc *reqCtx) (any, error) {
	pipe := bson.A{
		bson.D{{Key: "$currentOp", Value: bson.D{{Key: "allUsers", Value: true}, {Key: "idleConnections", Value: true}, {Key: "idleSessions", Value: false}}}},
		bson.D{{Key: "$project", Value: bson.D{
			{Key: "active", Value: 1}, {Key: "type", Value: 1}, {Key: "op", Value: 1}, {Key: "ns", Value: 1},
			{Key: "secs_running", Value: 1}, {Key: "client", Value: 1}, {Key: "appName", Value: 1}, {Key: "desc", Value: 1},
			{Key: "opid", Value: 1}, {Key: "waitingForLock", Value: 1}, {Key: "planSummary", Value: 1},
			{Key: "user", Value: bson.D{{Key: "$arrayElemAt", Value: bson.A{"$effectiveUsers.user", 0}}}},
		}}},
	}
	cur, err := rc.sess.Client.Database("admin").Aggregate(ctx, pipe)
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	type group struct {
		Client  string `json:"client"`
		AppName string `json:"appName"`
		User    string `json:"user"`
		Total   int    `json:"total"`
		Active  int    `json:"active"`
		Idle    int    `json:"idle"`
	}
	type opv struct {
		OpID       any     `json:"opid"`
		Op         string  `json:"op"`
		NS         string  `json:"ns"`
		Secs       float64 `json:"secsRunning"`
		Client     string  `json:"client"`
		AppName    string  `json:"appName"`
		User       string  `json:"user"`
		WaitingFor bool    `json:"waitingForLock"`
		Plan       string  `json:"planSummary,omitempty"`
	}
	groups := map[string]*group{}
	var ops []opv
	total, active, internal := 0, 0, 0
	for cur.Next(ctx) {
		var d bson.M
		if err := cur.Decode(&d); err != nil {
			return nil, err
		}
		host := mstr(d, "client")
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if host == "" {
			// Internal threads (replication, TTL monitor, ...), not client connections.
			internal++
			continue
		}
		total++
		isActive := mbool(d, "active")
		app, user := mstr(d, "appName"), mstr(d, "user")
		key := host + "\x00" + app + "\x00" + user
		g, ok := groups[key]
		if !ok {
			g = &group{Client: host, AppName: app, User: user}
			groups[key] = g
		}
		g.Total++
		if isActive {
			active++
			g.Active++
			if op := mstr(d, "op"); op != "" && op != "none" && !strings.HasPrefix(app, "mongo-portal") {
				ops = append(ops, opv{OpID: d["opid"], Op: op, NS: mstr(d, "ns"), Secs: mnum(d, "secs_running"), Client: host,
					AppName: app, User: user, WaitingFor: mbool(d, "waitingForLock"), Plan: mstr(d, "planSummary")})
			}
		} else {
			g.Idle++
		}
	}
	if err := cur.Err(); err != nil {
		return nil, err
	}
	list := make([]group, 0, len(groups))
	for _, g := range groups {
		list = append(list, *g)
	}
	slices.SortFunc(list, func(a, b group) int { return b.Total - a.Total })
	if len(list) > monMaxClients {
		list = list[:monMaxClients]
	}
	slices.SortFunc(ops, func(a, b opv) int {
		switch {
		case a.Secs > b.Secs:
			return -1
		case a.Secs < b.Secs:
			return 1
		}
		return 0
	})
	if len(ops) > monMaxOps {
		ops = ops[:monMaxOps]
	}
	if ops == nil {
		ops = []opv{}
	}
	return map[string]any{
		"total": total, "active": active, "idle": total - active, "internalThreads": internal,
		"byClient": list, "operations": ops, "clientGroups": len(groups),
	}, nil
}

// ---- small helpers for loosely typed command replies ----

// mdoc accepts an embedded document in either decoded form: the driver
// yields bson.D for documents nested in arrays and interface values.
func mdoc(v any) (bson.M, bool) {
	switch v := v.(type) {
	case bson.M:
		return v, true
	case bson.D:
		out := make(bson.M, len(v))
		for _, e := range v {
			out[e.Key] = e.Value
		}
		return out, true
	}
	return nil, false
}

func msub(m bson.M, k string) bson.M {
	if d, ok := mdoc(m[k]); ok {
		return d
	}
	return bson.M{}
}

func marr(m bson.M, k string) bson.A {
	if v, ok := m[k].(bson.A); ok {
		return v
	}
	return nil
}

func mstr(m bson.M, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func mbool(m bson.M, k string) bool {
	v, _ := m[k].(bool)
	return v
}

func mnum(m bson.M, k string) float64 {
	switch v := m[k].(type) {
	case int32:
		return float64(v)
	case int64:
		return float64(v)
	case float64:
		return v
	}
	return 0
}

func mnumbers(m bson.M, keys ...string) map[string]float64 {
	out := make(map[string]float64, len(keys))
	for _, k := range keys {
		out[k] = mnum(m, k)
	}
	return out
}

func mdate(m bson.M, k string) time.Time {
	switch v := m[k].(type) {
	case bson.DateTime:
		return v.Time()
	case time.Time:
		return v
	}
	return time.Time{}
}
