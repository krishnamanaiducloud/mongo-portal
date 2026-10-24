package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/krishnamanaiducloud/mongo-portal/internal/config"
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
		{"oplog", "find on local.oplog.rs", func(ctx context.Context) (any, error) { return s.monOplog(ctx, rc) }},
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
	th := s.Config.Monitoring.Thresholds
	writeJSON(w, http.StatusOK, map[string]any{
		"collectedAt": time.Now().UTC(),
		"profile":     rc.sess.Profile,
		"tls":         rc.sess.TLS,
		"session":     map[string]any{"pool": pool, "maxPoolSize": maxPool},
		"sections":    out,
		"alerts":      alerts(out, th),
		"thresholds": map[string]any{
			"replicationLagWarningSeconds": th.ReplicationLagWarning.Seconds(), "replicationLagCriticalSeconds": th.ReplicationLagCritical.Seconds(),
			"connectionsWarnPercent": th.ConnectionsWarnPercent, "cacheUsedWarnPercent": th.CacheUsedWarnPercent,
			"cacheDirtyWarnPercent": th.CacheDirtyWarnPercent, "oplogWindowWarningSeconds": th.OplogWindowWarning.Seconds(),
			"queueWarn": th.QueueWarn, "authFailuresWarnPerPoll": th.AuthFailuresWarnPerPoll,
			"slowOperationSeconds": s.Config.Monitoring.SlowOperation.Seconds(),
		},
	})
}

func (s *Server) adminCmd(ctx context.Context, rc *reqCtx, cmd bson.D) (bson.M, error) {
	var res bson.M
	err := rc.sess.Client.Database("admin").RunCommand(ctx, cmd).Decode(&res)
	return res, err
}

func (s *Server) monServer(ctx context.Context, rc *reqCtx) (any, error) {
	st, err := s.adminCmd(ctx, rc, bson.D{{Key: "serverStatus", Value: 1}, {Key: "metrics", Value: 0}, {Key: "tcmalloc", Value: 0}, {Key: "mirroredReads", Value: 0}})
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
			"physicalBytesIn": mnum(netw, "physicalBytesIn"), "physicalBytesOut": mnum(netw, "physicalBytesOut"),
		},
		"opcounters": mnumbers(msub(st, "opcounters"), "insert", "query", "update", "delete", "getmore", "command"),
		"memoryMB":   mnumbers(mem, "resident", "virtual"),
		"cache": map[string]any{
			"bytesInCache": mnum(cache, "bytes currently in the cache"),
			"maxBytes":     mnum(cache, "maximum bytes configured"),
			"dirtyBytes":   mnum(cache, "tracked dirty bytes in the cache"),
		},
		"eviction": map[string]any{
			"applicationThreadPages": mnum(cache, "pages evicted by application threads"),
			"modifiedPages":          mnum(cache, "modified pages evicted"),
			"unmodifiedPages":        mnum(cache, "unmodified pages evicted"),
			"pagesReadIntoCache":     mnum(cache, "pages read into cache"),
			"pagesWrittenFromCache":  mnum(cache, "pages written from cache"),
			"bytesReadIntoCache":     mnum(cache, "bytes read into cache"),
			"bytesWrittenFromCache":  mnum(cache, "bytes written from cache"),
		},
		"tickets":        tickets(msub(wt, "concurrentTransactions"), msub(msub(st, "queues"), "execution")),
		"latency":        latencies(msub(st, "opLatencies")),
		"cpu":            mnumbers(msub(st, "extra_info"), "user_time_us", "system_time_us", "page_faults"),
		"locks":          lockWaits(msub(st, "locks")),
		"authentication": authCounters(msub(msub(st, "security"), "authentication")),
		"activeClients":  mnumbers(msub(msub(st, "globalLock"), "activeClients"), "readers", "writers", "total"),
		"queue":          mnumbers(msub(msub(st, "globalLock"), "currentQueue"), "readers", "writers", "total"),
		"asserts":        mnumbers(msub(st, "asserts"), "regular", "warning", "msg", "user", "rollovers"),
		"transactions":   mnumbers(msub(st, "transactions"), "currentActive", "currentOpen", "totalCommitted", "totalAborted"),
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
	res := map[string]any{"set": mstr(st, "set"), "members": out, "term": mnum(st, "term"),
		"majorityVoteCount": mnum(st, "majorityVoteCount"), "writeMajorityCount": mnum(st, "writeMajorityCount"),
		"heartbeatIntervalMillis": mnum(st, "heartbeatIntervalMillis")}
	// Election metrics describe the last election this member took part in.
	if em := msub(st, "electionCandidateMetrics"); len(em) > 0 {
		e := map[string]any{"reason": mstr(em, "lastElectionReason"), "term": mnum(em, "electionTerm"), "role": "candidate"}
		if t := mdate(em, "lastElectionDate"); !t.IsZero() {
			e["date"] = t.UTC()
		}
		res["lastElection"] = e
	} else if ep := msub(st, "electionParticipantMetrics"); len(ep) > 0 {
		e := map[string]any{"term": mnum(ep, "electionTerm"), "role": "participant", "votedForCandidate": mbool(ep, "votedForCandidate")}
		if t := mdate(ep, "lastVoteDate"); !t.IsZero() {
			e["date"] = t.UTC()
		}
		res["lastElection"] = e
	}
	return res, nil
}

// monOplog reports the oplog size and the time window it covers (how long
// a secondary may be offline and still catch up).
func (s *Server) monOplog(ctx context.Context, rc *reqCtx) (any, error) {
	c := rc.sess.Client.Database("local").Collection("oplog.rs")
	first, last := bson.M{}, bson.M{}
	po := options.FindOne().SetProjection(bson.D{{Key: "ts", Value: 1}, {Key: "_id", Value: 0}})
	if err := c.FindOne(ctx, bson.D{}, po.SetSort(bson.D{{Key: "$natural", Value: 1}})).Decode(&first); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return map[string]any{"available": false}, nil
		}
		return nil, err
	}
	if err := c.FindOne(ctx, bson.D{}, options.FindOne().SetProjection(bson.D{{Key: "ts", Value: 1}, {Key: "_id", Value: 0}}).SetSort(bson.D{{Key: "$natural", Value: -1}})).Decode(&last); err != nil {
		return nil, err
	}
	t1, _ := first["ts"].(bson.Timestamp)
	t2, _ := last["ts"].(bson.Timestamp)
	out := map[string]any{"available": true, "first": time.Unix(int64(t1.T), 0).UTC(), "last": time.Unix(int64(t2.T), 0).UTC(),
		"windowSeconds": float64(t2.T) - float64(t1.T)}
	var stats bson.M
	if err := rc.sess.Client.Database("local").RunCommand(ctx, bson.D{{Key: "collStats", Value: "oplog.rs"}}).Decode(&stats); err == nil {
		out["sizeBytes"], out["maxSizeBytes"] = mnum(stats, "size"), mnum(stats, "maxSize")
	}
	return out, nil
}

func tickets(ct, exec bson.M) map[string]any {
	src := ct
	if len(exec) > 0 {
		src = exec // MongoDB 7.0+: queues.execution
	}
	r, w := msub(src, "read"), msub(src, "write")
	return map[string]any{"readOut": mnum(r, "out"), "readAvailable": mnum(r, "available"), "writeOut": mnum(w, "out"), "writeAvailable": mnum(w, "available")}
}

func latencies(l bson.M) map[string]any {
	out := map[string]any{}
	for _, k := range []string{"reads", "writes", "commands", "transactions"} {
		x := msub(l, k)
		out[k] = map[string]float64{"latencyMicros": mnum(x, "latency"), "ops": mnum(x, "ops")}
	}
	return out
}

func lockWaits(l bson.M) map[string]any {
	g := msub(l, "Global")
	sum := func(d bson.M) float64 {
		t := 0.0
		for _, v := range d {
			if f, ok := toFloat(v); ok {
				t += f
			}
		}
		return t
	}
	return map[string]any{"globalWaitCount": sum(msub(g, "acquireWaitCount")), "globalWaitMicros": sum(msub(g, "timeAcquiringMicros"))}
}

func authCounters(a bson.M) map[string]any {
	received, ok := 0.0, 0.0
	byMech := map[string]map[string]float64{}
	for mech, v := range msub(a, "mechanisms") {
		m, _ := mdoc(v)
		au := msub(m, "authenticate")
		r, s := mnum(au, "received"), mnum(au, "successful")
		received, ok = received+r, ok+s
		byMech[mech] = map[string]float64{"received": r, "successful": s}
	}
	return map[string]any{"received": received, "successful": ok, "failed": max(received-ok, 0), "byMechanism": byMech}
}

// alerts turns section data into warnings with the configured thresholds.
func alerts(secs map[string]monSection, th config.Thresholds) []map[string]any {
	out := []map[string]any{}
	add := func(sev, sec, msg string) {
		out = append(out, map[string]any{"severity": sev, "section": sec, "message": msg})
	}
	if rs, ok := secs["replicaSet"].Data.(map[string]any); ok {
		members, _ := rs["members"].([]map[string]any)
		primaries := 0
		for _, m := range members {
			name, _ := m["name"].(string)
			state, _ := m["state"].(string)
			if state == "PRIMARY" {
				primaries++
			}
			if h, _ := m["health"].(float64); h == 0 || state == "DOWN" || state == "UNKNOWN" {
				add("critical", "replicaSet", "Member "+name+" is not reachable ("+state+")")
			} else if state != "PRIMARY" && state != "SECONDARY" && state != "ARBITER" {
				add("warning", "replicaSet", "Member "+name+" is "+state)
			}
			if lag, ok := m["lagSeconds"].(float64); ok {
				switch {
				case lag >= th.ReplicationLagCritical.Seconds():
					add("critical", "replicaSet", fmt.Sprintf("Member %s lags %.0f s behind the primary", name, lag))
				case lag >= th.ReplicationLagWarning.Seconds():
					add("warning", "replicaSet", fmt.Sprintf("Member %s lags %.0f s behind the primary", name, lag))
				}
			}
		}
		if len(members) > 0 && primaries == 0 {
			add("critical", "replicaSet", "The replica set has no primary: writes are not possible")
		}
	}
	if sv, ok := secs["server"].Data.(map[string]any); ok {
		if c, ok := sv["connections"].(map[string]any); ok {
			cur, _ := c["current"].(float64)
			avail, _ := c["available"].(float64)
			if cur+avail > 0 && cur/(cur+avail)*100 >= th.ConnectionsWarnPercent {
				add("warning", "connections", fmt.Sprintf("%.0f%% of the connection limit is in use", cur/(cur+avail)*100))
			}
		}
		if c, ok := sv["cache"].(map[string]any); ok {
			used, _ := c["bytesInCache"].(float64)
			maxB, _ := c["maxBytes"].(float64)
			dirty, _ := c["dirtyBytes"].(float64)
			if maxB > 0 && used/maxB*100 >= th.CacheUsedWarnPercent {
				add("warning", "resources", fmt.Sprintf("WiredTiger cache is %.0f%% full: eviction pressure", used/maxB*100))
			}
			if maxB > 0 && dirty/maxB*100 >= th.CacheDirtyWarnPercent {
				add("warning", "resources", fmt.Sprintf("Dirty data is %.1f%% of the cache (write pressure)", dirty/maxB*100))
			}
		}
		if q, ok := sv["queue"].(map[string]float64); ok && q["total"] >= th.QueueWarn {
			add("warning", "resources", fmt.Sprintf("%.0f operations are queued waiting for locks or tickets", q["total"]))
		}
	}
	if ol, ok := secs["oplog"].Data.(map[string]any); ok {
		if w, ok := ol["windowSeconds"].(float64); ok && w > 0 && w < th.OplogWindowWarning.Seconds() {
			add("warning", "oplog", fmt.Sprintf("The oplog covers only %.1f hours", w/3600))
		}
	}
	if cn, ok := secs["connections"].Data.(map[string]any); ok {
		if n, _ := cn["slowOperations"].(int); n > 0 {
			add("info", "operations", fmt.Sprintf("%d operations are running longer than the slow threshold", n))
		}
	}
	return out
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case float64:
		return n, true
	}
	return 0, false
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
	// dbStats for the largest databases: data vs storage vs index size and
	// the file system the data lives on.
	stats := []map[string]any{}
	for _, d := range list[:min(len(list), 20)] {
		var st bson.M
		sctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := rc.sess.Client.Database(d.Name).RunCommand(sctx, bson.D{{Key: "dbStats", Value: 1}, {Key: "scale", Value: 1}}).Decode(&st)
		cancel()
		if err != nil {
			continue
		}
		stats = append(stats, map[string]any{"name": d.Name, "collections": mnum(st, "collections"), "objects": mnum(st, "objects"),
			"dataSize": mnum(st, "dataSize"), "storageSize": mnum(st, "storageSize"), "indexSize": mnum(st, "indexSize"),
			"indexes": mnum(st, "indexes"), "fsUsedSize": mnum(st, "fsUsedSize"), "fsTotalSize": mnum(st, "fsTotalSize")})
	}
	return map[string]any{"totalSize": res.TotalSize, "visibleSize": visible, "databases": list, "stats": stats}, nil
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
	slow := 0
	for _, o := range ops {
		if o.Secs >= s.Config.Monitoring.SlowOperation.Seconds() {
			slow++
		}
	}
	return map[string]any{
		"total": total, "active": active, "idle": total - active, "internalThreads": internal,
		"byClient": list, "operations": ops, "clientGroups": len(groups), "slowOperations": slow,
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
