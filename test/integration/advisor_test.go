//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// The cluster administrator test uses MongoDB's own privilege report for
// real built-in roles.
func TestClusterAdminFromRealPrivileges(t *testing.T) {
	ctx := context.Background()
	admin := adminClient(t).Database("admin")
	cases := map[string]struct {
		roles bson.A
		want  bool
	}{
		"ca-root":      {bson.A{bson.D{{Key: "role", Value: "root"}, {Key: "db", Value: "admin"}}}, true},
		"ca-cluster":   {bson.A{bson.D{{Key: "role", Value: "clusterAdmin"}, {Key: "db", Value: "admin"}}}, true},
		"ca-useradmin": {bson.A{bson.D{{Key: "role", Value: "userAdminAnyDatabase"}, {Key: "db", Value: "admin"}}}, true},
		"ca-data": {bson.A{bson.D{{Key: "role", Value: "readWriteAnyDatabase"}, {Key: "db", Value: "admin"}},
			bson.D{{Key: "role", Value: "dbAdminAnyDatabase"}, {Key: "db", Value: "admin"}}}, false},
		"ca-monitor": {bson.A{bson.D{{Key: "role", Value: "clusterMonitor"}, {Key: "db", Value: "admin"}}}, false},
	}
	for user, c := range cases {
		_ = admin.RunCommand(ctx, bson.D{{Key: "dropUser", Value: user}}).Err()
		if err := admin.RunCommand(ctx, bson.D{{Key: "createUser", Value: user}, {Key: "pwd", Value: user + "-pw"}, {Key: "roles", Value: c.roles}}).Err(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = admin.RunCommand(context.Background(), bson.D{{Key: "dropUser", Value: user}}).Err() })
		res, err := connect(t, rsProfile(t), user, user+"-pw", "admin")
		if err != nil {
			t.Fatalf("%s: %v", user, err)
		}
		if got := res.Status.ClusterAdmin(); got != c.want {
			t.Errorf("%s: ClusterAdmin() = %v, want %v", user, got, c.want)
		}
		_ = res.Client.Disconnect(ctx)
	}
}

// The advisor finds a full collection scan (with an index suggestion), a
// redundant index and missing constraints from real profiler entries and
// index definitions, and never returns a value used in a query.
func TestPerformanceAdvisor(t *testing.T) {
	ctx := context.Background()
	const sentinel = "marker-must-not-appear-5500"
	root := adminClient(t)
	db := root.Database("advdb")
	_ = db.Drop(ctx)
	t.Cleanup(func() {
		_ = db.RunCommand(context.Background(), bson.D{{Key: "profile", Value: 0}}).Err()
		_ = db.Drop(context.Background())
	})
	var docs []any
	for i := range 3000 {
		docs = append(docs, bson.D{{Key: "customer", Value: "c-" + string(rune('a'+i%26))}, {Key: "status", Value: []string{"open", "done"}[i%2]},
			{Key: "created", Value: time.Unix(int64(i), 0)}, {Key: "card", Value: sentinel}})
	}
	if _, err := db.Collection("orders").InsertMany(ctx, docs); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Collection("orders").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "status", Value: 1}}},
		{Keys: bson.D{{Key: "status", Value: 1}, {Key: "created", Value: -1}}},
	}); err != nil {
		t.Fatal(err)
	}
	// Test setup only: profile every operation of this scratch database.
	if err := db.RunCommand(ctx, bson.D{{Key: "profile", Value: 1}, {Key: "slowms", Value: 0}}).Err(); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		cur, err := db.Collection("orders").Find(ctx, bson.D{{Key: "card", Value: sentinel}, {Key: "customer", Value: "nobody-7731"}}, options.Find().SetLimit(5))
		if err != nil {
			t.Fatal(err)
		}
		_ = cur.All(ctx, &[]bson.D{})
	}

	admin := root.Database("admin")
	_ = admin.RunCommand(ctx, bson.D{{Key: "dropUser", Value: "advuser"}}).Err()
	if err := admin.RunCommand(ctx, bson.D{{Key: "createUser", Value: "advuser"}, {Key: "pwd", Value: "advuser-pw"}, {Key: "roles", Value: bson.A{
		bson.D{{Key: "role", Value: "read"}, {Key: "db", Value: "advdb"}}, bson.D{{Key: "role", Value: "dbAdmin"}, {Key: "db", Value: "advdb"}},
		bson.D{{Key: "role", Value: "clusterMonitor"}, {Key: "db", Value: "admin"}}}}}).Err(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.RunCommand(context.Background(), bson.D{{Key: "dropUser", Value: "advuser"}}).Err() })

	p := newPortal(t, rsProfile(t))
	u := p.login("ann", "others", "rs", "advuser", "advuser-pw")
	code, body, _ := u.raw("GET", "/api/v1/advisor?db=advdb", nil)
	if code != http.StatusOK {
		t.Fatalf("advisor: %d %s", code, body)
	}
	if strings.Contains(string(body), sentinel) || strings.Contains(string(body), "nobody-7731") {
		t.Fatalf("a query value reached the response: %s", body)
	}
	var rep struct {
		Findings []struct {
			Kind, Namespace, Suggestion, Severity string
			Evidence                              map[string]any
		} `json:"findings"`
		Sources []struct{ Name, State string } `json:"sources"`
		Scanned map[string]int                 `json:"scanned"`
	}
	if err := json.Unmarshal(body, &rep); err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, f := range rep.Findings {
		kinds[f.Kind] = f.Suggestion
	}
	if s := kinds["missing_index"]; !strings.Contains(s, `getCollection("orders").createIndex({ "card": 1, "customer": 1 })`) {
		t.Fatalf("missing index suggestion: %q in %s", s, body)
	}
	if s := kinds["redundant_index"]; !strings.Contains(s, `dropIndex("status_1")`) {
		t.Fatalf("redundant index: %q", s)
	}
	if _, ok := kinds["no_constraints"]; !ok {
		t.Fatalf("constraints: %s", body)
	}
	states := map[string]string{}
	for _, s := range rep.Sources {
		states[s.Name] = s.State
	}
	if states["Profiler (system.profile)"] != "available" || rep.Scanned["collections"] != 1 || rep.Scanned["queries"] == 0 {
		t.Fatalf("sources: %v scanned %v", states, rep.Scanned)
	}

	// A user without privileges on the database gets an empty, partial
	// report, not an error; the RBAC still requires monitoring get.
	r := p.login("rob", "others", "rs", "reader", "reader-pw")
	if code, body, _ := r.raw("GET", "/api/v1/advisor?db=advdb", nil); code != http.StatusOK || strings.Contains(string(body), `"kind":"missing_index"`) {
		t.Fatalf("unprivileged advisor: %d %s", code, body)
	}
	if code, _, _ := u.raw("GET", "/api/v1/advisor?db=admin", nil); code != http.StatusBadRequest {
		t.Fatalf("internal databases are refused: %d", code)
	}
}
