package advisor

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// sentinel appears in every value position; it must never reach a finding.
const sentinel = "marker-4111111111111111"

func secretFilter() bson.D {
	return bson.D{
		{Key: "email", Value: sentinel},
		{Key: "age", Value: bson.D{{Key: "$gt", Value: 42424242}, {Key: "$lt", Value: sentinel}}},
		{Key: "tags", Value: bson.D{{Key: "$in", Value: bson.A{sentinel, "x"}}}},
		{Key: "address", Value: bson.D{{Key: "street", Value: sentinel}}},
		{Key: "items", Value: bson.D{{Key: "$elemMatch", Value: bson.D{{Key: "sku", Value: sentinel}}}}},
		{Key: "name", Value: bson.D{{Key: "$regex", Value: sentinel}}},
		{Key: "$or", Value: bson.A{bson.D{{Key: "a", Value: sentinel}}, bson.D{{Key: "b", Value: bson.D{{Key: "$ne", Value: sentinel}}}}}},
		{Key: "$expr", Value: bson.D{{Key: "$eq", Value: bson.A{"$x", sentinel}}}},
		{Key: "$where", Value: "this.pw == '" + sentinel + "'"},
	}
}

func TestShapeNeverContainsValues(t *testing.T) {
	s := ShapeString(Shape(secretFilter()))
	if strings.Contains(s, "marker-") || strings.Contains(s, "4111") || strings.Contains(s, "42424242") {
		t.Fatalf("value leaked into the shape: %s", s)
	}
	for _, want := range []string{`"email":"?"`, `"$gt":"?"`, `"$in":"?"`, `"address":"?"`, `"$elemMatch":{"sku":"?"}`, `"$or"`, `"$expr":"?"`, `"$where":"?"`} {
		if !strings.Contains(s, want) {
			t.Errorf("shape lacks %s: %s", want, s)
		}
	}
	// The whole analysis output, including suggestions, stays clean.
	q := Query{NS: "app.users", PlanSummary: "COLLSCAN", DocsExamined: 500000, NReturned: 1, Millis: 2000,
		Filter: Shape(secretFilter()), Sort: SortShape(bson.D{{Key: "created", Value: -1}})}
	out, _ := json.Marshal(Analyze(nil, []Query{q}, time.Now()))
	if strings.Contains(string(out), "marker-") || strings.Contains(string(out), "42424242") {
		t.Fatalf("value leaked into findings: %s", out)
	}
}

func TestSuggestIndexESR(t *testing.T) {
	q := Query{
		Filter: Shape(bson.D{{Key: "amount", Value: bson.D{{Key: "$gte", Value: 10}}}, {Key: "status", Value: "open"},
			{Key: "region", Value: bson.D{{Key: "$in", Value: bson.A{"eu", "us"}}}}}),
		Sort: SortShape(bson.D{{Key: "created", Value: int32(-1)}}),
	}
	got := keysJS(SuggestIndex(q))
	if got != `{ "status": 1, "region": 1, "created": -1, "amount": 1 }` {
		t.Fatalf("ESR order: %s", got)
	}
	if k := SuggestIndex(Query{Filter: Shape(bson.D{{Key: "$or", Value: bson.A{bson.D{{Key: "a", Value: 1}}}}})}); k != nil {
		t.Fatalf("$or must not produce a single index: %v", k)
	}
}

func TestCommandsQuoteNames(t *testing.T) {
	cmd := CreateIndexCommand(`app"); db.dropDatabase(); ("`, "orders", bson.D{{Key: `x"y`, Value: 1}})
	if !strings.Contains(cmd, `"app\"); db.dropDatabase(); (\""`) || !strings.Contains(cmd, `"x\"y": 1`) {
		t.Fatalf("names must be JSON-quoted: %s", cmd)
	}
}

func TestQueryFindings(t *testing.T) {
	coll := Collection{DB: "app", Name: "orders", Count: 2_000_000, Indexes: []Index{
		{Name: "_id_", Keys: bson.D{{Key: "_id", Value: 1}}, Ops: -1},
		{Name: "status_1", Keys: bson.D{{Key: "status", Value: 1}}, Ops: -1},
	}}
	scan := Query{NS: "app.orders", PlanSummary: "COLLSCAN", DocsExamined: 2_000_000, NReturned: 3, Millis: 1500,
		Filter: Shape(bson.D{{Key: "customer", Value: "c-1"}})}
	unselective := Query{NS: "app.orders", PlanSummary: "IXSCAN { status: 1 }", KeysExamined: 900_000, DocsExamined: 900_000, NReturned: 10, Millis: 900,
		Filter: Shape(bson.D{{Key: "status", Value: "open"}, {Key: "customer", Value: "c-2"}})}
	sorted := Query{NS: "app.orders", PlanSummary: "IXSCAN { status: 1 }", KeysExamined: 50, DocsExamined: 50, NReturned: 50, Millis: 300, HasSortStage: true,
		Filter: Shape(bson.D{{Key: "status", Value: "open"}}), Sort: SortShape(bson.D{{Key: "created", Value: -1}})}
	fs := Analyze([]Collection{coll}, []Query{scan, scan, unselective, sorted}, time.Now())
	kinds := map[string]Finding{}
	for _, f := range fs {
		kinds[f.Kind] = f
	}
	if f := kinds["missing_index"]; f.Severity != Critical || !strings.Contains(f.Suggestion, `createIndex({ "customer": 1 })`) || f.Evidence["occurrences"] != int64(2) {
		t.Fatalf("missing index: %+v", f)
	}
	if f := kinds["inefficient_index"]; f.Suggestion == "" || !strings.Contains(f.Suggestion, `"status": 1, "customer": 1`) {
		t.Fatalf("inefficient index: %+v", f)
	}
	if f := kinds["in_memory_sort"]; !strings.Contains(f.Suggestion, `"status": 1, "created": -1`) {
		t.Fatalf("in-memory sort: %+v", f)
	}
	// An existing index with the suggested fields is not suggested again.
	covered := Query{NS: "app.orders", PlanSummary: "COLLSCAN", DocsExamined: 5000, NReturned: 1, Filter: Shape(bson.D{{Key: "status", Value: "x"}})}
	for _, f := range Analyze([]Collection{coll}, []Query{covered}, time.Now()) {
		if f.Kind == "missing_index" && (f.Suggestion != "" || !strings.Contains(f.Detail, `"status_1"`)) {
			t.Fatalf("covered: %+v", f)
		}
	}
	// Fast, small scans are not findings.
	if fs := Analyze(nil, []Query{{NS: "a.b", PlanSummary: "COLLSCAN", DocsExamined: 10, NReturned: 10}}, time.Now()); len(fs) != 0 {
		t.Fatalf("noise: %+v", fs)
	}
}

func TestCollectionFindings(t *testing.T) {
	now := time.Now()
	old := now.Add(-30 * 24 * time.Hour)
	c := Collection{DB: "app", Name: "users", Count: 10, AvgObjSize: 2 << 20, IndexStats: true, Indexes: []Index{
		{Name: "_id_", Keys: bson.D{{Key: "_id", Value: 1}}, Ops: 0, Since: old},
		{Name: "email_1", Keys: bson.D{{Key: "email", Value: 1}}, Ops: 5, Since: old},
		{Name: "email_1_name_1", Keys: bson.D{{Key: "email", Value: 1}, {Key: "name", Value: 1}}, Ops: 3, Since: old},
		{Name: "legacy_1", Keys: bson.D{{Key: "legacy", Value: 1}}, Ops: 0, Since: old},
		{Name: "fresh_1", Keys: bson.D{{Key: "fresh", Value: 1}}, Ops: 0, Since: now.Add(-time.Hour)},
		{Name: "sku_1", Keys: bson.D{{Key: "sku", Value: 1}}, Unique: true, Ops: 0, Since: old},
	}}
	got := map[string][]Finding{}
	for _, f := range Analyze([]Collection{c}, nil, now) {
		got[f.Kind] = append(got[f.Kind], f)
	}
	if r := got["redundant_index"]; len(r) != 1 || !strings.Contains(r[0].Title, "email_1") || !strings.Contains(r[0].Suggestion, `dropIndex("email_1")`) {
		t.Fatalf("redundant: %+v", r)
	}
	if u := got["unused_index"]; len(u) != 1 || !strings.Contains(u[0].Title, "legacy_1") {
		t.Fatalf("unused (only legacy_1: _id, unique and recently started ones excluded): %+v", u)
	}
	if l := got["large_documents"]; len(l) != 1 || l[0].Severity != Warning {
		t.Fatalf("large documents: %+v", l)
	}
	if len(got["no_constraints"]) != 0 {
		t.Fatal("a collection with a unique index has constraints")
	}
	bare := Collection{DB: "app", Name: "events", Count: 500_000, Indexes: []Index{{Name: "_id_", Keys: bson.D{{Key: "_id", Value: 1}}}}}
	got = map[string][]Finding{}
	for _, f := range Analyze([]Collection{bare}, nil, now) {
		got[f.Kind] = append(got[f.Kind], f)
	}
	if len(got["no_secondary_index"]) != 1 || len(got["no_constraints"]) != 1 || !strings.Contains(got["no_constraints"][0].Suggestion, "validationAction") {
		t.Fatalf("bare collection: %+v", got)
	}
}

func TestSources(t *testing.T) {
	line := `{"t":{"$date":"2026-10-25T10:00:00.000+00:00"},"s":"I","c":"COMMAND","id":51803,"ctx":"conn7","msg":"Slow query",` +
		`"attr":{"type":"command","ns":"app.orders","command":{"find":"orders","filter":{"card":"` + sentinel + `","total":{"$gt":{"$numberDecimal":"99.5"}}},"sort":{"created":-1},"$db":"app"},` +
		`"planSummary":"COLLSCAN","keysExamined":0,"docsExamined":120000,"nreturned":2,"durationMillis":850,"hasSortStage":true}}`
	q, ok := FromLogLine(line)
	if !ok || q.NS != "app.orders" || q.DocsExamined != 120000 || q.Millis != 850 || !q.HasSortStage {
		t.Fatalf("log line: %+v %v", q, ok)
	}
	if s := ShapeString(q.Filter); s != `{"card":"?","total":{"$gt":"?"}}` || ShapeString(q.Sort) != `{"created":-1}` {
		t.Fatalf("shape: %s %s", s, ShapeString(q.Sort))
	}
	if _, ok := FromLogLine(`{"id":20000,"msg":"other"}`); ok {
		t.Fatal("only slow query lines")
	}
	if _, ok := FromLogLine(strings.Replace(line, "app.orders", "admin.system.users", 1)); ok {
		t.Fatal("internal namespaces are skipped")
	}
	agg := bson.D{{Key: "op", Value: "command"}, {Key: "ns", Value: "app.orders"}, {Key: "planSummary", Value: "COLLSCAN"}, {Key: "millis", Value: int32(5)},
		{Key: "command", Value: bson.D{{Key: "aggregate", Value: "orders"}, {Key: "pipeline", Value: bson.A{
			bson.D{{Key: "$match", Value: bson.D{{Key: "status", Value: sentinel}}}}, bson.D{{Key: "$sort", Value: bson.D{{Key: "at", Value: int32(1)}}}}}}}}}
	q, ok = FromProfile(agg)
	if !ok || ShapeString(q.Filter) != `{"status":"?"}` || ShapeString(q.Sort) != `{"at":1}` {
		t.Fatalf("profile aggregate: %+v", q)
	}
	upd := bson.D{{Key: "op", Value: "update"}, {Key: "ns", Value: "app.orders"}, {Key: "planSummary", Value: "COLLSCAN"},
		{Key: "command", Value: bson.D{{Key: "q", Value: bson.D{{Key: "ref", Value: sentinel}}}, {Key: "u", Value: bson.D{{Key: "$set", Value: bson.D{{Key: "x", Value: sentinel}}}}}}}}
	q, _ = FromProfile(upd)
	if ShapeString(q.Filter) != `{"ref":"?"}` {
		t.Fatalf("profile update: %s", ShapeString(q.Filter))
	}
}
