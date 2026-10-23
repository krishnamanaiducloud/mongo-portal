package query

import (
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func mustDoc(t *testing.T, s string) bson.D {
	t.Helper()
	d, err := ParseDocument(s)
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return d
}

func TestFilterAllowsOrdinaryQueries(t *testing.T) {
	for _, s := range []string{
		``,
		`{}`,
		`{"status": "A", "qty": {"$lt": 30}}`,
		`{"$or": [{"a": 1}, {"b": {"$in": [1,2]}}]}`,
		`{"_id": {"$oid": "507f1f77bcf86cd799439011"}}`,
		`{"created": {"$gte": {"$date": "2024-01-01T00:00:00Z"}}}`,
		`{"price": {"$numberDecimal": "9.99"}}`,
		`{"name": {"$regex": "^ab", "$options": "i"}}`,
		`{"$expr": {"$gt": ["$a", "$b"]}}`,
		`{"$text": {"$search": "coffee"}}`,
	} {
		if err := Filter(mustDoc(t, s)); err != nil {
			t.Errorf("%s: unexpected error %v", s, err)
		}
	}
}

func TestFilterRejectsDangerousInput(t *testing.T) {
	for _, s := range []string{
		`{"$where": "this.a == 1"}`,
		`{"a": {"$elemMatch": {"$where": "sleep(1000)"}}}`,
		`{"$expr": {"$function": {"body": "function(){return true}", "args": [], "lang": "js"}}}`,
		`{"a": {"$code": "function(){}"}}`,
		`{"$or": [{"$expr": {"$accumulator": {}}}]}`,
		`{"a": {"$regex": "` + strings.Repeat("a", 2000) + `"}}`,
	} {
		d, err := ParseDocument(s)
		if err != nil {
			continue // rejected at parse time is also fine
		}
		if err := Filter(d); err == nil {
			t.Errorf("%s: expected rejection", s)
		}
	}
}

func TestParseRejectsNonObjects(t *testing.T) {
	for _, s := range []string{`[]`, `"x"`, `1`, `{bad json}`, `{"a":`} {
		if _, err := ParseDocument(s); err == nil {
			t.Errorf("%q should fail", s)
		}
	}
}

func TestNestingLimit(t *testing.T) {
	s := strings.Repeat(`{"a":`, 40) + `1` + strings.Repeat(`}`, 40)
	d, err := ParseDocument(s)
	if err != nil {
		return
	}
	if err := Filter(d); err == nil {
		t.Fatal("deep nesting should be rejected")
	}
}

func mustPipe(t *testing.T, s string) []bson.D {
	t.Helper()
	p, err := ParseArray(s)
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return p
}

func TestPipeline(t *testing.T) {
	ok := []string{
		`[{"$match": {"a": 1}}, {"$group": {"_id": "$b", "n": {"$sum": 1}}}, {"$sort": {"n": -1}}]`,
		`[{"$lookup": {"from": "o", "localField": "a", "foreignField": "b", "as": "x"}}]`,
		`[{"$lookup": {"from": "o", "pipeline": [{"$match": {"x": 1}}], "as": "x"}}]`,
		`[{"$facet": {"a": [{"$count": "n"}], "b": [{"$limit": 1}]}}]`,
	}
	for _, s := range ok {
		if err := Pipeline(mustPipe(t, s), Policy{}); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	bad := []string{
		`[{"$out": "copy"}]`,
		`[{"$match": {}}, {"$merge": {"into": "x"}}]`,
		`[{"$lookup": {"from": "o", "pipeline": [{"$out": "x"}], "as": "x"}}]`,
		`[{"$facet": {"a": [{"$merge": "x"}]}}]`,
		`[{"$unionWith": {"coll": "o", "pipeline": [{"$match": {"$where": "1"}}]}}]`,
		`[{"$currentOp": {}}]`,
		`[{"$match": {"$where": "1"}}]`,
		`[{"$group": {"_id": null, "x": {"$accumulator": {}}}}]`,
		`[{"$match": {}, "$limit": 1}]`,
		`[{"$unknownStage": {}}]`,
		`[{"$changeStream": {}}]`,
	}
	for _, s := range bad {
		if err := Pipeline(mustPipe(t, s), Policy{}); err == nil {
			t.Errorf("%s: expected rejection for developer policy", s)
		}
	}
	// SRE with write stages explicitly enabled: $out allowed only as last stage.
	sre := Policy{AllowWriteStages: true}
	if err := Pipeline(mustPipe(t, `[{"$match": {}}, {"$out": "copy"}]`), sre); err != nil {
		t.Errorf("sre $out: %v", err)
	}
	if err := Pipeline(mustPipe(t, `[{"$out": "copy"}, {"$match": {}}]`), sre); err == nil {
		t.Error("$out not last must be rejected")
	}
	if err := Pipeline(mustPipe(t, `[{"$lookup": {"from": "o", "pipeline": [{"$out": "x"}], "as": "x"}}]`), sre); err == nil {
		t.Error("nested $out must be rejected even for sre")
	}
	if !HasWriteStage(mustPipe(t, `[{"$merge": "x"}]`)) || HasWriteStage(mustPipe(t, `[{"$match": {}}]`)) {
		t.Error("HasWriteStage mismatch")
	}
}

func TestSort(t *testing.T) {
	if err := Sort(mustDoc(t, `{"a": 1, "b": -1}`)); err != nil {
		t.Fatal(err)
	}
	if err := Sort(mustDoc(t, `{"score": {"$meta": "textScore"}}`)); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{`{"a": 2}`, `{"a": "x"}`, `{"$where": 1}`} {
		if err := Sort(mustDoc(t, s)); err == nil {
			t.Errorf("%s should fail", s)
		}
	}
}

func TestIndex(t *testing.T) {
	spec, err := Index(mustDoc(t, `{"a": 1, "b": -1}`), mustDoc(t, `{"name": "a_b", "unique": true, "expireAfterSeconds": 3600, "partialFilterExpression": {"a": {"$gt": 1}}}`))
	if err != nil || spec.Name != "a_b" || !spec.Unique || spec.TTL == nil || *spec.TTL != 3600 {
		t.Fatalf("spec: %+v %v", spec, err)
	}
	if _, err := Index(mustDoc(t, `{"t": "text"}`), nil); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][2]string{
		{`{}`, `{}`},
		{`{"a": 5}`, `{}`},
		{`{"a": "weird"}`, `{}`},
		{`{"a": 1}`, `{"background": true}`},
		{`{"a": 1}`, `{"name": "bad name!"}`},
		{`{"a": 1}`, `{"expireAfterSeconds": -1}`},
		{`{"a": 1}`, `{"partialFilterExpression": {"$where": "1"}}`},
	} {
		if _, err := Index(mustDoc(t, c[0]), mustDoc(t, c[1])); err == nil {
			t.Errorf("%v should fail", c)
		}
	}
}

func TestNames(t *testing.T) {
	if !ValidDatabaseName("app") || ValidDatabaseName("a.b") || ValidDatabaseName("") || ValidDatabaseName("a/b") {
		t.Error("database names")
	}
	if !ValidCollectionName("orders.archive") || ValidCollectionName("a$b") || ValidCollectionName("") {
		t.Error("collection names")
	}
	if !SystemCollection("system.users") || SystemCollection("users") {
		t.Error("system")
	}
}
