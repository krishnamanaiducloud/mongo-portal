package query

import (
	"testing"
)

func TestReadNamespaces(t *testing.T) {
	stages, err := ParseArray(`[
		{"$lookup": {"from": "customers", "localField": "c", "foreignField": "_id", "as": "c"}},
		{"$unionWith": "archive"},
		{"$unionWith": {"coll": "old", "pipeline": [{"$lookup": {"from": "deep", "pipeline": [], "as": "d"}}]}},
		{"$facet": {"a": [{"$graphLookup": {"from": "tree", "startWith": "$p", "connectFromField": "p", "connectToField": "_id", "as": "t"}}]}}
	]`)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := ReadNamespaces(stages, "app")
	if !ok {
		t.Fatal("expected determinable namespaces")
	}
	want := map[string]bool{"customers": true, "archive": true, "old": true, "deep": true, "tree": true}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for _, n := range got {
		if n.DB != "app" || !want[n.Coll] {
			t.Errorf("unexpected %v", n)
		}
	}

	bad, _ := ParseArray(`[{"$lookup": {"from": 5, "as": "x"}}]`)
	if _, ok := ReadNamespaces(bad, "app"); ok {
		t.Error("non-string from must be undeterminable")
	}
}

func TestWriteTarget(t *testing.T) {
	cases := map[string]Namespace{
		`[{"$match": {}}, {"$out": "res"}]`:                     {"app", "res"},
		`[{"$out": {"db": "rep", "coll": "res"}}]`:              {"rep", "res"},
		`[{"$merge": "m"}]`:                                     {"app", "m"},
		`[{"$merge": {"into": "m", "whenMatched": "replace"}}]`: {"app", "m"},
		`[{"$merge": {"into": {"db": "other", "coll": "m"}}}]`:  {"other", "m"},
	}
	for src, want := range cases {
		st, err := ParseArray(src)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := WriteTarget(st, "app")
		if !ok || got != want {
			t.Errorf("%s: got %v %v want %v", src, got, ok, want)
		}
	}
	for _, src := range []string{`[{"$match": {}}]`, `[{"$merge": {"whenMatched": "replace"}}]`, `[{"$out": {"coll": 1}}]`} {
		st, _ := ParseArray(src)
		if _, ok := WriteTarget(st, "app"); ok {
			t.Errorf("%s: expected no determinable target", src)
		}
	}
}
