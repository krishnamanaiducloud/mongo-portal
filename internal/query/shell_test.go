package query

import (
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func mustValue(t *testing.T, s string) any {
	t.Helper()
	var wrap struct {
		V any `bson:"v"`
	}
	if err := bson.UnmarshalExtJSON([]byte(`{"v":`+s+`}`), false, &wrap); err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return wrap.V
}

func TestUpdate(t *testing.T) {
	for _, s := range []string{
		`{"$set": {"a": 1}}`,
		`{"$inc": {"n": 1}, "$push": {"tags": "x"}}`,
		`[{"$set": {"total": {"$add": ["$a", "$b"]}}}]`,
		`[{"$unset": "tmp"}]`,
	} {
		if err := Update(mustValue(t, s)); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	for _, s := range []string{
		`{}`, `{"a": 1}`, `[]`, `"x"`,
		`[{"$out": "x"}]`,
		`[{"$lookup": {"from": "o", "as": "x"}}]`,
		`[{"$set": {"x": {"$function": {"body": "f", "args": [], "lang": "js"}}}}]`,
		`{"$set": {"a": {"$code": "function(){}"}}}`,
	} {
		if err := Update(mustValue(t, s)); err == nil {
			t.Errorf("%s: expected rejection", s)
		}
	}
	if err := Replacement(mustValue(t, `{"a": 1}`).(bson.D)); err != nil {
		t.Error(err)
	}
	if err := Replacement(mustValue(t, `{"$set": {"a": 1}}`).(bson.D)); err == nil {
		t.Error("replacement with operators must be rejected")
	}
}

func TestClassifyCommand(t *testing.T) {
	cases := map[string]CommandClass{
		`{"ping": 1}`:               CommandRead,
		`{"dbStats": 1}`:            CommandRead,
		`{"serverStatus": 1}`:       CommandRead,
		`{"profile": -1}`:           CommandRead,
		`{"profile": 2}`:            CommandAdmin,
		`{"collMod": "c"}`:          CommandAdmin,
		`{"currentOp": 1}`:          CommandAdmin,
		`{"shutdown": 1}`:           CommandDenied,
		`{"createUser": "x"}`:       CommandDenied,
		`{"dropUser": "x"}`:         CommandDenied,
		`{"grantRolesToUser": "x"}`: CommandDenied,
		`{"eval": "1"}`:             CommandDenied,
		`{"$eval": "1"}`:            CommandDenied,
		`{"mapReduce": "c"}`:        CommandDenied,
		`{"replSetReconfig": {}}`:   CommandDenied,
		`{"replSetStepDown": 60}`:   CommandDenied,
		`{"setParameter": 1}`:       CommandDenied,
		`{"fsync": 1}`:              CommandDenied,
		`{"applyOps": []}`:          CommandDenied,
		`{"dropDatabase": 1}`:       CommandDenied,
		`{"find": "c"}`:             CommandDenied,
		`{"aggregate": "c"}`:        CommandDenied,
		`{"insert": "c"}`:           CommandDenied,
		`{"Ping": 1}`:               CommandDenied,
	}
	for s, want := range cases {
		_, got := ClassifyCommand(mustValue(t, s).(bson.D))
		if got != want {
			t.Errorf("%s: got %d want %d", s, got, want)
		}
	}
}

func TestCommandValidation(t *testing.T) {
	ok := []string{
		`{"ping": 1}`,
		`{"count": "c", "query": {"a": 1}}`,
		`{"explain": {"find": "c", "filter": {"a": 1}}, "verbosity": "queryPlanner"}`,
		`{"explain": {"aggregate": "c", "pipeline": [{"$match": {}}], "cursor": {}}}`,
		`{"renameCollection": "app.a", "to": "app.b"}`,
		`{"collMod": "c", "validator": {"a": {"$exists": true}}}`,
	}
	for _, s := range ok {
		if err := Command(mustValue(t, s).(bson.D), Policy{}); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	bad := []string{
		`{"count": "c", "query": {"$where": "true"}}`,
		`{"distinct": "c", "key": "a", "query": {"$expr": {"$function": {}}}}`,
		`{"explain": {"aggregate": "c", "pipeline": [{"$out": "x"}], "cursor": {}}}`,
		`{"explain": {"delete": "c", "deletes": []}}`,
		`{"renameCollection": "app.a", "to": "other.b"}`,
		`{"collMod": "v", "viewOn": "c", "pipeline": [{"$merge": "x"}]}`,
		`{"collMod": "c", "validator": {"$where": "1"}}`,
	}
	for _, s := range bad {
		if err := Command(mustValue(t, s).(bson.D), Policy{}); err == nil {
			t.Errorf("%s: expected rejection", s)
		}
	}
}
