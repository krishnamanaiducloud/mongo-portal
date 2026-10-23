package api

import (
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Command replies decode nested documents as bson.D (array elements) or
// bson.M; the helpers must read both.
func TestMonitorHelpersAcceptBothDocumentForms(t *testing.T) {
	reply := bson.M{
		"set": "rs0",
		"members": bson.A{
			bson.D{{Key: "name", Value: "a:27017"}, {Key: "stateStr", Value: "PRIMARY"}},
			bson.M{"name": "b:27017", "stateStr": "SECONDARY"},
			"not a document",
		},
		"config": bson.D{{Key: "version", Value: int32(3)}},
	}
	var states []string
	for _, m := range marr(reply, "members") {
		if mm, ok := mdoc(m); ok {
			states = append(states, mstr(mm, "stateStr"))
		}
	}
	if len(states) != 2 || states[0] != "PRIMARY" || states[1] != "SECONDARY" {
		t.Fatalf("states %v", states)
	}
	if v := mnum(msub(reply, "config"), "version"); v != 3 {
		t.Fatalf("config version %v", v)
	}
	if len(msub(reply, "missing")) != 0 {
		t.Fatal("missing sub-document should be empty")
	}
}
