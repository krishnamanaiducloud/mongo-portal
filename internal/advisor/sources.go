package advisor

import (
	"encoding/json"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// SlowQueryLogID is the log id of MongoDB's "Slow query" messages.
const SlowQueryLogID = 51803

// FromProfile converts a system.profile entry. Only the shape of the
// filter and sort is kept.
func FromProfile(doc bson.D) (Query, bool) {
	q := Query{
		NS: str(get(doc, "ns")), Op: str(get(doc, "op")), PlanSummary: str(get(doc, "planSummary")),
		Millis: num(get(doc, "millis")), KeysExamined: num(get(doc, "keysExamined")),
		DocsExamined: num(get(doc, "docsExamined")), NReturned: num(get(doc, "nreturned")),
		HasSortStage: get(doc, "hasSortStage") == true,
	}
	cmd, _ := asD(get(doc, "command"))
	if q.Op == "getmore" {
		cmd, _ = asD(get(doc, "originatingCommand"))
	}
	filter, sort := extract(cmd)
	q.Filter, q.Sort = Shape(filter), SortShape(sort)
	return q, q.NS != "" && q.PlanSummary != ""
}

// FromLogLine converts a "Slow query" line of the server log (getLog).
func FromLogLine(line string) (Query, bool) {
	var head struct {
		ID   int             `json:"id"`
		Attr json.RawMessage `json:"attr"`
	}
	if json.Unmarshal([]byte(line), &head) != nil || head.ID != SlowQueryLogID || len(head.Attr) == 0 {
		return Query{}, false
	}
	var attr bson.D
	if bson.UnmarshalExtJSON(head.Attr, false, &attr) != nil {
		return Query{}, false
	}
	q := Query{
		NS: str(get(attr, "ns")), Op: str(get(attr, "type")), PlanSummary: str(get(attr, "planSummary")),
		Millis: num(get(attr, "durationMillis")), KeysExamined: num(get(attr, "keysExamined")),
		DocsExamined: num(get(attr, "docsExamined")), NReturned: num(get(attr, "nreturned")),
		HasSortStage: get(attr, "hasSortStage") == true,
	}
	cmd, _ := asD(get(attr, "command"))
	if orig, ok := asD(get(attr, "originatingCommand")); ok && first(cmd) == "getMore" {
		cmd = orig
	}
	filter, sort := extract(cmd)
	q.Filter, q.Sort = Shape(filter), SortShape(sort)
	return q, q.NS != "" && q.PlanSummary != "" && !strings.HasPrefix(q.NS, "admin.") && !strings.HasPrefix(q.NS, "local.") && !strings.HasPrefix(q.NS, "config.")
}

// extract finds the filter and sort of a command: find, aggregate (first
// $match and $sort stages), count, distinct, findAndModify, update and
// delete statements.
func extract(cmd bson.D) (filter, sort any) {
	if pipe, ok := get(cmd, "pipeline").(bson.A); ok {
		for _, st := range pipe {
			sd, ok := asD(st)
			if !ok || len(sd) == 0 {
				continue
			}
			switch sd[0].Key {
			case "$match":
				if filter == nil {
					filter = sd[0].Value
				}
			case "$sort":
				if sort == nil {
					sort = sd[0].Value
				}
			case "$group", "$lookup", "$unwind", "$project", "$facet":
				return filter, sort
			}
		}
		return filter, sort
	}
	for _, k := range []string{"filter", "query", "q"} {
		if v := get(cmd, k); v != nil {
			filter = v
			break
		}
	}
	for _, k := range []string{"updates", "deletes"} {
		if arr, ok := get(cmd, k).(bson.A); ok && len(arr) > 0 && filter == nil {
			if st, ok := asD(arr[0]); ok {
				filter = get(st, "q")
			}
		}
	}
	return filter, get(cmd, "sort")
}

func get(d bson.D, key string) any {
	for _, e := range d {
		if e.Key == key {
			return e.Value
		}
	}
	return nil
}

func first(d bson.D) string {
	if len(d) == 0 {
		return ""
	}
	return d[0].Key
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func num(v any) int64 {
	n, _ := number(v)
	return int64(n)
}
