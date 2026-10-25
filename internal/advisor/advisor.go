// Package advisor turns read-only observations of a MongoDB deployment
// (index definitions and usage, collection statistics, profiler entries and
// slow-query log lines) into performance findings and index suggestions.
//
// It never sees or returns data values: queries are reduced to their shape
// (field names and operators, every value replaced by "?") before anything
// else looks at them. Suggestions are text for a person to review; nothing
// here executes them.
package advisor

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Severities, most important first.
const (
	Critical = "critical"
	Warning  = "warning"
	Info     = "info"
)

// Finding is one recommendation.
type Finding struct {
	Severity  string         `json:"severity"`
	Kind      string         `json:"kind"`
	Namespace string         `json:"namespace"`
	Title     string         `json:"title"`
	Detail    string         `json:"detail"`
	Evidence  map[string]any `json:"evidence,omitempty"`
	// Suggestion is a mongosh command to review; it is never executed.
	Suggestion string `json:"suggestion,omitempty"`
}

// Index is an index definition from listIndexes.
type Index struct {
	Name    string
	Keys    bson.D
	Unique  bool
	Sparse  bool
	Partial bool
	TTL     bool
	Hidden  bool
	// Collation or other options that make an index different from its
	// prefix (it can then not be replaced by a longer index).
	Special bool
	// Ops and Since come from $indexStats (Ops < 0: unknown).
	Ops   int64
	Since time.Time
}

// Collection is what the advisor knows about one collection.
type Collection struct {
	DB, Name     string
	Count        int64
	AvgObjSize   int64
	HasValidator bool
	Indexes      []Index
	// IndexStats reports whether $indexStats was readable.
	IndexStats bool
}

// NS returns db.collection.
func (c *Collection) NS() string { return c.DB + "." + c.Name }

// Query is one observed operation (profiler entry or slow-query log line),
// already reduced to its shape.
type Query struct {
	NS           string
	Op           string
	Filter       bson.D // shape: values are "?"
	Sort         bson.D // field order and directions only
	PlanSummary  string
	Millis       int64
	KeysExamined int64
	DocsExamined int64
	NReturned    int64
	HasSortStage bool
}

// redacted stands for every value in a query shape.
const redacted = "?"

// Shape reduces a filter to field names and operators. Values, including
// array elements and embedded documents compared by equality, become "?".
func Shape(v any) bson.D {
	d, ok := asD(v)
	if !ok {
		return nil
	}
	return shapeDoc(d)
}

func shapeDoc(d bson.D) bson.D {
	out := make(bson.D, 0, len(d))
	for _, e := range d {
		switch {
		case e.Key == "$and" || e.Key == "$or" || e.Key == "$nor":
			var parts bson.A
			if arr, ok := e.Value.(bson.A); ok {
				for _, x := range arr {
					if sd, ok := asD(x); ok {
						parts = append(parts, shapeDoc(sd))
					}
				}
			}
			out = append(out, bson.E{Key: e.Key, Value: parts})
		case strings.HasPrefix(e.Key, "$"):
			// $expr, $text, $where, $jsonSchema...: keep the operator only.
			out = append(out, bson.E{Key: e.Key, Value: redacted})
		default:
			out = append(out, bson.E{Key: e.Key, Value: shapeValue(e.Value)})
		}
	}
	return out
}

// shapeValue keeps query operators of a field condition, nothing else.
func shapeValue(v any) any {
	d, ok := asD(v)
	if !ok || len(d) == 0 || !strings.HasPrefix(d[0].Key, "$") {
		return redacted
	}
	ops := make(bson.D, 0, len(d))
	for _, e := range d {
		if !strings.HasPrefix(e.Key, "$") {
			return redacted
		}
		if e.Key == "$elemMatch" || e.Key == "$not" {
			if sd, ok := asD(e.Value); ok {
				ops = append(ops, bson.E{Key: e.Key, Value: shapeDoc(sd)})
				continue
			}
		}
		ops = append(ops, bson.E{Key: e.Key, Value: redacted})
	}
	return ops
}

// SortShape keeps the field names and directions of a sort specification.
func SortShape(v any) bson.D {
	d, ok := asD(v)
	if !ok {
		return nil
	}
	out := make(bson.D, 0, len(d))
	for _, e := range d {
		dir := 1
		if n, ok := number(e.Value); ok && n < 0 {
			dir = -1
		}
		out = append(out, bson.E{Key: e.Key, Value: dir})
	}
	return out
}

func asD(v any) (bson.D, bool) {
	switch x := v.(type) {
	case bson.D:
		return x, true
	case bson.Raw:
		var d bson.D
		if bson.Unmarshal(x, &d) == nil {
			return d, true
		}
	case bson.M:
		d := make(bson.D, 0, len(x))
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			d = append(d, bson.E{Key: k, Value: x[k]})
		}
		return d, true
	}
	return nil, false
}

func number(v any) (float64, bool) {
	switch n := v.(type) {
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case float64:
		return n, true
	case int:
		return float64(n), true
	}
	return 0, false
}

// ShapeString renders a shape compactly, e.g. {"status":"?","age":{"$gt":"?"}}.
func ShapeString(d bson.D) string {
	if len(d) == 0 {
		return "{}"
	}
	b, err := bson.MarshalExtJSON(d, false, false)
	if err != nil {
		return "{…}"
	}
	return string(b)
}

// esr splits filter fields into equality and range fields (Equality,
// Sort, Range rule). complex is set for filters an index suggestion cannot
// be derived from safely ($or, $expr, $text, $where, ...).
func esr(filter bson.D) (eq, rng []string, complex bool) {
	var walk func(d bson.D)
	walk = func(d bson.D) {
		for _, e := range d {
			if e.Key == "$and" {
				if arr, ok := e.Value.(bson.A); ok {
					for _, x := range arr {
						if sd, ok := asD(x); ok {
							walk(sd)
						}
					}
				}
				continue
			}
			if strings.HasPrefix(e.Key, "$") {
				complex = true
				continue
			}
			ops, ok := asD(e.Value)
			if !ok {
				eq = appendOnce(eq, e.Key)
				continue
			}
			isEq := false
			isRange := false
			for _, op := range ops {
				switch op.Key {
				case "$eq", "$in":
					isEq = true
				case "$elemMatch", "$not", "$nin", "$ne", "$regex", "$exists", "$type", "$mod", "$size", "$all":
					isRange = true
				default:
					isRange = true
				}
			}
			switch {
			case isEq && !isRange:
				eq = appendOnce(eq, e.Key)
			default:
				rng = appendOnce(rng, e.Key)
			}
		}
	}
	walk(filter)
	rng = slices.DeleteFunc(rng, func(f string) bool { return slices.Contains(eq, f) })
	return eq, rng, complex
}

func appendOnce(list []string, s string) []string {
	if slices.Contains(list, s) {
		return list
	}
	return append(list, s)
}

// maxSuggestedFields keeps suggested indexes small.
const maxSuggestedFields = 5

// SuggestIndex derives an index for a query shape: equality fields, then
// sort fields, then range fields. It returns nil when no index can be
// derived (no usable fields or a complex filter).
func SuggestIndex(q Query) bson.D {
	eq, rng, complex := esr(q.Filter)
	if complex {
		return nil
	}
	var keys bson.D
	add := func(f string, dir int) {
		if len(keys) >= maxSuggestedFields || slices.ContainsFunc(keys, func(e bson.E) bool { return e.Key == f }) {
			return
		}
		keys = append(keys, bson.E{Key: f, Value: dir})
	}
	for _, f := range eq {
		add(f, 1)
	}
	for _, e := range q.Sort {
		dir, _ := number(e.Value)
		add(e.Key, int(dir))
	}
	for _, f := range rng {
		add(f, 1)
	}
	return keys
}

// keysEqual compares index key patterns (names, order and directions).
func keysEqual(a, b bson.D) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Key != b[i].Key || dir(a[i].Value) != dir(b[i].Value) {
			return false
		}
	}
	return true
}

// isPrefix reports whether a is a strict prefix of b.
func isPrefix(a, b bson.D) bool {
	if len(a) >= len(b) {
		return false
	}
	return keysEqual(a, b[:len(a)])
}

func dir(v any) string {
	if n, ok := number(v); ok {
		if n < 0 {
			return "-1"
		}
		return "1"
	}
	return fmt.Sprint(v) // "text", "2dsphere", "hashed"
}

// covered reports whether an existing index starts with the suggested keys.
func covered(suggest bson.D, idx []Index) string {
	for _, ix := range idx {
		if len(ix.Keys) >= len(suggest) && keysEqual(suggest, ix.Keys[:len(suggest)]) {
			return ix.Name
		}
	}
	return ""
}

// CreateIndexCommand formats a createIndex call for mongosh. Names are
// JSON-quoted, so a collection name can never break out of the string.
func CreateIndexCommand(db, coll string, keys bson.D) string {
	return fmt.Sprintf("db.getSiblingDB(%s).getCollection(%s).createIndex(%s)", quote(db), quote(coll), keysJS(keys))
}

// DropIndexCommand formats a dropIndex call for mongosh.
func DropIndexCommand(db, coll, name string) string {
	return fmt.Sprintf("db.getSiblingDB(%s).getCollection(%s).dropIndex(%s)", quote(db), quote(coll), quote(name))
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func keysJS(keys bson.D) string {
	parts := make([]string, 0, len(keys))
	for _, e := range keys {
		v := dir(e.Value)
		if _, ok := number(e.Value); !ok {
			v = quote(v)
		}
		parts = append(parts, quote(e.Key)+": "+v)
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}
