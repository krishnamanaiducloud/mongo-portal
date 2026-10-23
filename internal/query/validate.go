// Package query parses and validates user supplied MongoDB query documents.
//
// Input is MongoDB Extended JSON. Validation rejects server-side JavaScript
// anywhere in the input, limits size and nesting, restricts aggregation to an
// allowlist of stages and blocks write stages ($out, $merge) unless the
// caller's policy explicitly permits them.
package query

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"
)

const (
	maxDepth       = 24
	maxNodes       = 5000
	maxRegexLength = 1024
	maxPipelineLen = 64
	maxInputBytes  = 256 << 10
	maxIndexKeys   = 32
	maxSortKeys    = 32
)

// Error is a validation error safe to return to the client.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

func errf(format string, a ...any) error { return &Error{Msg: fmt.Sprintf(format, a...)} }

// Policy controls what a validated pipeline may contain.
type Policy struct {
	AllowWriteStages bool
}

// Operators that execute JavaScript on the server, or that expose other
// users' sessions/operations, are rejected everywhere.
var deniedOperators = map[string]string{
	"$where":                   "server-side JavaScript is not permitted",
	"$function":                "server-side JavaScript is not permitted",
	"$accumulator":             "server-side JavaScript is not permitted",
	"$currentOp":               "administrative stage is not permitted",
	"$listSessions":            "administrative stage is not permitted",
	"$listLocalSessions":       "administrative stage is not permitted",
	"$changeStream":            "change streams are not permitted",
	"$planCacheStats":          "administrative stage is not permitted",
	"$queryStats":              "administrative stage is not permitted",
	"$listSampledQueries":      "administrative stage is not permitted",
	"$shardedDataDistribution": "administrative stage is not permitted",
}

var writeStages = []string{"$out", "$merge"}

// readStages are the aggregation stages a pipeline may use.
var readStages = []string{
	"$match", "$project", "$addFields", "$set", "$unset", "$group", "$sort",
	"$limit", "$skip", "$count", "$unwind", "$lookup", "$facet", "$bucket",
	"$bucketAuto", "$sortByCount", "$replaceRoot", "$replaceWith", "$sample",
	"$graphLookup", "$unionWith", "$redact", "$setWindowFields", "$geoNear",
	"$densify", "$fill", "$documents", "$indexStats", "$collStats",
}

var (
	nameRe = regexp.MustCompile(`^[A-Za-z0-9_.\-]{1,128}$`)
)

// ParseDocument parses Extended JSON (relaxed or canonical) into bson.D.
// Empty input yields an empty document.
func ParseDocument(s string) (bson.D, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return bson.D{}, nil
	}
	if len(s) > maxInputBytes {
		return nil, errf("query document exceeds %d bytes", maxInputBytes)
	}
	if s[0] != '{' {
		return nil, errf("expected a JSON object")
	}
	var d bson.D
	if err := bson.UnmarshalExtJSON([]byte(s), false, &d); err != nil {
		return nil, errf("invalid Extended JSON: %s", cleanErr(err))
	}
	return d, nil
}

// ParseArray parses an Extended JSON array of documents (a pipeline).
func ParseArray(s string) ([]bson.D, error) {
	s = strings.TrimSpace(s)
	if len(s) > maxInputBytes {
		return nil, errf("pipeline exceeds %d bytes", maxInputBytes)
	}
	if s == "" || s[0] != '[' {
		return nil, errf("expected a JSON array")
	}
	// Extended JSON parsing requires a document at the top level.
	var wrap struct {
		P []bson.D `bson:"p"`
	}
	if err := bson.UnmarshalExtJSON([]byte(`{"p":`+s+`}`), false, &wrap); err != nil {
		return nil, errf("invalid Extended JSON pipeline: %s", cleanErr(err))
	}
	return wrap.P, nil
}

// Filter validates a find/count filter.
func Filter(d bson.D) error {
	w := &walker{}
	return w.doc(d, 0)
}

// Projection validates a projection document.
func Projection(d bson.D) error { return Filter(d) }

// Sort validates a sort specification.
func Sort(d bson.D) error {
	if len(d) > maxSortKeys {
		return errf("sort has too many keys")
	}
	for _, e := range d {
		if e.Key == "" || strings.HasPrefix(e.Key, "$") {
			return errf("invalid sort key %q", e.Key)
		}
		switch v := e.Value.(type) {
		case int32, int64, float64:
			if n := toFloat(v); n != 1 && n != -1 {
				return errf("sort direction for %q must be 1 or -1", e.Key)
			}
		case bson.D:
			if len(v) != 1 || v[0].Key != "$meta" {
				return errf("sort value for %q is invalid", e.Key)
			}
		default:
			return errf("sort direction for %q must be 1 or -1", e.Key)
		}
	}
	return nil
}

// Pipeline validates an aggregation pipeline.
func Pipeline(stages []bson.D, p Policy) error {
	return pipeline(stages, p, 0, true)
}

func pipeline(stages []bson.D, p Policy, depth int, top bool) error {
	if len(stages) > maxPipelineLen {
		return errf("pipeline exceeds %d stages", maxPipelineLen)
	}
	w := &walker{}
	for i, st := range stages {
		if len(st) != 1 {
			return errf("pipeline stage %d must have exactly one operator", i)
		}
		name := st[0].Key
		if msg, bad := deniedOperators[name]; bad {
			return errf("%s: %s", name, msg)
		}
		if slices.Contains(writeStages, name) {
			if !p.AllowWriteStages {
				return errf("%s is a write stage and is not permitted for your role", name)
			}
			if !top || i != len(stages)-1 {
				return errf("%s must be the last stage of the top-level pipeline", name)
			}
			if err := w.value(st[0].Value, depth+1); err != nil {
				return err
			}
			continue
		}
		if !slices.Contains(readStages, name) {
			return errf("pipeline stage %q is not permitted", name)
		}
		// Recurse into sub-pipelines with the same policy minus write stages.
		sub := Policy{}
		switch name {
		case "$lookup", "$unionWith":
			if body, ok := st[0].Value.(bson.D); ok {
				for _, e := range body {
					if e.Key == "pipeline" {
						ps, err := toPipeline(e.Value)
						if err != nil {
							return err
						}
						if err := pipeline(ps, sub, depth+1, false); err != nil {
							return err
						}
					} else if err := w.value(e.Value, depth+1); err != nil {
						return err
					}
				}
				continue
			}
		case "$facet":
			body, ok := st[0].Value.(bson.D)
			if !ok {
				return errf("$facet must be a document")
			}
			for _, e := range body {
				ps, err := toPipeline(e.Value)
				if err != nil {
					return err
				}
				if err := pipeline(ps, sub, depth+1, false); err != nil {
					return err
				}
			}
			continue
		}
		if err := w.value(st[0].Value, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func toPipeline(v any) ([]bson.D, error) {
	arr, ok := v.(bson.A)
	if !ok {
		return nil, errf("sub-pipeline must be an array")
	}
	out := make([]bson.D, 0, len(arr))
	for _, s := range arr {
		d, ok := s.(bson.D)
		if !ok {
			return nil, errf("sub-pipeline stages must be documents")
		}
		out = append(out, d)
	}
	return out, nil
}

// HasWriteStage reports whether the top-level pipeline ends with $out/$merge.
func HasWriteStage(stages []bson.D) bool {
	if len(stages) == 0 {
		return false
	}
	last := stages[len(stages)-1]
	return len(last) == 1 && slices.Contains(writeStages, last[0].Key)
}

// walker recursively checks values for denied operators, JavaScript types,
// excessive nesting and oversized regular expressions.
type walker struct{ nodes int }

func (w *walker) doc(d bson.D, depth int) error {
	if depth > maxDepth {
		return errf("query nesting exceeds %d levels", maxDepth)
	}
	for _, e := range d {
		if msg, bad := deniedOperators[e.Key]; bad {
			return errf("%s: %s", e.Key, msg)
		}
		if slices.Contains(writeStages, e.Key) {
			return errf("%s is not permitted here", e.Key)
		}
		if e.Key == "$regex" {
			if s, ok := e.Value.(string); ok && len(s) > maxRegexLength {
				return errf("regular expression exceeds %d characters", maxRegexLength)
			}
		}
		if err := w.value(e.Value, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func (w *walker) value(v any, depth int) error {
	w.nodes++
	if w.nodes > maxNodes {
		return errf("query exceeds %d elements", maxNodes)
	}
	if depth > maxDepth {
		return errf("query nesting exceeds %d levels", maxDepth)
	}
	switch t := v.(type) {
	case bson.D:
		return w.doc(t, depth)
	case bson.A:
		for _, x := range t {
			if err := w.value(x, depth+1); err != nil {
				return err
			}
		}
	case bson.JavaScript, bson.CodeWithScope:
		return errf("JavaScript values are not permitted")
	case bson.Regex:
		if len(t.Pattern) > maxRegexLength {
			return errf("regular expression exceeds %d characters", maxRegexLength)
		}
	}
	return nil
}

// IndexSpec is a validated index definition.
type IndexSpec struct {
	Keys    bson.D
	Name    string
	Unique  bool
	Sparse  bool
	Hidden  bool
	TTL     *int32
	Partial bson.D
}

// Index validates an index key document and options.
func Index(keys bson.D, opts bson.D) (*IndexSpec, error) {
	if len(keys) == 0 || len(keys) > maxIndexKeys {
		return nil, errf("index must have between 1 and %d keys", maxIndexKeys)
	}
	for _, k := range keys {
		if k.Key == "" || (strings.HasPrefix(k.Key, "$") && k.Key != "$**") {
			return nil, errf("invalid index key %q", k.Key)
		}
		switch v := k.Value.(type) {
		case int32, int64, float64:
			if n := toFloat(v); n != 1 && n != -1 {
				return nil, errf("index direction for %q must be 1 or -1", k.Key)
			}
		case string:
			if !slices.Contains([]string{"text", "2dsphere", "2d", "hashed"}, v) {
				return nil, errf("index type %q is not supported", v)
			}
		default:
			return nil, errf("index value for %q is invalid", k.Key)
		}
	}
	spec := &IndexSpec{Keys: keys}
	for _, o := range opts {
		switch o.Key {
		case "name":
			s, ok := o.Value.(string)
			if !ok || !nameRe.MatchString(s) {
				return nil, errf("index name must match %s", nameRe.String())
			}
			spec.Name = s
		case "unique":
			b, ok := o.Value.(bool)
			if !ok {
				return nil, errf("unique must be boolean")
			}
			spec.Unique = b
		case "sparse":
			b, ok := o.Value.(bool)
			if !ok {
				return nil, errf("sparse must be boolean")
			}
			spec.Sparse = b
		case "hidden":
			b, ok := o.Value.(bool)
			if !ok {
				return nil, errf("hidden must be boolean")
			}
			spec.Hidden = b
		case "expireAfterSeconds":
			n := toFloat(o.Value)
			if math.IsNaN(n) || n < 0 || n > math.MaxInt32 || n != math.Trunc(n) {
				return nil, errf("expireAfterSeconds must be a non-negative integer")
			}
			v := int32(n)
			spec.TTL = &v
		case "partialFilterExpression":
			d, ok := o.Value.(bson.D)
			if !ok {
				return nil, errf("partialFilterExpression must be a document")
			}
			if err := Filter(d); err != nil {
				return nil, err
			}
			spec.Partial = d
		default:
			return nil, errf("index option %q is not supported", o.Key)
		}
	}
	return spec, nil
}

// ValidDatabaseName reports whether name is a legal database name.
func ValidDatabaseName(name string) bool {
	if name == "" || len(name) > 63 {
		return false
	}
	return !strings.ContainsAny(name, "/\\. \"$*<>:|?\x00")
}

// ValidCollectionName reports whether name is a legal collection name.
func ValidCollectionName(name string) bool {
	if name == "" || len(name) > 255 || strings.ContainsAny(name, "$\x00") {
		return false
	}
	return true
}

// SystemCollection reports whether the collection is a system namespace.
func SystemCollection(name string) bool { return strings.HasPrefix(name, "system.") }

// ValidIndexName reports whether name may be used to drop an index.
func ValidIndexName(name string) bool {
	return name != "" && len(name) <= 256 && !strings.ContainsAny(name, "\x00")
}

// ErrIDIndex is returned when dropping the mandatory _id index.
var ErrIDIndex = errors.New("the _id index cannot be dropped")

func toFloat(v any) float64 {
	switch n := v.(type) {
	case int32:
		return float64(n)
	case int64:
		return float64(n)
	case float64:
		return n
	}
	return math.NaN()
}

func cleanErr(err error) string {
	s := err.Error()
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
