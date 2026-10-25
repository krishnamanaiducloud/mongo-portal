package advisor

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Thresholds of the rules. Observations below them are not reported.
const (
	scanDocsWarn      = 1_000
	scanDocsCritical  = 100_000
	slowMillisCrit    = 1_000
	selectivityRatio  = 20
	sortMillisWarn    = 100
	unusedAfter       = 7 * 24 * time.Hour
	manyIndexes       = 15
	largeDocWarn      = 1 << 20
	largeDocCritical  = 8 << 20
	largeNoIndexCount = 100_000
	maxNamesListed    = 15
)

type group struct {
	ns, shape, sort, plan string
	sample                Query
	count                 int64
	millis, docs, keys    int64
	returned              int64
	sortStage             bool
}

func (g *group) avg(v int64) int64 {
	if g.count == 0 {
		return 0
	}
	return v / g.count
}

func planKind(summary string) string {
	switch {
	case strings.Contains(summary, "COLLSCAN"):
		return "COLLSCAN"
	case strings.Contains(summary, "IXSCAN"):
		return "IXSCAN"
	}
	return summary
}

// Analyze applies the rules to what was observed.
func Analyze(colls []Collection, queries []Query, now time.Time) []Finding {
	byNS := map[string]*Collection{}
	for i := range colls {
		byNS[colls[i].NS()] = &colls[i]
	}
	var out []Finding
	out = append(out, queryFindings(queries, byNS)...)
	for i := range colls {
		out = append(out, collectionFindings(&colls[i], now)...)
	}
	out = append(out, constraintFindings(colls)...)
	rank := map[string]int{Critical: 0, Warning: 1, Info: 2}
	slices.SortStableFunc(out, func(a, b Finding) int {
		if c := cmp.Compare(rank[a.Severity], rank[b.Severity]); c != 0 {
			return c
		}
		return cmp.Compare(a.Namespace, b.Namespace)
	})
	return out
}

func queryFindings(queries []Query, byNS map[string]*Collection) []Finding {
	groups := map[string]*group{}
	var order []string
	for _, q := range queries {
		g := &group{ns: q.NS, shape: ShapeString(q.Filter), sort: ShapeString(q.Sort), plan: planKind(q.PlanSummary)}
		key := g.ns + "\x00" + g.shape + "\x00" + g.sort + "\x00" + g.plan
		if prev, ok := groups[key]; ok {
			g = prev
		} else {
			g.sample = q
			groups[key] = g
			order = append(order, key)
		}
		g.count++
		g.millis += q.Millis
		g.docs += q.DocsExamined
		g.keys += q.KeysExamined
		g.returned += q.NReturned
		g.sortStage = g.sortStage || q.HasSortStage
	}
	var out []Finding
	for _, key := range order {
		g := groups[key]
		if f, ok := groupFinding(g, byNS[g.ns]); ok {
			out = append(out, f)
		}
	}
	return out
}

func groupFinding(g *group, c *Collection) (Finding, bool) {
	ev := map[string]any{
		"occurrences": g.count, "avgMillis": g.avg(g.millis), "avgDocsExamined": g.avg(g.docs),
		"avgKeysExamined": g.avg(g.keys), "avgReturned": g.avg(g.returned), "plan": g.sample.PlanSummary,
		"query": g.shape, "sort": g.sort,
	}
	f := Finding{Namespace: g.ns, Evidence: ev}
	avgDocs, avgKeys, avgRet, avgMs := g.avg(g.docs), g.avg(g.keys), max(g.avg(g.returned), 1), g.avg(g.millis)
	switch {
	case g.plan == "COLLSCAN" && (avgDocs >= scanDocsWarn || (g.count >= 5 && avgDocs >= 100)):
		f.Kind, f.Severity = "missing_index", Warning
		if avgDocs >= scanDocsCritical || avgMs >= slowMillisCrit {
			f.Severity = Critical
		}
		f.Title = "Query scans the whole collection"
		f.Detail = fmt.Sprintf("Each run reads about %d documents to return %d.", avgDocs, g.avg(g.returned))
	case g.plan == "IXSCAN" && avgKeys >= scanDocsWarn && avgKeys/avgRet >= selectivityRatio:
		f.Kind, f.Severity = "inefficient_index", Warning
		f.Title = "Index is not selective for this query"
		f.Detail = fmt.Sprintf("Each run examines about %d index keys to return %d documents.", avgKeys, g.avg(g.returned))
	case g.sortStage && len(g.sample.Sort) > 0 && (avgMs >= sortMillisWarn || avgDocs >= scanDocsWarn):
		f.Kind, f.Severity = "in_memory_sort", Warning
		f.Title = "Results are sorted in memory"
		f.Detail = "No index provides the sort order; MongoDB sorts after fetching (limited to 100 MB, then it fails or spills to disk)."
	default:
		return Finding{}, false
	}
	keys := SuggestIndex(g.sample)
	var indexes []Index
	if c != nil {
		indexes = c.Indexes
	}
	db, coll, _ := strings.Cut(g.ns, ".")
	switch {
	case len(keys) == 0:
		f.Detail += " The filter uses $or, $expr, $text or no fields, so no single index can be derived: index each $or branch, or add a selective condition."
	case covered(keys, indexes) != "":
		f.Detail += fmt.Sprintf(" Index %q already starts with these fields; check that the query's types and collation match it, or use explain() to see why it is not chosen.", covered(keys, indexes))
	default:
		f.Detail += " Suggested index (Equality, Sort, Range order):"
		f.Suggestion = CreateIndexCommand(db, coll, keys)
	}
	return f, true
}

func collectionFindings(c *Collection, now time.Time) []Finding {
	var out []Finding
	ns := c.NS()
	for _, a := range c.Indexes {
		if a.Name == "_id_" || a.Unique || a.Partial || a.Sparse || a.TTL || a.Hidden || a.Special {
			continue
		}
		for _, b := range c.Indexes {
			if b.Name != a.Name && !b.Partial && !b.Sparse && !b.Special && isPrefix(a.Keys, b.Keys) {
				out = append(out, Finding{Severity: Warning, Kind: "redundant_index", Namespace: ns,
					Title:      fmt.Sprintf("Index %q is redundant", a.Name),
					Detail:     fmt.Sprintf("Index %q starts with the same fields and can serve the same queries. Every index slows down writes and uses memory.", b.Name),
					Evidence:   map[string]any{"index": keysJS(a.Keys), "coveredBy": keysJS(b.Keys)},
					Suggestion: DropIndexCommand(c.DB, c.Name, a.Name)})
				break
			}
		}
	}
	if c.IndexStats {
		for _, ix := range c.Indexes {
			if ix.Name == "_id_" || ix.Unique || ix.TTL || ix.Ops != 0 || ix.Since.IsZero() || now.Sub(ix.Since) < unusedAfter {
				continue
			}
			out = append(out, Finding{Severity: Warning, Kind: "unused_index", Namespace: ns,
				Title: fmt.Sprintf("Index %q has not been used", ix.Name),
				Detail: fmt.Sprintf("No query used it since %s on the member that answered (usage counters reset when a member restarts; check the other members before dropping).",
					ix.Since.UTC().Format("2006-01-02")),
				Evidence:   map[string]any{"index": keysJS(ix.Keys), "since": ix.Since.UTC()},
				Suggestion: DropIndexCommand(c.DB, c.Name, ix.Name)})
		}
	}
	if len(c.Indexes) >= manyIndexes {
		out = append(out, Finding{Severity: Info, Kind: "many_indexes", Namespace: ns,
			Title:    fmt.Sprintf("%d indexes on one collection", len(c.Indexes)),
			Detail:   "Every write updates every index. Review unused and redundant indexes.",
			Evidence: map[string]any{"indexes": len(c.Indexes)}})
	}
	switch {
	case c.AvgObjSize >= largeDocCritical:
		out = append(out, largeDocs(c, Critical))
	case c.AvgObjSize >= largeDocWarn:
		out = append(out, largeDocs(c, Warning))
	}
	if c.Count >= largeNoIndexCount && len(c.Indexes) == 1 {
		out = append(out, Finding{Severity: Warning, Kind: "no_secondary_index", Namespace: ns,
			Title:    "Large collection with only the _id index",
			Detail:   fmt.Sprintf("%d documents and no other index: every query except lookups by _id scans the collection.", c.Count),
			Evidence: map[string]any{"documents": c.Count}})
	}
	return out
}

func largeDocs(c *Collection, sev string) Finding {
	return Finding{Severity: sev, Kind: "large_documents", Namespace: c.NS(),
		Title:    fmt.Sprintf("Average document size is %.1f MB", float64(c.AvgObjSize)/(1<<20)),
		Detail:   "Large documents are read whole into memory and the hard limit is 16 MB. Move growing arrays or large parts to their own collection, and use projections.",
		Evidence: map[string]any{"avgObjSize": c.AvgObjSize, "documents": c.Count}}
}

// constraintFindings lists, per database, collections that have data but
// neither schema validation nor a unique index besides _id.
func constraintFindings(colls []Collection) []Finding {
	perDB := map[string][]string{}
	var dbs []string
	for _, c := range colls {
		if c.Count == 0 || c.HasValidator || slices.ContainsFunc(c.Indexes, func(ix Index) bool { return ix.Unique && ix.Name != "_id_" }) {
			continue
		}
		if _, ok := perDB[c.DB]; !ok {
			dbs = append(dbs, c.DB)
		}
		perDB[c.DB] = append(perDB[c.DB], c.Name)
	}
	var out []Finding
	for _, db := range dbs {
		names := perDB[db]
		listed := names
		if len(listed) > maxNamesListed {
			listed = listed[:maxNamesListed]
		}
		out = append(out, Finding{Severity: Info, Kind: "no_constraints", Namespace: db,
			Title: fmt.Sprintf("%d collections without constraints", len(names)),
			Detail: "These collections have no schema validation and no unique index besides _id, so duplicates and malformed documents are accepted. " +
				"Add a unique index for natural keys, and schema validation (start with validationAction \"warn\" to see violations before enforcing).",
			Evidence: map[string]any{"collections": listed, "total": len(names)},
			Suggestion: fmt.Sprintf("db.getSiblingDB(%s).getCollection(%s).createIndex({ \"<natural key>\": 1 }, { unique: true })\n"+
				"db.getSiblingDB(%s).runCommand({ collMod: %s, validator: { $jsonSchema: { bsonType: \"object\", required: [\"<field>\"] } }, validationLevel: \"moderate\", validationAction: \"warn\" })",
				quote(db), quote(listed[0]), quote(db), quote(listed[0]))})
	}
	return out
}

// KeysOf converts an index key document to bson.D.
func KeysOf(v any) bson.D {
	d, _ := asD(v)
	return d
}
