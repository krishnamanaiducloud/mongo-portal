package query

import (
	"go.mongodb.org/mongo-driver/v2/bson"
)

// Namespace is a database and collection referenced by a pipeline.
type Namespace struct {
	DB, Coll string
}

// ReadNamespaces returns the collections a pipeline reads besides its own
// ($lookup, $graphLookup and $unionWith, including nested sub-pipelines and
// $facet). db is the database the pipeline runs in. ok is false when a
// reference cannot be determined, in which case callers must refuse.
func ReadNamespaces(stages []bson.D, db string) (out []Namespace, ok bool) {
	ok = true
	var walk func([]bson.D)
	walk = func(stages []bson.D) {
		for _, st := range stages {
			if len(st) != 1 {
				continue
			}
			body, isDoc := st[0].Value.(bson.D)
			switch st[0].Key {
			case "$lookup", "$graphLookup":
				if !isDoc {
					ok = false
					continue
				}
				from, hasFrom := lookupString(body, "from")
				if hasFrom {
					out = append(out, Namespace{DB: db, Coll: from})
				} else if _, present := lookup(body, "from"); present {
					ok = false
				}
				if p, present := lookup(body, "pipeline"); present {
					ps, err := toPipeline(p)
					if err != nil {
						ok = false
						continue
					}
					walk(ps)
				}
			case "$unionWith":
				if coll, isStr := st[0].Value.(string); isStr {
					out = append(out, Namespace{DB: db, Coll: coll})
					continue
				}
				if !isDoc {
					ok = false
					continue
				}
				if coll, has := lookupString(body, "coll"); has {
					out = append(out, Namespace{DB: db, Coll: coll})
				} else if _, present := lookup(body, "coll"); present {
					ok = false
				}
				if p, present := lookup(body, "pipeline"); present {
					ps, err := toPipeline(p)
					if err != nil {
						ok = false
						continue
					}
					walk(ps)
				}
			case "$facet":
				if !isDoc {
					ok = false
					continue
				}
				for _, e := range body {
					ps, err := toPipeline(e.Value)
					if err != nil {
						ok = false
						continue
					}
					walk(ps)
				}
			}
		}
	}
	walk(stages)
	return out, ok
}

// WriteTarget returns the collection written by a trailing $out or $merge
// stage. ok is false when the pipeline has no write stage or the target
// cannot be determined.
func WriteTarget(stages []bson.D, db string) (Namespace, bool) {
	if !HasWriteStage(stages) {
		return Namespace{}, false
	}
	last := stages[len(stages)-1][0]
	switch last.Key {
	case "$out":
		if coll, isStr := last.Value.(string); isStr {
			return Namespace{DB: db, Coll: coll}, coll != ""
		}
		if body, isDoc := last.Value.(bson.D); isDoc {
			return dbColl(body, db)
		}
	case "$merge":
		if coll, isStr := last.Value.(string); isStr {
			return Namespace{DB: db, Coll: coll}, coll != ""
		}
		body, isDoc := last.Value.(bson.D)
		if !isDoc {
			return Namespace{}, false
		}
		into, present := lookup(body, "into")
		if !present {
			return Namespace{}, false
		}
		if coll, isStr := into.(string); isStr {
			return Namespace{DB: db, Coll: coll}, coll != ""
		}
		if d, isDoc := into.(bson.D); isDoc {
			return dbColl(d, db)
		}
	}
	return Namespace{}, false
}

func dbColl(d bson.D, db string) (Namespace, bool) {
	coll, hasColl := lookupString(d, "coll")
	if !hasColl || coll == "" {
		return Namespace{}, false
	}
	if v, present := lookup(d, "db"); present {
		s, isStr := v.(string)
		if !isStr || s == "" {
			return Namespace{}, false
		}
		db = s
	}
	return Namespace{DB: db, Coll: coll}, true
}

func lookup(d bson.D, key string) (any, bool) {
	for _, e := range d {
		if e.Key == key {
			return e.Value, true
		}
	}
	return nil, false
}

func lookupString(d bson.D, key string) (string, bool) {
	v, ok := lookup(d, key)
	if !ok {
		return "", false
	}
	s, isStr := v.(string)
	return s, isStr
}
