# Performance advisor

**Performance advisor** (navigation, for roles with `monitoring get`) looks
at a deployment and recommends indexes and constraints. Select a database or
all databases and **Analyze**; it runs only when you ask.

## What it reads

Everything is read with **your own MongoDB session**, so MongoDB decides what
the advisor can see; the portal RBAC additionally limits it to databases and
collections you may view.

| Source | Needs (MongoDB privilege) | Used for |
| --- | --- | --- |
| `listCollections`, `listIndexes` | read on the database | index definitions, schema validators |
| `$collStats` (storage statistics) | `collStats` (read roles) | document counts, average document size |
| `$indexStats` | `indexStats` (dbAdmin, clusterMonitor) | unused indexes |
| `system.profile` (last 24 hours, 300 entries per database) | `find` on `system.profile` (dbAdmin); profiling enabled by a database administrator | slow and scanning queries |
| `getLog: "global"` (slow-query lines) | `getLog` (clusterMonitor) | slow and scanning queries |
| `profile: -1` | reads the profiling level without changing it | whether the profiler is on |

The page lists which sources were readable. A missing privilege makes the
analysis partial, never an error. Limits per run: 50 databases, 300
collections, 60 seconds, two concurrent runs per portal replica.

## What it reports

| Finding | When | Suggestion |
| --- | --- | --- |
| Missing index (critical/warning) | a query shape scans the collection (`COLLSCAN`) and examines ≥ 1,000 documents per run (critical from 100,000 or 1 s) | `createIndex` with **Equality, Sort, Range** field order, unless an existing index already starts with those fields |
| Inefficient index | an index scan examines ≥ 20 keys per returned document (and ≥ 1,000 keys) | a more selective compound index |
| In-memory sort | the plan sorts after fetching | an index that provides the sort order |
| Redundant index | an index is a prefix of another (same fields, order and direction; not unique, partial, sparse, TTL or with collation) | `dropIndex`, to review |
| Unused index | no use since ≥ 7 days on the member that answered (not `_id`, unique or TTL indexes) | `dropIndex`, after checking the other members |
| Many indexes | 15 or more on one collection | review |
| Large documents | average ≥ 1 MB (critical ≥ 8 MB; the limit is 16 MB) | restructure, projections |
| No secondary index | ≥ 100,000 documents and only the `_id` index | review queries |
| Constraints | collections with data but no schema validator and no unique index besides `_id` | a unique index for natural keys and a `$jsonSchema` validator, introduced with `validationAction: "warn"` first |

Constraints in MongoDB: `_id` is the primary key of every collection (always
unique and indexed). Further uniqueness is a unique (or partial unique)
index; required fields and types are a schema validator; relationships are
kept by the application or by embedding.

## Security

- **Read-only.** Only the commands above run; `profile: -1` reads the level
  without changing it. The advisor never enables the profiler, creates or
  drops indexes, or changes validators.
- **No data values.** Queries are reduced to their *shape* as soon as they
  are read: field names and operators stay, every value — strings, numbers,
  array elements, embedded documents, regular expressions, `$expr` and
  `$where` code — becomes `?`. Nothing else is kept. Tests assert that a
  secret used in queries never reaches a response.
- **Suggestions are text.** They are shown for copying into the shell after
  review; names are JSON-quoted so a collection or field name cannot change
  the command. The portal has no endpoint that runs them; creating an index
  through the portal still goes through the Indexes tab with its RBAC and
  confirmation.
- **Visibility.** Query shapes of other users come from the profiler and the
  server log, which MongoDB shows only to users with dbAdmin or
  clusterMonitor privileges.
- Every run is audited as `performance_advisor` with the number of findings.

## Getting better results

Ask a database administrator to enable the profiler for slow operations on
the databases that matter (this is a database setting; the portal does not
change it):

```js
db.getSiblingDB("<database>").setProfilingLevel(1, { slowms: 100 })
```

Usage counters of `$indexStats` start when a member starts: judge "unused"
only after a representative period, and check every member (secondaries may
serve reads) before dropping an index.
