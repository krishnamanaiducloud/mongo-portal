# Import and export

Import and export run with the user's own MongoDB session: MongoDB
privileges and portal RBAC both apply. Exports need `export create` and
`documents get` on the namespace; imports need `import create` and
`documents create` (and `documents update` for upserts). Every export,
import, dry run and cancellation is audited with document counts.

## Formats

| Format | Export | Import | Notes |
| --- | --- | --- | --- |
| Extended JSON lines (`ndjson`) | yes | yes | One document per line; the mongoexport/mongoimport default |
| JSON array (`json`) | yes | yes | Import also accepts documents one after another |
| CSV / TSV | yes | yes | Columns are field paths; nested values are Extended JSON |
| BSON | yes | yes | Concatenated BSON documents, as in mongodump `.bson` files |
| gzip | `gzip=true` | detected | Any format can be compressed |

Relaxed Extended JSON is easy to read; canonical Extended JSON
(`ejson=canonical`) keeps every type exactly (Int32 vs Int64 vs Double,
Decimal128, dates before 1970) and is the right choice for moving data
between deployments. BSON keeps everything byte for byte.

## Export

- **Collection:** filter, projection, sort and limit (Extended JSON) and,
  for CSV, the column list. The download streams from a MongoDB cursor to
  the browser; cancelling the download stops the export. Limited to
  `transfer.maxExportDocuments`.
- **Database:** a zip archive with one file per collection the user may
  export, `<collection>.metadata.json` (options and indexes) and
  `manifest.json` (document counts, SHA-256 of each file, whether each file
  is complete, who exported what and when).

An export is **not a backup**: collections are read one after another
without a snapshot. Use your MongoDB backup tooling (Ops Manager, Cloud
Manager or filesystem snapshots) for consistent, point-in-time backups.

## Import

1. Choose the file; the format is guessed from the extension.
2. **Preview** reads the first MiB and shows the resulting documents. For
   CSV/TSV it shows the columns with the detected types and lets you map
   each column to a field path (`address.city` creates embedded documents), a
   type (`string`, `int`, `long`, `double`, `decimal`, `bool`, `date`,
   `objectId` or `auto`) or skip it.
3. **Mode:** insert (existing `_id`s are reported as duplicates) or upsert
   by `_id` (replaces documents).
4. **Dry run** parses and validates the whole file without writing.

The upload is buffered in `transfer.tempDir` (with its SHA-256) and imported
in the background in batches of `transfer.batchSize`, unordered, so one bad
document does not stop the batch. MongoDB collection validators apply. Each
rejected document is reported with its record number, MongoDB error code and
message; the list can be downloaded. The import stops after
`transfer.maxErrors` rejected documents.

The **Jobs** tab shows progress (bytes read, documents written, rejected),
lets you cancel, and keeps finished reports for `transfer.jobRetention`.
Jobs run on the replica that received the upload and belong to the user's
MongoDB session: signing out cancels them.

## Limits

| Setting | Default |
| --- | --- |
| `transfer.maxImportBytes` | 256 MiB per file |
| `transfer.maxExportDocuments` | 10,000,000 |
| `transfer.batchSize` | 500 documents |
| `transfer.maxConcurrentJobs` | 2 per replica, 1 per user |
| `transfer.maxErrors` | 1000 |
| `transfer.tempDir` | `/tmp` (the manifests mount a 2 GiB emptyDir) |

Imports into `system.*` collections are refused. `transfer.enabled: false`
turns import and export off.

Native `mongodump --archive` and `mongorestore` are not run by the portal.
The debug image contains the MongoDB database tools for operators.
