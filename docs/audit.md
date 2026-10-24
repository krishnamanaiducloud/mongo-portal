# Audit

The portal records security-relevant events of its own users: sign-ins and
failures, MongoDB logins (with the method: password or OIDC), sign-outs,
session creation, expiry and revocation, authorization denials, every data
change, queries and shell operations, imports and exports, operations ended
with killOp, connection diagnostics (`profile_diagnostics`), cache
invalidations (`cache_invalidate`, with scope and per-cache errors), and audit
exports. MONGODB-OIDC failures carry a precise reason (for example
`token_audience_mismatch` or `login_required`). Events never contain passwords, tokens or
document contents.

This is **portal** auditing. MongoDB Enterprise has its own database audit
log (`auditLog` settings on the server), which also records clients that do
not use the portal. Use both where required.

## Event fields

`id`, `time`, `requestId`, `traceId` (correlates with traces), `ssoUser`,
`identity` and `provider`, `method`, `portalRole`, `mongoUser`, `profile`,
`action`, `database`, `collection`, `target`, `outcome` (success, denied,
failure), `reason`, `errorClass`, `durationMs`, `count`, `client` (IP),
`userAgent`, `session` (handle), `pod`, `seq` and `hash`.

## Where events go

1. **The log stream** (always): one JSON line per event with `"audit":true`
   on stdout. Forward it with the cluster logging stack (for example to
   Splunk or Elasticsearch). This is the primary durable trail.
2. **The replica's memory** (always): the last `audit.bufferSize` events,
   shown when there is no durable store.
3. **The shared store** (optional, `audit.persist: true`): every replica
   writes its events to the `audit_events` collection of the store database,
   in the background, in batches. The Audit page then searches the events of
   every replica. `audit.retention` adds a TTL index (for example `2160h`
   for 90 days); without it events stay until the database administrator
   removes them. If the store is unreachable, events still go to the log
   stream and the dropped count is shown on the status page and in the
   `mongo_portal_audit_events_dropped_total` metric.

## Tamper evidence

Each replica chains its events: `hash` is SHA-256 over the previous event's
hash and the event itself, and `seq` counts events per replica. Auditors can
verify a replica's stored chain (Audit page, event details, or
`GET /api/v1/audit/verify?pod=<pod>`): an altered, inserted or removed event
breaks the chain at its sequence number. This is tamper **evidence**. For
tamper-proof storage, forward the log stream to write-once storage or
restrict the store database so that the portal account can only insert
(a custom role with `insert` and `find` on the audit collection).

## Searching and exporting

Everyone sees their own events. `audit get all` (role:auditor and above)
shows every user's events. Filters: user, action, outcome, profile,
database, collection, text and a time range; results page backwards in time.
CSV and NDJSON exports contain the whole selection (up to 100,000 events),
are protected against spreadsheet formula injection and are themselves
audited (`audit_export`).

## The store account

```javascript
// as a MongoDB administrator
db.getSiblingDB("admin").createUser({
  user: "mongo-portal-store",
  pwd: passwordPrompt(),
  roles: [{ role: "readWrite", db: "mongo_portal" }],
})
```

Mount its credentials (Secret `mongo-portal-store`, keys `username` and
`password`) and configure `store` ([configuration.md](configuration.md)).
The account is used only for the audit trail and the session registry.
