# Monitoring

The **Monitoring** page (`/monitoring`, API `GET /api/v1/monitoring`) shows the
health of the MongoDB deployment of the current profile. It collects everything
with the signed-in user's **own MongoDB session**, so each user sees what their
MongoDB roles allow. The portal has no monitoring account of its own.

| Section | Shows | MongoDB command | Needs |
| --- | --- | --- | --- |
| Summary tiles | Connections, operations/s, network in/out per second, data on disk, uptime | `serverStatus`, `listDatabases` | `clusterMonitor` (sizes: `listDatabases`) |
| Topology | Every member: primary/secondary/arbiter, health, replication lag, ping, sync source, priority/votes, uptime | `replSetGetStatus`, `replSetGetConfig` | `clusterMonitor` |
| Connections | Used vs available, active vs idle, connections by client host, application and user, and your own portal session pool | `$currentOp` with `idleConnections` | `clusterMonitor` |
| Resources | WiredTiger cache and dirty cache, resident memory vs host memory, queues, transactions, asserts, host OS/CPU/memory | `serverStatus`, `hostInfo` | `clusterMonitor` |
| Active operations | The 50 longest-running client operations: type, namespace, duration, client, user, plan, lock waits | `$currentOp` | `clusterMonitor` |
| Storage | Total size on disk and each database's size and share | `listDatabases` | `listDatabases` (included in `clusterMonitor`) |
| Database statistics | Data, storage and index size, documents and file system use of the 20 largest databases | `dbStats` | `dbStats` on each database |
| Oplog | Window (how long a secondary may be offline), size and limit | find on `local.oplog.rs`, `collStats` | read on `local` (or `clusterMonitor` where it covers it) |
| Performance | Read and write latency, mongod CPU, page faults, global lock waits, evictions by application threads, failed authentications, execution tickets | `serverStatus` (`opLatencies`, `extra_info`, `locks`, `wiredTiger`, `security`) | `clusterMonitor` |
| Topology extras | Last election (date, reason), write majority | `replSetGetStatus` | `clusterMonitor` |

Sections are independent. A section the user may not run shows a short note
("needs more MongoDB privileges") and the rest of the page still works. Without
`clusterMonitor`, the topology falls back to the connection handshake (`hello`),
which every user may run: members with their primary/secondary role.

Only metadata is returned. Query texts, commands and documents from
`$currentOp` are never read. Portal RBAC applies as well: the page needs
`monitoring get` on the profile, and the database list follows `databases get`.

## Alerts and thresholds

The API compares the values with `monitoring.thresholds` and returns alerts
that the page and the dashboard show: unreachable members, no primary,
replication lag (warning and critical), connection use, cache fullness,
dirty cache, queued operations, a short oplog window and slow operations.
Thresholds are configuration ([configuration.md](configuration.md)); the
response includes the effective values. For paging and long-term alerting
use Prometheus or Ops Manager.

## Operations and connections

The **Operations** page (`GET /api/v1/operations`) lists running
operations, idle connections or both, with filters (client, application,
user, namespace, operation, minimum duration, internal threads) and paging.
Without the `inprog` privilege (part of `clusterMonitor`) users see only
their own operations.

**Ending an operation** (`operations kill`, `POST /api/v1/operations/kill`)
uses MongoDB's `killOp`. The portal first checks that the operation still
exists, is running and belongs to a client (internal threads are refused),
and the user confirms by typing the operation id. MongoDB authorizes the
call: users may end their own operations, other users' operations need the
`killop` privilege (for example `hostManager`). `killOp` ends an operation at
its next interruption point; it does not close connections, and idle
connections are never "killed". Every attempt is audited (`operation_kill`).

## Index usage

The collection's Indexes tab shows `$indexStats` (operations served by each
index since the member started) and flags unused indexes.

## Granting clusterMonitor

Run as a MongoDB administrator. This grants read-only monitoring of the
deployment, not data access:

```javascript
db.getSiblingDB("admin").grantRolesToUser("sam", [{ role: "clusterMonitor", db: "admin" }])
```

## Refresh and rates

The page refreshes every 10 seconds by default (choose Off, 5s, 10s or 30s). It
stops polling while the browser tab is hidden. Rates (operations/s, bytes/s,
latency, CPU, lock waits, evictions) are computed between two refreshes of the
same member, and the sparklines keep about one hour of samples in the browser. The series restart after a
failover or a server restart. The values describe the member the portal is
connected to for that request, normally the primary.

The Databases page also shows the total size on disk of the deployment.
