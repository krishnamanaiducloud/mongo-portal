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

Sections are independent. A section the user may not run shows a short note
("needs more MongoDB privileges") and the rest of the page still works. Without
`clusterMonitor`, the topology falls back to the connection handshake (`hello`),
which every user may run: members with their primary/secondary role.

Only metadata is returned. Query texts, commands and documents from
`$currentOp` are never read. Portal RBAC applies as well: the page needs
`server, get` on the profile, and the database list follows `databases, get`.

## Granting clusterMonitor

Run as a MongoDB administrator. This grants read-only monitoring of the
deployment, not data access:

```javascript
db.getSiblingDB("admin").grantRolesToUser("sam", [{ role: "clusterMonitor", db: "admin" }])
```

## Refresh and rates

The page refreshes every 10 seconds by default (choose Off, 5s, 10s or 30s). It
stops polling while the browser tab is hidden. Rates (operations/s, bytes/s) are
computed between two refreshes of the same member. The series restart after a
failover or a server restart. The values describe the member the portal is
connected to for that request, normally the primary.

The Databases page also shows the total size on disk of the deployment.
