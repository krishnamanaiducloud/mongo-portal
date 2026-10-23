# Operational runbook

## Health

| Check | Command / endpoint | Healthy |
| --- | --- | --- |
| Pods | `oc get pods -l app.kubernetes.io/name=mongo-portal` | `2/2 Running` |
| Liveness | `:9090/healthz` | `200 ok` |
| Readiness | `:9090/readyz` | `200 ready` (503 while draining) |
| Proxy | `:8443/oauth/healthz` | `200` |
| In-pod | `oc exec deploy/mongo-portal -c portal -- /usr/bin/mongo-portal healthcheck` | exit 0 |

Readiness does not depend on MongoDB: MongoDB connectivity is per user.

## Metrics and suggested alerts

| Metric | Alert idea |
| --- | --- |
| `mongo_portal_http_requests_total{code=~"5.."}` | 5xx rate > 5% for 10 min |
| `mongo_portal_auth_attempts_total{stage="mongodb",result="mongo_auth_failed"}` | spike → brute force or expired passwords |
| `mongo_portal_auth_attempts_total{result="rate_limited"}` | sustained → investigate source user |
| `mongo_portal_auth_attempts_total{stage="mongodb",result=~"mongo_unavailable|tls_verification_failed"}` | MongoDB or certificate problem |
| `mongo_portal_authorization_denials_total` | unexpected growth by `reason` |
| `mongo_portal_sessions_active` / `mongo_portal_mongodb_connections_open` | approaching `session.maxTotal` × `maxPoolSize` |
| `mongo_portal_mongodb_operation_duration_seconds` | p95 > 5 s |

## Logs and audit (Splunk)

All logs are single-line JSON on stdout. Cluster log forwarding
(`ClusterLogForwarder`) to Splunk HEC ships them unchanged. Useful searches:

```
audit=true action=mongodb_login outcome=failure | stats count by sso_user, reason
audit=true outcome=denied | stats count by action, reason
audit=true action IN (drop_collection, drop_index, delete_document, aggregate_write_stage)
msg=http_request status>=500
```

## Routine tasks

* **Scale:** `oc scale deploy/mongo-portal --replicas=3` (or edit overlay). Keep
  Route cookie affinity enabled.
* **Upgrade:** merge the release digest PR; sync Argo CD. Users on replaced pods
  re-authenticate to MongoDB.
* **Rotate keys/certs:** see [secrets.md](secrets.md).
* **Change groups or permissions:** edit `patch-rbac.yaml` (the `mongo-portal-rbac`
  ConfigMap) and sync. It is applied live within 30 seconds; an invalid edit is
  rejected and reported on the System status page. See [rbac.md](rbac.md).
* **Add a MongoDB profile:** add to `config.yaml`, update egress NetworkPolicy.
* **Terminate a user's access:** remove them from the OpenShift groups
  (effective at the next revalidation, at most 5 min) or deny them in the RBAC
  policy (within 30 s), and/or restart the pods to end all MongoDB sessions.

## Incidents

| Situation | Action |
| --- | --- |
| Suspected credential compromise of a MongoDB user | Change the password / drop the user in MongoDB; remove from portal groups; restart pods to drop live sessions |
| Portal compromise suspected | Scale to 0; rotate `mongo-portal-session` and `mongo-portal-proxy`; review audit logs; rotate passwords of users active during the window |
| MongoDB failover | No action: the driver reconnects and re-authenticates; brief errors possible |
| MongoDB down | Portal stays up; logins show "MongoDB is unreachable" |
