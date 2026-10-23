# Troubleshooting

| Symptom | Likely cause | Check / fix |
| --- | --- | --- |
| Pod `CrashLoopBackOff`, log `invalid configuration` | Config validation failed | `oc logs … -c portal`; the message lists every problem. Validate locally with `mongo-portal --check-config --config config.yaml`. |
| `tls.mode=disabled in production requires plaintextApproved=true` | Production plaintext gate | Enable MongoDB TLS, or record the approved exception in the overlay. |
| No "Log in with OpenShift" button | OpenShift login unavailable or not in OpenShift | System status page shows the reason (API/OAuth server unreachable, no token, untrusted certificate). See [oauth.md](oauth.md#checks-and-troubleshooting). MongoDB login keeps working. |
| "OpenShift sign-in did not complete" | Redirect URI not accepted, code exchange rejected | Route name must match the ServiceAccount annotation; `server.publicOrigin` must be the Route host; `oc logs deploy/mongo-portal \| grep 'token exchange'`. |
| "No portal access" or missing permissions | No RBAC role for the user or group | **My permissions** shows subjects, roles and rules; check `patch-rbac.yaml` / the `mongo-portal-rbac` ConfigMap and `oc get group <name> -o yaml`. |
| RBAC change has no effect | Rejected policy edit | Logs: `rbac policy update rejected`; the System status page shows the error. Fix the line; the previous policy stays active meanwhile. |
| OpenShift users are signed out after about an hour | API server unreachable for longer than `identity.openshift.maxStale` | Egress NetworkPolicy rule for 6443/443; API health. |
| "Authentication failed" at MongoDB login | Wrong password, wrong authentication database, mechanism not allowed | Try the user's auth DB (often `admin`); `db.getUser()` shows mechanisms; check `authMechanisms` in the profile. |
| "Too many login attempts" | Rate limit / lockout | Wait for `Retry-After`; lockout doubles up to `maxLockDuration`. |
| "TLS certificate verification with MongoDB failed" | Wrong/missing CA, hostname not in SAN, TLS profile against a plaintext server | `oc rsh` into the debug image: `openssl s_client -connect host:27017 -CAfile /etc/mongo-portal/mongodb-ca/ca.crt -servername host`. Never disable verification; fix the CA or certificate. |
| "MongoDB is unreachable" | DNS, NetworkPolicy egress, MongoDB down, wrong `replicaSet` name | Debug image: `dig +short host`, `curl -v telnet://host:27017`; check `hello` via `mongosh`. |
| Users keep being asked to sign in to MongoDB | Requests reaching different pods; idle timeout; pod restarts | Route cookie affinity annotations; `session.idleTimeout`; pod restarts in `oc get pods`. |
| `403 portal_role_forbidden` | RBAC does not allow the operation on that namespace | Expected. The message names the missing permission; **My permissions → Check access** explains it. |
| `403 mongo_unauthorized` | MongoDB user lacks the privilege | Expected; grant the specific role in MongoDB if justified. |
| `504` on queries | `maxTimeMS` exceeded | Add an index, narrow the filter, or raise `maxTimeMS` (≤ `query.maxMaxTime`). |
| Results "truncated" | Response byte cap | Use a projection or smaller page size. |
| Shell: "SyntaxError: … JavaScript expressions are not evaluated" | Shell input is JSON-only | Write literal values; use `ObjectId("…")`, `ISODate("…")` helpers. |
| Metrics not scraped | User-workload monitoring disabled or NetworkPolicy | Enable UWM; namespace label `network.openshift.io/policy-group: monitoring` must exist on the monitoring namespace. |
