# MongoDB Management Portal

A web portal for MongoDB on OpenShift where every database operation runs as
the signed-in user's **own MongoDB account**.

The Go backend is in [`cmd/`](../cmd/) and [`internal/`](../internal/), the
React UI in [`web/`](../web/), the Helm chart in
[`charts/mongo-portal`](../charts/mongo-portal/) (OpenShift and Kubernetes), and
the manifests in [`examples/`](../examples/): plain files in
`examples/openshift`, Kustomize overlays in `examples/kustomize`, Argo CD
applications in `examples/argocd`.

| Document | Contents |
| --- | --- |
| [ORGANIZATION_CONFIGURATION.md](ORGANIZATION_CONFIGURATION.md) | What each organization configures, who provides it, setup procedures, acceptance test, rollout and rollback |
| [architecture.md](architecture.md) | Components, request flow, authentication and authorization model |
| [configuration.md](configuration.md) | Every configuration key, TLS and non-TLS profiles |
| [preflight.md](preflight.md) | Read-only checks of an environment: CLI, UI diagnostics, OpenShift script |
| [cache.md](cache.md) | The portal's caches, invalidation across replicas, personal refresh and reconnect |
| [deployment.md](deployment.md) | Step-by-step OpenShift deployment, discovery commands |
| [oauth.md](oauth.md) | Built-in OpenShift login, passive behaviour, troubleshooting |
| [oidc.md](oidc.md) | OpenID Connect sign-in (Entra ID, Okta, Keycloak, SAML/LDAP brokers) |
| [mongodb-oidc.md](mongodb-oidc.md) | MONGODB-OIDC: IAM prerequisites, validating the deployment, migration and rollback |
| [rbac.md](rbac.md) | RBAC: policy format, roles, examples, where it is enforced |
| [mongodb-rbac.md](mongodb-rbac.md) | Creating developer and SRE MongoDB users |
| [import-export.md](import-export.md) | Import and export formats, field mapping, jobs, limits |
| [audit.md](audit.md) | Audit events, durable store, retention, tamper evidence, export |
| [sessions.md](sessions.md) | Session security, several replicas, the session registry and revocation |
| [observability.md](observability.md) | OpenTelemetry tracing, logs, Prometheus metrics |
| [monitoring.md](monitoring.md) | Monitoring page: replica set members, connections (active/idle), sizes, resources; clusterMonitor |
| [secrets.md](secrets.md) | Required Secrets and keys (no values) |
| [gitops.md](gitops.md) | Argo CD setup, scoping, release flow |
| [threat-model.md](threat-model.md) | Assets, threats, mitigations, residual risks |
| [runbook.md](runbook.md) | Operations: monitoring, rotation, scaling, incidents |
| [troubleshooting.md](troubleshooting.md) | Symptoms and fixes |
| [disaster-recovery.md](disaster-recovery.md) | Recovery considerations |
| [testing-report.md](testing-report.md) | What was tested, results, gaps |

## Quick start (local, disposable MongoDB)

```bash
docker build --target debug -t mongo-portal:debug .
bash test/container/smoke.sh mongo-portal:production mongo-portal:debug   # needs both images
bash test/integration/run.sh                                               # real MongoDB replica sets, TLS + non-TLS
```
