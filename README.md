# mongo-portal

A web portal for MongoDB on OpenShift where every database operation runs as
the signed-in user's **own MongoDB account**.

* **OpenShift login**: the ServiceAccount is the OAuth client, so no extra
  OAuth setup is needed. It is passive: when OpenShift login is
  unavailable the portal keeps working with MongoDB sign-in, without errors.
* **OpenID Connect sign-in** with Microsoft Entra ID, Okta, Keycloak or any
  corporate provider (SAML and LDAP through a broker), with PKCE, nonce and
  full ID token validation.
* **Individual MongoDB authentication**: no shared database account. SCRAM
  passwords or **MONGODB-OIDC**, where MongoDB Enterprise receives the user's
  own token from the identity provider it trusts. MongoDB enforces each
  user's own roles. After OpenShift or OIDC sign-in, MONGODB-OIDC profiles can
  connect automatically with the same corporate sign-in (no password, no
  second prompt).
* **RBAC** with a simple CSV policy in a ConfigMap, mapping OpenShift groups to
  roles. By default the portal follows each user's MongoDB privileges
  (`role:mongodb`); roles such as `role:readonly` can cap a group further.
* **Monitoring**: replica set members (primary/secondary, lag, health,
  elections), oplog window, connections (active, idle, by client), latency,
  CPU, locks, cache and eviction, storage, index usage and alerts with
  configurable thresholds; running operations with filters and killOp.
* **Import and export**: Extended JSON, CSV/TSV with field mapping, BSON and
  gzip, streamed exports, database archives with checksums, background
  imports with preview, dry run, progress and per-record error reports.
* **Audit**: every sign-in, change, export and administrative action, with a
  per-replica hash chain, optional durable store with retention, search and
  export. **Sessions** of every replica can be listed and revoked.
* **OpenTelemetry** tracing (OTLP HTTP or gRPC), trace-correlated logs and
  Prometheus metrics.
* **In-browser mongosh**: the real mongosh runtime in an isolated sandbox.
  Every operation goes through the portal's checks.
* **Configuration only**: `${NAME}` placeholders, a Helm chart for OpenShift
  and Kubernetes, and a read-only preflight (`mongo-portal preflight`,
  `helm test`, `scripts/preflight-openshift.sh`) that checks DNS, TLS,
  MongoDB and the identity providers without changing anything.
* TLS and plaintext connection profiles; Chainguard-based production and debug
  images that run as any UID with a read-only root filesystem.

## Deploy

| Directory | Use it when |
| --- | --- |
| [charts/mongo-portal](charts/mongo-portal/) | You use Helm (OpenShift or Kubernetes) |
| [examples/openshift](examples/openshift/) | You apply plain YAML files with `oc apply` (no Kustomize). Start here. |
| [examples/kustomize](examples/kustomize/) | You use Kustomize overlays (dev, test, prod) |
| [examples/argocd](examples/argocd/) | You deploy the Kustomize overlays with Argo CD |

The portal never creates, changes or deletes MongoDB workloads, volumes or
replica-set configuration.

## Documentation

| Document | Contents |
| --- | --- |
| [ORGANIZATION_CONFIGURATION.md](docs/ORGANIZATION_CONFIGURATION.md) | What an organization configures, who provides it, setup, acceptance test, rollout and rollback |
| [architecture.md](docs/architecture.md) | Components, request flow, authentication and authorization model |
| [configuration.md](docs/configuration.md) | Every configuration key, TLS and non-TLS profiles |
| [preflight.md](docs/preflight.md) | Read-only environment checks |
| [cache.md](docs/cache.md) | Portal caches, refresh and reconnect |
| [deployment.md](docs/deployment.md) | Step-by-step OpenShift deployment, discovery commands |
| [oauth.md](docs/oauth.md) | OpenShift login, passive behaviour, troubleshooting |
| [oidc.md](docs/oidc.md) | OpenID Connect sign-in |
| [mongodb-oidc.md](docs/mongodb-oidc.md) | MONGODB-OIDC, IAM prerequisites, migration and rollback |
| [import-export.md](docs/import-export.md) | Import and export |
| [audit.md](docs/audit.md) | Audit trail |
| [sessions.md](docs/sessions.md) | Sessions and the session registry |
| [observability.md](docs/observability.md) | Tracing, logs and metrics |
| [rbac.md](docs/rbac.md) | RBAC policy format, roles, examples |
| [mongodb-rbac.md](docs/mongodb-rbac.md) | Creating developer and SRE MongoDB users |
| [monitoring.md](docs/monitoring.md) | The monitoring page and the clusterMonitor role |
| [secrets.md](docs/secrets.md) | Required Secrets and keys (no values) |
| [gitops.md](docs/gitops.md) | Argo CD setup, scoping, release flow |
| [threat-model.md](docs/threat-model.md) | Assets, threats, mitigations, residual risks |
| [runbook.md](docs/runbook.md) | Operations: monitoring, rotation, scaling, incidents |
| [troubleshooting.md](docs/troubleshooting.md) | Symptoms and fixes |
| [disaster-recovery.md](docs/disaster-recovery.md) | Recovery considerations |
| [testing-report.md](docs/testing-report.md) | What was tested, results, gaps |

## Develop

```bash
# backend
go test -race ./internal/...
# frontend
cd web && npm ci --ignore-scripts && npm run lint && npm test && npm run build
# run locally against a local MongoDB (insecure dev identity, never in a cluster)
PORTAL_ALLOW_INSECURE_DEV_IDENTITY=true go run ./cmd/portal --config config/dev.example.yaml
cd web && npm run dev    # http://localhost:5173, proxies /api to :8080
```

## Test

```bash
make test               # unit tests (Go + web)
make integration        # disposable MongoDB replica sets (TLS + non-TLS), failover
make images smoke       # build both images, run them as arbitrary UIDs with a read-only rootfs
make scan               # govulncheck, gosec, npm audit, gitleaks, hadolint, trivy, grype, SBOMs
bash test/e2e/run.sh mongo-portal:production   # browser end-to-end test of the shell
bash test/oidc/run.sh  # MONGODB-OIDC against MongoDB Enterprise with a test identity provider
bash test/helm/validate.sh                       # Helm chart: lint, render, schemas, configuration
bash test/kind/run.sh mongo-portal:production    # Kubernetes: restricted pods, two replicas, NetworkPolicy, helm test
```

## Images

| Variant | Tag | Base | Contents |
| --- | --- | --- | --- |
| production | `<repository>:<version>` | `cgr.dev/chainguard/static` | portal binary, CA bundle, tzdata |
| debug | `<repository>:<version>-debug` | Wolfi packages on `scratch` | same binary + busybox, curl, bind-tools, openssl, iproute2, procps, jq, mongosh |

Both run as any UID with GID 0, need no writable path other than `/tmp`,
contain no package manager, and are built for `linux/amd64` and `linux/arm64`.
The published repository is listed in each release's notes; mirror it to an
approved registry where required.
Releases are cut by pushing a `v<version>` tag; CI refuses to overwrite an
existing image tag.
