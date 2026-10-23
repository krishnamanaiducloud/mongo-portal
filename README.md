# mongo-portal

A web portal for MongoDB on OpenShift, in the spirit of Mongo Express, where
every database operation runs as the signed-in user's **own MongoDB account**.

* **OpenShift login** like Argo CD: the ServiceAccount is the OAuth client, so no
  extra OAuth setup is needed. It is passive: when OpenShift login is
  unavailable the portal keeps working with MongoDB sign-in, without errors.
* **Individual MongoDB authentication**: no shared database account. MongoDB
  enforces each user's own roles.
* **RBAC** in the format of Argo CD's `argocd-rbac-cm`, mapping OpenShift groups
  to roles. By default the portal follows each user's MongoDB privileges
  (`role:mongodb`); roles such as `role:readonly` can cap a group further.
* **Monitoring**: replica set members (primary/secondary, lag, health),
  connections (active, idle, by client), operations, cache, memory and storage
  sizes, with each user's own MongoDB session.
* **In-browser mongosh**: the real mongosh runtime in an isolated sandbox.
  Every operation goes through the portal's checks.
* TLS and plaintext connection profiles; Chainguard-based production and debug
  images that run as any UID with a read-only root filesystem.

## Deploy on OpenShift

| Directory | Use it when |
| --- | --- |
| [examples/openshift](examples/openshift/) | You apply plain YAML files with `oc apply` (no Kustomize). Start here. |
| [examples/kustomize](examples/kustomize/) | You use Kustomize overlays (dev, test, prod) |
| [examples/argocd](examples/argocd/) | You deploy the Kustomize overlays with Argo CD |

The portal never creates, changes or deletes MongoDB workloads, volumes or
replica-set configuration.

## Documentation

| Document | Contents |
| --- | --- |
| [architecture.md](docs/architecture.md) | Components, request flow, authentication and authorization model |
| [configuration.md](docs/configuration.md) | Every configuration key, TLS and non-TLS profiles |
| [deployment.md](docs/deployment.md) | Step-by-step OpenShift deployment, discovery commands |
| [oauth.md](docs/oauth.md) | OpenShift login, passive behaviour, troubleshooting |
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
```

## Images

| Variant | Tag | Base | Contents |
| --- | --- | --- | --- |
| production | `docker.io/mohankrishna999/mongo-express:<version>` | `cgr.dev/chainguard/static` | portal binary, CA bundle, tzdata |
| debug | `docker.io/mohankrishna999/mongo-express:<version>-debug` | Wolfi packages on `scratch` | same binary + busybox, curl, bind-tools, openssl, iproute2, procps, jq, mongosh |

Both run as any UID with GID 0, need no writable path other than `/tmp`,
contain no package manager, and are built for `linux/amd64` and `linux/arm64`.
Releases are cut by pushing a `v<version>` tag; CI refuses to overwrite an
existing image tag.
