# Testing and validation report

## 0.0.4 (2026-10-25)

0.0.4 adds the performance advisor and lets `role:mongodb` users whose
MongoDB account administers the deployment manage caches. Everything below
the 0.0.4 section was re-run on the 0.0.4 code unless noted.

| Area | Result |
| --- | --- |
| Advisor unit tests (`internal/advisor`) | pass: query values never reach shapes or findings (strings, numbers, arrays, embedded documents, `$regex`, `$elemMatch`, `$or`, `$expr`, `$where`); Equality-Sort-Range suggestions; no suggestion for `$or`/`$expr`; existing indexes not suggested again; redundant, unused (not `_id`, unique, TTL or recently started), large-document and constraint rules; slow-log and profiler parsing (find, aggregate, update, getMore); names JSON-quoted in commands |
| Cache rule (`TestCacheFollowsMongoDBClusterAdmin`) | pass: cluster admin on `role:mongodb` allowed; data-only admin refused; cluster admin mapped to another role refused; explicit deny wins; no permission without a MongoDB session |
| `TestClusterAdminFromRealPrivileges` (real MongoDB 8.0) | pass: root, clusterAdmin and userAdminAnyDatabase are cluster administrators; readWriteAnyDatabase + dbAdminAnyDatabase and clusterMonitor are not |
| `TestPerformanceAdvisor` (real MongoDB 8.0) | pass: real profiler entries give a full-scan finding with `createIndex({ "card": 1, "customer": 1 })`; redundant index found; constraints finding; a secret value used in the queries is absent from the response; a user without privileges gets a partial report (200), not an error; internal databases refused |
| Integration suite | **21 / 21 pass** |
| MONGODB-OIDC suite (MongoDB Enterprise 7.0) | **6 / 6 pass** |
| Kubernetes deployment (kind) | **19 / 19 pass** |
| Go unit tests (race), vet, gofmt | pass (13 packages) |
| Web tests | **49 / 49 pass** (advisor runs only on request, findings, suggestions, severity filter) |
| Helm chart, Kustomize and plain manifests | valid (44 chart resources; 49 + 6 + 13 manifest resources); guardrails pass |
| Container smoke / browser e2e | 74 / 74 · PASS |
| govulncheck / gosec / npm audit | 0 affecting · 0 issues · 0 vulnerabilities |
| Trivy / Grype | 1 Unknown (GO-2026-5932, VEX `not_affected`) · no vulnerabilities |
| gitleaks | no leaks (a fake test marker named `secret` was flagged and renamed; it was never a credential) |
| Visual check | advisor page in a browser against a seeded MongoDB with the profiler on: redundant index and constraints findings, sources reported, no values shown |

Published from a clean `git archive` of commit `ac091a6` (amd64 and arm64,
SBOM and provenance; tags were new, earlier releases unchanged; not signed —
signing runs in the CI release job):

| Image | Index digest | Verified |
| --- | --- | --- |
| `docker.io/mohankrishna999/mongo-portal:0.0.4` | `sha256:5867a6204be8c78222da6064a94a4386c76176953efd2b3d0fe51cd8b0189d4e` | pulled image reports 0.0.4 (ac091a6); smoke 74 / 74 and browser e2e PASS on the published image; Trivy by digest: GO-2026-5932 only (VEX `not_affected`) |
| `docker.io/mohankrishna999/mongo-portal:0.0.4-debug` | `sha256:19df226b05bf8e0793c25ab310f9edbef3905852cf8a44a7835f4de4b8691faf` | smoke 74 / 74; Trivy by digest: same |

Security notes for the advisor: read-only commands only (`listCollections`,
`listIndexes`, `$indexStats`, `$collStats`, `find` on `system.profile`,
`getLog`, `profile: -1`), run with the user's own session; RBAC
`monitoring get` plus per-namespace visibility; two concurrent runs per
replica, 60-second deadline, size limits; values removed at the source;
suggestions are text and never executed; each run audited.

## 0.0.3

Release: **0.0.3** · Date: 2026-10-24 · Environment: Windows 10 + WSL2 Ubuntu,
Docker 29, Go 1.27.3 (toolchain pinned in `go.mod`), Node 24, MongoDB 8.0 test
containers, MongoDB Enterprise 7.0 for MONGODB-OIDC, kind (Kubernetes 1.35)
for the deployment test. No OpenShift cluster, no production identity
provider and no production MongoDB were available or contacted.

## Validation matrix

PASS means the test ran and passed here. Live OpenShift tests could not run
(no cluster access) and are **BLOCKED**, never PASS.

| Capability | Local test | Integration test | Live OpenShift test | Status |
| --- | --- | --- | --- | --- |
| OpenShift OAuth | PASS (fake OAuth server: code flow, PKCE, state, replay, `users/~`, revalidation) | NOT APPLICABLE (needs an OpenShift OAuth server) | BLOCKED | Implemented; not live-tested |
| Generic OIDC sign-in | PASS (test IdP: discovery, PKCE, nonce, issuer/audience/expiry/signature, groups, logout) | NOT TESTED against a real tenant | BLOCKED (needs organization IdP) | Implemented; requires organization configuration |
| MongoDB OIDC | PASS (silent connect, fallback, token checks) | PASS (MongoDB Enterprise 7.0 + test IdP: 6 / 6, including SSO → MongoDB without a second sign-in) | BLOCKED (needs organization IdP and MongoDB) | Implemented and tested; not live-validated |
| SCRAM | PASS | PASS (replica set, TLS and non-TLS; kind) | BLOCKED | Implemented and tested |
| TLS | PASS (preflight: untrusted CA, verification) | PASS (custom CA, client certificates, wrong CA, host name mismatch, no downgrade; preflight) | BLOCKED | Implemented and tested |
| RBAC | PASS | PASS (read-only, MongoDB-enforced roles, cache RBAC on kind) | BLOCKED | Implemented and tested |
| Shared sessions | PASS | PASS (registry and revocation across two replicas: integration and kind) | BLOCKED | Implemented and tested on Kubernetes |
| Cache management | PASS (API, UI) | PASS (invalidation applied by both replicas: integration and kind) | BLOCKED | Implemented and tested on Kubernetes |
| Audit logging | PASS | PASS (durable store, search across replicas, hash chain, tamper detection) | BLOCKED | Implemented and tested |
| MongoDB monitoring | PASS | PASS (members, connections, oplog, expected waits vs slow) | BLOCKED | Implemented and tested |
| Shell | PASS | PASS (integration, browser e2e) | BLOCKED | Implemented and tested |
| Import / export | PASS | PASS (round trips in every format, validators, RBAC, MongoDB privileges) | BLOCKED | Implemented and tested |
| OpenShift random UID | PASS (smoke: UIDs 1000680000, 123456, 65532, GID 0, read-only rootfs) | PASS (kind, Pod Security restricted, UID 1000680000) | BLOCKED (SCC admission not exercised) | Emulated; OpenShift admission not tested |
| Multi-replica deployment | PASS | PASS (kind: two replicas, rolling restart, NetworkPolicy enforcement) | BLOCKED | Tested on Kubernetes, not OpenShift |

## Results

| Area | Command | Result |
| --- | --- | --- |
| Go format / vet | `gofmt -l`, `go vet ./...` (+ `-tags integration`, `-tags oidc`), `go mod verify` | clean |
| Go unit tests | `go test -race ./internal/...` | **pass** (12 packages) |
| Web lint / types | `npm run lint`, `npm run typecheck` | clean |
| Web unit tests | `npm test` (Vitest) | **48 / 48 pass** (6 files) |
| Web build | `npm run build` | pass |
| Integration (real MongoDB) | `test/integration/run.sh` | **19 / 19 tests pass** |
| MONGODB-OIDC (MongoDB Enterprise 7.0 + test IdP) | `test/oidc/run.sh` | **6 / 6 tests pass** |
| Kubernetes deployment (kind) | `test/kind/run.sh` | **19 / 19 checks pass** |
| Helm chart | `test/helm/validate.sh` | lint, required values, schema, 44 / 44 rendered resources valid (Kubernetes, OpenShift 4.18, CRD schemas), guardrails, rendered configuration valid |
| Container smoke | `test/container/smoke.sh` (3 UIDs × 2 images) | **74 / 74 checks pass** |
| Browser end to end | `test/e2e/run.sh` (Chromium) | **PASS** |
| Kustomize + schema | `kubectl kustomize` + `kubeconform -strict` | 49 / 49 valid; Argo CD 6 / 6; plain manifests 13 / 13 |
| Manifest guardrails | no StatefulSet/PVC/Secret, no fixed UID/fsGroup, no privileged, no cluster RBAC in app overlays | pass |
| Configuration check | `--check-config` on dev, test and plain OpenShift configurations, and on the Helm-rendered ones | valid |
| OpenShift preflight script | `scripts/preflight-openshift.sh` with `OC=kubectl` against the kind deployment | ran end to end (OpenShift-only checks skipped, in-pod preflight passed); resource versions unchanged afterwards (read-only) |

### New in 0.0.3 (tests)

| Test | Covers |
| --- | --- |
| `TestSeamlessMongoDBOIDCAfterSSO` (Enterprise) | a corporate sign-in on behalf of another client leaves an IdP session (as OpenShift OAuth federation does); the portal connects with `prompt=none`; the IdP shows no further sign-in; MongoDB authenticates `testidp/u-1001` and refuses a write it does not grant; without an IdP session the portal continues interactively |
| `TestPreflightReadsServerIdP` (Enterprise) | the preflight reads the issuer and client id MongoDB announces without obtaining a token; a client id mismatch fails |
| `TestMongoDBOIDCSilentConnect`, `TestMongoDBOIDCTokenChecks` | silent request, interactive continuation, `interactiveFallback: false`, `authParams`; opaque, wrong-issuer and wrong-audience tokens refused before MongoDB with precise reasons |
| `TestExpectedWaitsAreNotSlow` | a change stream waiting for events is an expected wait (not slow); a long query is slow |
| `TestPreflightAgainstDeployments` | topology, version, TLS verification, host name mismatch, replica set name mismatch; API requires an identity |
| `TestCacheInvalidationAcrossReplicas`, `TestCacheManagement` | invalidation published by one replica, applied once by the other, results per replica; RBAC, confirmation, audit |
| `TestRevalidateIdentities` | invalidating identities makes OpenShift sign-ins pick up group changes on the next request |
| `TestPlaceholders*`, `TestMongoOIDCOptions` | `${NAME}`, defaults, typed values, escapes, unset variables named, values cannot inject YAML |
| kind checks | restricted admission with UID 1000680000; `helm test` preflight; registry listing and revocation across replicas; durable audit and chain verification; cache invalidation on both replicas; NetworkPolicy allow and block; rolling restart, session end and reconnect |
| Web | automatic connection once (and cancellable), no automatic connection after a failure, no build details on the sign-in page, Caches page confirmation |

The integration and unit tests from 0.0.2 (authentication, TLS, CRUD, shell,
monitoring, failover, import/export, killOp, shared store) are unchanged and
pass; see the 0.0.2 tables in the repository history.

## Security scans

| Scanner | Scope | Result |
| --- | --- | --- |
| govulncheck | reachable Go vulnerabilities | **0 affecting**; 1 module-level advisory not reachable (below) |
| gosec | Go source (excluding test fixtures) | **0 issues** |
| npm audit | web dependencies | **0 vulnerabilities** |
| gitleaks | repository | **no leaks** |
| hadolint | Dockerfile | clean |
| actionlint + shellcheck | CI workflow, new scripts | clean (one style note, SC2129, left as is) |
| Trivy config | rendered manifests and chart, HIGH and CRITICAL | clean |
| Trivy image | production and debug | raw: 1 Unknown (GO-2026-5932); with `security/vex` applied: no open findings, GO-2026-5932 shown as suppressed `not_affected` |
| Grype | production and debug | no vulnerabilities |
| Syft SBOM | production / debug | 46 / 118 packages |

A clean scan means no **known** vulnerabilities were found by these tools at
scan time; it is not proof that none exist.

### GO-2026-5932

| Question | Finding |
| --- | --- |
| Affected module and packages | `golang.org/x/crypto`, packages `openpgp`, `openpgp/packet`, `armor`, `clearsign`, `errors`, `elgamal`, `s2k` (advisory: unmaintained and unsafe by design; reviewed by the Go team) |
| Installed version | v0.58.0 (all versions affected; no fixed version exists) |
| Dependency path | the MongoDB driver (`ocsp`) and `youmark/pkcs8` (`pbkdf2`, `scrypt`) require the module |
| Linked into the binary | no: `go list -deps ./cmd/portal` contains only `x/crypto/pbkdf2`, `scrypt` and `ocsp`; govulncheck symbol analysis finds no use |
| In the runtime image | the module appears in the binary's build information (which is why Trivy reports it), not the `openpgp` code |
| Mitigation | none needed in code; CI fails if `openpgp` becomes a dependency; OpenVEX statement `security/vex/mongo-portal.openvex.json` (`not_affected`, `vulnerable_code_not_present`) |
| Owner / review | repository maintainers; review by 2027-01-22 or when x/crypto changes |

| Other exception | Component | Severity | Reason | Mitigation | Review |
| --- | --- | --- | --- | --- | --- |
| KSV-0125 | images from a public registry | Medium | policy finding, not a vulnerability | digests pinned; mirror to an approved registry where required | at production onboarding |

## Problems found and fixed during this release

- With the documented store grant (readWrite), changing `audit.retention`
  made the store unavailable (`collMod` not permitted). Fixed: the store
  stays usable and the change is logged for the database administrator.
- Slow-operation alerts counted awaitable `hello`, change streams, tailable
  cursors and oplog tailing. Fixed: shown as expected waits.
- Zero timestamps were rendered as "1/1/1". Fixed.
- CI: two of three manifest guardrails could not fail the job. Fixed.
- UI: sidebar icons were never rendered (icons passed to `NavItem` with
  custom links). Fixed.
- A unit test flaked under load (request timeout). Timeout raised; 20 / 20
  repeated runs passed.

## Not environment-validated

* OpenShift: OAuth login against a real OAuth server, SCC admission, Routes
  with re-encrypt and cookie affinity, OVN-Kubernetes NetworkPolicy,
  ServiceMonitor scraping (Kubernetes equivalents were tested on kind).
* Identity providers: Microsoft Entra ID, Okta or Keycloak tenants;
  OpenShift federated to the IdP that MongoDB trusts (the acceptance test in
  [ORGANIZATION_CONFIGURATION.md](ORGANIZATION_CONFIGURATION.md)).
* The target MongoDB Enterprise deployment and its OIDC configuration (never
  inspected or changed).
* CI on GitHub: the workflow was linted, not run; publishing needs the
  repository variables and secrets listed in the workflow header.

## Published images

Built from a clean `git archive` of commit `b69b80c` with BuildKit for
linux/amd64 and linux/arm64, with SBOM and `mode=max` provenance attached.
The tags did not exist before; 0.0.1 and 0.0.2 are unchanged. The images are
not signed (keyless signing runs in the CI release job, which needs the
repository settings listed in the workflow).

| Image | Index digest | Verified |
| --- | --- | --- |
| `docker.io/mohankrishna999/mongo-portal:0.0.3` | `sha256:02127f7f2b9c20e558a124174e27f55e3839c4e79e7e28f243dbf9ba22c7db2a` | pulled image reports 0.0.3 (b69b80c, go1.27.3), source and revision labels match; smoke 74 / 74 and browser e2e PASS on the published image; Trivy by digest: 1 Unknown (GO-2026-5932, VEX `not_affected`) |
| `docker.io/mohankrishna999/mongo-portal:0.0.3-debug` | `sha256:b807320f22d75457228bd8cdb5518c794354bd7cb93b195a919b280cb9853c59` | smoke 74 / 74 (both images); Trivy by digest: 1 Unknown (same) |

The prod overlay and `examples/openshift/deployment.yml` pin the production
digest; dev uses `0.0.3-debug`, test `0.0.3`. The Helm chart has no default
repository: set `image.repository` and `image.digest` per environment.
