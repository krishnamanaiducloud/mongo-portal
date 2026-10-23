# Testing and validation report

Releases up to 0.4.0 were developed in [mongo-express](https://github.com/krishnamanaiducloud/mongo-express); their
reports below also cover the mongo-express images built there.

## Release 0.4.0: MongoDB-following default role, monitoring, shell console

0.4.0 makes `role:mongodb` (follow the user's MongoDB privileges) the default
role. The default role now applies only to users the policy does not map. It
also adds the Monitoring page and API, the total size on the Databases page,
and a terminal-style shell console. Results before publication (local images,
linux/amd64):

| Suite | Result |
| --- | --- |
| Go unit tests, `go vet` | pass, incl. `TestDefaultRoleOnlyForUnmappedUsers`, `TestMonitoringIsPassive` (every section fails independently, 401 without a session), helpers for both decoded document forms |
| Integration (real MongoDB replica sets, TLS + non-TLS) | pass, incl. new `TestMonitoring` (3 members, 1 primary, connections total = active + idle, total size, own pool; a user without `clusterMonitor` gets an explanation while sizes still work) and `TestDefaultRoleFollowsMongoDB` (unmapped writer inserts; unmapped reader refused by MongoDB) |
| Web (`tsc`, ESLint, Vitest 39 tests, build) | pass, incl. Monitoring page with and without `clusterMonitor` (hello topology fallback), shell highlighter round trip, `role:mongodb` label |
| Container smoke | 74 / 74 |
| Browser e2e | PASS, incl. the redesigned shell (completion, confirmations, interrupt) and the Monitoring page for a user without `clusterMonitor` |
| mongo-express mocha (177, 11 pending), ESLint, image tests | pass, 40 / 40 (default role only for unmapped subjects) |

Defect found by the new integration test and fixed: replica set members were
missing because array elements decode as `bson.D`, not `bson.M`.

Published from commit 7c45b53 (multi-arch linux/amd64 + linux/arm64, SBOM and
max-mode provenance; the tags did not exist before):

| Image | Digest | Verification |
| --- | --- | --- |
| `docker.io/mohankrishna999/mongo-express:0.4.0` (portal) | `sha256:a35cb8b2bba1b5bb89c4487033120020b5fc4c407eaa987b4e34b7c0c8bb7cfb` | pulled image reports 0.4.0 (7c45b53) go1.27.3; smoke 74/74 and browser e2e PASS on the published image; Trivy by digest: 1 Unknown (GO-2026-5932, not reachable: govulncheck 0 called) |
| `docker.io/mohankrishna999/mongo-express:0.4.0-debug` (portal) | `sha256:54f9a731f25684f2be2fac4c1ab7d81e4650ded268408f4eef5d1a9f7c049459` | Trivy by digest: 1 Unknown (same) |

The prod overlay and `examples/openshift/deployment.yml` pin the 0.4.0
digest; dev uses `0.4.0-debug`, test `0.4.0`. The mongo-express images stay
at 0.0.2; its default-role change ships with the next mongo-express image.

## Release 0.3.0: built-in OpenShift login, RBAC, passive integrations

0.3.0 replaces the OAuth proxy sidecar with a built-in OpenShift login (Argo CD
style), adds Argo CD-style RBAC and makes every optional integration passive.
The mongo-express images (0.0.2) gain the same OpenShift login and RBAC.
Results before publication (local images, linux/amd64):

| Suite | Result |
| --- | --- |
| Go unit tests (`go test -race ./internal/...`), `go vet` | pass: rbac, identity (fake TLS OpenShift: discovery, PKCE, token exchange incl. Basic→body fallback, users/~, passive states, cookie revalidation/revocation/maxStale, forged cookies), api (MongoDB-only login, requireSSO, namespace RBAC, pipeline RBAC, shell RBAC, OAuth redirect flow: state, replay, denied, open redirect), config, session, query, audit |
| Web (`tsc`, ESLint, Vitest 34 tests, build) | pass (one Vitest run timed out on the real-mongosh test under heavy host load; re-run passed) |
| Container smoke (`test/container/smoke.sh`) | 74 / 74, incl. HTTPS listener with a verified certificate and anonymous `/me` returning sign-in options |
| Browser e2e (`test/e2e`) | PASS, incl. MongoDB-only sign-in with RBAC on the MongoDB user, server-side refusal after UI confirmation, permissions page and access check, status page, command palette |
| mongo-express mocha (177, 11 pending) and ESLint | pass, incl. RBAC policy, OpenShift client (fake cluster), sign-in/OAuth/RBAC routes |
| mongo-express image tests (`scripts/test-images.sh`) | 40 / 40, incl. passive OpenShift login outside OpenShift and RBAC on the local account, for both images |
| Manifests (kustomize + kubeconform, OpenShift 4.18 schemas) | all overlays valid; no StatefulSet/PVC/Secret, no fixed UID, no cluster RBAC from app overlays, no OAuth proxy |
| Scans | mongo-express minimal: Trivy no findings; debug: 8 × UNKNOWN GO-2026-5932 (documented exception); hadolint clean |

Published from commit 74ec358 (multi-arch linux/amd64 + linux/arm64, SBOM and
max-mode provenance attached; existing tags were checked and none overwritten):

| Image | Digest | Verification |
| --- | --- | --- |
| `docker.io/mohankrishna999/mongo-express:0.3.0` (portal) | `sha256:92c5cf140e3106ead1e53bf0372fd7b98000786af7a63a3574139a565ffc78f6` | pulled image reports 0.3.0 (74ec358) go1.27.3; smoke 74/74 and browser e2e PASS on the published image; Trivy by digest: 1 Unknown |
| `docker.io/mohankrishna999/mongo-express:0.3.0-debug` (portal) | `sha256:0182e3e5ee7cf6542824a8b445c8f4ad119f58694c5a84b6f861456368f8a375` | Trivy by digest: 1 Unknown |
| `docker.io/mohankrishna999/mongo-express:0.0.2` (mongo-express) | `sha256:2d97adc4b4b196efc6d207ff5ec0adc4c1704c3b67097f960ef7a0ca1a3167a2` | image tests 40/40 on the published images; Trivy by digest: no findings |
| `docker.io/mohankrishna999/mongo-express:0.0.2-debug` (mongo-express) | `sha256:8d5516717165e2f77c0135577e6e9b058f89d3b29c6112619780c99aa83ac52d` | Trivy by digest: 8 × UNKNOWN (GO-2026-5932, documented) |

The prod overlays pin these digests; dev uses the debug tags, test (portal) `0.3.0`.

Not covered: a real OpenShift OAuth server end to end. The flow is exercised
against faithful fakes of the discovery, token and `users/~` endpoints; verify
on a cluster as described in [deployment.md](deployment.md#7-verify).

## Release 0.2.0 — in-browser mongosh shell

0.2.0 replaces the 0.1.0 mongosh-style command grammar with the real mongosh
runtime (`@mongosh/browser-runtime-core` 5.11.2) running in an opaque-origin
sandbox and worker (see architecture.md). Results for 0.2.0:

| Area | Result |
| --- | --- |
| Go unit tests (race) | pass; new: shell authorization (developer writes, unsupported ops, denied/admin commands, JS operators, write stages, cursor options, CSRF), destructive confirmation, command classification and validation, cursor registry, sandbox CSP, ETag/gzip static serving |
| Web tests (Vitest) | **27/27**; new: the real mongosh runtime driven through `PortalServiceProvider` (find modifiers and BSON types, JS loops across getMore, printjson, toArray/it/aggregate/count/show, writes, createIndex names, refused connections/sessions/watch, error codes, autocompletion) and broker policy (allowlist, read-only role, typed drop confirmation, remembered bulk confirmations, destructive runCommand) |
| Integration (real MongoDB) | **10/10**; new `TestShellOperations` (non-TLS and TLS): insertMany, server-side cursor paging with getMore and closure, aggregate, countDocuments, distinct, explain, dbStats, createUser refused, unconfirmed vs confirmed updateMany, bulkWrite, findOneAndUpdate, unique index + duplicate key, confirmed dropIndexes, dropCollection; SRE with read-only MongoDB user refused by MongoDB; developer reads allowed, writes refused |
| Browser e2e (Chromium 1.63, `test/e2e`) | **all checks pass**: find/BSON rendering, JS loop over 30 docs = 435, printjson, aggregate, show collections, developer write/`$out`/`$where`/`shutdown`/`new Mongo()` refused; sandbox isolation: no cookies, parent DOM, localStorage, IndexedDB; fetch, XHR and external importScripts blocked; main page CSP has no eval; sandbox CSP opaque origin + `connect-src 'none'`; Tab completion; SRE insertMany/updateOne, deleteMany cancel → no change, confirm → deleted, drop requires typing the name, `while(true){}` interrupted and shell recovers |
| Container smoke | 73/73 (production and debug, 3 arbitrary UIDs, read-only rootfs) |
| Scans | govulncheck 0 affecting; gosec 0; npm audit 0 (after overriding `basic-ftp` to 6.2.2, GHSA-c475-qrg2-pj4r, build-time-only transitive dependency of `@mongosh/types`, not in the browser bundle); Trivy/Grype: 0 Critical/High/Medium/Low in both images, 1 Unknown (GO-2026-5932, below); gitleaks: no leaks |

Defects found by the new tests and fixed: `distinct` results were serialised
as Binary instead of an array (integration test); runaway scripts froze the
portal tab because the sandboxed iframe shared the page's thread (browser
e2e; runtime moved into a worker); the TypeScript-based autocompleter did not
work in the browser and added ~11 MB (browser e2e; classic completer selected
and the module stubbed, bundle 13.5 MB → 2.5 MB).

Published from commit `266c53b1e8ef370137d6168c6025d5e881f6f16e` (clean
`git archive`, multi-arch, SBOM + `mode=max` provenance; existing tags not
overwritten, `latest` unchanged):

| Image | Index digest | Post-publish verification |
| --- | --- | --- |
| `docker.io/mohankrishna999/mongo-express:0.2.0` | `sha256:7422334b3057a7852746a134ac86c30bf10a44e2b53e0e4336c8850b66ba3059` | provenance commit = 266c53b (amd64, arm64); arm64 binary aarch64; pulled image reports 0.2.0 (266c53b) go1.27.3; smoke 73/73 and browser e2e PASS run against the published image; Trivy by digest: 1 Unknown |
| `docker.io/mohankrishna999/mongo-express:0.2.0-debug` | `sha256:3c45857f331c12ccaf23a0d53e189f4518b32df561c9999135ef2b9e1c93f68b` | labels + provenance = 266c53b; mongosh 2.13.0 runs as arbitrary UID; Trivy by digest: 1 Unknown |

The prod overlay pins `0.2.0` by digest; dev uses `0.2.0-debug`, test `0.2.0`.

Known limitations of the shell: no connections to other deployments,
`db.auth()`, sessions/transactions, change streams, client-side encryption,
`load()`, legacy Bulk API; `dropDatabase` off by default. Sessions remain
per pod.

---

## Release 0.1.0

Release: **0.1.0** · Date: 2026-10-22 · Environment: Windows 10 + WSL2 Ubuntu,
Docker 29.6, Go 1.27.3 (Chainguard), Node 24/26, MongoDB 8.0 test containers.
No OpenShift cluster was available; cluster-level items are listed under
"Not environment-validated".

## Results

| Area | Command | Result |
| --- | --- | --- |
| Go format / vet | `gofmt -l`, `go vet ./...` (+ `-tags integration`) | clean |
| Go unit tests | `go test -race ./internal/...` | **pass** (9 packages) |
| Web lint / types | `npm run lint`, `npm run typecheck` | clean |
| Web unit tests | `npm test` (Vitest) | **18/18 pass** |
| Web build | `npm run build` | pass |
| OpenAPI contract | `TestOpenAPIContract` (routes ⇔ `openapi.yaml`) | pass |
| Integration (real MongoDB) | `test/integration/run.sh` | **9/9 tests pass** |
| Container smoke | `test/container/smoke.sh` (3 UIDs × 2 images) | **73/73 checks pass** |
| Kustomize + schema | `kubectl kustomize` + `kubeconform -strict` (K8s 1.31, OpenShift 4.18 Route, CRDs) | dev/test/prod 11/11 valid each; Argo CD 4/4 valid |
| Manifest guardrails | no StatefulSet/PVC/Secret, no runAsUser/fsGroup/privileged | pass |

### Integration tests (disposable 3-member replica set + TLS replica set)

| Test | Covers |
| --- | --- |
| `TestNonTLSAuthentication` | valid login, wrong password, unknown user, **auth-database mismatch**, SCRAM-SHA-1 legacy user, mechanism restriction |
| `TestTLSAuthentication` | TLS with **custom CA + client certificate**, client cert required by server, **untrusted CA**, **hostname mismatch**, no plaintext→TLS or TLS→plaintext downgrade |
| `TestUnavailableAndTimeout` | unreachable host, blackhole address, bounded timeouts |
| `TestConcurrentSessionsAreIndependent` | 15 parallel logins as 3 users, each connection authenticated as its own principal |
| `TestDeveloperReadOnlyEndToEnd` | developer with a write-capable MongoDB user still cannot insert/index/drop; `$out` blocked and verified not written; Decimal128 round-trip |
| `TestSRERespectsMongoDBRoles` | SRE portal role + read-only MongoDB user → MongoDB denies insert/index/drop (403) |
| `TestSRECrudEndToEnd` (TLS and non-TLS) | create collection, insert (Long/Date/ObjectId), get, replace, `_id` immutability, unique index + duplicate (409), confirmation required for drop, count, `$where` rejected, delete, stats, drop, server info, logout |
| `TestQueryLimitsAndTimeouts` | pagination/hasMore, server-side `maxTimeMS` |
| `TestReplicaSetFailover` | primary step-down (rs1→rs3); existing session keeps working (driver re-authentication) |

### Unit / API security tests (selection)

SSO required; identity headers from untrusted peers ignored; group → role
mapping; OpenShift token/user mismatch (spoofing) rejected; API outage fails
closed after max staleness; CSRF (missing, forged, other user's token, cross
origin, cross site, form posts); lockout after failures and `Retry-After`; SSRF
attempt via profile; unknown JSON fields; cookie flags; session rotation and
fixation; cross-user cookie reuse destroys the session; developer write denial
on every write route; confirmation headers; `_id_` and `system.*` protection;
idle expiry; **backend restart requires re-authentication**; security headers
and CSP; body limits; operator injection via document id; error classification
(timeouts during SASL never count as bad credentials); TLS config (no
`InsecureSkipVerify`, CA required, client cert reload on rotation); query
validator (JS operators, nested write stages, regex/nesting/element limits).

### Container smoke test (production and debug, UIDs 1000680000, 123456, 65532, GID 0)

Read-only root filesystem, all capabilities dropped, `no-new-privileges`:
ready, built-in healthcheck, UI served with CSP, SSO identity accepted,
unauthenticated → 401, MongoDB login sets `__Host-` cookie with `HttpOnly;
Secure; SameSite=Strict`, authenticated query, invalid password → 401,
password absent from logs. Production image has no shell; neither image has a
package manager; `mongosh` runs and connects from the debug image as an
arbitrary UID; debug tools (sh, curl, dig, nslookup, openssl, ss, ip, ps, top,
jq) present and executable.

## Defects found by testing and fixed

| Defect | Found by | Fix |
| --- | --- | --- |
| Network timeouts during SCRAM handshake were classified as bad credentials (would trigger lockout) | integration (concurrency) | classify only server-reported `AuthenticationFailed` as auth failure |
| HTTP mux pattern conflict between `GET /` (UI) and `/api/` caused a startup panic | container smoke | register UI on `/` with method check; added `TestServerWithUI` |
| Debug image lacked busybox applet links (`--no-scripts`) | container smoke | create links from the package's applet list at build time |
| Overlay image overrides did not apply; ConfigMap not content-hashed | kustomize render | match full image names; base `configMapGenerator` |
| Web lockfile excluded by repository `.gitignore` | staging review | scoped un-ignore for `portal/web/package-lock.json` |

## Security scans (final images)

| Scanner | Scope | Result |
| --- | --- | --- |
| govulncheck v1.9.0 (Go 1.27.3) | reachable Go vulnerabilities | **0 affecting**; 1 module-level advisory not reachable (below) |
| gosec | Go SAST | 0 issues (5 reviewed: 2 bounded int conversions, 2 cookie `Secure` from validated config, 1 local health URL — annotated with justification) |
| npm audit | runtime and all deps | **0 vulnerabilities** |
| gitleaks | working tree (portal/, examples/openshift/) | **no leaks** |
| hadolint | Dockerfile | clean (justified inline ignores: root in build-only stage, rolling Wolfi pins via base digest, pipefail via SHELL) |
| Trivy image | production | **0 Critical / 0 High / 0 Medium / 0 Low**, 1 Unknown |
| Trivy image | debug | **0 Critical / 0 High / 0 Medium / 0 Low**, 1 Unknown |
| Grype (from Syft SBOM) | both | 1 Unknown (same advisory) |
| Trivy config | rendered prod manifests | 0 High/Critical; 2 Medium KSV-0125 "untrusted registry" (site registry allowlist policy) |
| Syft | SBOM SPDX + CycloneDX | production 42 packages, debug 114 packages |

Initial scans found `golang.org/x/net` v0.59.0 (1 Critical, several High,
fixed in 0.60.0) and Go standard-library issues in the local 1.26 toolchain.
Remediated by upgrading x/net to 0.61.0 (and x/crypto, x/sys, x/text) and
pinning `toolchain go1.27.3`.

A clean scan result means no **known** vulnerabilities were found by these
tools at scan time; it is not proof of absence of vulnerabilities.

### Exceptions

| ID | Component | Severity | Exploitability | Why no remediation | Mitigation | Review |
| --- | --- | --- | --- | --- | --- | --- |
| GO-2026-5932 | `golang.org/x/crypto` v0.58.0 (`openpgp` package) | Unknown (advisory: package unmaintained, unsafe by design) | Not reachable: the portal never imports `x/crypto/openpgp` (govulncheck symbol analysis) | No fixed version exists; the module is required transitively by the MongoDB driver | Keep x/crypto current (Dependabot); govulncheck gate in CI fails if it becomes reachable | 2027-01-22 |
| KSV-0125 | Deployment images (docker.io, quay.io) | Medium | Policy finding, not a vulnerability | Registry choice is site policy | Production pins digests; mirror to an approved registry and configure the allowlist | at production onboarding |

## Published images

Built from a clean `git archive` of commit `b8f25d23b6311c3888798a7e9b3a41b640788e72`
with BuildKit (cross-compiled, no emulation), SBOM and `mode=max` provenance
attestations attached. Existing tags were checked first and not overwritten;
`latest` was not changed.

| Image | Index digest | Platforms | Verified |
| --- | --- | --- | --- |
| `docker.io/mohankrishna999/mongo-express:0.1.0` | `sha256:7592c5d020168ffc2c11f5a49d6efc51f3d94901e9b4de1aab1ef52adc978918` | linux/amd64, linux/arm64 | revision label + provenance = b8f25d2, user 65532:0, arm64 binary is aarch64, pulled image runs, Trivy: 1 Unknown |
| `docker.io/mohankrishna999/mongo-express:0.1.0-debug` | `sha256:b97e4bbd6a5a3f37cfc86374e0e54fb20d396845b32a87882a39425b42c1ea0e` | linux/amd64, linux/arm64 | same; mongosh 2.13.0 runs as arbitrary UID, Trivy: 1 Unknown |

Not done: cosign signatures (no signing key/identity configured locally; the CI
release job signs keylessly). arm64 images were inspected but not executed
(no arm64 host or emulator available).

## Not environment-validated (requires an OpenShift cluster)

* OpenShift OAuth proxy flow end to end (redirect, callback, token forwarding)
  — the portal side is unit-tested against a fake OpenShift API.
* Group lookup with the real `user.openshift.io` API and ClusterRole.
* restricted-v2 SCC admission and UID-range assignment (emulated: arbitrary
  UIDs, read-only rootfs, dropped capabilities; Pod Security "restricted" kind
  test script provided in `portal/test/container/restricted-k8s.sh`).
* Route re-encrypt with the service CA, cookie affinity across replicas.
* NetworkPolicy enforcement (rendered and schema-validated only).
* ServiceMonitor scraping by user-workload monitoring; Splunk forwarding.
* Argo CD sync behaviour (manifests validated against the Argo CD CRD schemas).
* Connectivity to the existing production MongoDB (never contacted).
