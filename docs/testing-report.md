# Testing and validation report

Release: **0.0.1** · Date: 2026-10-23 · Environment: Windows 10 + WSL2 Ubuntu,
Docker, Go 1.27.3 (toolchain pinned in `go.mod`), Node 24, MongoDB 8.0 test
containers. No OpenShift cluster was available; cluster-level items are listed
under "Not environment-validated".

## Results

| Area | Command | Result |
| --- | --- | --- |
| Go format / vet | `gofmt -l`, `go vet ./...` (+ `-tags integration`), `go mod verify` | clean |
| Go unit tests | `go test -race ./internal/...` | **pass** (10 packages) |
| Web lint / types | `npm run lint`, `npm run typecheck` | clean |
| Web unit tests | `npm test` (Vitest) | **39 / 39 pass** |
| Web build | `npm run build` | pass |
| Integration (real MongoDB) | `test/integration/run.sh` | **12 / 12 tests pass** |
| Container smoke | `test/container/smoke.sh` (3 UIDs × 2 images) | **74 / 74 checks pass** |
| Browser end to end | `test/e2e/run.sh` (Chromium) | **PASS** |
| Kustomize + schema | `kubectl kustomize` + `kubeconform -strict` (Kubernetes 1.31, OpenShift 4.18, CRD schemas) | dev, test, prod and cluster: 35 / 35 valid; Argo CD: 6 / 6; plain manifests: 13 / 13 |
| Manifest guardrails | no StatefulSet/PVC/Secret, no fixed UID/fsGroup, no privileged, no cluster RBAC in the app overlays | pass |
| Configuration check | `mongo-portal --check-config` on the dev and test configurations | valid |

### Integration tests (disposable 3-member replica set and TLS replica set)

| Test | Covers |
| --- | --- |
| `TestNonTLSAuthentication` | valid login, wrong password, unknown user, authentication-database mismatch, SCRAM-SHA-1 legacy user, mechanism restriction |
| `TestTLSAuthentication` | TLS with custom CA and client certificate, client certificate required by the server, untrusted CA, hostname mismatch, no plaintext/TLS downgrade |
| `TestUnavailableAndTimeout` | unreachable host, blackhole address, bounded timeouts |
| `TestConcurrentSessionsAreIndependent` | parallel logins as several users, each connection authenticated as its own principal |
| `TestDeveloperReadOnlyEndToEnd` | a group mapped to `role:readonly` cannot write even with a write-capable MongoDB user; `$out` blocked and verified not written |
| `TestSRERespectsMongoDBRoles` | admin portal role with a read-only MongoDB user: MongoDB denies writes (403) |
| `TestSRECrudEndToEnd` (TLS and non-TLS) | collections, documents (Long/Date/ObjectId/Decimal128), `_id` immutability, unique index and duplicate key (409), confirmations, `$where` rejected, stats, server info, logout |
| `TestQueryLimitsAndTimeouts` | pagination, server-side `maxTimeMS` |
| `TestShellOperations` | shell API: writes, cursor paging, aggregate, count, distinct, explain, confirmations, refused commands |
| `TestMonitoring` | replica set members (one primary), connections total = active + idle, total size, session pool; a user without `clusterMonitor` gets an explanation while sizes still work |
| `TestDefaultRoleFollowsMongoDB` | unmapped users follow their MongoDB privileges: a writer inserts, a reader is refused by MongoDB |
| `TestReplicaSetFailover` | primary step-down; existing sessions keep working |

### Unit and API security tests (selection)

Optional and required SSO; OpenShift OAuth flow against a fake OAuth server
(discovery, PKCE, state, replay, open-redirect protection, token exchange,
`users/~`), sealed cookies (forgery, revalidation, revocation, staleness);
identity headers from untrusted peers ignored; RBAC policy parsing, deny rules,
namespace globs, default role only for unmapped users; CSRF (missing, forged,
other user's token, cross origin, cross site); login lockout and `Retry-After`;
SSRF attempt via profile; unknown JSON fields; cookie flags; session rotation
and fixation; idle expiry; restart requires re-authentication; security
headers and CSP; body limits; operator injection; error classification; TLS
configuration (no `InsecureSkipVerify`, CA required, client certificate
reload); query validator; monitoring sections fail independently.

### Container smoke test (production and debug, UIDs 1000680000, 123456, 65532, GID 0)

Read-only root filesystem, all capabilities dropped, `no-new-privileges`:
ready, built-in healthcheck, UI served with CSP, HTTPS listener with a verified
certificate, sign-in options for anonymous users, MongoDB login sets a
`__Host-` cookie with `HttpOnly; Secure; SameSite=Strict`, authenticated query,
invalid password rejected, password absent from logs. The production image has
no shell; neither image has a package manager; the debug image's `mongosh` runs
as an arbitrary UID.

## Security scans

| Scanner | Scope | Result |
| --- | --- | --- |
| govulncheck | reachable Go vulnerabilities | **0 affecting**; 1 module-level advisory not reachable (below) |
| npm audit | web dependencies | **0 vulnerabilities** (after updating the transitive `ip-address` to 10.7.4, GHSA-rxp7-6hxx-x8q5, moderate) |
| gitleaks | repository | **no leaks** |
| hadolint | Dockerfile | clean |
| Trivy image | production and debug | 0 Critical / High / Medium / Low; 1 Unknown (below) |

A clean scan means no **known** vulnerabilities were found by these tools at
scan time; it is not proof that none exist.

### Exceptions

| ID | Component | Severity | Exploitability | Why no remediation | Mitigation | Review |
| --- | --- | --- | --- | --- | --- | --- |
| GO-2026-5932 | `golang.org/x/crypto` v0.58.0 (`openpgp` package) | Unknown (advisory: package unmaintained) | Not reachable: the portal never imports `x/crypto/openpgp` (govulncheck symbol analysis) | No fixed version exists; the module is required transitively by the MongoDB driver | Keep x/crypto current (Dependabot); the govulncheck gate in CI fails if it becomes reachable | 2027-01-22 |
| KSV-0125 | Deployment images (docker.io) | Medium | Policy finding, not a vulnerability | Registry choice is site policy | Production pins digests; mirror to an approved registry if required | at production onboarding |

## Not environment-validated (requires an OpenShift cluster)

* The OpenShift OAuth login end to end against a real OAuth server (exercised
  against faithful fakes of the discovery, token and `users/~` endpoints).
* restricted-v2 SCC admission and UID-range assignment (emulated: arbitrary
  UIDs, read-only root filesystem, dropped capabilities; script in
  `test/container/restricted-k8s.sh`).
* Route re-encrypt with the service CA, cookie affinity across replicas.
* NetworkPolicy enforcement (rendered and schema-validated only).
* ServiceMonitor scraping and log forwarding.
* Argo CD sync behaviour (manifests validated against the Argo CD CRD schemas).
* Connectivity to an existing production MongoDB (never contacted).
