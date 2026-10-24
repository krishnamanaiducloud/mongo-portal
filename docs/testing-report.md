# Testing and validation report

Release: **0.0.2** · Date: 2026-10-24 · Environment: Windows 10 + WSL2 Ubuntu,
Docker, Go 1.27.3 (toolchain pinned in `go.mod`), Node 24, MongoDB 8.0 test
containers, MongoDB Enterprise 7.0 for MONGODB-OIDC. No OpenShift cluster, no
production identity provider and no production MongoDB were available or
contacted; those items are listed under "Not environment-validated".

## Results

| Area | Command | Result |
| --- | --- | --- |
| Go format / vet | `gofmt -l`, `go vet ./...` (+ `-tags integration`, `-tags oidc`), `go mod verify` | clean |
| Go unit tests | `go test -race ./internal/...` | **pass** (11 packages; see note) |
| Web lint / types | `npm run lint`, `npm run typecheck` | clean |
| Web unit tests | `npm test` (Vitest) | **45 / 45 pass** (6 files) |
| Web build | `npm run build` | pass |
| Integration (real MongoDB) | `test/integration/run.sh` | **16 / 16 tests pass** |
| MONGODB-OIDC (MongoDB Enterprise 7.0 + test identity provider) | `test/oidc/run.sh` | **4 / 4 tests pass** |
| Container smoke | `test/container/smoke.sh` (3 UIDs × 2 images) | **74 / 74 checks pass** |
| Browser end to end | `test/e2e/run.sh` (Chromium) | **PASS** |
| Kustomize + schema | `kubectl kustomize` + `kubeconform -strict` (Kubernetes 1.31, OpenShift 4.18, CRD schemas) | dev, test, prod, cluster and all components: 49 / 49 valid; Argo CD: 6 / 6; plain manifests: 13 / 13 |
| Manifest guardrails | no StatefulSet/PVC/Secret, no fixed UID/fsGroup, no privileged, no cluster RBAC in the app overlays | pass |
| Configuration check | `mongo-portal --check-config` on the dev, test and plain OpenShift configurations | valid |

Note: in the first full run `TestOpenShiftLoginFlow` failed once with a probe
timeout against its local fake server while the race-instrumented build was
competing for CPU. It then passed 20 / 20 in isolation and the whole unit
suite passed 3 / 3; the test's request timeout was raised from 3 s to 10 s.
No product code was changed for it.

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
| `TestExportImportRoundTrip` | 750 documents exported and re-imported identically as canonical NDJSON, gzip-compressed JSON array and BSON; filtered, projected CSV export; gzip-compressed CSV import with field mapping; database archive whose manifest matches its files |
| `TestImportRulesAndAuthorization` | collection validators, upsert by `_id`, dry run writes nothing, `role:readonly` may export but not import (portal RBAC), a read-only MongoDB user's import fails per batch (MongoDB), system collections refused |
| `TestOperationsAndKill` | `$currentOp` listing filtered by namespace; `killOp` requires confirmation, is refused by MongoDB for a user without the `killop` privilege, ends the target operation, and a second kill is refused; idle connections listed separately and never killable |
| `TestSharedStoreAuditAndRegistry` | two replicas share the store: audit events of one are searchable on the other, an administrator on one replica sees and revokes a session held by the other; altering a stored event breaks the hash chain; the retention TTL index exists |

### MONGODB-OIDC tests (MongoDB Enterprise 7.0, test identity provider)

| Test | Covers |
| --- | --- |
| `TestMongoDBOIDCEndToEnd` | authorization code flow with PKCE through the portal; the session is `MONGODB-OIDC` as `testidp/u-1001` on `$external`; MongoDB allows reads and refuses writes per that user's roles |
| `TestMongoDBOIDCRefresh` | after the access token expires, reads keep working and a token refresh is observed, without a new sign-in |
| `TestMongoDBOIDCRefusals` | an identity unknown to MongoDB is rejected by MongoDB; a client id different from what the server announces is refused before a token is sent; no session in either case |
| `TestSCRAMAlongsideOIDC` | SCRAM users keep working on the same deployment |

### Unit and API security tests (selection)

Optional and required SSO; OpenShift OAuth flow against a fake OAuth server
(discovery, PKCE, state, replay, open-redirect protection, token exchange,
`users/~`); portal OIDC against a test provider (discovery, PKCE, state and
nonce, issuer, audience, expiry and signature checks, group
restriction, username claim, logout); sealed cookies (forgery, revalidation,
revocation, staleness); identity headers from untrusted peers ignored; RBAC
policy parsing, deny rules, namespace and profile globs, new resources and
roles, default role only for unmapped users; CSRF (missing, forged, other
user's token, cross origin, cross site); login lockout and `Retry-After`; SSRF
attempt via profile; unknown JSON fields; cookie flags; session rotation and
fixation; idle expiry; admin session listing and revocation; audit search,
CSV export without formula injection, chain verification;
export codecs (BOM, CSV quoting, types); restart requires re-authentication;
security headers and CSP; body limits; operator injection; error
classification; TLS configuration (no `InsecureSkipVerify`, CA required,
client certificate reload); query validator; monitoring sections
fail independently.

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
| gosec | Go source (excluding test fixtures) | **0 issues** after fixes (below) |
| npm audit | web dependencies | **0 vulnerabilities** (after the updates below) |
| gitleaks | repository | **no leaks** |
| hadolint | Dockerfile | clean |
| Trivy config | rendered manifests, HIGH and CRITICAL | clean |
| Trivy image | production and debug | 0 Critical / High / Medium / Low; 1 Unknown (below) |
| Grype | production and debug | no vulnerabilities |
| Syft SBOM | production / debug | 46 / 118 packages |

A clean scan means no **known** vulnerabilities were found by these tools at
scan time; it is not proof that none exist.

### Fixes made for this release

* npm: `@mongosh/browser-runtime-core` updated to 5.11.3; overrides pin the
  transitive `body-parser` to 2.4.0 and `zod` to 4.6.x, which resolved the
  high-severity advisories `npm audit` reported for those packages.
* gosec G115 (integer conversion): the audit TTL is clamped to `MaxInt32`
  seconds before conversion.
* gosec G104 (unchecked error): the OpenShift probe's response body close is
  handled explicitly.
* gosec G304 / G703 (file path), G710 (redirect), G118 (goroutine context):
  reviewed and annotated with the reason. The client secret path comes from
  the operator's configuration, never from a request; the redirects go to the
  configured identity provider's authorization endpoint from discovery; the
  import job intentionally outlives the upload request and is cancelled
  through the job or when the user's session ends.

### Exceptions

| ID | Component | Severity | Exploitability | Why no remediation | Mitigation | Review |
| --- | --- | --- | --- | --- | --- | --- |
| GO-2026-5932 | `golang.org/x/crypto` (`openpgp` package) | Unknown (advisory: package unmaintained) | Not reachable: the portal never imports `x/crypto/openpgp` (govulncheck symbol analysis) | No fixed version exists; the module is required transitively by the MongoDB driver | Keep x/crypto current (Dependabot); the govulncheck gate in CI fails if it becomes reachable | 2027-01-22 |
| KSV-0125 | Deployment images (docker.io) | Medium | Policy finding, not a vulnerability | Registry choice is site policy | Production pins digests; mirror to an approved registry if required | at production onboarding |

## Published images

Built from a clean `git archive` of commit `0517a8f` with BuildKit for
linux/amd64 and linux/arm64, with SBOM and `mode=max` provenance attached. The
tags did not exist before; `latest` is not used.

| Image | Index digest | Verified |
| --- | --- | --- |
| `docker.io/mohankrishna999/mongo-portal:0.0.2` | `sha256:9f0fa1e290548e8a348202eb3725d11ef5085a775fe9ea0fa767fe565a08dc9d` | pulled image reports 0.0.2 (0517a8f, go1.27.3), source and revision labels match, runs as an arbitrary UID with a read-only root filesystem; smoke 74 / 74 and browser e2e PASS on the published image; Trivy by digest: 1 Unknown (GO-2026-5932, above) |
| `docker.io/mohankrishna999/mongo-portal:0.0.2-debug` | `sha256:d1c69ebffa31ee5569bfd056d7fa74124a9a52f6e9433040d1841e4f16b15462` | smoke 74 / 74 (both images); Trivy by digest: 1 Unknown (same) |

The prod overlay and `examples/openshift/deployment.yml` pin the production
digest; dev uses `0.0.2-debug`, test `0.0.2`. The 0.0.1 images are unchanged.

## Not environment-validated

* The OpenShift OAuth login end to end against a real OAuth server (exercised
  against faithful fakes of the discovery, token and `users/~` endpoints).
* Portal OIDC with Microsoft Entra ID, Okta or Keycloak (exercised against a
  standards-conformant test provider; provider-specific claims and group
  overage need checking at onboarding, see `docs/oidc.md`).
* MONGODB-OIDC against the production MongoDB Enterprise deployment and
  identity provider; its OIDC configuration was not inspected or changed.
* restricted-v2 SCC admission and UID-range assignment (emulated: arbitrary
  UIDs, read-only root filesystem, dropped capabilities; script in
  `test/container/restricted-k8s.sh`).
* Route re-encrypt with the service CA, cookie affinity across replicas.
* NetworkPolicy enforcement and the OTLP egress component (rendered and
  schema-validated only).
* HorizontalPodAutoscaler behaviour (rendered and schema-validated only).
* ServiceMonitor scraping, log forwarding and export to an OpenTelemetry
  collector.
* Argo CD sync behaviour (manifests validated against the Argo CD CRD schemas).
* Connectivity to an existing production MongoDB (never contacted).
