# Security threat model

## Assets

| Asset | Where it lives |
| --- | --- |
| MongoDB user passwords | Browser form → portal process memory (driver credential) only |
| Data in MongoDB | MongoDB; transiently in portal responses |
| Portal session bearer token | `__Host-` HttpOnly cookie; SHA-256 hash in pod memory |
| OpenShift access token (scope `user:info`) | AES-256-GCM sealed `__Host-` cookie (HttpOnly, Secure, SameSite=Strict); used only to re-check identity and groups (`users/~`) |
| Portal ServiceAccount token | Pod (projected); OAuth client secret only; no RBAC permissions |
| Session key (CSRF HMAC, SSO and OAuth-state cookie encryption) | Kubernetes Secret |
| RBAC policy | ConfigMap (`mongo-portal-rbac`), managed in Git/Argo CD |

## Trust boundaries

Browser ↔ Route (TLS) ↔ portal (TLS, service CA) ↔ MongoDB (TLS or plaintext
per profile); portal ↔ Kubernetes API and OpenShift OAuth server (TLS, verified).
Browser ↔ OpenShift OAuth server (user sign-in at the IdP).

## Threats and mitigations (STRIDE)

| Threat | Mitigation | Verified by |
| --- | --- | --- |
| **Spoofing** identity | Built-in OAuth code flow with state + PKCE (S256); identity read with the user's token from `users/~`; sealed SSO cookie (forgery or another key is rejected); identity headers only with `identity.header` and only from trusted CIDRs (others ignored) | `identity_test` (flow, tampered cookie, untrusted peer), `oauth_test TestOpenShiftOAuthFlow` (state mismatch, replay, denied, bad code) |
| Unauthorized user | RBAC on every request and shell operation against the concrete namespace; groups re-validated every 5 min; revoked tokens sign the user out; after `maxStale` without the API the sign-in ends | `rbac_test`, `TestNamespaceScopedRBAC`, `TestResolverRevokedToken`, `TestResolverSSOCookieLifecycle` |
| OAuth code interception / open redirect | Redirect URI restricted by the ServiceAccount redirect reference; PKCE; return paths must be local (`//host`, `/\host` rejected) | `TestOpenShiftOAuthFlow` |
| RBAC bypass through aggregation | `$lookup`/`$graphLookup`/`$unionWith` sources and `$out`/`$merge` targets authorized; undeterminable references refused | `TestNamespaceScopedRBAC`, `namespaces_test` |
| Session hijack / fixation | 256-bit random token, HttpOnly/Secure/SameSite=Strict `__Host-` cookie, rotation on login, owner binding qualified by identity source (SSO vs MongoDB-only) destroys cross-identity use, idle/absolute expiry | `TestSessionRotationOnLogin`, `TestCrossUserCookieRejected`, `TestSSOSessionNeedsSSO`, `TestMongoDBOnlyLogin`, `TestSessionExpiry` |
| CSRF (incl. login CSRF) | Per-session token / HMAC pre-login token bound to the principal, or for anonymous browsers to a random HttpOnly cookie; Origin and Sec-Fetch-Site checks; JSON-only bodies | `TestLoginCSRFAndOrigin`, `TestMongoDBOnlyLogin`, `TestSREWriteNeedsCSRF…` |
| **Tampering**: read-only users write | RBAC on all write routes and shell operations, independent of the UI; `$out`/`$merge` need write permission on the target | `TestDeveloperCannotWriteViaDirectAPI`, integration `TestDeveloperReadOnlyEndToEnd`, e2e |
| Privilege beyond MongoDB grants | Every operation runs as the user; MongoDB enforces | integration `TestSRERespectsMongoDBRoles` |
| NoSQL injection | Extended JSON parsed by the driver (no string concatenation); operator-free `_id` tokens; JS operators rejected; strict JSON decoding | `validate_test`, `TestDecodeIDRejectsOperators` |
| Server-side JavaScript | `$where`, `$function`, `$accumulator`, Code values rejected at any depth; no `runCommand`/`eval` API; shell grammar never evaluates JS | `TestFilterRejectsDangerousInput`, `shell.test.ts` |
| SSRF via connection settings | Hosts only from admin profiles; login accepts a profile *name*; URIs with credentials/TLS/auth options rejected | `TestLoginFailureAndLockout`, `config_test` |
| TLS downgrade / MITM to MongoDB | Explicit mode, no fallback, verification cannot be disabled, hostname checked, custom CA | integration `TestTLSAuthentication` (wrong CA, hostname mismatch, both downgrade directions) |
| Malicious or pasted shell script steals session / CSRF token | mongosh runs in an opaque-origin sandbox + worker: no cookies, storage, DOM access or network (`connect-src 'none'`); only the broker can call the API | browser e2e (`test/e2e`): cookie/storage/IndexedDB/parent access, fetch, XHR, importScripts all blocked |
| Shell script performs destructive operations silently | Broker confirmation dialogs (typed for drops), server-required `X-Confirm`, portal role and MongoDB privileges | `TestShellDestructiveConfirmationForSRE`, broker tests, e2e cancel/confirm |
| Shell used to reach other hosts or switch identity | `Mongo()`/`connect()`/`db.auth()` unsupported in the provider; no such server operations exist | provider tests, e2e "connecting elsewhere refused" |
| Arbitrary commands through `db.runCommand` | Server-side command allowlist; admin commands SRE-only; JS denied inside commands | `TestClassifyCommand`, `TestShellAuthorization`, integration `TestShellOperations` |
| Runaway script freezes the portal | Runtime in a dedicated worker; Interrupt terminates it | e2e "recovers after interrupting an infinite loop" |
| **Repudiation** | Structured audit events for logins, denials, writes with SSO + MongoDB identities and request id | `audit_test`; log review |
| **Information disclosure**: credentials | Passwords never logged/stored/returned; telemetry has no query/document content; hosts hidden from UI | `TestLoginSessionCookieAndLogout`, smoke test "password not in logs" |
| Error leakage | Classified, generic error messages; no stack traces to clients | `mongoconn` classification tests |
| XSS | React escaping, no `dangerouslySetInnerHTML` (lint rule), strict CSP (`script-src 'self'`, no inline), `nosniff` | `components.test.tsx`, header tests |
| Clickjacking | `frame-ancestors 'none'`, `X-Frame-Options: DENY` | header tests |
| **DoS**: brute force | Per-SSO-user (or per-client-address) rate limit, per-account lockout with backoff (only on server-confirmed failures), concurrent login cap | `TestLoginFailureAndLockout`, `limiter_test` |
| Resource exhaustion | Body limits, query limits/skip cap, server-side `maxTimeMS`, response byte cap, session caps, pool size per session, container limits | `TestQueryLimitsAndTimeouts`, `TestSecurityHeadersAndBodyLimit` |
| **Elevation**: container escape | Non-root arbitrary UID, read-only rootfs, all capabilities dropped, no privilege escalation, RuntimeDefault seccomp, restricted-v2 SCC, no shell/package manager in production image | smoke test, manifest checks |
| Lateral movement | NetworkPolicies: ingress only router + monitoring; egress DNS, MongoDB pods, API/OAuth (443/6443); ServiceAccount without permissions | manifest review (cluster test pending) |
| Supply chain | Base images pinned by digest (Chainguard), lockfiles, `go mod verify`, `npm ci --ignore-scripts`, mongosh checksum-pinned, SBOMs, vulnerability scans, Dependabot | security scan reports |

## Residual risks

1. **Plaintext MongoDB traffic** in the current environment (TLS disabled on the
   server). Credentials and data can be read by anyone with network access between
   pod and MongoDB. Mitigation: NetworkPolicy, production start-up gate requiring a
   recorded exception. Remediation: enable MongoDB TLS and switch profiles.
2. Passwords are held in process memory for the session lifetime (required for
   driver re-authentication). A memory dump of the pod would expose them.
3. Sessions are per pod; pod loss logs users out of MongoDB (by design).
4. In-memory audit buffer and rate limiter are per pod; durable audit relies on
   log forwarding (Splunk). Rate limits are per replica (effective limit ×replicas).
5. Kubernetes API egress rule is port-based by default; narrow it to the API
   endpoint IPs per cluster.
6. The debug image contains a shell and network tools; restrict its use to
   troubleshooting windows.
7. Without SSO (or with `defaultRole` set), anyone who reaches the Route and holds valid
   MongoDB credentials gets the default role (`role:mongodb`: their own MongoDB
   privileges, nothing more). MongoDB authentication remains
   required; set `identity.requireSSO: true` and/or `rbac.defaultRole: ""` for a
   deny-by-default posture.
8. The shell sandbox page needs `'unsafe-eval'` to evaluate JavaScript. It is
   confined to an opaque origin with no network access; a sandbox escape would
   require a browser vulnerability. A user can still do, through the shell,
   anything their own portal role and MongoDB privileges allow (by design).
9. The sandbox could navigate itself to another same-origin URL (the portal
   page's `frame-src 'self'` prevents other origins); query strings are not
   logged by the portal.
10. The OpenShift access token is kept (encrypted) in a browser cookie for
    revalidation. It has scope `user:info` only. Signing out removes the cookie
    but does not revoke the token at the OAuth server; it expires with its lifetime.
