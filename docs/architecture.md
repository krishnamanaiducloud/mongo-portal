# Architecture

```
Browser ──HTTPS──▶ OpenShift Route (re-encrypt)
                      │  TLS to the service-CA certificate
                      ▼
          ┌──────────── Pod ──────────────────────────────┐
          │ portal :8443  UI + REST API + /oauth/* (HTTPS) │──▶ Kubernetes API (OAuth discovery, users/~)
          │ portal :9090  /healthz /readyz /metrics       │──▶ OpenShift OAuth server (token exchange)
          └───────────────────────┬───────────────────────┘     (both optional: passive when unreachable)
                                  │ one MongoDB client per user session,
                                  │ authenticated with that user's credentials
                                  ▼  (TLS or plaintext, per profile)
                    Existing MongoDB replica set (unchanged)
```

## Components

| Component | Technology | Responsibility |
| --- | --- | --- |
| Portal backend | Go 1.26+, `mongo-driver/v2`, `net/http`, `slog`, Prometheus, OpenTelemetry | Built-in OpenShift login, sessions, RBAC, validated MongoDB operations, profile health checks, audit |
| Web UI | React 19, TypeScript, Vite, PatternFly 6, TanStack Query | Sign-in, explorer, document browser/editor, query console, mongosh shell, indexes, command palette, permissions, system status, session/audit views |
| Images | Chainguard `static` (production), Wolfi rootfs (debug) | Same binary in both; debug adds troubleshooting tools and `mongosh` |

The UI is compiled and embedded in the Go binary. The pod has no other runtime
dependency: no OAuth proxy, no Redis, no database of its own.

## Optional integrations are passive

| Integration | When it is unavailable |
| --- | --- |
| OpenShift login | Not offered; MongoDB-only login works ([oauth.md](oauth.md)) |
| RBAC ConfigMap | Configuration policy and default role apply; invalid edits are rejected and the last good policy stays |
| MongoDB deployment | Shown as offline/degraded on the login and status pages (unauthenticated `hello` health checks); logins report a clear error |
| Tracing (OTLP) | Logged once; tracing stays off |
| Session key Secret | Logged; a random per-pod key is used |

Readiness (`/readyz`) never depends on any of these.

## Authentication: two stages

**Stage A: single sign-on (optional).** The built-in OpenShift login performs
the OAuth authorization-code flow with PKCE, with the portal ServiceAccount as
the OAuth client. It then reads the user's name and groups from
`GET /apis/user.openshift.io/v1/users/~` with the user's own token. The result
is kept in an AES-GCM encrypted, HttpOnly `__Host-` cookie and re-checked every
5 minutes. A generic trusted proxy (`identity.header`) is also supported. See
[oauth.md](oauth.md).

Without SSO, the request is anonymous. That is not an error: the public
endpoints (`/me`, `/status`, `/profiles`, `POST /session`) still work, so users
can sign in with MongoDB credentials, unless `identity.requireSSO` is set.

**Stage B: MongoDB.** The user picks an administrator-defined connection
profile and enters MongoDB username, password and authentication database. The
backend builds a client from the profile (hosts and TLS settings come only from
configuration), authenticates with SCRAM-SHA-256/SCRAM-SHA-1, pings the server
and confirms the principal with `connectionStatus`. Only then is a session
created. The password is passed to the driver and kept only in process memory
for re-authenticating new pool connections (for example after failover). It is
never logged, persisted or returned. Without SSO, the MongoDB user
(`mongodb:<user>@<authSource>`) is the principal.

## Sessions

* Server-side, in-memory, per pod. The browser holds a random 256-bit bearer
  token in a `__Host-` cookie (`HttpOnly`, `Secure`, `SameSite=Strict`).
* Bound to its principal, qualified by source (an SSO user or a MongoDB-only
  user). Presenting the cookie under another identity destroys the session, and
  an SSO user's session is unusable without the SSO sign-in.
* New identifier on every login (rotation, fixation protection), idle timeout
  (default 15 min), absolute timeout (default 8 h), per-user and global caps,
  explicit logout and termination of one's other sessions.
* Expired or closed sessions disconnect their MongoDB client.
* **Multi-replica strategy:** the Route uses cookie-based affinity. The OpenShift
  sign-in and OAuth state cookies are sealed with the shared session key, so any
  replica accepts them. MongoDB sessions are per pod: if a request reaches a pod
  that does not own the session, the API returns `mongo_session_required` and
  the UI asks for the MongoDB login again. Credentials are never shared between
  pods.

## Authorization: two boundaries

1. **Portal RBAC** ([rbac.md](rbac.md)): a CSV policy (`p`/`g` lines)
   maps OpenShift users and groups, or MongoDB-only users, to roles. Every
   endpoint and shell operation checks the concrete database or namespace. That
   includes collections reached through `$lookup`/`$unionWith` and the targets
   of `$out`/`$merge`. Denials return 403 `portal_role_forbidden` and are audited.
2. **MongoDB privileges** of the authenticated user: every operation runs as that
   user, so MongoDB is the final authority. An admin-role user with a read-only
   MongoDB user cannot write. MongoDB `Unauthorized` errors are returned as 403
   and audited.

The UI offers an action only when both allow it. It uses `connectionStatus`
privileges and the RBAC decisions as hints; they never replace enforcement.

## Query safety

All query input is MongoDB Extended JSON parsed by the driver (no JavaScript
evaluation anywhere, including the mongosh-style shell, which is a fixed
grammar parsed in the browser into API calls). The validator:

* rejects `$where`, `$function`, `$accumulator` and JavaScript BSON values anywhere;
* allows only an allowlist of aggregation stages; `$out`/`$merge` are allowed only
  when `query.allowWriteStages: true`, only as the final top-level stage, and only
  for users whose RBAC role may write the target collection;
* bounds nesting depth, element count, regex length, pipeline length;
* enforces `limit`, `skip`, server-side `maxTimeMS` (via context deadlines /
  CSOT) and a response size cap;
* addresses single-document writes by `_id` only; id tokens containing operators
  are rejected so an id can never widen into a filter.

Destructive operations (drop collection, drop index, delete document) require
an `X-Confirm` header naming the target; the UI collects a typed confirmation.

## In-browser mongosh shell

The Shell page runs the **real mongosh runtime** (`@mongosh/browser-runtime-core`:
evaluator, shell API and autocompletion),
so JavaScript, variables, loops, `printjson`, cursor helpers and Tab completion
behave as in mongosh. It is isolated in three layers:

```
portal page (strict CSP)                sandbox iframe (opaque origin)         dedicated worker (same opaque origin)
  ShellPage + broker  ◀── MessagePort ──────────────────────────────────────▶  mongosh runtime + PortalServiceProvider
      │  allowlist, confirmations,        bootstrap only: starts the worker     evaluates user JavaScript
      │  concurrency limit                and hands it the port                 no network, no cookies, no storage
      ▼
  POST /api/v1/shell  (session cookie + CSRF; server validates every op again)
```

* `/shell-sandbox.html` is served with `Content-Security-Policy: sandbox allow-scripts;
  script-src 'self' 'unsafe-eval'; connect-src 'none'; worker-src blob:; frame-ancestors 'self'; …`.
  The sandbox (and the worker it starts) therefore has an **opaque origin**: it
  cannot read the portal's cookies, storage or DOM, and cannot make any network
  request. `'unsafe-eval'` (required to evaluate JavaScript) is granted only
  there; the portal page itself keeps `script-src 'self'` without eval.
* The runtime runs in a worker so runaway scripts never block the portal page;
  **Interrupt** removes the sandbox, which terminates the worker.
* mongosh calls the driver through `PortalServiceProvider`, which turns each
  call into a typed operation (`find`, `aggregate`, `getMore`, `insertOne`,
  `updateMany`, `runCommand`, …) sent over the MessagePort. The broker on the
  portal page enforces an operation allowlist, fails writes early for read-only
  roles, asks for confirmation of bulk and destructive operations (typed
  confirmation for drops), and limits concurrency.
* The server (`/api/v1/shell`) applies the same checks as the rest of the API:
  RBAC on each operation's namespace (`shell use`, plus e.g. `documents update
  app/orders`; administrative commands need `shell admin`), JavaScript operators rejected anywhere, `$out`/`$merge` policy,
  `runCommand` allowlist (user/role management, `eval`, `mapReduce`, `shutdown`,
  replica-set changes and similar are always denied), server-checked
  `X-Confirm` for destructive operations, no writes to `local`, `config` or
  `system.*`, time/size limits, and real server-side cursors with per-session
  caps. Every write is audited. MongoDB enforces the user's privileges last.
* Not supported: connecting to other deployments (`Mongo()`, `connect()`),
  `db.auth()`, sessions/transactions, change streams, client-side encryption,
  `load()`/files, the legacy Bulk API. `dropDatabase` is disabled unless
  `shell.allowDropDatabase: true`.

## Transport security to MongoDB

Each profile declares `tls.mode: enabled | disabled` explicitly (no default):

* **enabled:** certificate and hostname verification are always on (disabling is
  rejected at startup), custom CA bundle, optional client certificate, TLS 1.2/1.3
  minimum. Certificate files are re-read for each new login; client key pairs are
  reloaded when the mounted Secret changes.
* **disabled:** plaintext, logged as a warning at startup and on each login, and
  shown as a permanent red banner in the UI. With `environment: production` the
  portal refuses to start unless `plaintextApproved: true` is recorded with a
  `securityExceptionRef`.

There is no fallback between the modes, and TLS options in profile URIs are
rejected so verification cannot be weakened through the URI. HTTPS on the Route
does **not** encrypt portal→MongoDB traffic; only `tls.mode: enabled` does.

## Observability

* JSON logs (stdout) with request id, route pattern, status, latency, trace id,
  user and identity source. Query contents, document contents, passwords and tokens are never logged.
* Audit events (`"audit": true`) for SSO and MongoDB logins, sign-outs, RBAC and
  MongoDB denials and every write, with the user's roles and identity source.
* Prometheus metrics on `:9090/metrics` (`mongo_portal_*`): HTTP requests/latency,
  auth attempts by stage/result, authorization denials by source/reason,
  active sessions, open MongoDB connections, MongoDB operation latency, build info.
* OpenTelemetry traces (OTLP/HTTP) when `OTEL_EXPORTER_OTLP_ENDPOINT` is set; span
  attributes carry route patterns and operation names only.

## Repository layout

```
portal/
  cmd/portal/            main, graceful shutdown, healthcheck subcommand
  internal/api/          HTTP server, middleware, handlers, openapi.yaml (embedded)
  internal/identity/     built-in OpenShift OAuth client, SSO cookie, header/dev sources
  internal/rbac/         policy engine and hot-reloading store
  internal/mongoconn/    client options, TLS, error classification, privileges, profile health
  internal/query/        Extended JSON parsing and validation
  internal/session/      in-memory session store
  internal/ratelimit/    login throttling and lockout
  internal/audit|metrics|telemetry|config|webui/
  web/                   React application
  test/integration/      real MongoDB tests (run.sh starts disposable containers)
  test/container/        image smoke tests
  scripts/               security scanning
  Dockerfile             production + debug targets
examples/openshift/
  mongo-portal/base/     Deployment, Service, Route, SA (OAuth client), RBAC policy, NetworkPolicies, PDB, config
  mongo-portal/components/monitoring/  ServiceMonitor
  mongo-portal/overlays/{dev,test,prod}/
  cluster/               SCCs
  argocd/                AppProjects and Applications
```
