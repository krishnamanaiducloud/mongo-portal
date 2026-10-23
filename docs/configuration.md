# Configuration reference

The portal reads one YAML file (`--config`, default
`/etc/mongo-portal/config.yaml`; overlays mount it at
`/etc/mongo-portal/config/config.yaml`). Unknown keys are rejected. Validate a
file with `mongo-portal --check-config --config file.yaml`.

Secrets are never placed in this file; it references mounted files instead.

## Top level

| Key | Default | Description |
| --- | --- | --- |
| `environment` | — | Free-form label shown in the UI. `prod`/`production` enables strict checks. |

## `server`

| Key | Default | Description |
| --- | --- | --- |
| `listenAddress` | `127.0.0.1:8080` | UI/API listener. In OpenShift `0.0.0.0:8443` with `tls` (re-encrypt Route). |
| `tls.certFile` / `tls.keyFile` | — | Serve HTTPS with this certificate (OpenShift service CA: `/etc/tls/private/tls.crt`/`tls.key`). Reloaded when the files change. |
| `opsListenAddress` | `0.0.0.0:9090` | `/healthz`, `/readyz`, `/metrics` only. Readiness never depends on MongoDB or SSO. |
| `publicOrigin` | — | e.g. `https://portal.apps.example.com`. When set, unsafe requests must carry this exact `Origin` and the OAuth redirect URI is built from it. |
| `maxBodyBytes` | `1048576` | Limit for JSON request bodies (document bodies use `query.maxDocumentBytes`). |
| `readTimeout` / `writeTimeout` | `30s` / `90s` | HTTP server timeouts. |
| `shutdownDelay` / `shutdownTimeout` | `5s` / `30s` | Graceful shutdown: delay after readiness turns false, then drain. |
| `hsts` | `false` | Send `Strict-Transport-Security`. |

## `identity`

Single sign-on is optional. Without an available SSO source users sign in with
MongoDB credentials only; see [oauth.md](oauth.md).

| Key | Default | Description |
| --- | --- | --- |
| `openshift.enabled` | `auto` | Built-in OpenShift login. `auto`: offered whenever the pod runs in OpenShift and the OAuth server is reachable. `true`: same, but unavailability is logged as a warning. `false`: off. |
| `openshift.apiURL` | `https://kubernetes.default.svc` | API server (OAuth discovery, `users/~`). |
| `openshift.caFile` / `extraCAFiles` | service account `ca.crt` / — | Trusted CAs (plus system roots). Missing files are skipped. |
| `openshift.serviceAccountTokenFile` / `namespaceFile` | service account mounts | OAuth client secret / namespace. |
| `openshift.clientID` | from the token | Override of `system:serviceaccount:<ns>:<name>`. |
| `openshift.scopes` | `[user:info]` | Requested OAuth scopes. |
| `openshift.probeInterval` | `1m` | Re-check while unavailable (5× longer while healthy). |
| `openshift.revalidateInterval` / `maxStale` | `5m` / `1h` | Re-check signed-in users; how long a sign-in survives an unreachable API. |
| `openshift.requestTimeout` | `5s` | Per request to the API/OAuth server. |
| `requireSSO` | `false` | Refuse MongoDB-only logins (no fallback while SSO is unavailable). |
| `header.enabled` / `userHeader` / `groupsHeader` | `false` / `X-Forwarded-User` / `X-Forwarded-Groups` | Trust identity headers from a generic authenticating proxy. |
| `trustedProxyCIDRs` | loopback | Peers allowed to send identity headers (others are ignored). |
| `dev.enabled` / `user` / `groups` | `false` | Fixed local-development identity; requires `PORTAL_ALLOW_INSECURE_DEV_IDENTITY=true`, forbidden in production. |
| `ssoLogoutURL` | — | IdP logout page opened after **Sign out**. |
| `mode` | — | Deprecated: `openshift`, `header` or `dev`, mapped to the settings above. |
| `developerGroups` / `sreGroups` | — | Deprecated: become `g, <group>, role:readonly` / `role:admin` RBAC lines. |

## `rbac`

Portal RBAC; see [rbac.md](rbac.md).

| Key | Default | Description |
| --- | --- | --- |
| `defaultRole` | `role:mongodb` | Role of signed-in users the policy does not map (SSO or MongoDB-only). `role:mongodb` follows each user's MongoDB privileges; `role:readonly` makes them read-only; `""` grants nothing. |
| `policy` | — | Inline CSV (`p` and `g` lines). Invalid lines stop startup. |
| `policyDir` | `/etc/mongo-portal/rbac` | Optional directory with `policy.csv` and `policy.default` (the `mongo-portal-rbac` ConfigMap). Missing is fine. |
| `reloadInterval` | `30s` | How often `policyDir` is re-read. Invalid updates are rejected; the previous policy stays active. |

## `monitoring`

| Key | Default | Description |
| --- | --- | --- |
| `profileHealthInterval` | `30s` | Background health check of every connection profile with the unauthenticated `hello` command (no credentials). Shown on the login page and the System status page. Negative disables it. |

## `session`

| Key | Default | Description |
| --- | --- | --- |
| `cookieName` | `__Host-mongo_portal_session` | |
| `secureCookie` | `true` | Only `false` with the `dev` identity. |
| `idleTimeout` / `absoluteTimeout` | `15m` / `8h` | |
| `maxPerUser` / `maxTotal` | `3` / `200` | Oldest session of the user is evicted at the per-user cap. |
| `keyFile` | — | Key (≥ 32 bytes) for pre-login CSRF tokens and for encrypting the OpenShift sign-in and OAuth state cookies; must be the same on all replicas. If missing or unreadable the portal logs a warning and uses a random key (sign-ins then do not survive restarts or move between replicas). Env override `PORTAL_SESSION_KEY_FILE`. |

## `query`

| Key | Default | Description |
| --- | --- | --- |
| `defaultLimit` / `maxLimit` / `maxSkip` | `20` / `200` / `100000` | Paging bounds. |
| `defaultMaxTime` / `maxMaxTime` | `10s` / `60s` | Server-side execution limit (sent as `maxTimeMS`). |
| `maxResponseBytes` | `8 MiB` | Results beyond this are truncated (flagged in the response). |
| `maxDocumentBytes` | `4 MiB` | Insert/replace size limit. |
| `maxCount` | `1000000` | Cap for `countDocuments`. |
| `allowWriteStages` | `false` | Permit `$out`/`$merge` (final stage only) for users whose RBAC role may create, update and delete documents in the target collection. `allowWriteStagesForSRE` is a deprecated alias. |

## `login`

| Key | Default | Description |
| --- | --- | --- |
| `attemptsPerWindow` / `window` | `10` / `5m` | Attempts per SSO user (per client address for MongoDB-only logins). |
| `failuresBeforeLock` / `lockDuration` / `maxLockDuration` | `5` / `5m` / `30m` | Lockout per (profile, auth DB, MongoDB user); doubles on repeat. Only server-confirmed authentication failures count. |
| `maxConcurrent` / `timeout` | `20` / `15s` | Concurrent login handshakes and per-login deadline. |

## `shell` (in-browser mongosh)

| Key | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Serve the shell API (`/api/v1/shell`). |
| `maxCursors` / `cursorIdleTimeout` | `20` / `10m` | Open server-side cursors per session; idle cursors are closed. |
| `maxCursorDocuments` | `100000` | Total documents one cursor may return. |
| `maxBatchDocuments` | `1000` | Documents per `find`/`aggregate`/`getMore` response (also bounded by `query.maxResponseBytes`). |
| `maxInsertDocuments` | `1000` | Maximum documents in `insertMany` / operations in `bulkWrite`. |
| `allowDropDatabase` | `false` | Permit `db.dropDatabase()` for users with `databases delete` (always confirmed by typing the name). |

## `profiles[]`

| Key | Default | Description |
| --- | --- | --- |
| `name` | — | DNS-label style identifier. |
| `displayName` / `description` | name / — | Shown on the login screen. Hosts are never shown. |
| `uri` | — | `mongodb://` or `mongodb+srv://` hosts and non-security options. Credentials and `tls*`/`ssl*`/`auth*` options are rejected. |
| `replicaSet` | — | Replica set name (or put `replicaSet=` in the URI). |
| `defaultAuthSource` | `admin` | Pre-filled authentication database. |
| `authMechanisms` | both SCRAM | Allowed: `SCRAM-SHA-256`, `SCRAM-SHA-1`. |
| `readPreference` | `primary` | |
| `connectTimeout` / `serverSelectionTimeout` / `operationTimeout` | `10s` / `10s` / `2m` | |
| `maxPoolSize` / `maxConnIdleTime` | `5` / `5m` | Per user session. |
| `plaintextApproved` / `securityExceptionRef` | `false` / — | Required to use `tls.mode: disabled` in production. |
| `tls.mode` | **required** | `enabled` or `disabled`. |
| `tls.verifyServerCertificate` | `true` | `false` is rejected. |
| `tls.caFile` | system roots | PEM bundle of the CA(s) that signed the MongoDB certificates. |
| `tls.useSystemRoots` | `false` | Also trust the image's system roots in addition to `caFile`. |
| `tls.clientCertFile` / `clientKeyFile` | — | Mutual TLS (both or neither). |
| `tls.minVersion` | `1.2` | `1.2` or `1.3`. |
| `tls.serverName` | — | Override the verified host name (rarely needed). |

### Examples

Existing non-TLS replica set (non-production):

```yaml
profiles:
  - name: primary
    uri: mongodb://mongo-0.mongo.db.svc:27017,mongo-1.mongo.db.svc:27017,mongo-2.mongo.db.svc:27017/
    replicaSet: rs0
    tls:
      mode: disabled
```

TLS with a corporate CA and client certificate:

```yaml
profiles:
  - name: primary-tls
    uri: mongodb://mongo-0.mongo.db.svc:27017,mongo-1.mongo.db.svc:27017/
    replicaSet: rs0
    tls:
      mode: enabled
      verifyServerCertificate: true
      caFile: /etc/mongo-portal/mongodb-ca/ca.crt
      clientCertFile: /etc/mongo-portal/mongodb-client/tls.crt
      clientKeyFile: /etc/mongo-portal/mongodb-client/tls.key
      minVersion: "1.2"
```

## Environment variables

| Variable | Purpose |
| --- | --- |
| `PORTAL_CONFIG` | Config path (alternative to `--config`). |
| `PORTAL_LISTEN_ADDRESS`, `PORTAL_OPS_LISTEN_ADDRESS`, `PORTAL_PUBLIC_ORIGIN`, `PORTAL_SESSION_KEY_FILE` | Overrides. |
| `PORTAL_LOG_LEVEL` | `debug`, `info` (default), `warn`, `error`. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` / `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | Enables tracing (standard OTel variables, including headers/TLS). An unusable exporter configuration is logged and tracing stays off. |
| `OTEL_SERVICE_NAME` | Defaults to `mongo-portal`. |
