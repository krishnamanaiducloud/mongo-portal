# Organization configuration

The portal is deployed by configuration alone: no organization's names,
domains, hosts, identity providers, namespaces or registry accounts are built
into the code, the images or the chart. This page lists what each
organization provides, who provides it, and how to check it. All examples use
placeholders (`${NAME}`); see [configuration.md](configuration.md#placeholders)
for how the portal resolves them.

## Two authentication layers

```
            Layer A: who may use the portal                 Layer B: what MongoDB lets the user do
browser ─▶ OpenShift OAuth  or  OIDC sign-in  ─▶ portal ─▶ MONGODB-OIDC (user's own token)  or  SCRAM (user's own password) ─▶ MongoDB
            (portal RBAC roles from groups)                  (MongoDB roles of that user)
```

- **Layer A** identifies the person and gives portal roles (RBAC). It never
  grants database access by itself.
- **Layer B** authenticates the person to MongoDB with their own MongoDB
  identity. The portal never uses a shared privileged account for users.
- With MONGODB-OIDC and `autoConnect`, both layers complete with one
  corporate sign-in when OpenShift (or the portal's OIDC sign-in) and MongoDB
  trust the same identity provider; see [mongodb-oidc.md](mongodb-oidc.md).
  With SCRAM, the second step is an explicit, labelled credentials form.

## Responsibilities

| Team | Provides |
| --- | --- |
| OpenShift administrator | namespace, the optional dedicated SCC and its use binding, Route host or ingress, OAuth identity providers of the cluster, egress to MongoDB and the IdP, user-workload monitoring |
| Identity-provider administrator | client registrations (portal sign-in; MongoDB human flows), redirect URIs, groups/roles claims, JWT access tokens with MongoDB's audience, `prompt=none` without consent prompts |
| MongoDB administrator | hosts and replica set name, CA bundle, MongoDB users or `$external` identities and roles, the `oidcIdentityProviders` server setting, the store account (readWrite on its database) |
| Application administrator | portal configuration and RBAC policy, image digest, Helm values or overlays, rollout and rollback |
| Security team | approval of non-TLS exceptions, retention of audit data, review of the VEX statement and scan results, secret management |
| Network team | DNS, firewall and NetworkPolicy paths: portal → MongoDB (27017), portal → IdP and API server (443/6443), MongoDB → IdP JWKS (443), router → portal (8443) |

## Configuration keys

Secret values are always files from mounted Secrets (`*File` keys); the
configuration and the chart values hold only their paths and names.

| Key | Description | Required | Default | Example placeholder | Secret | Team | Validation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `image.repository` / `image.digest` (chart) | image source and immutable digest | yes | — | `${PORTAL_IMAGE_REPOSITORY}` / `${PORTAL_IMAGE_DIGEST}` | no | application | `helm template`; preflight script compares the running image |
| `platform` (chart) | `openshift` or `kubernetes` | yes | `openshift` | — | no | application | `helm lint` (schema) |
| `server.publicOrigin` | external URL; fixes OAuth redirect URIs and the allowed Origin | production | — | `${PORTAL_PUBLIC_URL}` | no | application | preflight `public origin` |
| `route.host` / `ingress.host` (chart) | external host name | no (Route: cluster assigns) | — | `${PORTAL_ROUTE_HOST}` | no | OpenShift | preflight script `route` |
| `identity.openshift.enabled` | built-in OpenShift login | no | `auto` | — | no | OpenShift | preflight `OpenShift OAuth` |
| `identity.oidc.providers[].issuer` / `clientID` | corporate OIDC sign-in | for OIDC sign-in | — | `${ORG_OIDC_ISSUER_URL}` / `${PORTAL_OIDC_CLIENT_ID}` | no | IdP | preflight `OIDC provider` |
| `identity.oidc.providers[].clientSecretFile` | confidential client secret | confidential clients | — | `/etc/mongo-portal/oidc/<file>` from Secret `mongo-portal-oidc` | **yes** | IdP / security | sign-in test |
| `identity.oidc.providers[].groupsClaim` / `requiredGroups` | groups for RBAC; admission | no | `groups` / — | `${ORG_GROUPS_CLAIM}` | no | IdP | `/permissions` page after sign-in |
| `identity.requireSSO` | refuse MongoDB-only logins | recommended in production | `false` | — | no | security | login page |
| RBAC policy (`rbac.policy`, chart `rbacPolicy.policy`) | groups → portal roles | yes (in practice) | built-in roles, default `role:mongodb` | `g, ${PORTAL_ADMIN_GROUP}, role:admin` | no | application / security | System status → RBAC; `/permissions` |
| `session.keyFile` | key shared by replicas (≥ 32 bytes) | with more than one replica | random per pod | Secret `mongo-portal-session`, key `session-key` | **yes** | security | preflight `session key` (length only) |
| `session.idleTimeout` / `absoluteTimeout` | session lifetimes | no | `15m` / `8h` | `${SESSION_IDLE_TIMEOUT:-15m}` | no | security | `--check-config` |
| `session.registry` | sessions of every replica visible and revocable | multi-replica recommended | `false` | — | no | application | Sessions page shows all replicas |
| `store.*` (`enabled`, `profile`, `database`, `usernameFile`, `passwordFile`) | shared state (audit, registry, cache sync) | for durable audit and multi-replica features | disabled | Secret `mongo-portal-store` (`username`, `password`) | **yes** (credentials) | MongoDB | preflight `shared store` (privileges, nothing written) |
| `audit.persist` / `retention` | durable audit with TTL | recommended | `false` / keep | `${AUDIT_RETENTION:-2160h}` | no | security | Audit page "durable"; chain verification |
| `profiles[].uri` / `replicaSet` | MongoDB hosts (no credentials, no TLS options) | yes | — | `mongodb://${MONGODB_HOSTS}/` / `${MONGODB_REPLICA_SET}` | no | MongoDB | preflight `DNS`, `TCP`, `MongoDB topology` |
| `profiles[].tls.mode` / `caFile` | TLS and the CA that signed MongoDB's certificates | yes (mode) | — | `enabled`; ConfigMap `mongo-portal-mongodb-ca` (`ca.crt`) | no (CA is public) | MongoDB | preflight `TLS` (verification, host name, expiry) |
| `profiles[].tls.clientCertFile` / `clientKeyFile` | mutual TLS | if MongoDB requires client certificates | — | Secret `mongo-portal-mongodb-client` | **yes** | MongoDB / security | preflight `client certificate` |
| `profiles[].plaintextApproved` / `securityExceptionRef` | explicit non-TLS exception | only for `tls.mode: disabled` in production | `false` | `${SECURITY_EXCEPTION_ID}` | no | security | `--check-config` refuses otherwise |
| `profiles[].authMechanisms` | offered mechanisms; the password form is shown only for SCRAM mechanisms | no | both SCRAM | `[SCRAM-SHA-256, MONGODB-OIDC]` | no | MongoDB | login page |
| `profiles[].oidc.issuer` / `clientID` | the IdP MongoDB trusts | for MONGODB-OIDC | — | `${MONGODB_OIDC_ISSUER_URL}` / `${MONGODB_OIDC_CLIENT_ID}` | no | MongoDB / IdP | preflight `MONGODB-OIDC server` (compares with what the server announces) |
| `profiles[].oidc.audience` | audience MongoDB expects | recommended | — | `${MONGODB_OIDC_AUDIENCE}` | no | IdP | precise `token_audience_mismatch` at sign-in |
| `profiles[].oidc.scopes` / `authParams` | scopes (`offline_access` for refresh) and extra parameters | no | `[openid]` | `[openid, offline_access, ${MONGODB_OIDC_SCOPE}]` | no | IdP | sign-in test |
| `profiles[].oidc.autoConnect` / `interactiveFallback` | connect SSO users without a second sign-in | no | `false` / `true` | — | no | application | acceptance test below |
| `profiles[].oidc.clientSecretFile` | confidential MongoDB client | if the client is confidential | — | Secret `mongo-portal-oidc` | **yes** | IdP / security | sign-in test |
| `monitoring.slowOperation` / `slowOperationIgnoreApps` / `thresholds.*` | alerting thresholds | no | see [configuration.md](configuration.md) | `${SLOW_OPERATION:-5s}` | no | MongoDB / SRE | Monitoring page |
| `telemetry.tracing.endpoint` / `caFile` / `headersFile` | OTLP export | no | off | `${OTEL_COLLECTOR_URL}`; headers from a Secret | headers: **yes** | SRE | System status → tracing |
| `cache.syncInterval` | cross-replica cache invalidation | no | `10s` | — | no | application | Caches page "applied on" |
| `networkPolicy.egress.mongodb` (chart) | allowed MongoDB destinations | yes when NetworkPolicy is on | none | namespace `${MONGODB_NAMESPACE}`, labels or `${MONGODB_CIDR}` | no | network | preflight `TCP` from inside the pod |
| `openshift.requiredSCC` (chart) | admit only under the dedicated SCC | recommended on OpenShift | — | `mongo-portal-restricted` | no | OpenShift | preflight script `SCC` |

## Setup procedures

Each procedure ends with a check. Run `mongo-portal preflight` (or
`helm test`) after every change.

### 1. OpenShift OAuth only

1. Deploy with `platform: openshift`, `route.enabled: true` (the chart sets
   the service account's OAuth redirect reference to the Route).
2. Map OpenShift groups to roles in the RBAC policy.
3. Check: the login page offers **Log in with OpenShift**; after sign-in
   `/permissions` shows the expected roles; preflight `OpenShift OAuth` passes.

### 2. Generic enterprise OIDC sign-in

1. IdP: register a client with redirect URI
   `https://${PORTAL_HOST}/oauth/oidc/<name>/callback`, groups (or roles)
   claim, PKCE; confidential clients get a Secret `mongo-portal-oidc`.
2. Configure `identity.oidc.providers[]` (issuer, clientID, groupsClaim,
   optional `requiredGroups`), see [oidc.md](oidc.md).
3. Check: preflight `OIDC provider` passes; sign-in works; `/permissions`
   shows the groups.

### 3. MongoDB SCRAM

1. MongoDB administrator: one MongoDB user per person (or per team) with the
   intended roles ([mongodb-rbac.md](mongodb-rbac.md)).
2. Profile with `authMechanisms: [SCRAM-SHA-256]` (default includes SCRAM-SHA-1
   for legacy users).
3. Check: the login page shows the credentials form with "Database sign-in is
   separate from portal sign-in"; a read-only user cannot write.

### 4. MongoDB OIDC federation

1. Follow the IAM checklist in [mongodb-oidc.md](mongodb-oidc.md).
2. MongoDB administrator enables MONGODB-OIDC alongside SCRAM (change
   approval; the portal never changes the server).
3. Profile: `authMechanisms: [SCRAM-SHA-256, MONGODB-OIDC]`, `oidc.issuer`,
   `clientID`, `audience`, `scopes: [openid, offline_access]`, and
   `autoConnect: true` when OpenShift/portal sign-in uses the same IdP.
4. Check: preflight `MONGODB-OIDC server` passes (the server announces the
   same issuer and client id); then the acceptance test below.

### 5. TLS-enabled MongoDB

1. ConfigMap `mongo-portal-mongodb-ca` with `ca.crt`; Secret
   `mongo-portal-mongodb-client` if MongoDB requires client certificates.
2. `tls.mode: enabled`, `caFile`, optional `clientCertFile`/`clientKeyFile`.
   Verification cannot be disabled.
3. Check: preflight `TLS` shows "verified", the expected issuer and expiry.

### 6. Non-TLS development environments (explicit only)

1. `tls.mode: disabled`. In production additionally `plaintextApproved: true`
   and `securityExceptionRef` (the approval id); otherwise startup fails.
2. The UI marks such profiles "Unencrypted" and shows a banner in every
   session. There is no automatic downgrade from TLS to plaintext.

### 7. Several replicas

1. Secret `mongo-portal-session` (`session-key`, ≥ 32 random bytes), the
   same for all replicas.
2. Shared store (below) with `session.registry: true`.
3. Route/ingress cookie affinity (set by the chart) keeps a browser on its
   replica. MongoDB connections live in the replica that opened them: when a
   replica stops, its users reconnect (silently with MONGODB-OIDC
   `autoConnect`).
4. Check: Sessions page lists sessions of all replicas; Caches page shows
   invalidations applied on every replica.

### 8. Audit persistence

1. MongoDB administrator: a store account with readWrite on the store
   database only; Secret `mongo-portal-store` (`username`, `password`).
2. `store.enabled: true` (profile, database), `audit.persist: true`,
   `audit.retention` per policy.
3. Check: preflight `shared store` passes; the Audit page says "durable";
   **Verify chain** reports intact.

## Acceptance test (with the organization's real configuration)

The decisive end-to-end test cannot run without the organization's cluster,
identity provider and MongoDB deployment. Run it in a non-production
environment and keep the evidence:

| Step | Expected | Evidence |
| --- | --- | --- |
| 1. Open the portal, **Log in with OpenShift** | corporate IdP sign-in (federated by OpenShift) | browser |
| 2. Back at the portal | "Connecting to <profile>…" then the dashboard; **no** MongoDB password and no second sign-in | browser; audit `mongodb_login` method `mongodb-oidc`, outcome success |
| 3. Session page | MongoDB user `<authNamePrefix>/<claim>` in `$external`, mechanism MONGODB-OIDC | screenshot |
| 4. Read a permitted collection; try a write the MongoDB role does not allow | read works; write refused by MongoDB (403 `mongo_unauthorized`) | audit entries |
| 5. Wait past the access token lifetime, then read again | still works (refresh) | no new sign-in |
| 6. A user without a MongoDB identity | "MongoDB rejected your OIDC identity" | audit failure |
| 7. Restart a portal pod holding a session | the user is reconnected silently | audit: a new `mongodb_login` |

Until this has passed, record MONGODB-OIDC single sign-on as *implemented,
tested against MongoDB Enterprise with a test IdP, not live-validated*.

## Controlled rollout and rollback

Before deploying:

```bash
oc -n ${K8S_NAMESPACE} get deploy -l app.kubernetes.io/name=mongo-portal -o jsonpath='{..image}'   # current (rollback) image
helm -n ${K8S_NAMESPACE} history ${PORTAL_RELEASE}                                                  # Helm revisions
K8S_NAMESPACE=${K8S_NAMESPACE} scripts/preflight-openshift.sh                                       # read-only baseline
```

1. Deploy to a non-production namespace first with the new digest:
   `helm upgrade --install ${PORTAL_RELEASE} charts/mongo-portal -n ${K8S_NAMESPACE} -f values-${ENV}.yaml --set image.digest=${PORTAL_IMAGE_DIGEST}`
   (or update the Kustomize overlay digest and sync in Argo CD).
2. `helm test ${PORTAL_RELEASE} --logs` and the preflight script; then the
   relevant parts of the acceptance test.
3. Production: the same values with the production file; the rolling update
   keeps a ready replica (`maxUnavailable: 0`, PDB). Users of a replica that
   is replaced reconnect.

Rollback (no MongoDB change is involved):

```bash
helm -n ${K8S_NAMESPACE} rollback ${PORTAL_RELEASE} <previous-revision>      # Helm
# or set the previous digest in the overlay and sync (GitOps), or:
oc -n ${K8S_NAMESPACE} rollout undo deploy/<portal-deployment>
```

The portal never modifies MongoDB workloads, replica set configuration, Ops
Manager, PVCs or MongoDB users; neither deployment nor rollback restarts a
database pod. Configuration-only changes (RBAC policy) apply without a
restart.
