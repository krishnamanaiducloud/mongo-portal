# OpenShift login (single sign-on)

The portal has a built-in OpenShift login that works like Argo CD's OpenShift
connector. No OAuth proxy sidecar is needed.

## Passive by design

OpenShift login is **optional**. It is offered when it can work, and it is
silently left out when it cannot:

| Situation | What users see |
| --- | --- |
| Portal runs in OpenShift and the OAuth server is reachable | **Log in with OpenShift** button, then the MongoDB login |
| OAuth server or API server unreachable (network policy, outage) | MongoDB login only, with a short note. No error page |
| Not running in OpenShift (no service account token, plain Kubernetes, local run) | MongoDB login only; OpenShift is not mentioned |
| `identity.openshift.enabled: "false"` | MongoDB login only |

The portal checks availability in the background: every minute while the
server is unavailable, every five minutes while it is healthy, and once more
when someone clicks the button. The **System status** page, `GET /api/v1/status`
and one log line per state change show the current state and the reason.

To make SSO mandatory, set `identity.requireSSO: true`. MongoDB-only logins are
then refused, and while OpenShift is unavailable nobody can sign in.

## How it works

```
browser ──▶ Route (re-encrypt) ──▶ portal :8443 (service-CA certificate)
   │ 1. GET /oauth/start          → 302 to the OpenShift OAuth server (your IdP)
   │ 2. user signs in; OAuth server redirects to /oauth/callback?code&state
   │ 3. portal checks state, exchanges code+PKCE verifier at the token endpoint
   │    (client = the portal service account), then GET users/~ with the user's
   │    token → user name and groups
   │ 4. encrypted __Host-mongo_portal_sso cookie (HttpOnly, Secure, SameSite=Strict)
   ▼
MongoDB login with the user's own credentials → database pages
```

* **OAuth client:** the portal ServiceAccount (`system:serviceaccount:<ns>:mongo-portal`).
  Its secret is the mounted service account token, re-read for every
  exchange because projected tokens rotate.
* **Redirect URI:** the annotation
  `serviceaccounts.openshift.io/oauth-redirectreference.primary` on the
  ServiceAccount references the Route. The OAuth server accepts only redirect URIs
  on that host, so a forged `Host` header cannot redirect authorization codes.
  The callback is `https://<route-host>/oauth/callback`, or uses
  `server.publicOrigin` when that is set.
* **Scope:** `user:info` only. The token can read the user's identity and nothing else.
* **Groups:** `GET /apis/user.openshift.io/v1/users/~` returns the user's
  OpenShift groups. This is the same source as Argo CD's connector. The service
  account has **no** RBAC permissions; the old group-reader ClusterRole is gone.
* **State and PKCE:** the state, the PKCE verifier (S256) and the return path are
  sealed (AES-256-GCM) in a short-lived `__Host-mongo_portal_oauth` cookie
  (SameSite=Lax, 10 minutes, single use). Any replica that shares
  `session.keyFile` can finish the login.
* **SSO cookie:** contains the user name, the groups the RBAC policy refers to
  and the access token, encrypted with a key derived from `session.keyFile`.
  The browser cannot read or forge it. It expires with the token, or after
  `session.absoluteTimeout`.
* **Revalidation:** every `identity.openshift.revalidateInterval` (5 minutes) the
  token is checked again with `users/~`, which picks up group changes and revoked
  tokens. If the API server is unreachable, the sign-in stays valid for
  `maxStale` (1 hour) and then ends.
* **TLS:** the API server and the OAuth server are verified against the service
  account CA bundle (which in OpenShift includes the default ingress CA), the
  system roots, and `extraCAFiles`. Verification is never disabled.
* **Client authentication:** HTTP Basic with form-encoded credentials (RFC 6749
  §2.3.1). If the server rejects that, the portal retries with the credentials
  in the request body.

## Groups and roles

Groups map to portal roles in the RBAC policy ([rbac.md](rbac.md)), exactly
like Argo CD's `argocd-rbac-cm`:

```csv
g, mongo-portal-sre-prod, role:admin
g, mongo-portal-developers-prod, role:mongodb    # their MongoDB privileges decide
```

```bash
oc adm groups new mongo-portal-sre-prod
oc adm groups add-users mongo-portal-sre-prod alice
# or sync from LDAP: oc adm groups sync --sync-config=ldap-sync.yaml --confirm
```

Group changes take effect at the next revalidation (5 minutes at most).

## Without OpenShift

Users sign in with their MongoDB credentials, and the MongoDB user becomes the
RBAC subject `mongodb:<user>@<authSource>`. The default role applies unless the
policy maps that user, so SREs keep their access during an OpenShift outage:

```csv
g, mongodb:sre-alice@admin, role:admin
```

## Other SSO sources

* `identity.header.enabled: true`: trusts `X-Forwarded-User` /
  `X-Forwarded-Groups` from a generic authenticating proxy (for example
  oauth2-proxy), but only from `identity.trustedProxyCIDRs`. Headers from any
  other peer are ignored.
* `identity.dev`: a fixed identity for local development only. It needs
  `PORTAL_ALLOW_INSECURE_DEV_IDENTITY=true` and is refused in production.

## Sign-out

* **Disconnect from MongoDB** ends the MongoDB session. The OpenShift sign-in
  remains.
* **Sign out** (`POST /api/v1/auth/logout`) ends both for this browser. If
  `identity.ssoLogoutURL` is set (for example your IdP's logout endpoint), the
  browser goes there afterwards.

## Checks and troubleshooting

```bash
# The OAuth server the portal uses (no authentication needed); debug image:
oc rsh deploy/mongo-portal curl -s https://kubernetes.default.svc/.well-known/oauth-authorization-server
oc get sa mongo-portal -o jsonpath='{.metadata.annotations}'        # redirect reference present?
oc logs deploy/mongo-portal | grep -i 'openshift login'              # state changes and reasons
```

| Symptom | Cause / fix |
| --- | --- |
| No OpenShift button; status says "API server is not reachable" | Egress NetworkPolicy blocks 443/6443 to the API, or the pod has no token (`automountServiceAccountToken`) |
| Status says "OAuth server … not reachable" | Egress to the ingress router (443) is blocked. Allow it, or check `HTTPS_PROXY`/`NO_PROXY` |
| `x509: certificate signed by unknown authority` in the reason | The ingress certificate is from a CA outside the service account bundle. Add it with `identity.openshift.extraCAFiles` |
| Login returns "did not complete" | The redirect URI does not match the Route (check the ServiceAccount annotation and `server.publicOrigin`), or the clock is skewed |
| Login works, but the user has only the default role | The user's group is not in the policy, or the group name differs (`oc get groups`) |
