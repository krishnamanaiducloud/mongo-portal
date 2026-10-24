# OpenID Connect sign-in

Besides the built-in OpenShift login ([oauth.md](oauth.md)), the portal can
sign users in with any OpenID Connect provider: Microsoft Entra ID, Okta,
Keycloak, Ping, Auth0 or a corporate provider. SAML 2.0 and LDAP / Active
Directory directories are supported through a broker that speaks OIDC to the
portal (Keycloak, Dex, ADFS, Entra ID): the portal does not implement SAML or
LDAP itself.

Portal sign-in decides **who** the user is (and their groups for RBAC). It
does not give MongoDB access: users still connect to MongoDB with their own
credentials or with [MONGODB-OIDC](mongodb-oidc.md).

## What the portal checks

- Authorization code flow with PKCE (S256), `state` (in a sealed, short-lived
  cookie) and `nonce`.
- The discovery document's issuer must equal the configured issuer exactly.
- ID token: signature against the provider's JWKS, issuer, audience (the
  client id), authorized party when there are several audiences, expiry, and
  the nonce.
- Optional `requiredGroups`: only members of these groups may sign in.

Tokens are not stored: the portal keeps a sealed cookie with the user name,
the groups the RBAC policy uses and an expiry (`sessionMaxAge`, default
`session.absoluteTimeout`).

Providers are passive like OpenShift login: when discovery fails the button
is replaced by a short "not available" note and every other sign-in method
keeps working. With `identity.requireSSO: true` MongoDB-only login is refused
and users wait for a provider instead.

## Configuration

```yaml
server:
  publicOrigin: https://mongo-portal.apps.example.com     # fixes the redirect URI
identity:
  oidc:
    providers:
      - name: corp                       # URL and RBAC name: idp:corp
        displayName: Corporate SSO
        issuer: https://login.example.com/
        clientID: mongo-portal
        clientSecretFile: /etc/mongo-portal/oidc/corp-client-secret   # omit for a public client
        scopes: [openid, profile, email]
        usernameClaim: preferred_username   # then email, then sub
        groupsClaim: groups
        requiredGroups: []                  # optional allow list
        sessionMaxAge: 8h
        logoutRedirect: true                # end_session_endpoint on sign-out
        # caFile: /etc/mongo-portal/oidc/idp-ca.crt
```

Register the redirect URI `https://<route-host>/oauth/oidc/<name>/callback`
at the provider. Mount client secrets as files (Secret `mongo-portal-oidc`,
mounted at `/etc/mongo-portal/oidc`).

## RBAC subjects

An OIDC user matches `<user>`, `user:<user>`, each group as `<group>` and
`group:<group>`, and `idp:<provider>` (every user of that provider):

```csv
g, mongo-dbas, role:dbadmin
g, idp:corp, role:readonly
```

Session ownership is qualified by provider, so the same user name at two
providers is two principals.

## Provider notes

| Provider | Notes |
| --- | --- |
| Microsoft Entra ID | Issuer `https://login.microsoftonline.com/<tenant>/v2.0`. Groups arrive as object ids unless the app sends group names or app roles; large group sets are sent as an overage claim the portal does not resolve, so use app roles (`groupsClaim: roles`). |
| Okta | Add a groups claim to the ID token in the authorization server; issuer is the authorization server URL. |
| Keycloak | Issuer `https://<host>/realms/<realm>`; add a "groups" mapper to the client. Keycloak can broker SAML and LDAP/AD. |
| ADFS | OIDC application group; issuer `https://<host>/adfs`. |

## Errors on the login page

| Reason | Meaning |
| --- | --- |
| issuer_mismatch | The provider announces a different issuer than configured |
| audience_mismatch | The ID token was issued for another client |
| token_expired | Clock skew between the portal and the provider, or a stale token |
| not_in_group | `requiredGroups` excludes the user |
| unavailable | Discovery or the token endpoint cannot be reached |

Every sign-in and failure is audited as `sso_login` with the provider name.
