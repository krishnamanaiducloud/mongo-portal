# MongoDB OIDC (MONGODB-OIDC)

With MONGODB-OIDC, users connect to MongoDB with their corporate identity
instead of a MongoDB password. The portal runs the OpenID Connect
authorization code flow (with PKCE) against the identity provider (IdP) that
the MongoDB deployment trusts, and hands the user's own access token to
MongoDB. MongoDB validates the token (signature, issuer, audience, expiry) and
maps it to a MongoDB user or roles.

SCRAM keeps working on the same deployment: a profile can offer both
mechanisms, and service accounts keep their passwords.

## How the flow works

1. The user selects a profile and chooses **Connect with … (MongoDB OIDC)**.
2. The portal redirects to the IdP: `client_id` and scopes of the profile,
   `code_challenge` (S256), `state` and `nonce`.
3. The IdP redirects back to `https://<portal>/oauth/mongodb/callback`. The
   portal checks the state, exchanges the code for an access token and a
   refresh token, and verifies the ID token (if one is returned) against the
   IdP's keys and the nonce.
4. The portal opens a MongoDB client for this user with the driver's OIDC
   callback. During authentication MongoDB tells the driver which IdP it
   trusts (issuer and client id). The portal **refuses to send the token**
   when these differ from the profile: a misconfigured profile can never hand
   a token to a server that expects another provider.
5. MongoDB accepts or rejects the token. On success the session's MongoDB
   user is the one MongoDB reports, for example `corp/<sub>` in `$external`.
6. When the access token expires, MongoDB asks the driver to authenticate
   again and the portal refreshes the token with the refresh token. Without a
   refresh token (no `offline_access` scope) the user connects again.

Tokens live only in the memory of the portal replica that holds the session.
They are never written to cookies, logs, the audit trail or the shared store.

The portal's own sign-in (OpenShift or another OIDC provider) is **not**
reused for MongoDB. When both use the same corporate IdP and the user already
has an IdP session, the second redirect completes without a prompt, so the
user sees one sign-in.

## Requirements

| Component | Requirement |
| --- | --- |
| MongoDB | Enterprise Advanced 7.0 or later, `authenticationMechanisms` including `MONGODB-OIDC`, an `oidcIdentityProviders` entry with `supportsHumanFlows: true` |
| Transport | TLS between the portal and MongoDB (bearer tokens); the configuration refuses MONGODB-OIDC without TLS in production |
| MongoDB to IdP | Every `mongod` must reach the IdP's discovery and JWKS URLs over HTTPS and trust their certificate |
| Portal to IdP | The portal pods must reach the IdP (443) and trust its certificate (`oidc.caFile` adds a CA) |
| IdP | A client registration for MongoDB human flows (below) |

## IAM prerequisites checklist

Give this list to the identity team. Do not assume the OpenShift or portal
sign-in client can be reused.

1. **Which IdP MongoDB trusts.** Use the issuer from the MongoDB resource
   (`issuerURI`) or `oidcIdentityProviders[].issuer`. The OpenShift OAuth
   server issues opaque tokens (`sha256~…`), not JWTs: MongoDB cannot use it.
   If OpenShift sign-in federates to a corporate IdP (`oc get oauth cluster
   -o yaml`, `identityProviders[].openID.issuer`), that corporate IdP may be
   the same one MongoDB trusts. Compare the issuer URLs exactly (trailing
   slashes matter).
2. **A client for MongoDB human flows** (separate from the portal's
   sign-in client is recommended):
   - client id = MongoDB's `clientId`;
   - public client with PKCE (S256), or a confidential client whose secret
     is mounted for the portal (`oidc.clientSecretFile`);
   - grant types: authorization code and refresh token;
   - redirect URIs: `https://<portal-route-host>/oauth/mongodb/callback`
     (and, for mongosh or Compass on workstations, their documented
     loopback redirect).
3. **Audience.** The access token's `aud` must equal MongoDB's `audience`.
   Some IdPs only put an API audience in tokens requested for that API's
   scope (for example Microsoft Entra ID: request `api://<app-id>/<scope>` and
   set `requestScopes` and the profile's `scopes` to it).
4. **Scopes.** `openid`, the audience scope if required, and
   `offline_access` for refresh tokens (otherwise users reconnect when the
   access token expires).
5. **Principal claim.** MongoDB's `principalName` / `userClaim` (default
   `sub`) must be stable per person. Entra ID's `sub` is pairwise per
   application; prefer `oid` there, and create the MongoDB users accordingly.
6. **Authorization.** With `authorizationType: UserID` (no authorization
   claim), create one `$external` user per person, named
   `<authNamePrefix>/<claim value>`. With `GroupMembership`, the token needs a
   groups claim and MongoDB roles are named `<authNamePrefix>/<group>`.
7. **Token lifetime.** Access tokens of 5–60 minutes work; refresh tokens
   set how long a portal session can last without a new sign-in (the portal
   also ends sessions after `session.absoluteTimeout`).
8. **Network.** Egress from the MongoDB namespace to the IdP's JWKS URL;
   egress from the portal namespace to the IdP (the portal's NetworkPolicy
   allows 443).

## Validate the existing deployment (read-only)

```bash
# Operator and CRD version; the OIDC fields the installed CRD accepts
oc get csv -n <operator-namespace>
oc explain mongodb.spec.security.authentication --recursive | grep -i -A3 oidc

# The declared configuration (no secrets in this part of the spec)
oc get mongodb <name> -n <mongodb-namespace> -o jsonpath='{.spec.security.authentication}' | jq .

# What the running server actually uses (needs a user allowed to run getParameter)
mongosh "<uri>" --tls --tlsCAFile ca.pem -u <admin> --authenticationDatabase admin --eval '
  printjson(db.adminCommand({getParameter: 1, authenticationMechanisms: 1, oidcIdentityProviders: 1}))'
```

The declared YAML and the running server can differ (operator reconciliation
pending or failed). Trust `getParameter`. In the server log, JWKS fetch
failures name the issuer; fix network or trust before enabling users.

With the MongoDB Enterprise Kubernetes Operator the configuration looks like
this (check the field names against `oc explain` for your operator version):

```yaml
spec:
  security:
    tls:
      enabled: true
    authentication:
      enabled: true
      modes: ["SCRAM", "OIDC"]          # keep SCRAM for existing clients
      oidcProviderConfigs:
        - configurationName: corp        # becomes the authNamePrefix
          issuerURI: https://login.example.com/
          audience: mongodb-prod
          clientId: mongodb-human-flows
          userClaim: sub
          authorizationMethod: WorkforceIdentityFederation
          authorizationType: UserID
          requestedScopes: ["offline_access"]
```

Changing this resource changes authentication on the running database. It is
not done by the portal and needs a change approval.

## Configure the portal profile

```yaml
profiles:
  - name: prod
    uri: mongodb://db-0.db-svc.mongodb.svc:27017,db-1.db-svc.mongodb.svc:27017,db-2.db-svc.mongodb.svc:27017/
    replicaSet: db
    authMechanisms: [SCRAM-SHA-256, MONGODB-OIDC]
    tls:
      mode: enabled
      caFile: /etc/mongo-portal/mongodb-ca/ca.crt
    oidc:
      issuer: https://login.example.com/        # = issuerURI / oidcIdentityProviders[].issuer
      clientID: mongodb-human-flows             # = clientId
      scopes: [openid, offline_access]          # plus an audience scope if the IdP needs one
      # clientSecretFile: /etc/mongo-portal/oidc/mongodb-client-secret
      # caFile: /etc/mongo-portal/oidc/idp-ca.crt
      # allowedHosts: [db-0.db-svc.mongodb.svc]  # default: the URI hosts
```

`allowedHosts` limits where the driver may send tokens (default: the hosts of
the URI). The login page shows the OIDC button for profiles that offer it,
and hides the password form for profiles that offer only MONGODB-OIDC.

## Errors and what they mean

| Shown to the user | Cause | Fix |
| --- | --- | --- |
| MongoDB and this profile disagree about the identity provider | The server's issuer or client id differs from the profile | Align `profiles[].oidc` with the server |
| MongoDB rejected your OIDC identity | Valid token, but no `$external` user or role for this identity, or the audience/issuer is wrong on the server | Create the user or role; check the server log |
| MONGODB-OIDC is not enabled on the server | `authenticationMechanisms` lacks MONGODB-OIDC | Server configuration |
| The identity provider of this deployment is not reachable | Portal cannot reach discovery or token endpoints | Egress, DNS, CA |
| Your OIDC sign-in for MongoDB has expired | No refresh token, or it was revoked | Connect again; request `offline_access` |

Every attempt is audited as `mongodb_login` with method `mongodb-oidc`.

## Migration plan

1. **Verify** (read-only, above): server version, effective mechanisms, IdP
   reachability from the MongoDB pods.
2. **Enable OIDC alongside SCRAM** on the server (`modes: [SCRAM, OIDC]`).
   Existing SCRAM clients are not affected.
3. **Pilot users:** create their `$external` users (or group roles); add
   MONGODB-OIDC to the profile's `authMechanisms` with the `oidc` block. The
   password form stays available.
4. **Broaden** by group. Keep SCRAM for service accounts and break-glass
   users.
5. **Optionally** make the profile OIDC-only (`authMechanisms:
   [MONGODB-OIDC]`) once every person has an `$external` identity.

## Rollback

- **Portal:** remove MONGODB-OIDC from `authMechanisms` and the `oidc` block,
  then roll the Deployment. Existing OIDC sessions end at the restart; SCRAM
  logins are unchanged.
- **Server:** remove OIDC from the authentication modes (change approval).
  SCRAM users are unaffected; `$external` users can stay defined.

## Workload identity

User sessions never use a shared identity. The machine (workload) OIDC flow
is not used for user operations. The shared store connection (audit trail,
session registry) uses its own least-privilege SCRAM or X.509 account.

## Tested

`test/oidc/run.sh` starts MongoDB Enterprise with SCRAM and MONGODB-OIDC and
a test IdP, then runs the full browser flow through the portal: successful
connection as `testidp/<sub>`, MongoDB-enforced read-only privileges, token
expiry with refresh, an unknown identity refused by MongoDB, a client id
mismatch refused before the token is sent, and SCRAM on the same server.
MongoDB Enterprise is used there for development testing only.
