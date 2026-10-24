# Sessions

A portal session is one authenticated MongoDB client for one user. It holds
the user's MongoDB credential (password, or OIDC tokens) in the memory of
the replica that created it, because the driver needs it to authenticate new
connections (for example after a failover). Credentials are never written to
disk, cookies, the shared store or logs.

| Property | Behaviour |
| --- | --- |
| Cookie | `__Host-mongo_portal_session`: `HttpOnly`, `Secure`, `SameSite=Strict`; a random 256-bit secret, stored only as a hash |
| Rotation | A new secret on every login; any previous session of the browser is destroyed |
| CSRF | A per-session token in the `X-CSRF-Token` header for every change |
| Idle timeout | `session.idleTimeout` (15 min); status and identity checks do not count as activity (an open Monitoring or Operations page with auto-refresh does) |
| Absolute timeout | `session.absoluteTimeout` (8 h) |
| Limits | `maxPerUser` (oldest sessions are closed), `maxTotal` per replica |
| Ownership | A session is bound to the principal that created it; a cookie used by another principal destroys the session |

## Several replicas

Sessions cannot move between replicas without sharing credentials, which
the portal never does. The Route keeps each browser on one replica with a
cookie (OpenShift default). When a replica stops, its users connect to
MongoDB again; single sign-on is not affected (the SSO cookie is sealed with
the shared session key).

With the **session registry** (`session.registry: true`, needs `store`),
every replica publishes session metadata (user, MongoDB user, profile,
method, client, replica, created, last activity, expiry; no credentials) to
the store every `session.registrySyncInterval` (10 s):

- **My session** lists the user's sessions on every replica;
- **Sessions** (`sessions get all`, role:auditor and above) lists everyone's;
- **Revoke** (`sessions delete all`, role:platform-admin and above) closes
  one session or every session of a user. The holding replica closes it at
  its next sync. Revocations are audited.

Revoking a session ends the user's MongoDB connection. It does not end their
single sign-on at the identity provider; remove access there (or in the
RBAC policy) to keep a user out.

| Strategy | Trade-off |
| --- | --- |
| Per-replica sessions (default) | Simple, nothing shared; administrators see one replica |
| Registry in the store (recommended for several replicas) | Inventory and revocation everywhere; needs the store; still re-login when a replica goes away |
| Shared credentials (not offered) | Survives pod loss, but stores reusable passwords centrally: rejected |
