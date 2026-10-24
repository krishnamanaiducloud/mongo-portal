# Caches

The portal keeps a few small caches of its own. They are never MongoDB's
cache (WiredTiger) or storage: refreshing them never deletes data, never
touches MongoDB, and never affects PVCs.

## What is cached

| Cache | Holds | Normally refreshed | Invalidating |
| --- | --- | --- | --- |
| `identities` | OpenShift token reviews (30 s) and the groups carried in sign-in cookies | every `identity.openshift.revalidateInterval` (5 min) | every OpenShift sign-in re-checks its token and groups on its next request (for example after a group change) |
| `sign-in-providers` | discovery documents and signing keys of OpenShift OAuth and OIDC providers | while unavailable every `probeInterval`, otherwise 5× less often | checks every provider now |
| `mongodb-oidc-providers` | discovery of the identity providers the MongoDB deployments trust | after 10 minutes | discovered again at the next connection |
| `rbac-policy` | the policy from the configuration and the RBAC ConfigMap | every `rbac.reloadInterval` (30 s) | re-read now; an invalid policy is rejected and the previous one stays active |
| `profile-health` | reachability of each profile (login page) | every `monitoring.profileHealthInterval` | every profile is checked now |

Each replica has its own copy.

## Administrators: the Caches page

**Caches** (navigation, for roles with `cache get`) shows each cache on the
replica serving the page: entries, last refresh and the last error. With
`cache delete` you can invalidate selected caches:

- **All replicas** (needs `store.enabled`): applied on this replica at once
  and published to the shared store; every other replica applies it within
  `cache.syncInterval` (10 s) and records its result. The page lists recent
  invalidations with the replicas that applied them and any errors.
- **This replica**: applied only here.

Invalidation needs a typed confirmation and is audited as `cache_invalidate`
(who, which caches, scope, errors). Built-in roles: `role:platform-admin`
and `role:admin` may view and invalidate; others may not.

API: `GET /api/v1/admin/caches`, `POST /api/v1/admin/caches/invalidate`
`{"caches": [...], "scope": "all"|"replica", "confirm": "invalidate"}`.

## Everyone: Refresh & connection

The refresh button in the header (also in the user menu) offers, for the
current user and browser only:

| Action | Effect |
| --- | --- |
| Refresh portal data | reloads everything shown from the server |
| Refresh database list | discovers databases and collections again |
| Refresh connection status | re-reads sign-in, MongoDB session and profile health |
| Reconnect to MongoDB | ends the MongoDB session and connects again (silently with MONGODB-OIDC, otherwise with the credentials form) |
| Clear personal UI data | forgets recent namespaces and the last profile in this browser; saved shell snippets only when ticked; the theme is kept |

The browser keeps no credentials, tokens or documents; see
[sessions.md](sessions.md).
