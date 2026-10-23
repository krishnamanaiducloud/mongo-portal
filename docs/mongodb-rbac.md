# MongoDB RBAC setup

The portal never uses a shared MongoDB account. Each person needs their own
MongoDB user; the portal can never exceed what that user is granted. By default
(`role:mongodb`) the portal follows these MongoDB privileges exactly: a user
with `readWrite` can edit, a user with `read` cannot. Portal roles such as
`role:readonly` can add a second, independent cap ([rbac.md](rbac.md)).

Run these with an existing administrator account (for example with `mongosh`
from the debug image or a MongoDB pod). Use `passwordPrompt()` so passwords do
not land in shell history.

## Developer (read-only)

```javascript
use admin
db.createRole({
  role: "portalReader",
  privileges: [
    { resource: { db: "app", collection: "" },
      actions: ["find", "listCollections", "listIndexes", "dbStats", "collStats"] }
  ],
  roles: []
})
db.createUser({
  user: "dana",
  pwd: passwordPrompt(),
  roles: [ { role: "portalReader", db: "admin" } ],
  mechanisms: ["SCRAM-SHA-256"]
})
```

The built-in `read` role on a database also works (`{role: "read", db: "app"}`).
`listDatabases` is optional: without it the portal shows only databases named
in the user's privileges.

## SRE (scoped administration)

Grant what the job requires, not `root`:

```javascript
use admin
db.createUser({
  user: "sam",
  pwd: passwordPrompt(),
  roles: [
    { role: "readWrite", db: "app" },     // document CRUD
    { role: "dbAdmin",  db: "app" },      // indexes, collection stats, drop collection
    { role: "clusterMonitor", db: "admin" } // optional: listDatabases, server status
  ],
  mechanisms: ["SCRAM-SHA-256"]
})
```

Membership in the SRE OpenShift group does **not** grant MongoDB privileges.
An SRE whose MongoDB user is read-only gets HTTP 403 from MongoDB for writes
(verified by the integration test `TestSRERespectsMongoDBRoles`).

## Mechanisms and auth database

* Prefer `SCRAM-SHA-256`. Legacy users created with only `SCRAM-SHA-1` work
  when the profile allows it (`authMechanisms`).
* Users created in a database other than `admin` must enter that database as
  the authentication database on the login screen.

## Review and revocation

```javascript
db.getSiblingDB("admin").getUser("sam", { showPrivileges: true })
db.getSiblingDB("admin").revokeRolesFromUser("sam", [{ role: "dbAdmin", db: "app" }])
db.getSiblingDB("admin").dropUser("dana")
```

Revoking a role or dropping a user takes effect on the next operation
(MongoDB returns `Unauthorized`, shown as 403). A changed password does not
affect connections that are already authenticated; it applies when the driver
opens a new connection, at which point the authentication failure ends the
portal session. To cut access immediately, also terminate the session (or
remove the person from the portal groups, which blocks every request within
one minute).
