# Portal RBAC

The portal decides what each user may do with a CSV policy. MongoDB
still authorizes every operation with the user's own credentials, so portal RBAC
can only **narrow** access. It can never grant more than the MongoDB user has.

## Policy format

```csv
p, <role>, <resource>, <action>, <object>[, allow|deny[, <profile>]]
g, <subject>, <role>
```

* **Roles** are named `role:<name>`. A `g` line may also make one role inherit
  another (`g, role:team, role:editor`).
* **Subjects:**
  * OpenShift or OIDC user and group names, as given;
  * `user:<name>` or `group:<name>`, to be explicit;
  * `idp:<provider>` for every user of an OIDC provider;
  * `mongodb:<user>@<authSource>` or `mongodb:<user>` for MongoDB-only sign-ins
    (when SSO is not used or not available).
* **Objects** are globs over `<db>` or `<db>/<collection>`: `*` matches any text
  (including `/`), `?` matches one character.
* **Profile scope** (optional last field): a glob over connection profile
  names. The rule then applies only to requests in a MongoDB session of a
  matching profile (`dev-*`, `prod`). Without it a rule applies to every
  profile. Environments are separate deployments with their own policy
  ConfigMap (the overlays), so environment scoping is the policy itself.
* A request is allowed when a rule of the user's roles allows it **and no rule
  denies it**. Everything else is denied.

| Resource | Actions | Object |
| --- | --- | --- |
| `databases` | `get`, `delete` | `<db>` |
| `collections` | `get`, `create`, `update` (rename), `delete` | `<db>/<coll>` |
| `documents` | `get`, `create`, `update`, `delete` | `<db>/<coll>` |
| `indexes` | `get`, `create`, `delete` | `<db>/<coll>` |
| `shell` | `use`, `admin` (administrative `runCommand`s such as `currentOp`, `killOp`) | `*` / `<db>` |
| `server` | `get` | profile name |
| `monitoring` | `get` | profile name |
| `operations` | `get`, `kill` (killOp) | profile name |
| `export` | `create` | `<db>/<coll>` or `<db>` (database archive) |
| `import` | `create` | `<db>/<coll>` |
| `audit` | `get` | `self` or `all` |
| `sessions` | `get`, `delete` | `self` or `all` |
| `settings` | `get` | `*` |

Exports also need `documents get`, imports `documents create` (and
`documents update` for upserts) on the same namespace.

Creating a database means creating its first collection (`collections:create`).

## Built-in roles

| Role | Grants |
| --- | --- |
| `role:mongodb` | Everything MongoDB allows the user, including import, export and killOp: the portal adds no limit of its own (portal administration and other users' audit events excepted). The shipped default role |
| `role:readonly` | Browse, query, export, monitoring; use the shell; own sessions and audit events |
| `role:editor` | readonly, plus document and index changes, creating collections and import |
| `role:dbadmin` | editor, plus dropping collections and databases, administrative shell commands and killOp |
| `role:monitoring` | Monitoring and running operations only, no data |
| `role:auditor` | monitoring, plus every user's audit events and the session inventory, no data |
| `role:platform-admin` | auditor, plus revoking sessions and the settings page; **no data access** |
| `role:admin` | Everything (break-glass): data, portal administration and every audit event |

Portal administration and database administration are separate:
`role:platform-admin` cannot read data, `role:dbadmin` cannot administer the
portal. MongoDB privileges still apply to every data operation of every role.

Policies may add rules to the built-in roles or define their own.

## Default role

`policy.default` (or `rbac.defaultRole`) is the role of users **the policy does
not map**. A user matched by any `g` line gets only the mapped roles, so mapping a
group to `role:readonly` really restricts it.

The shipped default is `role:mongodb`: unmapped users can do exactly what their
MongoDB user may do. A MongoDB user with `readWrite` can edit documents, and one
with only `read` is refused by MongoDB. Every user still needs valid MongoDB
credentials.

Other choices:

* `role:readonly`: every unmapped user is read-only in the portal, whatever their
  MongoDB privileges;
* an empty value: unmapped users get nothing and see an explanatory "No portal
  access" page.

## Where the policy comes from

1. `rbac.policy` (inline in the configuration) and the deprecated
   `identity.developerGroups` / `sreGroups`, which become
   `g, <group>, role:readonly` / `role:admin`.
2. `rbac.policyDir` (default `/etc/mongo-portal/rbac`): `policy.csv` and
   `policy.default`, which are the keys of the `mongo-portal-rbac` ConfigMap
   ([`rbac-policy.yaml`](../examples/kustomize/base/rbac-policy.yaml)).

The directory is re-read every `rbac.reloadInterval` (30 seconds). Changes apply
without restarting pods or ending sessions. An invalid edit is **rejected** and
the previous policy stays active. The error appears in the logs, on the System
status page and on My permissions. A missing ConfigMap is not an error; the
configuration policy applies.

## Examples

```csv
# Teams by OpenShift group
g, mongo-portal-sre-prod, role:admin
g, mongo-portal-developers-prod, role:mongodb   # follow their MongoDB privileges
g, mongo-portal-auditors-prod, role:readonly    # read-only even with MongoDB write access

# The payments team may change orders, but never delete the archive
p, role:payments, documents, *, shop/orders*, allow
p, role:payments, documents, delete, shop/orders_archive, deny
g, payments-team, role:payments

# Keep SREs productive while OpenShift is down (MongoDB-only sign-in)
g, mongodb:sre-alice@admin, role:admin

# Hide a sensitive database entirely from developers
p, role:readonly, databases, get, hr, deny

# Developers may write only in dev profiles; production stays read-only
p, role:dev-writer, documents, *, *, allow, dev-*
g, mongo-portal-developers, role:readonly
g, mongo-portal-developers, role:dev-writer

# Every Entra ID user may browse; operators may end operations
g, idp:corp, role:readonly
g, mongo-ops, role:monitoring
p, role:monitoring, operations, kill, *, allow
```

## Where it is enforced

* **Every API endpoint** checks the concrete object, for example
  `documents update app/orders` for a document replace.
* **Database and collection lists** only show objects with `get` permission.
* **Aggregations:** collections read through `$lookup`, `$graphLookup` and
  `$unionWith` (also nested and in `$facet`) need `documents get`. The target of
  `$out`/`$merge` needs `documents create`, `update` and `delete`, and
  `query.allowWriteStages` must be enabled.
* **The shell:** every mongosh operation maps to a resource and action on its
  namespace. Administrative `runCommand`s need `shell admin`.
* **Import, export, operations, monitoring, sessions and settings** check
  their resource; killOp additionally needs MongoDB's `killop` privilege for
  other users' operations.
* **Every denial is audited** (`rbac_denied`) and counted in
  `mongo_portal_authorization_denials_total`.
* **The UI** offers an action only when both RBAC and the user's MongoDB
  privileges allow it. **My permissions** shows the user's roles and rules, and a
  live **Check access** tool that asks the server.

`GET /api/v1/permissions?resource=documents&action=update&object=app/orders`
returns the same decision the server uses.
