# Deployment on OpenShift

This deploys **only** the portal, from [`examples/openshift/`](../examples/openshift/) (plain files) or
[`examples/kustomize/`](../examples/kustomize/) (Kustomize overlays).
It never creates, modifies or restarts the existing MongoDB StatefulSet,
Services, PVCs or replica-set configuration.

## 1. Discover the existing MongoDB deployment

Do not guess these values; read them from the cluster.

```bash
# Where MongoDB runs
oc get statefulsets -A | grep -i mongo
MONGO_NS=<namespace from above>
MONGO_STS=<statefulset name>

# Service DNS names (headless service gives per-member names)
oc get svc -n "$MONGO_NS"
oc get sts "$MONGO_STS" -n "$MONGO_NS" -o jsonpath='{.spec.serviceName}{"\n"}'
oc get sts "$MONGO_STS" -n "$MONGO_NS" -o jsonpath='{.spec.selector.matchLabels}{"\n"}'
oc get pods -n "$MONGO_NS" -o wide
#   member DNS: <pod>.<serviceName>.<MONGO_NS>.svc.cluster.local:27017

# Pod labels (for the NetworkPolicy egress selector)
oc get pods -n "$MONGO_NS" --show-labels | grep -i mongo

# Replica-set name and members (read-only commands; run with an existing admin account)
oc exec -n "$MONGO_NS" <mongo-pod> -- mongosh --quiet -u <admin> -p --authenticationDatabase admin \
  --eval 'const s = rs.status(); print(s.set); s.members.forEach(m => print(m.name, m.stateStr))'

# TLS status
oc exec -n "$MONGO_NS" <mongo-pod> -- mongosh --quiet -u <admin> -p --authenticationDatabase admin \
  --eval 'printjson(db.adminCommand({getCmdLineOpts:1}).parsed.net)'

# Authentication database of existing users (usually "admin")
oc exec -n "$MONGO_NS" <mongo-pod> -- mongosh --quiet -u <admin> -p --authenticationDatabase admin \
  --eval 'db.getSiblingDB("admin").system.users.find({}, {user:1, db:1, _id:0}).forEach(printjson)'
```

## 2. Prerequisites

* OpenShift 4.x. The integrated OAuth server (with your corporate IdP) is used
  when it is reachable; without it the portal works with MongoDB logins only.
* OpenShift Groups for the portal roles, for example
  `mongo-portal-sre-prod` and `mongo-portal-developers-prod`
  (`oc adm groups new …`, or LDAP/OIDC group sync).
* A namespace for the portal (`oc new-project mongo-portal-prod`), with network
  access to the MongoDB pods on 27017 and to the API/OAuth servers on 443/6443.
* Individual MongoDB users for every portal user ([mongodb-rbac.md](mongodb-rbac.md)).
* Pull access to `docker.io/mohankrishna999/mongo-portal`. No OAuth proxy image is needed.

## 3. Apply the SecurityContextConstraints (once per cluster)

The portal pods run under the dedicated `mongo-portal-restricted` SCC
(restricted-v2 plus a mandatory read-only root filesystem and a minimal volume
allowlist), requested with the `openshift.io/required-scc` annotation. A
cluster administrator applies it once:

```bash
oc apply -k examples/kustomize/cluster
oc get scc mongo-portal-restricted
```

The namespace grants the portal ServiceAccount `use` of it with the RoleBinding
in `examples/kustomize/base/rbac-scc.yaml`. The SCC is restricted-v2 plus a
mandatory read-only root filesystem: it allows any UID from the namespace
range and grants no privileged access.

## 4. Create the Secrets (once per namespace)

See [secrets.md](secrets.md). Minimum:

```bash
NS=mongo-portal-prod
oc create secret generic mongo-portal-session -n $NS --from-literal=session-key="$(openssl rand -hex 32)"
# Only for TLS profiles:
oc create configmap mongo-portal-mongodb-ca -n $NS --from-file=ca.crt=./mongodb-ca.pem
oc create secret tls mongo-portal-mongodb-client -n $NS --cert=client.crt --key=client.key   # mutual TLS only
```

`mongo-portal-tls` (the HTTPS serving certificate) is created automatically by
the service CA.

## 5. Configure the overlay

Edit `examples/kustomize/overlays/<env>/`:

| File | What to set |
| --- | --- |
| `kustomization.yaml` | `namespace`, image tag or digest |
| `config.yaml` | MongoDB hosts (`uri`), `replicaSet`, `defaultAuthSource`, TLS block; optionally `identity.requireSSO`, `identity.ssoLogoutURL` |
| `patch-rbac.yaml` | OpenShift group names → roles; optional `mongodb:<user>@admin` lines for MongoDB-only sign-in ([rbac.md](rbac.md)) |
| `patch-networkpolicy.yaml` | MongoDB namespace and pod labels; optionally narrow the API egress |

The RBAC ConfigMap (`mongo-portal-rbac`) is not hashed: edits are picked up by
the running pods within 30 seconds, without a restart.

Production additionally requires a TLS decision in `config.yaml`: enable MongoDB
TLS, or record an approved exception (`plaintextApproved: true`,
`securityExceptionRef`). Without one, the portal refuses to start.

Render and review before applying:

```bash
oc kustomize examples/kustomize/overlays/prod | less
oc kustomize examples/kustomize/overlays/prod | oc apply --dry-run=server -f -
```

## 6. Deploy

GitOps (recommended): see [gitops.md](gitops.md). Manual:

```bash
oc apply -k examples/kustomize/overlays/prod
oc rollout status deploy/mongo-portal -n mongo-portal-prod
oc get route mongo-portal -n mongo-portal-prod -o jsonpath='https://{.spec.host}{"\n"}'
```

## 7. Verify

```bash
oc get pods -n $NS -l app.kubernetes.io/name=mongo-portal \
  -o custom-columns=NAME:.metadata.name,SCC:.metadata.annotations.openshift\\.io/scc
#   SCC must be mongo-portal-restricted
oc logs deploy/mongo-portal -n $NS | grep -E '"mongo portal started"|openshift login|rbac policy loaded'
oc exec deploy/mongo-portal -n $NS -- /usr/bin/mongo-portal healthcheck && echo healthy
```

Then browse to the Route:

1. **Log in with OpenShift**, then MongoDB login, then databases.
2. **System status** shows OpenShift sign-in *Available*, the RBAC policy from
   the ConfigMap, and the MongoDB deployments *Online*.
3. **My permissions** shows the expected roles. A developer whose MongoDB user
   is read-only sees no write controls, and MongoDB refuses writes with 403.
4. **Monitoring** shows the replica set members, connections and sizes (for
   MongoDB users with `clusterMonitor`; others see what their roles allow).
5. Optional: block egress to the OAuth server for a moment. The button
   disappears within a minute and MongoDB login keeps working.

## Debug image

Use `…:<version>-debug` (the dev overlay default), or switch temporarily:

```bash
oc set image deploy/mongo-portal portal=docker.io/mohankrishna999/mongo-portal:<version>-debug -n $NS   # temporary
oc rsh deploy/mongo-portal
  dig +short <mongo-host>; curl -sv telnet://<mongo-host>:27017; openssl s_client -connect <host>:27017 -CAfile /etc/mongo-portal/mongodb-ca/ca.crt
  curl -s https://kubernetes.default.svc/.well-known/oauth-authorization-server
  mongosh "mongodb://<host>:27017/?replicaSet=<rs>" -u <your-user> --authenticationDatabase admin
```

The debug image has no package manager and runs under the same restricted
security context; revert to the production image afterwards.
