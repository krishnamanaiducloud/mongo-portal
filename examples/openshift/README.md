# MongoDB portal on OpenShift

Plain manifests (no Kustomize) for the MongoDB portal, one file per resource.
The portal is a web UI for MongoDB where
**every user works with their own MongoDB account**: users click
**Log in with OpenShift** (or, while OpenShift login is unavailable, sign in
with MongoDB credentials only), then enter their MongoDB username and
password. MongoDB enforces each user's own roles, and the portal RBAC policy
can narrow them further. It does not install or change MongoDB.

| File | What it is | Scope |
| --- | --- | --- |
| [scc.yml](scc.yml) | SecurityContextConstraints + ClusterRole to use it | cluster (cluster-admin, once) |
| [serviceaccount.yml](serviceaccount.yml) | ServiceAccount (OAuth client of the OpenShift login) + RoleBinding for the SCC | namespace |
| [configmap.yml](configmap.yml) | Portal configuration: MongoDB hosts, TLS, login, session | namespace |
| [rbac-configmap.yml](rbac-configmap.yml) | Who may do what (OpenShift groups → roles) | namespace |
| [session-secret.yml](session-secret.yml) | Session key (create with `oc create secret` instead) | namespace |
| [deployment.yml](deployment.yml) | The portal (2 replicas, image pinned by digest) | namespace |
| [service.yml](service.yml) | Service; OpenShift creates the HTTPS certificate from its annotation | namespace |
| [route.yml](route.yml) | HTTPS Route (re-encrypt) | namespace |
| [networkpolicy.yml](networkpolicy.yml) | Allowed traffic in and out | namespace |
| [pdb.yml](pdb.yml) | Keeps one pod up during node maintenance | namespace |

## 1. Edit

| File | Replace |
| --- | --- |
| `configmap.yml` | `REPLACE-mongodb-host-*`, `REPLACE-replica-set`, and make the **TLS decision** (see below) |
| `networkpolicy.yml` | `REPLACE-mongodb-namespace`, `REPLACE-mongodb-pod-label` |
| `rbac-configmap.yml` | `REPLACE-sre-group`, `REPLACE-developer-group` (`oc get groups`) |

Find the MongoDB values on the cluster (read-only commands):

```bash
oc get statefulset -A | grep -i mongo                     # namespace + name
oc get svc -n <mongodb-ns>                                # service name
oc get pods -n <mongodb-ns> --show-labels                 # pod labels
#   host names: <pod>.<service>.<mongodb-ns>.svc.cluster.local:27017
```

**TLS decision.** With `environment: production` the portal refuses to start
while the profile uses an unencrypted MongoDB connection, until you either:

* enable TLS: `tls.mode: enabled` with `caFile`, and create the CA ConfigMap
  (`oc create configmap mongo-portal-mongodb-ca --from-file=ca.crt=./ca.pem`), or
* record an approved exception: `plaintextApproved: true` and
  `securityExceptionRef: <ticket>`.

For a non-production namespace, set `environment: dev` instead. Unencrypted
connections then work, with a permanent warning banner.

## 2. Deploy (in this order)

```bash
NS=mongo-portal

# 1. Namespace
oc new-project $NS

# 2. Security policy: cluster-admin, once per cluster
oc apply -f scc.yml

# 3. Session key
oc create secret generic mongo-portal-session -n $NS \
  --from-literal=session-key="$(openssl rand -hex 32)"

# 4. The portal
oc apply -n $NS -f serviceaccount.yml
oc apply -n $NS -f configmap.yml
oc apply -n $NS -f rbac-configmap.yml
oc apply -n $NS -f service.yml
oc apply -n $NS -f deployment.yml
oc apply -n $NS -f route.yml
oc apply -n $NS -f networkpolicy.yml
oc apply -n $NS -f pdb.yml

# 5. Check
oc rollout status deploy/mongo-portal -n $NS
oc get route mongo-portal -n $NS -o jsonpath='https://{.spec.host}{"\n"}'
```

Open the URL: **Log in with OpenShift**, then sign in to MongoDB with your
own MongoDB user. The **System status** page shows whether OpenShift login,
the RBAC policy and the MongoDB deployment are available.

`mongo-portal-tls` is created by OpenShift when `service.yml` is applied; you
do not create it.

## Changing things later

* `configmap.yml`: apply, then `oc rollout restart deploy/mongo-portal -n $NS`.
* `rbac-configmap.yml`: apply only. Active within 30 seconds, no restart; an
  invalid edit is rejected and the previous policy stays.
* New image: change `image:` in `deployment.yml` and apply.

## If something is not working

| Symptom | Check |
| --- | --- |
| Pod not created: "unable to validate against any security context constraint" | `scc.yml` not applied, or the RoleBinding in `serviceaccount.yml` is missing |
| Pod restarts, log says `plaintextApproved` | Make the TLS decision in `configmap.yml` (see above) |
| No "Log in with OpenShift" button | The System status page shows the reason. Usually egress to 443/6443 is blocked in `networkpolicy.yml`. MongoDB login still works |
| "MongoDB is unreachable" at login | Host names in `configmap.yml`, or the MongoDB rule in `networkpolicy.yml` |

More: [docs](../../docs/README.md), especially
[configuration](../../docs/configuration.md),
[RBAC](../../docs/rbac.md) and
[OpenShift login](../../docs/oauth.md).
