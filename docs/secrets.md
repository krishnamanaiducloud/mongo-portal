# Secret configuration reference

No Secret is stored in Git and none is managed by Argo CD (the AppProject
blacklists `Secret`). Create them out of band, or with your secret operator
(for example External Secrets or Vault), in the portal namespace.

| Name | Type | Keys | Used by | Required |
| --- | --- | --- | --- | --- |
| `mongo-portal-session` | Opaque | `session-key`: random, ≥ 32 bytes | Pre-login CSRF tokens; encryption of the OpenShift sign-in and OAuth state cookies. Must be identical for all replicas | yes |
| `mongo-portal-tls` | kubernetes.io/tls | `tls.crt`, `tls.key` | HTTPS serving certificate (re-encrypt Route) | created by the service CA |
| `mongo-portal-mongodb-ca` | **ConfigMap** | `ca.crt`: PEM bundle | MongoDB TLS verification | TLS profiles only |
| `mongo-portal-mongodb-client` | kubernetes.io/tls | `tls.crt`, `tls.key` | MongoDB mutual TLS | when MongoDB requires client certs |

The OpenShift OAuth client secret is the portal's own service account token,
which Kubernetes mounts and rotates. Nothing has to be created for it.

Creation:

```bash
NS=<portal namespace>
oc create secret generic mongo-portal-session -n "$NS" \
  --from-literal=session-key="$(openssl rand -hex 32)"
oc create configmap mongo-portal-mongodb-ca -n "$NS" --from-file=ca.crt=ca-bundle.pem
oc create secret tls mongo-portal-mongodb-client -n "$NS" --cert=portal-client.crt --key=portal-client.key
```

Rotation:

* `mongo-portal-session`: rotate, then `oc rollout restart deploy/mongo-portal`.
  Users sign in again (OpenShift and MongoDB); sessions are in memory anyway.
* Serving certificate: rotated by the service CA. The portal reloads it from
  disk without a restart.
* MongoDB CA / client certificate: update the ConfigMap/Secret. Kubelet
  refreshes the files; new logins use the new CA, and the client key pair is
  reloaded automatically when it changes. Existing sessions keep their current
  connections until they reconnect or expire.

What is deliberately **not** a Secret: MongoDB user passwords. Users type them at
login; the portal never stores them. OpenShift access tokens exist only inside
the encrypted SSO cookie and in process memory.

If the session key is missing or unreadable, the portal starts anyway with a
random key and logs a warning. That is acceptable for a single replica; with
several replicas, sign-ins then work only on the pod that issued them.

## Optional Secrets (0.0.2 features)

| Secret | Keys | Used for | Mounted at |
| --- | --- | --- | --- |
| `mongo-portal-oidc` | one file per client secret, named as in `clientSecretFile` (for example `corp-client-secret`, `mongodb-client-secret`) | Confidential OIDC clients (portal sign-in or MONGODB-OIDC) | `/etc/mongo-portal/oidc` |
| `mongo-portal-store` | `username`, `password` | The shared store account (audit trail, session registry) | `/etc/mongo-portal/store` |

```bash
oc create secret generic mongo-portal-oidc -n <portal-namespace> --from-file=corp-client-secret=./client-secret
oc create secret generic mongo-portal-store -n <portal-namespace> --from-literal=username=mongo-portal-store --from-file=password=./store-password
```

Both are optional (the Deployment mounts them with `optional: true`). Public
OIDC clients with PKCE need no secret. The store account needs `readWrite` on
the store database only; it never runs user operations.
