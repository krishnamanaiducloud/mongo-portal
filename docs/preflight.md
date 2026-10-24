# Preflight: checking an environment without changing it

Three read-only checks show whether a configuration can work where it is
deployed. None of them writes anything, restarts anything, sends a user's
password or token to MongoDB, or prints secret values.

| Check | Runs where | Use it |
| --- | --- | --- |
| `mongo-portal preflight` | anywhere the portal image runs (a pod, `helm test`, a workstation) | before go-live, after configuration changes, when a profile shows as offline |
| **Diagnose connection** (UI) / `GET /api/v1/profiles/{name}/diagnostics` | the portal replica serving the request | when a user cannot connect; needs `monitoring get` on the profile |
| `scripts/preflight-openshift.sh` | an administrator's workstation with `oc` | to verify a deployment: pods, image digest, Route, SCC, Secrets present, NetworkPolicies, then the in-pod preflight |

## `mongo-portal preflight`

```bash
mongo-portal preflight --config /etc/mongo-portal/config/config.yaml [--format json] [--profile primary] [--oidc-user name] [--timeout 10s]
```

Exit status: `0` no failures, `1` failures, `2` invalid configuration.

| Area | Checks |
| --- | --- |
| portal | public origin set (production), session key readable and long enough (length only), portal TLS certificate (pair, expiry), transfer directory writable |
| identity | OpenShift OAuth discovery; each OIDC provider's discovery and keys |
| store | the store account signs in and holds readWrite on the store database (privileges read with `connectionStatus`; nothing is written) |
| each profile | DNS (and SRV), TCP to every host, TLS handshake with the configured CA (verification, host name, expiry), `hello` from a member (replica set name, primary), `buildInfo` (version, edition) |
| MONGODB-OIDC profiles | the provider's discovery, keys and PKCE support; MongoDB version (Enterprise 7.0+); **which issuer and client id the server announces** (the first step of the MONGODB-OIDC conversation, before any token) compared with the profile |

It also lists the environment variables the configuration file references
(names only). With the Helm chart, `helm test <release>` runs it in the
cluster with the portal's configuration, mounts and NetworkPolicy.

Example output (sample values):

```text
STATUS  AREA             CHECK                  TARGET                        DETAIL
PASS    portal           session key            /etc/mongo-portal/session/... readable, at least 32 bytes (value not shown)
PASS    identity         OpenShift OAuth        https://oauth-openshift...    discovery succeeded
PASS    store            shared store           primary/mongo_portal          signed in; readWrite privileges on mongo_portal (nothing written)
PASS    profile primary  TLS                    db-0.example.test:27017       verified TLS 1.3, issuer "Corp CA", expires 2027-03-01 (128 days)
PASS    profile primary  MongoDB topology                                     replica set "rs0", 3 members, primary db-0.example.test:27017
PASS    profile primary  MongoDB version                                      7.0.14 Enterprise
FAIL    profile primary  MONGODB-OIDC server                                  MongoDB announces client id "mongodb-human", the profile uses "portal"
```

## `scripts/preflight-openshift.sh`

```bash
K8S_NAMESPACE=<portal-namespace> PORTAL_EXPECTED_IMAGE=<repository>@sha256:<digest> \
  PORTAL_PUBLIC_URL=https://<route-host> scripts/preflight-openshift.sh
```

Uses only `get` and, at the end, `exec` of `mongo-portal preflight` inside a
running portal pod (skip with `IN_POD_PREFLIGHT=0`). Missing permissions are
reported as **BLOCKED**, not as failures, so the script can be run with a
namespace-scoped role. For Kubernetes without OpenShift set `OC=kubectl`.

Checked: cluster and OpenShift version, cluster domain, OAuth identity
providers, the portal Deployment (ready replicas, image pinned by digest,
optionally equal to the expected one), pods (phase, restarts, SCC assigned,
UID, read-only root filesystem, no privilege escalation), Route (host,
re-encrypt), Service (service CA certificate), ServiceAccount (OAuth
redirect reference), whether the expected Secrets and the CA ConfigMap exist
(values are never read), and NetworkPolicies.

## If live access is not available

The checks need network access from where they run. Without access to the
cluster or the databases they cannot pass; their output says which check
could not run. Do not treat a check that did not run as passed.
