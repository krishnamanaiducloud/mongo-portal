# mongo-portal Helm chart

Deploys the portal on OpenShift (Route with re-encrypt TLS from the service
CA, the service account as OpenShift OAuth client, optional dedicated SCC) or
on Kubernetes (Ingress, TLS Secret you provide). Nothing organization-specific
is built in: set the image, MongoDB hosts and identity providers in a values
file per environment. The chart creates no Secrets and never touches MongoDB
workloads.

```bash
helm upgrade --install mongo-portal charts/mongo-portal -n <namespace> -f values-<env>.yaml \
  --set image.repository=<registry>/<path>/mongo-portal --set image.digest=sha256:<digest>
helm test mongo-portal -n <namespace> --logs     # read-only preflight in the cluster
```

| Value | Purpose |
| --- | --- |
| `image.repository`, `image.digest` / `image.tag`, `image.variant` | required repository; digest for production; `debug` selects the diagnostic image |
| `platform` | `openshift` or `kubernetes` |
| `config` | the portal configuration ([docs/configuration.md](../../docs/configuration.md)); `${NAME}` placeholders resolved from `env` |
| `env`, `extraEnv`, `envFrom` | values for the placeholders (the default configuration needs `MONGODB_URI`) |
| `rbacPolicy` | the RBAC ConfigMap (policy lines, default role) |
| `secrets.*`, `mongodbCA.configMap` | names of the optional Secrets and the CA ConfigMap |
| `tls` | the portal's HTTPS certificate (service CA on OpenShift) |
| `openshift.requiredSCC`, `openshift.sccRoleBinding` | dedicated SCC (created once by a cluster administrator) |
| `route`, `ingress`, `service` | exposure |
| `networkPolicy` | ingress from the router/ingress and monitoring; egress to DNS, MongoDB, HTTPS |
| `autoscaling`, `podDisruptionBudget`, `serviceMonitor`, `resources`, `podSecurityContext` | operations |

Examples with placeholders: [examples/values-openshift.yaml](examples/values-openshift.yaml),
[examples/values-kubernetes.yaml](examples/values-kubernetes.yaml). Validation
without a cluster: `test/helm/validate.sh`; on a cluster: `test/kind/run.sh`.
See [docs/ORGANIZATION_CONFIGURATION.md](../../docs/ORGANIZATION_CONFIGURATION.md).
