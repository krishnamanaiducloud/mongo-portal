# Kustomize overlays

The same deployment as [../openshift](../openshift/), as a Kustomize base with
`dev`, `test` and `prod` overlays. Use it with `oc apply -k` or Argo CD
([../argocd](../argocd/)).

| Path | Contents |
| --- | --- |
| `cluster/` | SecurityContextConstraints and the ClusterRole to use it. Cluster scope, applied once by a cluster administrator |
| `base/` | ServiceAccount (OAuth client), configuration, RBAC policy, Deployment, Service, Route, NetworkPolicy, PodDisruptionBudget |
| `overlays/<env>/` | Per-environment configuration, RBAC groups, network policy and image digest |
| `components/monitoring/` | Optional ServiceMonitor for the Prometheus metrics |

Order:

```bash
oc apply -k cluster                     # once per cluster (cluster-admin)
oc kustomize overlays/dev               # review what will be applied
oc apply -n <namespace> -k overlays/dev
```

Replace every `REPLACE-` value first. Configuration reference:
[docs/configuration.md](../../docs/configuration.md).
