# GitOps with Argo CD

## Resources

`examples/argocd/application.yaml` contains:

* **AppProject `mongo-portal`** – source repo restricted to this repository,
  destinations restricted to the three portal namespaces, and a resource
  *allowlist*: ServiceAccount, ConfigMap (configuration and the RBAC policy),
  Service, Deployment, Route, NetworkPolicy, PodDisruptionBudget, ServiceMonitor
  and RoleBinding. No cluster-scoped kinds are allowed (the SCCs live in the
  separate `mongo-cluster` project). StatefulSets, PVCs and Secrets are explicitly blacklisted,
  so Argo CD cannot create, adopt, modify or prune MongoDB workloads even if a
  manifest were added by mistake.
* **Applications** `mongo-portal-dev`, `mongo-portal-test` (automated sync with
  prune and self-heal) and `mongo-portal-prod` (manual sync only, no cascading
  finalizer).

Pruning only ever affects objects that Argo CD created from the Application's
own path (tracked via its instance label/annotation). Existing resources in the
namespace are never adopted unless they are rendered from the overlay.

```bash
ARGO_NS=openshift-gitops       # or your Argo CD namespace
# Adjust destination namespaces / repoURL / targetRevision first.
oc apply -n "$ARGO_NS" -f examples/argocd/application.yaml
# The Argo CD application controller needs rights in the portal namespaces:
oc label namespace mongo-portal-prod argocd.argoproj.io/managed-by="$ARGO_NS"
```

The portal needs no cluster-scoped objects of its own, so a namespace-scoped
Argo CD instance can manage it. Only the SCC prerequisites
(`examples/argocd/cluster.yaml`, manual sync) need a cluster-scoped
instance or a one-time `oc apply -k examples/kustomize/cluster` by a cluster admin.

RBAC changes (`patch-rbac.yaml`) are ordinary ConfigMap updates. The pods pick
them up within 30 seconds without a rollout, so a sync does not interrupt users.

## Release flow

1. CI (`.github/workflows/portal-ci.yml`) runs lint, tests, integration tests,
   scans, builds both images and renders/validates all overlays on every PR.
2. A maintainer pushes a tag `portal-vX.Y.Z`. The `release` job (protected
   GitHub environment, manual approval) builds multi-arch images, scans them,
   pushes `X.Y.Z` and `X.Y.Z-debug`, generates SBOM + provenance, and opens a PR
   that pins `examples/kustomize/overlays/prod` to the new digest.
3. Dev/test sync automatically from `master`; production is synced manually in
   Argo CD after the digest PR is reviewed and merged.

Rollback: revert the digest commit (or sync the previous revision in Argo CD).
Rollouts are zero-downtime (`maxUnavailable: 0`), but users on replaced pods
must sign in to MongoDB again.

## Drift

`ignoreDifferences` covers the cluster-assigned `Route.spec.host`. The
generated ConfigMap name carries a content hash, so configuration edits roll the
Deployment and old ConfigMaps are pruned after the sync.
