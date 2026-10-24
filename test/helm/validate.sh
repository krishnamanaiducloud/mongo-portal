#!/usr/bin/env bash
# Validates the Helm chart without a cluster: lint, required values and
# schema, rendering for OpenShift and Kubernetes (the example values filled
# with sample values), Kubernetes/OpenShift/CRD schemas, guardrails, and the
# rendered portal configuration with the portal's own validation.
# Requires helm, kubeconform, envsubst, python3 with PyYAML and Go.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
C="$ROOT/charts/mongo-portal"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
OS='https://raw.githubusercontent.com/melmorabity/openshift-json-schemas/main/v4.18-standalone-strict/{{.ResourceKind}}{{.KindSuffix}}.json'
CRD='https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'
fail() { echo "FAIL: $*" >&2; exit 1; }

helm lint "$C" --set image.repository=registry.example.test/mongo-portal
out="$(helm template t "$C" 2>&1 || true)"
grep -q "image.repository is required" <<<"$out" || fail "image.repository must be required"
! helm template t "$C" --set image.repository=r --set image.digest=latest >/dev/null 2>&1 || fail "an invalid digest must be rejected"

# Sample organization values for the example files (never real ones).
export PORTAL_IMAGE_REPOSITORY=registry.example.test/platform/mongo-portal
PORTAL_IMAGE_DIGEST="sha256:$(printf '%064d' 0)"; export PORTAL_IMAGE_DIGEST
export PORTAL_ROUTE_HOST=portal.apps.cluster.example.test PORTAL_HOST=portal.example.test
export MONGODB_PROFILE_DISPLAY_NAME=Orders MONGODB_HOSTS=db-0.example.test:27017,db-1.example.test:27017 MONGODB_REPLICA_SET=rs0
export MONGODB_OIDC_ISSUER_URL=https://idp.example.test MONGODB_OIDC_CLIENT_ID=mongo-client MONGODB_OIDC_AUDIENCE=api://mongodb
export PORTAL_ADMIN_GROUP=dba PORTAL_PLATFORM_GROUP=platform PORTAL_DEVELOPER_GROUP=dev
export MONGODB_NAMESPACE=mongodb MONGODB_POD_LABEL_KEY=app MONGODB_POD_LABEL_VALUE=mongodb
export INGRESS_CLASS=nginx PORTAL_INGRESS_TLS_SECRET=portal-ingress-tls ORG_SSO_DISPLAY_NAME="Corporate SSO"
export ORG_OIDC_ISSUER_URL=https://idp.example.test PORTAL_OIDC_CLIENT_ID=portal INGRESS_NAMESPACE=ingress-nginx MONGODB_CIDR=10.20.0.0/24
for p in openshift kubernetes; do
  mkdir -p "$OUT/values"
  envsubst < "$C/examples/values-$p.yaml" > "$OUT/values/$p.yaml"
  helm template mp "$C" -n portal -f "$OUT/values/$p.yaml" > "$OUT/$p.yaml"
done
helm template mp "$C" -n portal --set image.repository=r > "$OUT/defaults.yaml"
helm template mp "$C" -n portal --set image.repository=r --set platform=kubernetes --set autoscaling.enabled=true \
  --set serviceMonitor.enabled=true --set ingress.enabled=true --set ingress.host=p.example.test --set image.variant=debug > "$OUT/all.yaml"
grep -q "image: r:$(helm show chart "$C" | sed -n 's/^appVersion: //p')-debug" "$OUT/all.yaml" || fail "debug variant tag"
grep -q "image: $PORTAL_IMAGE_REPOSITORY@sha256:" "$OUT/openshift.yaml" || fail "digest must be used when set"

kubeconform -strict -summary -kubernetes-version 1.31.0 -schema-location default -schema-location "$OS" -schema-location "$CRD" "$OUT"/openshift.yaml "$OUT"/kubernetes.yaml "$OUT"/defaults.yaml "$OUT"/all.yaml
if grep -nE '^\s+(runAsUser|fsGroup):|privileged: true|^kind: (Secret|StatefulSet|PersistentVolumeClaim|ClusterRole|ClusterRoleBinding)$' "$OUT"/openshift.yaml "$OUT"/kubernetes.yaml "$OUT"/defaults.yaml; then
  fail "guardrails: no fixed UIDs, privileged containers, Secrets, MongoDB workloads or cluster RBAC"
fi

cd "$ROOT"
go build -o "$OUT/portal" ./cmd/portal
extract() {
  python3 - "$1" <<'PY'
import sys, yaml
for d in yaml.safe_load_all(open(sys.argv[1])):
    if d and d.get("kind") == "ConfigMap" and d["metadata"]["name"].endswith("-config"):
        print(d["data"]["config.yaml"])
PY
}
for p in openshift kubernetes; do
  extract "$OUT/$p.yaml" > "$OUT/$p-config.yaml"
  "$OUT/portal" --check-config --config "$OUT/$p-config.yaml"
done
extract "$OUT/defaults.yaml" > "$OUT/defaults-config.yaml"
MONGODB_URI=mongodb://db.example.test:27017/ "$OUT/portal" --check-config --config "$OUT/defaults-config.yaml"
out="$("$OUT/portal" --check-config --config "$OUT/defaults-config.yaml" 2>&1 || true)"
grep -q MONGODB_URI <<<"$out" || fail "an unset MONGODB_URI must be reported"
echo "helm chart: ok"
