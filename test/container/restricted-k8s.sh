#!/usr/bin/env bash
# Deploys the portal pod spec into a disposable kind cluster whose namespace
# enforces Pod Security "restricted" (the upstream equivalent of OpenShift's
# restricted-v2 SCC), running as an OpenShift-style namespace UID with GID 0.
# It does not use any existing cluster or context.
#
# Usage: restricted-k8s.sh <production-image> <debug-image>
set -euo pipefail
PROD="${1:?production image}"
DEBUG="${2:?debug image}"
CLUSTER="mongo-portal-psa-$$"
KCFG="$(mktemp)"
export KUBECONFIG="$KCFG"
cleanup() { kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true; rm -f "$KCFG"; }
trap cleanup EXIT

kind create cluster --name "$CLUSTER" --kubeconfig "$KCFG" --wait 120s >/dev/null
kind load docker-image --name "$CLUSTER" "$PROD" "$DEBUG" mongo:8.0 >/dev/null

kubectl create namespace portal >/dev/null
kubectl label namespace portal pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/enforce-version=latest >/dev/null

kubectl -n portal apply -f - >/dev/null <<'EOF'
apiVersion: v1
kind: Pod
metadata: {name: mongo, labels: {app: mongo}}
spec:
  securityContext: {runAsNonRoot: true, runAsUser: 999, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: mongo
      image: mongo:8.0
      imagePullPolicy: Never
      args: ["--wiredTigerCacheSizeGB", "0.25", "--bind_ip_all"]
      securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: ["ALL"]}}
      volumeMounts: [{name: data, mountPath: /data/db}]
  volumes: [{name: data, emptyDir: {}}]
---
apiVersion: v1
kind: Service
metadata: {name: mongo}
spec: {selector: {app: mongo}, ports: [{port: 27017}]}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: portal-config}
data:
  config.yaml: |
    environment: psa-test
    identity: {mode: header, developerGroups: [devs], sreGroups: [sres]}
    profiles:
      - name: local
        uri: mongodb://mongo:27017/
        tls: {mode: disabled}
EOF

for variant in production debug; do
  img="$PROD"; [ "$variant" = debug ] && img="$DEBUG"
  # Same pod/container security settings as examples/kustomize/base/deployment.yaml; the
  # explicit runAsUser/runAsGroup emulate what OpenShift injects.
  kubectl -n portal apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata: {name: portal-$variant}
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000680000
    runAsGroup: 0
    seccompProfile: {type: RuntimeDefault}
  containers:
    - name: portal
      image: $img
      imagePullPolicy: Never
      args: ["--config=/etc/mongo-portal/config/config.yaml"]
      ports: [{name: metrics, containerPort: 9090}]
      readinessProbe: {httpGet: {path: /readyz, port: metrics}, periodSeconds: 2}
      livenessProbe: {httpGet: {path: /healthz, port: metrics}}
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        capabilities: {drop: ["ALL"]}
      volumeMounts:
        - {name: config, mountPath: /etc/mongo-portal/config, readOnly: true}
        - {name: tmp, mountPath: /tmp}
  volumes:
    - {name: config, configMap: {name: portal-config}}
    - {name: tmp, emptyDir: {medium: Memory, sizeLimit: 64Mi}}
EOF
done

kubectl -n portal wait --for=condition=Ready pod/portal-production pod/portal-debug --timeout=120s
echo "== admitted by Pod Security 'restricted' and Ready:"
kubectl -n portal get pods -o custom-columns=NAME:.metadata.name,READY:.status.containerStatuses[0].ready,UID:.spec.securityContext.runAsUser
echo "== identity inside debug pod:"
kubectl -n portal exec portal-debug -- sh -c 'id; touch /should-fail 2>&1 || true; mongosh --quiet mongodb://mongo:27017 --eval "db.runCommand({ping:1}).ok"'
echo "== a privileged variant is rejected:"
if kubectl -n portal run bad --image="$PROD" --image-pull-policy=Never --overrides='{"spec":{"containers":[{"name":"bad","image":"'"$PROD"'","securityContext":{"privileged":true}}]}}' 2>&1 | grep -q 'violates PodSecurity'; then
  echo "privileged pod rejected (as expected)"
else
  echo "UNEXPECTED: privileged pod not rejected"; exit 1
fi
echo "PSA restricted test: PASS"
