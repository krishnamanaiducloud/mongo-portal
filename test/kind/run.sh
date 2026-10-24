#!/usr/bin/env bash
# Deployment test on a real Kubernetes cluster (kind), using the Helm chart:
#   - Pod Security "restricted" enforced on the portal namespace, an
#     OpenShift-style arbitrary UID with GID 0, read-only root filesystem
#   - two replicas sharing a MongoDB store: session registry and revocation
#     across replicas, durable audit, cache invalidation across replicas
#   - NetworkPolicy: only the allowed namespace reaches the portal
#   - helm test: the read-only preflight in the cluster
#   - a rolling restart: MongoDB sessions end and users reconnect
# It creates its own cluster (default name mongo-portal-e2e) and deletes it
# afterwards; other clusters are never touched. This is Kubernetes, not
# OpenShift: Routes, SCCs and OpenShift OAuth are not exercised.
#
# Usage: run.sh <portal-image>     (requires docker, kind, kubectl, helm, jq, curl)
set -euo pipefail
IMAGE="${1:?portal image}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CLUSTER="${KIND_CLUSTER:-mongo-portal-e2e}"
NODE_IMAGE="${KIND_NODE_IMAGE:-}"
MONGO_IMAGE="${MONGO_IMAGE:-mongo:8.0}"
NS=portal-e2e
WORK="$(mktemp -d)"
KCTX="kind-$CLUSTER"
k() { kubectl --context "$KCTX" "$@"; }
PIDS=()
pass=0; fail=0
ok() { pass=$((pass + 1)); echo "  PASS $*"; }
bad() { fail=$((fail + 1)); echo "  FAIL $*"; }
cleanup() {
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  [ "${KEEP_CLUSTER:-}" = 1 ] || kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then echo "cluster $CLUSTER already exists; refusing to reuse it" >&2; exit 1; fi
echo ">> creating kind cluster $CLUSTER"
kind create cluster --name "$CLUSTER" ${NODE_IMAGE:+--image "$NODE_IMAGE"} --wait 120s >/dev/null
# The node is Ready before the bootstrap RBAC policy is: wait for it.
for _ in $(seq 1 60); do [ "$(k auth can-i create namespaces 2>/dev/null)" = yes ] && break; sleep 2; done
docker image inspect "$MONGO_IMAGE" >/dev/null 2>&1 || docker pull -q "$MONGO_IMAGE" >/dev/null
docker tag "$IMAGE" mongo-portal:kind-e2e
# kind imports every platform of an image; a multi-platform image of which
# Docker holds only the local platform then fails. Fall back to importing a
# single-platform archive into the node.
load() {
  kind load docker-image --name "$CLUSTER" "$1" >/dev/null 2>&1 && return
  local arch; arch="linux/$(docker version -f '{{.Server.Arch}}')"
  docker save --platform "$arch" "$1" | docker exec -i "$CLUSTER-control-plane" ctr --namespace=k8s.io images import --digests --snapshotter=overlayfs - >/dev/null
}
load mongo-portal:kind-e2e
load "$MONGO_IMAGE"

echo ">> MongoDB (namespace mongodb, not restricted: the official image starts as root)"
ROOT_PW="$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')"
READER_PW="r$(head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')"
STORE_PW="s$(head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')"
k create namespace mongodb >/dev/null
k -n mongodb create secret generic root --from-literal=password="$ROOT_PW" >/dev/null
k -n mongodb apply -f - >/dev/null <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: {name: mongodb}
spec:
  selector: {matchLabels: {app: mongodb}}
  template:
    metadata: {labels: {app: mongodb}}
    spec:
      containers:
        - name: mongod
          image: $MONGO_IMAGE
          args: ["--wiredTigerCacheSizeGB", "0.25"]
          env:
            - {name: MONGO_INITDB_ROOT_USERNAME, value: root}
            - {name: MONGO_INITDB_ROOT_PASSWORD, valueFrom: {secretKeyRef: {name: root, key: password}}}
          ports: [{containerPort: 27017}]
---
apiVersion: v1
kind: Service
metadata: {name: mongodb}
spec:
  selector: {app: mongodb}
  ports: [{port: 27017}]
EOF
k -n mongodb rollout status deploy/mongodb --timeout=180s >/dev/null
MPOD="$(k -n mongodb get pod -l app=mongodb -o jsonpath='{.items[0].metadata.name}')"
for _ in $(seq 1 90); do
  k -n mongodb logs "$MPOD" 2>/dev/null | grep -q 'MongoDB init process complete' && break; sleep 2
done
for _ in $(seq 1 30); do k -n mongodb exec "$MPOD" -- mongosh --quiet -u root -p "$ROOT_PW" --eval 'db.adminCommand({ping:1})' >/dev/null 2>&1 && break; sleep 2; done
k -n mongodb exec "$MPOD" -- mongosh --quiet -u root -p "$ROOT_PW" --eval "
  const a = db.getSiblingDB('admin');
  a.createUser({user:'reader', pwd:'$READER_PW', roles:[{role:'read', db:'app'}]});
  a.createUser({user:'portalstore', pwd:'$STORE_PW', roles:[{role:'readWrite', db:'mongo_portal'}]});
  db.getSiblingDB('app').orders.insertMany([{_id:1},{_id:2}]);" >/dev/null

echo ">> portal namespace with Pod Security restricted, secrets, TLS"
k create namespace $NS >/dev/null
k label namespace $NS pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/enforce-version=latest >/dev/null
k create namespace portal-e2e-clients >/dev/null
k create namespace outsider >/dev/null
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -e GOCACHE=/tmp/gocache -e GOFLAGS=-buildvcs=false -v "$ROOT:/src:ro" -v "$WORK:/out" -w /src \
  "${GO_IMAGE:-cgr.dev/chainguard/go:latest}" run ./test/integration/gencerts -out /out/certs -hosts "mp-mongo-portal.$NS.svc,mp-mongo-portal,localhost" >/dev/null
k -n $NS create secret generic mp-tls --from-file=tls.crt="$WORK/certs/server.pem" --from-file=tls.key="$WORK/certs/server.pem" >/dev/null
k -n $NS create secret generic mongo-portal-session --from-literal=session-key="$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')" >/dev/null
k -n $NS create secret generic mongo-portal-store --from-literal=username=portalstore --from-literal=password="$STORE_PW" >/dev/null

cat > "$WORK/values.yaml" <<'EOF'
image: {repository: mongo-portal, tag: kind-e2e, pullPolicy: Never}
platform: kubernetes
replicaCount: 2
podSecurityContext: {runAsUser: 1000680000, runAsGroup: 0}
tls: {enabled: true, secretName: mp-tls, serviceCA: false}
route: {enabled: false}
env:
  MONGODB_URI: mongodb://mongodb.mongodb.svc.cluster.local:27017/
config:
  environment: e2e
  identity:
    header: {enabled: true}
  session: {registry: true, registrySyncInterval: 2s}
  cache: {syncInterval: 2s}
  store: {enabled: true, profile: primary, database: mongo_portal, usernameFile: /etc/mongo-portal/store/username, passwordFile: /etc/mongo-portal/store/password}
  audit: {persist: true, retention: 24h}
  profiles:
    - name: primary
      displayName: kind MongoDB
      uri: "${MONGODB_URI}"
      tls: {mode: disabled}
rbacPolicy:
  policy: |
    g, platform, role:platform-admin
    g, devs, role:readonly
networkPolicy:
  ingress:
    from:
      - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: portal-e2e-clients}}
    metricsFrom: []
  egress:
    dns:
      - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: kube-system}}
    mongodb:
      - to:
          - namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: mongodb}}
        ports: [27017]
EOF
echo ">> helm install"
helm --kube-context "$KCTX" install mp "$ROOT/charts/mongo-portal" -n $NS -f "$WORK/values.yaml" --wait --timeout 180s >/dev/null
k -n $NS rollout status deploy/mp-mongo-portal --timeout=120s >/dev/null && ok "two replicas ready under Pod Security restricted" || bad "rollout"

mapfile -t PODS < <(k -n $NS get pod -l app.kubernetes.io/name=mongo-portal,app.kubernetes.io/component!=preflight -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
[ "${#PODS[@]}" = 2 ] && ok "pods: ${PODS[*]}" || bad "expected 2 pods, got ${#PODS[@]}"
sc="$(k -n $NS get pod "${PODS[0]}" -o jsonpath='{.spec.securityContext.runAsUser}:{.spec.securityContext.runAsGroup}:{.spec.containers[0].securityContext.readOnlyRootFilesystem}:{.spec.containers[0].securityContext.capabilities.drop[0]}')"
[ "$sc" = "1000680000:0:true:ALL" ] && ok "arbitrary UID 1000680000, GID 0, read-only root filesystem, capabilities dropped" || bad "security context $sc"

echo ">> helm test (read-only preflight inside the cluster)"
if helm --kube-context "$KCTX" test mp -n $NS --logs --timeout 120s > "$WORK/helmtest.log" 2>&1; then ok "helm test preflight"; else bad "helm test"; fi
grep -E '^(PASS|WARN|FAIL|SKIP) ' "$WORK/helmtest.log" | sed 's/^/    /' | head -20

echo ">> per-replica API through port-forward"
port=18443
for p in "${PODS[@]}"; do
  k -n $NS port-forward "pod/$p" "$port:8443" >/dev/null 2>&1 &
  PIDS+=("$!")
  port=$((port + 1))
done
sleep 4
CA="$WORK/certs/ca.crt"
# api <port> <jar> <user> <groups> <method> <path> [json]
api() {
  local port=$1 jar=$2 user=$3 groups=$4 method=$5 path=$6 body=${7:-}
  local csrf=""; [ -f "$jar.csrf" ] && csrf=$(cat "$jar.csrf")
  curl -sS --cacert "$CA" --resolve "mp-mongo-portal:$port:127.0.0.1" -b "$jar" -c "$jar" -X "$method" \
    -H "X-Forwarded-User: $user" -H "X-Forwarded-Groups: $groups" -H "X-CSRF-Token: $csrf" \
    ${body:+-H 'Content-Type: application/json' --data "$body"} -w '\n%{http_code}' "https://mp-mongo-portal:$port/api/v1$path"
}
code() { tail -n1; }
json() { sed '$d'; }
start() { api "$1" "$2" "$3" "$4" GET /me | json | jq -r .csrfToken > "$2.csrf"; }

A=18443; B=18444
start $A "$WORK/dana" dana devs
r=$(api $A "$WORK/dana" dana devs POST /session "{\"profile\":\"primary\",\"username\":\"reader\",\"password\":\"$READER_PW\"}")
[ "$(echo "$r" | code)" = 200 ] && ok "SCRAM login on replica A" || bad "login: $r"
echo "$r" | json | jq -r .csrfToken > "$WORK/dana.csrf"
[ "$(api $A "$WORK/dana" dana devs GET /databases | code)" = 200 ] && ok "databases on replica A" || bad "databases"

start $B "$WORK/pat" pat platform
seen=""
for _ in $(seq 1 15); do
  seen=$(api $B "$WORK/pat" pat platform GET "/admin/sessions?user=dana" | json | jq -r '[.sessions[]? | .pod] | join(",")')
  [ -n "$seen" ] && break; sleep 1
done
[ "$seen" = "${PODS[0]}" ] && ok "replica B lists the session held by replica A ($seen)" || bad "registry listing: '$seen'"
owner=$(api $B "$WORK/pat" pat platform GET "/admin/sessions?user=dana" | json | jq -r '.sessions[0].owner')
r=$(api $B "$WORK/pat" pat platform POST /admin/sessions/revoke "{\"owner\":\"$owner\"}")
[ "$(echo "$r" | code)" = 200 ] && ok "revoke on replica B" || bad "revoke: $r"
gone=""
for _ in $(seq 1 15); do
  [ "$(api $A "$WORK/dana" dana devs GET /session | code)" = 401 ] && gone=1 && break; sleep 1
done
[ -n "$gone" ] && ok "the revoked session ends on replica A" || bad "revoked session still active on A"

n=0
for _ in $(seq 1 15); do
  n=$(api $B "$WORK/pat" pat platform GET "/audit?scope=all&action=mongodb_login&user=dana" | json | jq '[.events[]?] | length')
  [ "$n" -ge 1 ] && break; sleep 1
done
[ "$n" -ge 1 ] && ok "durable audit: replica B finds the login made on replica A" || bad "audit events on B: $n"
[ "$(api $B "$WORK/pat" pat platform GET "/audit/verify?pod=${PODS[0]}" | json | jq -r .intact)" = true ] && ok "audit hash chain of replica A verifies" || bad "audit chain"

start $A "$WORK/pat-a" pat platform
r=$(api $A "$WORK/pat-a" pat platform POST /admin/caches/invalidate '{"caches":["rbac-policy","identities"],"scope":"all","confirm":"invalidate"}')
[ "$(echo "$r" | code)" = 200 ] && ok "cache invalidation on replica A" || bad "invalidate: $r"
applied=""
for _ in $(seq 1 20); do
  applied=$(api $B "$WORK/pat" pat platform GET /admin/caches | json | jq -r '[.recent[0].applied[]?.pod] | sort | join(",")')
  [ "$(echo "$applied" | tr ',' '\n' | grep -c .)" = 2 ] && break; sleep 1
done
[ "$(echo "$applied" | tr ',' '\n' | grep -c .)" = 2 ] && ok "both replicas applied the invalidation ($applied)" || bad "applied on: '$applied'"
[ "$(api $A "$WORK/dana" dana devs GET /admin/caches | code)" = 403 ] && ok "a read-only user cannot see caches" || bad "cache RBAC"

echo ">> NetworkPolicy"
probe() {
  k -n "$1" run "probe-$RANDOM" --rm -i --restart=Never --quiet --image="$MONGO_IMAGE" --overrides='{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":1000,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"p","image":"'"$MONGO_IMAGE"'","command":["bash","-c","timeout 6 bash -c \"</dev/tcp/mp-mongo-portal.'"$NS"'.svc/443\" && echo open || echo blocked"],"securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}}]}}' 2>/dev/null | tail -1
}
[ "$(probe portal-e2e-clients)" = open ] && ok "allowed namespace reaches the portal" || bad "allowed namespace blocked"
[ "$(probe outsider)" = blocked ] && ok "other namespaces are blocked" || bad "outsider namespace reached the portal"

echo ">> rolling restart"
start $A "$WORK/erin" erin devs
api $A "$WORK/erin" erin devs POST /session "{\"profile\":\"primary\",\"username\":\"reader\",\"password\":\"$READER_PW\"}" | json | jq -r .csrfToken > "$WORK/erin.csrf"
for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
PIDS=()
k -n $NS rollout restart deploy/mp-mongo-portal >/dev/null
k -n $NS rollout status deploy/mp-mongo-portal --timeout=180s >/dev/null && ok "rolling restart completed with maxUnavailable 0" || bad "rollout restart"
k -n $NS port-forward svc/mp-mongo-portal 18450:443 >/dev/null 2>&1 &
PIDS+=("$!")
sleep 4
c=$(api 18450 "$WORK/erin" erin devs GET /session | code)
[ "$c" = 401 ] && ok "after the restart the MongoDB session ends and the user is asked to reconnect (401)" || bad "session after restart: $c"
# Like the UI: a fresh pre-login CSRF token, then sign in again.
start 18450 "$WORK/erin" erin devs
r=$(api 18450 "$WORK/erin" erin devs POST /session "{\"profile\":\"primary\",\"username\":\"reader\",\"password\":\"$READER_PW\"}")
[ "$(echo "$r" | code)" = 200 ] && ok "reconnect after the restart" || bad "reconnect: $r"

echo ">> kind result: $pass passed, $fail failed"
[ "$fail" = 0 ]
