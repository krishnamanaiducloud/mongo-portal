#!/usr/bin/env bash
# Runs the integration test suite against disposable MongoDB containers.
#
# Starts, on a private Docker network:
#   rs1, rs2, rs3  three-member replica set "rs0" with authentication, no TLS
#   mongotls       one-member replica set "rstls", requireTLS + client certificates
# then runs `go test -tags integration` in a Go container on the same network
# and removes everything afterwards. It never touches any other MongoDB.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORTAL="$(cd "$HERE/../.." && pwd)"
NET="portal-it-$$"
MONGO_IMAGE="${MONGO_IMAGE:-mongo:8.0}"
GO_IMAGE="${GO_IMAGE:-cgr.dev/chainguard/go:latest}"
WORK="$(mktemp -d)"
ADMIN_PW="$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')"
CONTAINERS=(rs1 rs2 rs3 mongotls)

cleanup() {
  for c in "${CONTAINERS[@]}"; do docker rm -f "$c-$$" >/dev/null 2>&1 || true; done
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo ">> generating test PKI"
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -e GOCACHE=/tmp/gocache -e GOMODCACHE=/tmp/gomod -e GOFLAGS=-buildvcs=false -v portal-it-gomod:/tmp/gomod -v portal-it-gocache:/tmp/gocache \
  -v "$PORTAL:/src:ro" -v "$WORK:/out" -w /src "$GO_IMAGE" \
  run ./test/integration/gencerts -out /out/certs -hosts "mongotls-$$,mongotls,localhost"
head -c 756 /dev/urandom | base64 -w0 > "$WORK/keyfile"
chmod 0400 "$WORK/keyfile"

docker network create "$NET" >/dev/null
start_mongod() { # name, extra args...
  local name="$1"; shift
  docker run -d --name "$name-$$" --hostname "$name" --network "$NET" --network-alias "$name" \
    -v "$WORK/keyfile:/kf.src:ro" -v "$WORK/certs:/certs:ro" \
    --entrypoint bash "$MONGO_IMAGE" -c \
    "cp /kf.src /tmp/kf && chown mongodb /tmp/kf && chmod 400 /tmp/kf && exec gosu mongodb mongod --bind_ip_all --keyFile /tmp/kf --wiredTigerCacheSizeGB 0.25 $*" >/dev/null
}

echo ">> starting MongoDB containers"
for n in rs1 rs2 rs3; do start_mongod "$n" --replSet rs0; done
start_mongod mongotls --replSet rstls --tlsMode requireTLS --tlsCertificateKeyFile /certs/server.pem --tlsCAFile /certs/ca.crt
# Second network alias that is NOT in the server certificate (hostname mismatch test).
docker network disconnect "$NET" "mongotls-$$"
docker network connect --alias mongotls --alias mongotls-wrongname "$NET" "mongotls-$$"

msh() { local c="$1"; shift; docker exec "$c-$$" mongosh --quiet "$@"; }
mtls() { msh mongotls --tls --host localhost --tlsCAFile /certs/ca.crt --tlsCertificateKeyFile /certs/client.pem "$@"; }

wait_for() { # description, command...
  local d="$1"; shift
  for _ in $(seq 1 90); do if "$@" >/dev/null 2>&1; then return 0; fi; sleep 1; done
  echo "timeout waiting for $d" >&2; exit 1
}
wait_for "rs1" msh rs1 --eval 'db.adminCommand({ping:1})'
wait_for "rs2" msh rs2 --eval 'db.adminCommand({ping:1})'
wait_for "rs3" msh rs3 --eval 'db.adminCommand({ping:1})'
wait_for "mongotls" mtls --eval 'db.adminCommand({ping:1})'

echo ">> initiating replica sets"
msh rs1 --eval 'rs.initiate({_id:"rs0",members:[{_id:0,host:"rs1:27017",priority:2},{_id:1,host:"rs2:27017"},{_id:2,host:"rs3:27017"}]})'
mtls --eval 'rs.initiate({_id:"rstls",members:[{_id:0,host:"mongotls:27017"}]})'
wait_for "rs0 primary" msh rs1 --eval 'if(!db.hello().isWritablePrimary) quit(1)'
wait_for "rstls primary" mtls --eval 'if(!db.hello().isWritablePrimary) quit(1)'

USERS_JS='
const a = db.getSiblingDB("admin");
a.createUser({user:"root", pwd:process.env.ADMIN_PW, roles:["root"]});
a.auth("root", process.env.ADMIN_PW);
a.createUser({user:"reader", pwd:"reader-pw", roles:[{role:"read", db:"app"}], mechanisms:["SCRAM-SHA-256"]});
a.createUser({user:"writer", pwd:"writer-pw", roles:[{role:"readWrite", db:"app"},{role:"dbAdmin", db:"app"},{role:"readWrite", db:"scratch"},{role:"dbAdmin", db:"scratch"}]});
a.createUser({user:"legacy", pwd:"legacy-pw", roles:[{role:"read", db:"app"}], mechanisms:["SCRAM-SHA-1"]});
a.createUser({user:"monitor", pwd:"monitor-pw", roles:[{role:"clusterMonitor", db:"admin"},{role:"read", db:"app"}]});
a.createUser({user:"opsadmin", pwd:"opsadmin-pw", roles:[{role:"clusterMonitor", db:"admin"},{role:"hostManager", db:"admin"}]});
a.createUser({user:"portalstore", pwd:"portalstore-pw", roles:[{role:"readWrite", db:"mongo_portal"}]});
db.getSiblingDB("app").createUser({user:"appuser", pwd:"appuser-pw", roles:[{role:"read", db:"app"}]});
const app = a.getSiblingDB("app");
app.orders.insertMany([
  {_id: 1, status: "A", total: NumberDecimal("10.50"), created: new Date(0), tags: ["x"]},
  {_id: 2, status: "B", total: NumberDecimal("3.00"), created: new Date(), nested: {a: {b: 1}}},
  {_id: 3, status: "A", total: NumberDecimal("7.25"), bin: BinData(0, "AAEC"), uuid: UUID()}
]);
app.orders.createIndex({status: 1});
'
echo ">> creating users and fixtures"
docker exec -e ADMIN_PW="$ADMIN_PW" "rs1-$$" mongosh --quiet --eval "$USERS_JS"
docker exec -e ADMIN_PW="$ADMIN_PW" "mongotls-$$" mongosh --quiet --tls --host localhost --tlsCAFile /certs/ca.crt --tlsCertificateKeyFile /certs/client.pem --eval "$USERS_JS"

echo ">> running integration tests"
docker run --rm --network "$NET" -u "$(id -u):$(id -g)" \
  -e HOME=/tmp -e GOCACHE=/tmp/gocache -e GOMODCACHE=/tmp/gomod -e GOFLAGS=-buildvcs=false -v portal-it-gomod:/tmp/gomod -v portal-it-gocache:/tmp/gocache \
  -e IT_RS_URI="mongodb://rs1:27017,rs2:27017,rs3:27017/?replicaSet=rs0" \
  -e IT_TLS_URI="mongodb://mongotls:27017/?replicaSet=rstls" \
  -e IT_TLS_WRONGNAME_URI="mongodb://mongotls-wrongname:27017/?directConnection=true" \
  -e IT_CERTS=/certs -e IT_ADMIN_PW="$ADMIN_PW" \
  -v "$PORTAL:/src:ro" -v "$WORK/certs:/certs:ro" -w /src "$GO_IMAGE" \
  test -tags integration -count=1 -v ./test/integration/... 2>&1 | tee "$WORK/test.log"
status=${PIPESTATUS[0]}
grep -E '^(--- |ok|FAIL|PASS)' "$WORK/test.log" || true
exit "$status"
