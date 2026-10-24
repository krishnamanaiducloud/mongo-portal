#!/usr/bin/env bash
# MONGODB-OIDC end-to-end test against a disposable MongoDB Enterprise
# server. Starts, on a private Docker network:
#   idp        the test OpenID Connect provider (TLS, issuer https://idp:8443)
#   mongooidc  MongoDB Enterprise with SCRAM-SHA-256 and MONGODB-OIDC, TLS
# then runs `go test -tags oidc ./test/oidc` and removes everything.
# MongoDB Enterprise is used here for development testing only.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORTAL="$(cd "$HERE/../.." && pwd)"
NET="portal-oidc-$$"
ENT_IMAGE="${ENT_IMAGE:-mongodb/mongodb-enterprise-server:7.0-ubi8}"
GO_IMAGE="${GO_IMAGE:-cgr.dev/chainguard/go:latest}"
WORK="$(mktemp -d)"
ADMIN_PW="$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')"
GOVOL=(-e HOME=/tmp -e GOCACHE=/tmp/gocache -e GOMODCACHE=/tmp/gomod -e GOFLAGS=-buildvcs=false -v portal-it-gomod:/tmp/gomod -v portal-it-gocache:/tmp/gocache)

cleanup() {
  docker rm -f "idp-$$" "mongooidc-$$" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo ">> generating test PKI"
docker run --rm -u "$(id -u):$(id -g)" "${GOVOL[@]}" -v "$PORTAL:/src:ro" -v "$WORK:/out" -w /src "$GO_IMAGE" \
  run ./test/integration/gencerts -out /out/certs -hosts "mongooidc,idp,localhost"
chmod -R a+r "$WORK/certs"

docker network create "$NET" >/dev/null
echo ">> starting the test identity provider"
docker run -d --name "idp-$$" --network "$NET" --network-alias idp -u "$(id -u):$(id -g)" "${GOVOL[@]}" \
  -v "$PORTAL:/src:ro" -v "$WORK/certs:/certs:ro" -w /src "$GO_IMAGE" \
  run ./test/oidc/idpserver -cert /certs/server.pem -key /certs/server.pem >/dev/null
for _ in $(seq 1 180); do
  if docker logs "idp-$$" 2>&1 | grep -q "test idp listening"; then break; fi
  sleep 1
done
docker logs "idp-$$" 2>&1 | grep -q "test idp listening" || { docker logs "idp-$$"; echo "idp did not start" >&2; exit 1; }

echo ">> starting MongoDB Enterprise ($ENT_IMAGE)"
# mongod fetches the provider's JWKS over TLS: trust the test CA.
docker run -d --name "mongooidc-$$" --hostname mongooidc --network "$NET" --network-alias mongooidc \
  -v "$WORK/certs:/certs:ro" -v "$WORK/certs/ca.crt:/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem:ro" \
  --entrypoint mongod "$ENT_IMAGE" --bind_ip_all --dbpath /data/db --tlsMode requireTLS \
  --tlsCertificateKeyFile /certs/server.pem --tlsCAFile /certs/ca.crt --tlsAllowConnectionsWithoutCertificates --auth \
  --setParameter authenticationMechanisms=SCRAM-SHA-256,MONGODB-OIDC \
  --setParameter 'oidcIdentityProviders=[{"issuer":"https://idp:8443","audience":"mongodb-test","authNamePrefix":"testidp","clientId":"mongo-portal-test","useAuthorizationClaim":false,"supportsHumanFlows":true,"requestScopes":["offline_access"]}]' >/dev/null

msh() { timeout 30 docker exec "mongooidc-$$" mongosh --quiet --tls --host mongooidc --tlsCAFile /certs/ca.crt "$@"; }
for _ in $(seq 1 60); do if msh --eval 'db.adminCommand({ping:1})' >/dev/null 2>&1; then break; fi; sleep 2; done
msh --eval 'db.adminCommand({ping:1})' >/dev/null || { docker logs "mongooidc-$$" | tail -30; exit 1; }

echo ">> creating users"
# The first user is created through the localhost exception.
docker exec -e ADMIN_PW="$ADMIN_PW" "mongooidc-$$" mongosh --quiet --tls --host localhost --tlsCAFile /certs/ca.crt --eval '
const a = db.getSiblingDB("admin");
a.createUser({user:"root", pwd:process.env.ADMIN_PW, roles:["root"]});
a.auth("root", process.env.ADMIN_PW);
a.createUser({user:"scramuser", pwd:"scram-pw", roles:[{role:"read", db:"app"}], mechanisms:["SCRAM-SHA-256"]});
db.getSiblingDB("$external").createUser({user:"testidp/u-1001", roles:[{role:"read", db:"app"}]});
a.getSiblingDB("app").orders.insertMany([{_id:1, total:5}, {_id:2, total:7}]);
'

echo ">> running MONGODB-OIDC tests"
docker run --rm --network "$NET" -u "$(id -u):$(id -g)" "${GOVOL[@]}" \
  -v "$PORTAL:/src:ro" -v "$WORK/certs:/certs:ro" -w /src "$GO_IMAGE" \
  test -tags oidc -count=1 -v ./test/oidc/... 2>&1 | tee "$WORK/test.log"
status=${PIPESTATUS[0]}
if [ "$status" -ne 0 ]; then docker logs "mongooidc-$$" 2>&1 | grep -iE 'oidc|jwks|auth' | tail -20 || true; fi
grep -E '^(--- |ok|FAIL|PASS)' "$WORK/test.log" || true
exit "$status"
