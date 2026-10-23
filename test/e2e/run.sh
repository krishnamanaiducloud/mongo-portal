#!/usr/bin/env bash
# Browser end-to-end test of the mongosh shell against disposable MongoDB.
#
# Starts MongoDB and the portal image on a private network, then runs
# Playwright/Chromium inside the portal container's network namespace so the
# portal is reached as http://localhost (a secure context, so Secure
# __Host- cookies work). SSO identity is injected as trusted proxy headers;
# one scenario uses no SSO at all (MongoDB-only sign-in).
#
# Usage: run.sh <portal-image>
set -euo pipefail
IMAGE="${1:?portal image}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MONGO_IMAGE="${MONGO_IMAGE:-mongo:8.0}"
PW_IMAGE="${PW_IMAGE:-mcr.microsoft.com/playwright:v1.63.0-noble}"
NET="portal-e2e-$$"
WORK="$(mktemp -d)"
ROOT_PW="$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')"
READER_PW="r$(head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')"
WRITER_PW="w$(head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')"
cleanup() {
  docker rm -f "e2e-mongo-$$" "e2e-portal-$$" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

docker network create "$NET" >/dev/null
docker run -d --name "e2e-mongo-$$" --network "$NET" --network-alias mongo \
  -e MONGO_INITDB_ROOT_USERNAME=root -e MONGO_INITDB_ROOT_PASSWORD="$ROOT_PW" "$MONGO_IMAGE" --wiredTigerCacheSizeGB 0.25 >/dev/null
# The mongo image restarts mongod after creating the root user: wait for that.
for _ in $(seq 1 120); do docker logs "e2e-mongo-$$" 2>&1 | grep -q 'MongoDB init process complete' && break; sleep 1; done
for _ in $(seq 1 60); do docker exec "e2e-mongo-$$" mongosh --quiet -u root -p "$ROOT_PW" --eval 'db.adminCommand({ping:1})' >/dev/null 2>&1 && break; sleep 1; done
docker exec -e READER_PW="$READER_PW" -e WRITER_PW="$WRITER_PW" "e2e-mongo-$$" mongosh --quiet -u root -p "$ROOT_PW" --eval '
  const a = db.getSiblingDB("admin");
  a.createUser({ user: "reader", pwd: process.env.READER_PW, roles: [{ role: "read", db: "app" }] });
  a.createUser({ user: "writer", pwd: process.env.WRITER_PW, roles: [{ role: "readWrite", db: "app" }, { role: "dbAdmin", db: "app" }] });
  const app = db.getSiblingDB("app");
  app.orders.insertMany(Array.from({ length: 30 }, (_, n) => ({ n, sku: "S" + n, created: new Date() })));
' >/dev/null

cat > "$WORK/config.yaml" <<'EOF'
environment: e2e
server:
  listenAddress: 127.0.0.1:8080
  opsListenAddress: 127.0.0.1:9090
identity:
  header:
    enabled: true
  openshift:
    enabled: "false"
rbac:
  policy: |
    g, sres, role:admin
    g, devs, role:readonly
    g, mongodb:writer@admin, role:editor
profiles:
  - name: local
    displayName: E2E MongoDB
    uri: mongodb://mongo:27017/
    tls:
      mode: disabled
EOF
chmod 0644 "$WORK/config.yaml"; chmod 0755 "$WORK"
docker run -d --name "e2e-portal-$$" --network "$NET" --user 1000680000:0 --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges -v "$WORK/config.yaml:/etc/mongo-portal/config.yaml:ro" "$IMAGE" >/dev/null
sleep 3

cp "$HERE/shell.e2e.mjs" "$WORK/"
set +e
docker run --rm --network "container:e2e-portal-$$" --ipc=host \
  -e READER_PW="$READER_PW" -e WRITER_PW="$WRITER_PW" -e PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 -e npm_config_update_notifier=false \
  -v "$WORK:/e2e" -w /e2e "$PW_IMAGE" \
  bash -c 'npm init -y >/dev/null && npm install --no-fund --no-audit --silent playwright@1.63.0 && node shell.e2e.mjs'
status=$?
docker logs "e2e-portal-$$" 2>&1 | grep -E '"level":"(ERROR|WARN)"' | grep -v plaintext | tail -5 || true
exit $status
