#!/usr/bin/env bash
# Security scans for the portal. Writes reports to $OUT (default ./reports).
#
# Usage: scripts/security-scan.sh <production-image> <debug-image>
# Requires: go, npm, docker, trivy, grype, syft, gitleaks, hadolint.
# govulncheck and gosec are installed with `go install` when missing.
#
# Exit status is non-zero when a fixable HIGH/CRITICAL vulnerability is
# found in either image, or when govulncheck reports a reachable vulnerability.
set -uo pipefail
PROD="${1:?production image}"
DEBUG="${2:?debug image}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${OUT:-$ROOT/reports}"
mkdir -p "$OUT"
export PATH="$PATH:$(go env GOPATH)/bin"
status=0
section() { printf '\n==== %s\n' "$*"; }

section "govulncheck (Go dependencies + standard library, reachability analysis)"
command -v govulncheck >/dev/null || go install golang.org/x/vuln/cmd/govulncheck@latest
(cd "$ROOT" && govulncheck ./... | tee "$OUT/govulncheck.txt") || status=1

section "gosec (Go SAST)"
command -v gosec >/dev/null || go install github.com/securego/gosec/v2/cmd/gosec@latest
(cd "$ROOT" && gosec -quiet -exclude-dir=test -fmt text ./... | tee "$OUT/gosec.txt") || status=1

section "npm audit (frontend dependencies)"
(cd "$ROOT/web" && npm audit --omit=dev | tee "$OUT/npm-audit-prod.txt"; npm audit | tee "$OUT/npm-audit-all.txt") || status=1

section "gitleaks (secrets in working tree and git history)"
REPO="$(git -C "$ROOT" rev-parse --show-toplevel 2>/dev/null || echo "$ROOT")"
gitleaks dir "$ROOT" --no-banner --redact -r "$OUT/gitleaks-dir.json" && echo "working tree: no leaks" || status=1
if [ -d "$REPO/.git" ]; then
  gitleaks git "$REPO" --no-banner --redact -r "$OUT/gitleaks-history.json" && echo "history: no leaks" || echo "history: findings (see report)"
fi

section "hadolint (Dockerfile)"
hadolint "$ROOT/Dockerfile" | tee "$OUT/hadolint.txt" || status=1

section "trivy config (Dockerfile + Kubernetes manifests)"
DEPLOY="$(cd "$ROOT/examples/kustomize" 2>/dev/null && pwd)"
trivy config --quiet --severity HIGH,CRITICAL --exit-code 0 "$ROOT/Dockerfile" | tee "$OUT/trivy-config-dockerfile.txt"
if [ -n "$DEPLOY" ]; then
  for env in dev test prod; do kubectl kustomize "$DEPLOY/overlays/$env" > "$OUT/rendered-$env.yaml"; done
  trivy config --quiet --severity MEDIUM,HIGH,CRITICAL "$OUT"/rendered-prod.yaml | tee "$OUT/trivy-config-k8s.txt"
fi

section "trivy fs (lockfiles, secrets)"
trivy fs --quiet --scanners vuln,secret --severity HIGH,CRITICAL "$ROOT" | tee "$OUT/trivy-fs.txt"

for v in production:"$PROD" debug:"$DEBUG"; do
  name="${v%%:*}"; img="${v#*:}"
  section "SBOM ($name) - syft SPDX + CycloneDX"
  syft -q "$img" -o spdx-json="$OUT/sbom-$name.spdx.json" -o cyclonedx-json="$OUT/sbom-$name.cdx.json"
  echo "packages: $(jq '.packages | length' "$OUT/sbom-$name.spdx.json")"

  section "trivy image ($name)"
  trivy image --quiet --scanners vuln --format table "$img" | tee "$OUT/trivy-$name.txt"
  trivy image --quiet --scanners vuln --format json -o "$OUT/trivy-$name.json" "$img"
  if ! trivy image --quiet --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 "$img" >/dev/null; then
    echo "FIXABLE HIGH/CRITICAL vulnerabilities in $name"; status=1
  fi

  section "grype ($name)"
  grype -q "sbom:$OUT/sbom-$name.spdx.json" -o table | tee "$OUT/grype-$name.txt"
  grype -q "sbom:$OUT/sbom-$name.spdx.json" --only-fixed --fail-on high >/dev/null || { echo "grype: fixable high+ in $name"; status=1; }
done

section "trivy config (MEDIUM+ details)"
grep -E 'KSV|AVD|MEDIUM|HIGH' "$OUT/trivy-config-k8s.txt" | head -20 || true

section "summary"
for f in "$OUT"/trivy-production.json "$OUT"/trivy-debug.json; do
  printf '%s: ' "$(basename "$f")"
  jq -r '[.Results[]?.Vulnerabilities[]?.Severity] | group_by(.) | map("\(.[0])=\(length)") | join(" ") | if . == "" then "no vulnerabilities" else . end' "$f"
done
exit $status
