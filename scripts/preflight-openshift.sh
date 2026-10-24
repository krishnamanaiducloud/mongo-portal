#!/usr/bin/env bash
# Read-only preflight of a mongo-portal deployment on OpenShift (or
# Kubernetes with OC=kubectl). It only reads: no create, apply, patch,
# delete, restart or scale, and it never prints Secret values (only whether
# a Secret exists). Checks that need a permission the caller lacks are
# reported as BLOCKED, not as failures.
#
# Environment (organization-specific values are never built in):
#   K8S_NAMESPACE              namespace of the portal (required)
#   PORTAL_RELEASE             label app.kubernetes.io/instance, or empty for any
#   PORTAL_EXPECTED_IMAGE      expected image reference (repository@sha256:...), optional
#   PORTAL_PUBLIC_URL          expected public URL (https://host), optional
#   OC                         client binary (default oc)
#   IN_POD_PREFLIGHT=0         skip running "mongo-portal preflight" inside a pod
#
# Usage: K8S_NAMESPACE=<namespace> scripts/preflight-openshift.sh
set -uo pipefail
OC="${OC:-oc}"
NS="${K8S_NAMESPACE:?set K8S_NAMESPACE}"
SEL="app.kubernetes.io/name=mongo-portal${PORTAL_RELEASE:+,app.kubernetes.io/instance=$PORTAL_RELEASE}"
pass=0; warn=0; fail=0; blocked=0
say() { printf '%-8s %-28s %s\n' "$1" "$2" "$3"; }
ok() { pass=$((pass + 1)); say PASS "$1" "$2"; }
wn() { warn=$((warn + 1)); say WARN "$1" "$2"; }
no() { fail=$((fail + 1)); say FAIL "$1" "$2"; }
bl() { blocked=$((blocked + 1)); say BLOCKED "$1" "$2"; }
skip=0
sk() { skip=$((skip + 1)); say SKIP "$1" "$2"; }
# get <check> <args...>: runs a read-only client call and leaves its output
# in OUT. Reports BLOCKED on missing permissions and SKIP for API types this
# cluster does not have (OpenShift types on Kubernetes). Call it directly,
# not in $(...), so that its reports count.
get() {
  local check=$1; shift
  if OUT=$("$OC" "$@" 2>&1); then return 0; fi
  if grep -qiE 'forbidden|unauthorized' <<<"$OUT"; then bl "$check" "no permission: $OC $*"
  elif grep -qiE "doesn't have a resource type|could not find the requested resource|no matches for kind" <<<"$OUT"; then sk "$check" "not available on this cluster"
  else no "$check" "$(head -1 <<<"$OUT")"; fi
  return 1
}

echo "mongo-portal read-only preflight: namespace $NS ($("$OC" whoami 2>/dev/null || echo 'unknown user'))"
echo
if get "cluster version" version -o json; then v=$OUT
  ok "cluster version" "$(jq -r '"server " + (.serverVersion.gitVersion // "?") + (if .openshiftVersion then ", OpenShift " + .openshiftVersion else "" end)' <<<"$v" 2>/dev/null)"
fi
if get "cluster domain" get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}'; then ok "cluster domain" "$OUT"; fi
if get "OAuth identity providers" get oauth.config.openshift.io cluster -o jsonpath='{range .spec.identityProviders[*]}{.name}({.type}) {end}'; then idps=$OUT
  if [ -n "$idps" ]; then ok "OAuth identity providers" "$idps"; else wn "OAuth identity providers" "none configured (only kubeadmin/htpasswd style logins)"; fi
fi
get "namespace" get namespace "$NS" -o name && ok "namespace" "$NS exists"

if get "deployment" -n "$NS" get deploy -l "$SEL" -o json; then deps=$OUT
  n=$(jq '.items | length' <<<"$deps")
  if [ "$n" = 0 ]; then no "deployment" "no Deployment with labels $SEL"; else
    while read -r name ready image; do
      r=${ready%/*}; want=${ready#*/}
      if [ "$r" = "$want" ] && [ "$r" != 0 ]; then ok "deployment $name" "$ready ready"; else no "deployment $name" "$ready ready"; fi
      case "$image" in *@sha256:*) ok "image $name" "$image" ;; *) wn "image $name" "$image is not pinned by digest" ;; esac
      if [ -n "${PORTAL_EXPECTED_IMAGE:-}" ] && [ "$image" != "$PORTAL_EXPECTED_IMAGE" ]; then no "image $name" "expected $PORTAL_EXPECTED_IMAGE"; fi
    done < <(jq -r '.items[] | "\(.metadata.name) \(.status.readyReplicas // 0)/\(.spec.replicas) \(.spec.template.spec.containers[0].image)"' <<<"$deps")
  fi
fi

if get "pods" -n "$NS" get pod -l "$SEL" -o json; then pods=$OUT
  while IFS=$'\t' read -r name phase restarts scc uid rofs esc; do
    if [ "$phase" = Running ]; then ok "pod $name" "Running, $restarts restarts, SCC $scc, UID $uid"; else no "pod $name" "$phase"; fi
    if [ "$rofs" = true ] && [ "$esc" = false ]; then ok "pod $name security" "read-only root filesystem, no privilege escalation"
    else no "pod $name security" "readOnlyRootFilesystem=$rofs allowPrivilegeEscalation=$esc"; fi
  done < <(jq -r '.items[] | [.metadata.name, .status.phase, ((.status.containerStatuses // []) | map(.restartCount) | add // 0 | tostring),
    (.metadata.annotations["openshift.io/scc"] // "-"), ((.spec.securityContext.runAsUser // .spec.containers[0].securityContext.runAsUser // "-") | tostring),
    ((.spec.containers[0].securityContext.readOnlyRootFilesystem // false) | tostring),
    (.spec.containers[0].securityContext.allowPrivilegeEscalation | if . == null then true else . end | tostring)] | @tsv' <<<"$pods")
fi

if get "route" -n "$NS" get route -l "$SEL" -o json; then rt=$OUT
  while read -r name host term admitted; do
    if [ "$term" = reencrypt ]; then ok "route $name" "https://$host ($term, admitted=$admitted)"; else wn "route $name" "https://$host termination $term"; fi
    if [ -n "${PORTAL_PUBLIC_URL:-}" ] && [ "https://$host" != "${PORTAL_PUBLIC_URL%/}" ]; then wn "route $name" "PORTAL_PUBLIC_URL is $PORTAL_PUBLIC_URL"; fi
  done < <(jq -r '.items[] | "\(.metadata.name) \(.spec.host) \(.spec.tls.termination // "none") \(.status.ingress[0].conditions[0].status // "?")"' <<<"$rt")
fi
if get "service" -n "$NS" get svc -l "$SEL" -o json; then svc=$OUT
  while read -r name certsecret; do
    ok "service $name" "serving certificate secret: $certsecret"
  done < <(jq -r '.items[] | "\(.metadata.name) \(.metadata.annotations["service.beta.openshift.io/serving-cert-secret-name"] // "-")"' <<<"$svc")
fi
if get "service account" -n "$NS" get sa -l "$SEL" -o json; then sa=$OUT
  while read -r name refs; do
    if [ "$refs" -gt 0 ]; then ok "service account $name" "OpenShift OAuth client (redirect reference set)"
    else wn "service account $name" "no OAuth redirect reference: OpenShift login is not offered"; fi
  done < <(jq -r '.items[] | "\(.metadata.name) \((.metadata.annotations // {}) | keys | map(select(startswith("serviceaccounts.openshift.io/oauth-redirectreference"))) | length)"' <<<"$sa")
fi

# Secrets and ConfigMaps: existence only (values are never read).
for s in mongo-portal-session mongo-portal-tls mongo-portal-oidc mongo-portal-store mongo-portal-mongodb-client; do
  if out=$("$OC" -n "$NS" get secret "$s" -o name 2>&1); then ok "secret $s" "exists (value not read)";
  elif grep -qi forbidden <<<"$out"; then bl "secret $s" "no permission to check existence";
  elif grep -qi notfound <<<"${out// /}"; then say INFO "secret $s" "not present (optional unless configured)";
  else no "secret $s" "$(head -1 <<<"$out")"; fi
done
if out=$("$OC" -n "$NS" get configmap mongo-portal-mongodb-ca -o name 2>&1); then ok "configmap mongo-portal-mongodb-ca" "exists"
elif ! grep -qi notfound <<<"${out// /}"; then no "configmap mongo-portal-mongodb-ca" "$(head -1 <<<"$out")"
else say INFO "configmap mongo-portal-mongodb-ca" "not present (needed when MongoDB uses a private CA)"; fi
if get "network policies" -n "$NS" get networkpolicy -o jsonpath='{range .items[*]}{.metadata.name} {end}'; then np=$OUT
  if [ -n "$np" ]; then ok "network policies" "$np"; else wn "network policies" "none in $NS"; fi
fi

if [ "${IN_POD_PREFLIGHT:-1}" = 1 ]; then
  pod=$("$OC" -n "$NS" get pod -l "$SEL" --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  if [ -n "$pod" ]; then
    echo
    echo "In-pod preflight ($pod): DNS, MongoDB TLS and topology, identity providers, store; read-only"
    if out=$("$OC" -n "$NS" exec "$pod" -c portal -- /usr/bin/mongo-portal preflight 2>&1); then ok "in-pod preflight" "no failures"
    elif grep -qiE 'forbidden' <<<"$out"; then bl "in-pod preflight" "no permission for pods/exec"
    else no "in-pod preflight" "failures reported below"; fi
    sed 's/^/    /' <<<"$out"
  fi
fi
echo
echo "$pass passed, $warn warnings, $fail failed, $skip skipped, $blocked blocked by permissions"
[ "$fail" = 0 ]
