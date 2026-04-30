#!/bin/bash
#
# test-repo.sh
#   End-to-end verification of the published copyfail / afalg-defense
#   dnf repository on EL8 / EL9 / EL10. Uses podman; everything happens
#   inside disposable containers - no host-side state is touched.
#
# What this exercises:
#   1. The .repo file is reachable on gh-pages
#   2. dnf can fetch repodata, validate the detached repomd.xml.asc
#      against the published gpgkey, and resolve the meta package
#   3. RPM signatures verify (gpgcheck=1, repo_gpgcheck=1)
#   4. All three subpackages land on the right paths
#   5. The shim is loadable under LD_PRELOAD without breaking dyn-linked
#      binaries (smoke-test on /bin/true)
#   6. AF_ALG socket creation returns EPERM with the shim in place
#   7. AF_INET still works (surgical block, not blanket socket disable)
#   8. copyfail-shim-enable wires /etc/ld.so.preload correctly
#   9. AF_ALG is blocked from a fresh process (no explicit LD_PRELOAD)
#  10. copyfail-local-check runs and emits valid posture JSON
#  11. copyfail-shim-disable removes the line atomically
#  12. dnf remove leaves /etc/ld.so.preload sane (preun scriptlet)
#
# Usage:
#   bash test-repo.sh                 # all three ELs
#   bash test-repo.sh 9               # just EL9
#   bash test-repo.sh 8 9             # EL8 and EL9
#   REPO_URL=... bash test-repo.sh    # override repo source (default: gh-pages)

set -uo pipefail

REPO_URL="${REPO_URL:-https://rfxn.github.io/copyfail/copyfail.repo}"
KEY_URL="${KEY_URL:-https://rfxn.github.io/copyfail/RPM-GPG-KEY-copyfail}"

ELS=("$@")
if [ "${#ELS[@]}" -eq 0 ]; then
    ELS=(8 9 10)
fi

# RHEL stand-ins. CentOS Stream 8 went EOL May 2024 and its baked-in
# mirrorlist URLs no longer resolve, so we use AlmaLinux for EL8 and
# CentOS Stream for EL9/EL10 (both still actively maintained and the
# closest free analogues to their RHEL counterparts).
declare -A IMAGE
IMAGE[8]="docker.io/library/almalinux:8"
IMAGE[9]="quay.io/centos/centos:stream9"
IMAGE[10]="quay.io/centos/centos:stream10"

c_red()   { printf '\033[31m%s\033[0m' "$*"; }
c_green() { printf '\033[32m%s\033[0m' "$*"; }
c_dim()   { printf '\033[2m%s\033[0m' "$*"; }

step() {
    printf '  %s %s\n' "$(c_dim '·')" "$*"
}

# Each test runs inside the container. Returns 0 = pass, non-zero = fail.
# We trap output and let the caller decide PASS/FAIL.
run_test_in() {
    local image="$1"
    podman run --rm -i --network=host \
        -e REPO_URL="$REPO_URL" \
        -e KEY_URL="$KEY_URL" \
        "$image" /bin/bash <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }

# 0. Distro identity
. /etc/os-release
ok "running on $PRETTY_NAME"

# 1. Add the dnf repo
curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/copyfail.repo \
    || fail "could not fetch $REPO_URL"
ok "fetched copyfail.repo"

# 2. Install. Tests gpgkey import, repo_gpgcheck on repomd.xml, and
#    gpgcheck on each RPM in one shot.
dnf install -y python3 >/dev/null 2>&1 || true
dnf install -y afalg-defense 2>&1 | tail -8
rpm -q afalg-defense afalg-defense-shim afalg-defense-auditor \
    || fail "subpackages not all installed"
ok "dnf install -y afalg-defense (gpgcheck + repo_gpgcheck)"

# 3. Files are where we expect
test -f /usr/lib64/no-afalg.so          || fail "shim .so missing"
test -x /usr/sbin/copyfail-shim-enable  || fail "enable helper missing"
test -x /usr/sbin/copyfail-shim-disable || fail "disable helper missing"
test -x /usr/sbin/copyfail-local-check  || fail "auditor missing"
ok "all expected files installed"

# 4. Shim loads under LD_PRELOAD without breaking dyn-linked binaries
LD_PRELOAD=/usr/lib64/no-afalg.so /bin/true \
    || fail "LD_PRELOAD smoke-test on /bin/true failed"
ok "LD_PRELOAD smoke-test passed"

# 5. AF_ALG -> EPERM with shim
out=$(LD_PRELOAD=/usr/lib64/no-afalg.so python3 -c \
    "import socket
try:
    socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    print('UNBLOCKED')
except PermissionError:
    print('BLOCKED')" 2>&1)
[ "$out" = "BLOCKED" ] || fail "AF_ALG not blocked under LD_PRELOAD: $out"
ok "AF_ALG blocked (EPERM) with shim"

# 6. AF_INET still works (surgical block)
LD_PRELOAD=/usr/lib64/no-afalg.so python3 -c \
    "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.close()" \
    || fail "AF_INET broken under shim - shim is NOT surgical"
ok "AF_INET still works (surgical block confirmed)"

# 7. copyfail-shim-enable
/usr/sbin/copyfail-shim-enable >/tmp/enable.log 2>&1 \
    || { cat /tmp/enable.log; fail "copyfail-shim-enable returned non-zero"; }
grep -Fxq /usr/lib64/no-afalg.so /etc/ld.so.preload \
    || fail "/etc/ld.so.preload does not contain shim line"
ok "copyfail-shim-enable wired /etc/ld.so.preload"

# 8. AF_ALG blocked WITHOUT explicit LD_PRELOAD now (preload took)
out=$(python3 -c \
    "import socket
try:
    socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    print('UNBLOCKED')
except PermissionError:
    print('BLOCKED')" 2>&1)
[ "$out" = "BLOCKED" ] || fail "AF_ALG not blocked via /etc/ld.so.preload: $out"
ok "AF_ALG blocked via /etc/ld.so.preload (no explicit LD_PRELOAD needed)"

# 9. Auditor runs and emits posture JSON. --skip-trigger to avoid the
#    live AF_ALG probe (we just verified that path manually).
/usr/sbin/copyfail-local-check --json --skip-trigger --skip-hardening \
    --no-progress > /tmp/audit.json 2>/dev/null
python3 -c "
import json, sys
d = json.load(open('/tmp/audit.json'))
assert d['schema_version'] == '1.1', d
assert 'posture' in d
assert 'verdict' in d['posture']
assert d['posture']['layers']['ld_preload_shim'] == 'ok', d['posture']['layers']
print('verdict:', d['posture']['verdict'])
print('ld_preload_shim layer:', d['posture']['layers']['ld_preload_shim'])
" || fail "auditor JSON output invalid or shim layer != ok"
ok "auditor reports ld_preload_shim layer ok"

# 10. copyfail-shim-disable
/usr/sbin/copyfail-shim-disable >/tmp/disable.log 2>&1 \
    || { cat /tmp/disable.log; fail "copyfail-shim-disable returned non-zero"; }
if [ -f /etc/ld.so.preload ] && grep -Fxq /usr/lib64/no-afalg.so /etc/ld.so.preload; then
    fail "shim line still in /etc/ld.so.preload after disable"
fi
ok "copyfail-shim-disable removed the line atomically"

# 11. dnf remove. The %preun scriptlet should be a no-op now (we already
#    disabled), but if the operator forgot, the scriptlet must still
#    leave /etc/ld.so.preload sane.
echo "/usr/lib64/no-afalg.so" > /etc/ld.so.preload   # simulate forgotten enable
dnf remove -y afalg-defense afalg-defense-shim afalg-defense-auditor >/dev/null 2>&1
if [ -f /etc/ld.so.preload ]; then
    grep -Fxq /usr/lib64/no-afalg.so /etc/ld.so.preload \
        && fail "preun left dangling shim line in /etc/ld.so.preload"
fi
ok "dnf remove + %preun scrubbed /etc/ld.so.preload safely"

echo "=== ALL CHECKS PASSED ==="
INNER
}

# Sanity: verify the live URLs are reachable BEFORE we burn container time.
echo "Probing $REPO_URL ..."
http_code=$(curl -sSI -o /dev/null -w '%{http_code}' "$REPO_URL")
if [ "$http_code" != "200" ]; then
    echo "$(c_red FATAL): repo file at $REPO_URL returned HTTP $http_code"
    exit 2
fi
echo "  $(c_green ok)  HTTP 200"

echo "Probing $KEY_URL ..."
http_code=$(curl -sSI -o /dev/null -w '%{http_code}' "$KEY_URL")
if [ "$http_code" != "200" ]; then
    echo "$(c_red FATAL): public key at $KEY_URL returned HTTP $http_code"
    exit 2
fi
echo "  $(c_green ok)  HTTP 200"
echo

# Run each EL
declare -A RESULT
overall_rc=0
for el in "${ELS[@]}"; do
    if [ -z "${IMAGE[$el]:-}" ]; then
        echo "$(c_red SKIP) EL$el: no image mapped"
        RESULT[$el]="skip"
        continue
    fi
    image="${IMAGE[$el]}"
    echo "============================================================"
    echo "EL$el ($image)"
    echo "============================================================"

    # Pre-pull so we can fail loud on registry issues.
    if ! podman pull -q "$image" >/dev/null 2>&1; then
        echo "$(c_red FAIL): could not pull $image"
        RESULT[$el]="pull-fail"
        overall_rc=1
        echo
        continue
    fi
    step "image pulled"

    if run_test_in "$image"; then
        RESULT[$el]="$(c_green PASS)"
    else
        RESULT[$el]="$(c_red FAIL)"
        overall_rc=1
    fi
    echo
done

echo "============================================================"
echo "summary"
echo "============================================================"
for el in "${ELS[@]}"; do
    printf '  EL%-3s  %s\n' "$el" "${RESULT[$el]:-unknown}"
done

exit "$overall_rc"
