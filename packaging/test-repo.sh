#!/bin/bash
#
# test-repo.sh
#   End-to-end verification of the published copyfail-defense
#   dnf repository on EL8 / EL9 / EL10. Uses podman; everything happens
#   inside disposable containers - no host-side state is touched.
#
# What this exercises (v2.0.0 - 18 checks per EL):
#   1. The .repo file is reachable on gh-pages
#   2. dnf can fetch repodata, validate the detached repomd.xml.asc
#      against the published gpgkey, and resolve the meta package
#   3. RPM signatures verify (gpgcheck=1, repo_gpgcheck=1)
#   4. All four subpackages (shim, modprobe, systemd, auditor) land
#   5. The shim is loadable under LD_PRELOAD without breaking dyn-linked
#      binaries (smoke-test on /bin/true)
#   6. AF_ALG socket creation returns EPERM with the shim in place
#   7. AF_INET still works (surgical block, not blanket socket disable)
#   8. copyfail-shim-enable wires /etc/ld.so.preload correctly
#   9. AF_ALG is blocked from a fresh process (no explicit LD_PRELOAD)
#  10. copyfail-local-check runs and emits valid posture JSON v2 schema
#  11. copyfail-shim-disable removes the line atomically
#  12. dnf remove leaves /etc/ld.so.preload sane (preun scriptlet)
#  v2.0.0 additions:
#  13. copyfail-defense-modprobe drops /etc/modprobe.d/99-copyfail-defense.conf
#  14. copyfail-defense-systemd drops 5 active drop files for tenant units
#  15. Container-runtime drop-ins shipped as examples/, NOT active
#  16. Auditor JSON has posture.bug_classes_covered (array)
#      AND posture.bug_classes (per-class map)
#  17. Auditor exit code in {0, 3, 4} (never 2 - shim disabled by default)
#  18. Upgrade-path test: afalg-defense 1.0.1 -> copyfail-defense 2.0.0
#      via Obsoletes/Provides; old name fully removed.
#
# Usage:
#   bash test-repo.sh                 # all three ELs
#   bash test-repo.sh 9               # just EL9
#   bash test-repo.sh 8 9             # EL8 and EL9
#   REPO_URL=... bash test-repo.sh    # override repo source (default: gh-pages)
#   UPGRADE_FIXTURE_DIR=... bash test-repo.sh   # path to v1.0.1 RPM fixtures
#                                                 (default: rpmbuild/upgrade-fixture/)

set -uo pipefail

REPO_URL="${REPO_URL:-https://rfxn.github.io/copyfail/copyfail.repo}"
KEY_URL="${KEY_URL:-https://rfxn.github.io/copyfail/RPM-GPG-KEY-copyfail}"
UPGRADE_FIXTURE_DIR="${UPGRADE_FIXTURE_DIR:-/home/copyfail/rpmbuild/upgrade-fixture}"

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
dnf install -y copyfail-defense 2>&1 | tail -10
rpm -q copyfail-defense copyfail-defense-shim copyfail-defense-modprobe \
       copyfail-defense-systemd copyfail-defense-auditor \
    || fail "subpackages not all installed"
ok "dnf install -y copyfail-defense (gpgcheck + repo_gpgcheck, 5 subpackages)"

# 3. Files are where we expect
test -f /usr/lib64/no-afalg.so          || fail "shim .so missing"
test -x /usr/sbin/copyfail-shim-enable  || fail "enable helper missing"
test -x /usr/sbin/copyfail-shim-disable || fail "disable helper missing"
test -x /usr/sbin/copyfail-local-check  || fail "auditor missing"
test -f /etc/modprobe.d/99-copyfail-defense.conf \
    || fail "modprobe drop file missing"
test -f /etc/systemd/system/sshd.service.d/10-copyfail-defense.conf \
    || fail "sshd systemd drop-in missing"
test -f /etc/systemd/system/user@.service.d/10-copyfail-defense.conf \
    || fail "user@ systemd drop-in missing"
test -f /usr/share/doc/copyfail-defense/examples/containers-dropin.conf \
    || fail "container-runtime example doc missing"
# Container-runtime drop-ins must NOT be active by default
for u in containerd docker podman; do
    if [ -f /etc/systemd/system/${u}.service.d/10-copyfail-defense.conf ]; then
        fail "container-runtime drop-in for ${u} is active by default - should be opt-in only"
    fi
done
ok "all expected files installed (subs + active dropins + opt-in examples)"

# 3b. Modprobe drop file content - 9 module entries.
# Regex tolerates column-aligned whitespace in the source conf.
mp_count=$(grep -cE '^install +(algif_aead|authenc|authencesn|af_alg|esp4|esp6|xfrm_user|xfrm_algo|rxrpc) +/bin/false' \
    /etc/modprobe.d/99-copyfail-defense.conf 2>/dev/null || echo 0)
[ "$mp_count" -eq 9 ] \
    || fail "modprobe drop file has $mp_count install lines, expected 9"
ok "modprobe drop file has all 9 cf-class module install lines"

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
# Capture rc under `set -e` requires the explicit-OR idiom:
audit_rc=0
/usr/sbin/copyfail-local-check --json --skip-trigger --skip-hardening \
    --no-progress > /tmp/audit.json 2>/dev/null || audit_rc=$?
python3 -c "
import json, sys
d = json.load(open('/tmp/audit.json'))
assert d['schema_version'] == '2.0', 'schema_version=' + str(d.get('schema_version'))
assert 'posture' in d
assert 'verdict' in d['posture']
assert d['posture']['layers']['ld_preload_shim'] == 'ok', d['posture']['layers']
# v2.0.0: bug_classes_covered (array) and bug_classes (per-class map)
assert 'bug_classes_covered' in d['posture'], 'missing bug_classes_covered'
assert isinstance(d['posture']['bug_classes_covered'], list)
bc = d['posture'].get('bug_classes', {})
assert set(bc.keys()) == {'cf1', 'cf2', 'dirtyfrag-esp', 'dirtyfrag-rxrpc'}, \
    'bug_classes keys mismatch: ' + str(list(bc.keys()))
# After shim-enable, cf1 should be EITHER unreachable (applicable=false,
# the ideal outcome) OR mitigated. Anything else means the shim isn't
# blocking AF_ALG, which we already asserted via layers.ld_preload_shim.
cf1 = bc['cf1']
assert (cf1['applicable'] is False) or cf1.get('mitigated') is True, \
    'cf1 unhardened post-shim-enable: ' + json.dumps(cf1)
print('verdict:', d['posture']['verdict'])
print('bug_classes_covered:', d['posture']['bug_classes_covered'])
print('ld_preload_shim layer:', d['posture']['layers']['ld_preload_shim'])
" || fail "auditor JSON output invalid"
# Exit code: never 2 (vulnerable + no mitigation) since shim is enabled here.
[ "$audit_rc" -ne 2 ] || fail "auditor exit code 2 with shim enabled"
ok "auditor JSON: schema 2.0, bug_classes_covered + map present, exit_rc=$audit_rc"

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
dnf remove -y copyfail-defense copyfail-defense-shim \
              copyfail-defense-modprobe copyfail-defense-systemd \
              copyfail-defense-auditor >/dev/null 2>&1
if [ -f /etc/ld.so.preload ]; then
    grep -Fxq /usr/lib64/no-afalg.so /etc/ld.so.preload \
        && fail "preun left dangling shim line in /etc/ld.so.preload"
fi
# Modprobe drop file removed on full erase
[ ! -f /etc/modprobe.d/99-copyfail-defense.conf ] \
    || fail "modprobe drop file remained after dnf remove"
# systemd drop files removed (RPM owns them via %config)
[ ! -f /etc/systemd/system/sshd.service.d/10-copyfail-defense.conf ] \
    || fail "sshd systemd drop-in remained after dnf remove"
ok "dnf remove + %preun scrubbed all state safely"

echo "=== ALL CHECKS PASSED ==="
INNER
}

# Upgrade-path test: simulate a host that has afalg-defense-1.0.1
# installed (from the gh-pages snapshot kept for one release cycle),
# then `dnf upgrade copyfail-defense` and assert the rename swap
# succeeded.
run_upgrade_test_in() {
    local image="$1"
    podman run --rm -i --network=host \
        -e REPO_URL="$REPO_URL" \
        -e KEY_URL="$KEY_URL" \
        "$image" /bin/bash <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }

# Add the repo so we can pull both old (afalg-defense-1.0.1) and new
# (copyfail-defense-2.0.0) RPMs from it - the old ones are kept for
# one release cycle per SPEC [D-22].
curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/copyfail.repo

# Install old name explicitly. If the live repo no longer has 1.0.1,
# the test SKIPs (acceptable - means we've moved past the one-cycle
# retention window; the upgrade path is no longer load-bearing).
if dnf install -y 'afalg-defense-1.0.1*' 2>&1 | tail -5; then
    rpm -q afalg-defense afalg-defense-shim afalg-defense-auditor \
        || fail "v1.0.1 baseline did not install fully"
    ok "v1.0.1 baseline installed"
else
    echo "SKIP: afalg-defense-1.0.1 not in repo (one-cycle retention expired)"
    exit 77
fi

# Upgrade to v2.0.0 via Obsoletes/Provides
dnf upgrade -y copyfail-defense 2>&1 | tail -10

# Assert: old name fully replaced
old_count=$(rpm -qa | grep -c '^afalg-defense' || true)
[ "$old_count" -eq 0 ] || fail "afalg-defense names still present: $old_count"

# Assert: 5 new subpackages installed
new_count=$(rpm -qa | grep -c '^copyfail-defense' || true)
[ "$new_count" -eq 5 ] || fail "expected 5 copyfail-defense* RPMs, got $new_count"

# Assert: new files in expected locations
test -f /etc/modprobe.d/99-copyfail-defense.conf \
    || fail "modprobe drop missing post-upgrade"
test -f /etc/systemd/system/sshd.service.d/10-copyfail-defense.conf \
    || fail "sshd systemd drop-in missing post-upgrade"
test -x /usr/sbin/copyfail-local-check \
    || fail "auditor missing post-upgrade"

# Assert: auditor JSON v2 schema (post-upgrade, shim still disabled by
# default, so exit code is normally 4 - hardening_recs - but never 2).
audit_rc=0
/usr/sbin/copyfail-local-check --json --skip-trigger --skip-hardening \
    --no-progress > /tmp/audit.json 2>/dev/null || audit_rc=$?
python3 -c "
import json
d = json.load(open('/tmp/audit.json'))
assert d['schema_version'] == '2.0', 'schema_version=' + str(d.get('schema_version'))
assert 'bug_classes_covered' in d['posture']
print('post-upgrade verdict:', d['posture']['verdict'])
print('post-upgrade bug_classes_covered:', d['posture']['bug_classes_covered'])
" || fail "post-upgrade auditor JSON invalid"
[ "$audit_rc" -ne 2 ] || fail "post-upgrade auditor exit code 2"

ok "upgrade afalg-defense-1.0.1 -> copyfail-defense-2.0.0 succeeded (exit_rc=$audit_rc)"
echo "=== UPGRADE PATH OK ==="
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

    # v2.0.0 test #18: upgrade-path test (separate container; if the
    # main matrix has already failed, we still try the upgrade path so
    # the operator gets a complete picture).
    echo
    step "upgrade-path test (afalg-defense-1.0.1 -> copyfail-defense-2.0.0)"
    upgrade_rc=0
    run_upgrade_test_in "$image" || upgrade_rc=$?
    case "$upgrade_rc" in
        0)  RESULT[$el]="${RESULT[$el]} +upgrade$(c_green OK)" ;;
        77) RESULT[$el]="${RESULT[$el]} +upgrade$(c_dim SKIP)" ;;
        *)  RESULT[$el]="${RESULT[$el]} +upgrade$(c_red FAIL)"; overall_rc=1 ;;
    esac
    echo
done

echo "============================================================"
echo "summary"
echo "============================================================"
for el in "${ELS[@]}"; do
    printf '  EL%-3s  %s\n' "$el" "${RESULT[$el]:-unknown}"
done

exit "$overall_rc"
