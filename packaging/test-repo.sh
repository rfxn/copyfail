#!/bin/bash
# shellcheck disable=SC2317
#
# test-repo.sh
#   End-to-end verification of the published copyfail-defense
#   dnf repository on EL8 / EL9 / EL10. Uses podman; everything happens
#   inside disposable containers - no host-side state is touched.
#
# What this exercises (v2.0.1 fixup pass - 27 checks per EL):
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
#  13. copyfail-defense-modprobe drops split modprobe conf files (cf1/cf2-xfrm/rxrpc)
#  14. copyfail-defense-systemd drops 5 active drop files for tenant units
#  15. Container-runtime drop-ins shipped as examples/, NOT active
#  16. Auditor JSON has posture.bug_classes_covered (array)
#      AND posture.bug_classes (per-class map)
#  17. Auditor exit code in {0, 3, 4} (never 2 - shim disabled by default)
#  18. Upgrade-path test: afalg-defense 1.0.1 -> copyfail-defense 2.0.0
#      via Obsoletes/Provides; old name fully removed.
#  v2.0.1 additions:
#  19. clean_host: all 3 modprobe + 10 systemd files present; auto-detect.json clean
#  20. ipsec_host: cf2-xfrm correctly suppressed; JSON flags ipsec; signals[] has 2 entries (M-1 canary)
#  21. afs_host: rxrpc + rxrpc-af suppressed across all 5 units; JSON flags afs
#  22. rootless_host: user@ 15-userns suppressed; 12-rxrpc-af applied; JSON correct
#  23. subuid_no_storage: subuid+passwd alone does NOT trip rootless detection (cPanel FP)
#  24. force_full: all mitigations applied despite all signals tripping
#  25. redetect: post-install AFS signal triggers correct refresh via copyfail-redetect
#  26. split_upgrade: v2.0.0->v2.0.1 pretrans correctly renames monolithic files
#  v2.0.1 fixup-pass additions:
#  27. systemd_only: install -systemd alone still pulls meta; detect.sh runs (M-2 canary)
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
for f in cf1 cf2-xfrm rxrpc; do
    test -f "/etc/modprobe.d/99-copyfail-defense-${f}.conf" \
        || fail "modprobe ${f} drop file missing"
done
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
mp_count=$(grep -chE '^install +(algif_aead|authenc|authencesn|af_alg|esp4|esp6|xfrm_user|xfrm_algo|rxrpc) +/bin/false' \
    /etc/modprobe.d/99-copyfail-defense-{cf1,cf2-xfrm,rxrpc}.conf 2>/dev/null || echo 0)
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
# Modprobe drop files removed on full erase
for f in cf1 cf2-xfrm rxrpc; do
    [ ! -f "/etc/modprobe.d/99-copyfail-defense-${f}.conf" ] \
        || fail "modprobe ${f} drop file remained after dnf remove"
done
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
test -f /etc/modprobe.d/99-copyfail-defense-cf1.conf \
    || fail "modprobe cf1 drop missing post-upgrade"
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

# v2.0.1: detection scenario tests. Each pre-stages a workload
# fingerprint, installs copyfail-defense, and asserts the right
# conditional drop files landed/didn't.

run_clean_host_test_in() {
    local image="$1"
    podman run --rm -i --network=host \
        -e REPO_URL="$REPO_URL" -e KEY_URL="$KEY_URL" \
        "$image" /bin/bash <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }

curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/copyfail.repo
dnf install -y python3 jq >/dev/null 2>&1 || true
dnf install -y copyfail-defense 2>&1 | tail -5

# All 3 modprobe files present
for f in cf1 cf2-xfrm rxrpc; do
    test -f "/etc/modprobe.d/99-copyfail-defense-${f}.conf" \
        || fail "modprobe ${f} drop missing on clean host"
done
# All 5 always-on (10-) drop files
for u in user@ sshd cron crond atd; do
    test -f "/etc/systemd/system/${u}.service.d/10-copyfail-defense.conf" \
        || fail "10-* drop missing for ${u}"
done
# All 5 conditional (12-rxrpc-af) drop files (rev 2: AFS-gated, present on clean host)
for u in user@ sshd cron crond atd; do
    test -f "/etc/systemd/system/${u}.service.d/12-copyfail-defense-rxrpc-af.conf" \
        || fail "12-rxrpc-af drop missing for ${u} on clean host"
done
# All 5 conditional (15-) drop files (clean host = no suppression)
for u in user@ sshd cron crond atd; do
    test -f "/etc/systemd/system/${u}.service.d/15-copyfail-defense-userns.conf" \
        || fail "15-* drop missing for ${u} on clean host"
done
# auto-detect.json present and reports nothing
test -f /var/lib/copyfail-defense/auto-detect.json \
    || fail "auto-detect.json missing"
jq -e '.schema_version == "2" and
       .detected.ipsec.present == false and
       .detected.afs.present == false and
       .detected.rootless_containers.present == false' \
       /var/lib/copyfail-defense/auto-detect.json >/dev/null \
    || fail "auto-detect.json reports workloads on clean host (or wrong schema)"
ok "clean host: all 18 drop files present + JSON reports clean"
echo "=== CLEAN HOST OK ==="
INNER
}

run_ipsec_host_test_in() {
    local image="$1"
    podman run --rm -i --network=host \
        -e REPO_URL="$REPO_URL" -e KEY_URL="$KEY_URL" \
        "$image" /bin/bash <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }

# Pre-stage TWO IPsec signals BEFORE installing the package. Per
# v2.0.1 fixup M-1, the JSON signals[] field must be a list of N
# entries, not a single concatenated string. A single signal would
# never have caught the bash NUL-stripping bug, so this test
# deliberately stages two and asserts len(signals.ipsec) >= 2.
mkdir -p /etc /etc/strongswan/conf.d
cat >/etc/ipsec.conf <<'EOC'
# libreswan-style stub
conn home
    left=192.0.2.1
    right=192.0.2.2
    auto=add
EOC
# Second signal: non-empty conf in a strongswan conf.d directory.
cat >/etc/strongswan/conf.d/local.conf <<'EOC'
# strongswan-style stub
charon { send_vendor_id = yes }
EOC

curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/copyfail.repo
dnf install -y python3 jq >/dev/null 2>&1 || true
dnf install -y copyfail-defense 2>&1 | tail -5

# cf2-xfrm SUPPRESSED, cf1 + rxrpc PRESENT
test ! -f /etc/modprobe.d/99-copyfail-defense-cf2-xfrm.conf \
    || fail "cf2-xfrm drop file present despite IPsec signal"
test -f /etc/modprobe.d/99-copyfail-defense-cf1.conf \
    || fail "cf1 drop file (always-on) missing"
test -f /etc/modprobe.d/99-copyfail-defense-rxrpc.conf \
    || fail "rxrpc drop file (unrelated to IPsec) missing"
# JSON should flag ipsec
jq -e '.detected.ipsec.present == true and
       .suppressed.modprobe_cf2_xfrm == true' \
       /var/lib/copyfail-defense/auto-detect.json >/dev/null \
    || fail "auto-detect.json missing IPsec/suppression flags"
# v2.0.1 fixup M-1 canary: the signals[] array must be a JSON list of
# DISTINCT entries, not a single concatenated string. Bash NUL-stripping
# in command substitution previously collapsed N signals to 1 merged
# string. We staged 2 signals; assert >=2 entries.
ipsec_signal_count=$(jq -r '.detected.ipsec.signals | length' \
    /var/lib/copyfail-defense/auto-detect.json)
[ "$ipsec_signal_count" -ge 2 ] \
    || fail "ipsec.signals has $ipsec_signal_count entries, expected >=2 (NUL-marshalling bug?)"
# Confirm each entry is a non-empty distinct string, not the concatenation.
jq -e '.detected.ipsec.signals | all(type == "string" and length > 0)' \
    /var/lib/copyfail-defense/auto-detect.json >/dev/null \
    || fail "ipsec.signals entries must each be non-empty strings"
ok "ipsec host: cf2-xfrm correctly suppressed; signals array has $ipsec_signal_count distinct entries"
echo "=== IPSEC HOST OK ==="
INNER
}

run_afs_host_test_in() {
    local image="$1"
    podman run --rm -i --network=host \
        -e REPO_URL="$REPO_URL" -e KEY_URL="$KEY_URL" \
        "$image" /bin/bash <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }

mkdir -p /etc/openafs
echo "lan.example.com" > /etc/openafs/ThisCell

curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/copyfail.repo
dnf install -y python3 jq >/dev/null 2>&1 || true
dnf install -y copyfail-defense 2>&1 | tail -5

test ! -f /etc/modprobe.d/99-copyfail-defense-rxrpc.conf \
    || fail "rxrpc drop file present despite AFS signal"
test -f /etc/modprobe.d/99-copyfail-defense-cf1.conf \
    || fail "cf1 drop file missing"
test -f /etc/modprobe.d/99-copyfail-defense-cf2-xfrm.conf \
    || fail "cf2-xfrm drop file (unrelated to AFS) missing"
# Rev 2: 12-rxrpc-af also suppressed for ALL 5 units on AFS hosts.
for u in user@ sshd cron crond atd; do
    test ! -f "/etc/systemd/system/${u}.service.d/12-copyfail-defense-rxrpc-af.conf" \
        || fail "12-rxrpc-af present for ${u} despite AFS signal"
done
# The 10-* and 15-* drops still present (AFS doesn't suppress those).
for u in user@ sshd cron crond atd; do
    test -f "/etc/systemd/system/${u}.service.d/10-copyfail-defense.conf" \
        || fail "10-* drop missing for ${u} on AFS host"
    test -f "/etc/systemd/system/${u}.service.d/15-copyfail-defense-userns.conf" \
        || fail "15-userns drop missing for ${u} on AFS host"
done
jq -e '.detected.afs.present == true and
       .suppressed.modprobe_rxrpc == true and
       .suppressed.systemd_rxrpc_af == true' \
       /var/lib/copyfail-defense/auto-detect.json >/dev/null \
    || fail "auto-detect.json missing AFS/suppression flags"
ok "afs host: rxrpc + rxrpc-af correctly suppressed across all 5 units"
echo "=== AFS HOST OK ==="
INNER
}

run_rootless_host_test_in() {
    local image="$1"
    podman run --rm -i --network=host \
        -e REPO_URL="$REPO_URL" -e KEY_URL="$KEY_URL" \
        "$image" /bin/bash <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }

# Rev 2 fixup (reviewer C-1): pre-stage the storage-tree signal
# (canonical podman rootless fingerprint), NOT /etc/subuid (which
# has near-100% FP rate on cPanel hosts and was dropped from the
# signal set). The /etc/subuid line is preserved here only as a
# negative test: it should NOT trip detection on its own.
useradd -m -u 1000 alice 2>/dev/null || true
echo "alice:100000:65536" >> /etc/subuid    # negative test - does NOT trip

# Positive test: stage the storage tree that podman creates on
# first rootless container run. detect.sh signal 1 fires here.
install -d -o alice -g alice -m 0700 \
    /home/alice/.local/share/containers/storage/overlay-containers
# Touch with recent mtime so the -mtime -180 gate passes.
touch /home/alice/.local/share/containers/storage/overlay-containers

curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/copyfail.repo
dnf install -y python3 jq >/dev/null 2>&1 || true
dnf install -y copyfail-defense 2>&1 | tail -5

# 15-userns DROP for user@ ONLY; sshd/cron/crond/atd 15-* PRESENT;
# all 10-* PRESENT; all 3 modprobe files PRESENT.
test ! -f /etc/systemd/system/user@.service.d/15-copyfail-defense-userns.conf \
    || fail "user@ 15-userns drop present despite rootless signal"
for u in sshd cron crond atd; do
    test -f "/etc/systemd/system/${u}.service.d/15-copyfail-defense-userns.conf" \
        || fail "${u} 15-userns drop missing (should be applied)"
done
for u in user@ sshd cron crond atd; do
    test -f "/etc/systemd/system/${u}.service.d/10-copyfail-defense.conf" \
        || fail "${u} 10-* always-on drop missing"
done
# Rev 2: 12-rxrpc-af present for all 5 units on rootless-only host
# (AFS not detected, so AF_RXRPC cut applies).
for u in user@ sshd cron crond atd; do
    test -f "/etc/systemd/system/${u}.service.d/12-copyfail-defense-rxrpc-af.conf" \
        || fail "${u} 12-rxrpc-af drop missing on rootless-only host"
done
for f in cf1 cf2-xfrm rxrpc; do
    test -f "/etc/modprobe.d/99-copyfail-defense-${f}.conf" \
        || fail "modprobe ${f} drop missing"
done
jq -e '.detected.rootless_containers.present == true and
       .suppressed.systemd_userns_user_at == true and
       .suppressed.systemd_rxrpc_af == false' \
       /var/lib/copyfail-defense/auto-detect.json >/dev/null \
    || fail "auto-detect.json missing rootless/suppression flags"
# Negative test: with subuid populated but storage tree missing,
# rev 2 detect.sh should NOT trip (cPanel-FP fix per C-1). We can't
# easily verify this via jq because the storage tree IS present
# above; instead, install a 2nd container without the storage tree
# to confirm subuid alone doesn't trip. (Test #22b below.)
ok "rootless host: user@ 15-userns suppressed; 12-rxrpc-af applied"
echo "=== ROOTLESS HOST OK ==="
INNER
}

# Rev 2 fixup test (reviewer C-1): subuid alone must NOT trip
# rootless detection. cPanel hosts have hundreds of regular users
# with auto-populated /etc/subuid; if subuid alone tripped detection,
# the userns cut would be suppressed on every cPanel install,
# inverting the protection guarantee. This test asserts the cPanel-
# shaped fixture (regular user + populated subuid, NO storage tree)
# does NOT detect rootless.
run_subuid_no_storage_test_in() {
    local image="$1"
    podman run --rm -i --network=host \
        -e REPO_URL="$REPO_URL" -e KEY_URL="$KEY_URL" \
        "$image" /bin/bash <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }

# cPanel-shaped fixture: regular users + subuid, but NO podman
# storage tree, NO /run/user containers, NO podman.socket.
for i in 1 2 3 4 5; do
    useradd -m -u "$((1000 + i))" "cpuser${i}" 2>/dev/null || true
    echo "cpuser${i}:$((100000 + i*65536)):65536" >> /etc/subuid
    echo "cpuser${i}:$((100000 + i*65536)):65536" >> /etc/subgid
done
# Crucially: do NOT create /home/cpuser*/.local/share/containers/.

curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/copyfail.repo
dnf install -y python3 jq >/dev/null 2>&1 || true
dnf install -y copyfail-defense 2>&1 | tail -5

# Detection must report rootless=false despite the populated subuid.
jq -e '.detected.rootless_containers.present == false and
       .suppressed.systemd_userns_user_at == false' \
       /var/lib/copyfail-defense/auto-detect.json >/dev/null \
    || fail "subuid alone tripped rootless detection (cPanel FP regression)"
# user@ 15-userns must be PRESENT (cut applies on cPanel-shaped host).
test -f /etc/systemd/system/user@.service.d/15-copyfail-defense-userns.conf \
    || fail "user@ 15-userns missing despite no rootless signal"
ok "subuid+passwd alone does not trip rootless detection (C-1 cPanel FP fix)"
echo "=== SUBUID-NO-STORAGE OK ==="
INNER
}

run_force_full_test_in() {
    local image="$1"
    podman run --rm -i --network=host \
        -e REPO_URL="$REPO_URL" -e KEY_URL="$KEY_URL" \
        "$image" /bin/bash <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }

# Pre-stage all three signals AND force-full sentinel.
# Rev 2: rootless signal switched from /etc/subuid to storage-tree
# (per C-1), so we must stage the actual storage path.
mkdir -p /etc/openafs /etc/copyfail
printf 'conn home\n    left=192.0.2.1\n' > /etc/ipsec.conf
echo "lan.example.com" > /etc/openafs/ThisCell
useradd -m -u 1000 alice 2>/dev/null || true
install -d -o alice -g alice -m 0700 \
    /home/alice/.local/share/containers/storage/overlay-containers
touch /etc/copyfail/force-full

curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/copyfail.repo
dnf install -y python3 jq >/dev/null 2>&1 || true
dnf install -y copyfail-defense 2>&1 | tail -5

# ALL files should be present despite all three signals tripping.
for f in cf1 cf2-xfrm rxrpc; do
    test -f "/etc/modprobe.d/99-copyfail-defense-${f}.conf" \
        || fail "modprobe ${f} suppressed despite force-full"
done
for u in user@ sshd cron crond atd; do
    test -f "/etc/systemd/system/${u}.service.d/15-copyfail-defense-userns.conf" \
        || fail "15-userns suppressed for ${u} despite force-full"
    # Rev 2: 12-rxrpc-af also force-applied.
    test -f "/etc/systemd/system/${u}.service.d/12-copyfail-defense-rxrpc-af.conf" \
        || fail "12-rxrpc-af suppressed for ${u} despite force-full"
done
jq -e '.force_full == true' \
       /var/lib/copyfail-defense/auto-detect.json >/dev/null \
    || fail "auto-detect.json force_full not set"
ok "force-full sentinel: all mitigations applied despite signals"
echo "=== FORCE-FULL OK ==="
INNER
}

run_redetect_test_in() {
    local image="$1"
    podman run --rm -i --network=host \
        -e REPO_URL="$REPO_URL" -e KEY_URL="$KEY_URL" \
        "$image" /bin/bash <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }

curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/copyfail.repo
dnf install -y python3 jq >/dev/null 2>&1 || true
dnf install -y copyfail-defense 2>&1 | tail -5

# Clean install: all 3 modprobe files + 5+5 systemd files.
test -f /etc/modprobe.d/99-copyfail-defense-rxrpc.conf \
    || fail "rxrpc drop file missing pre-redetect"

# Now create AFS signal AND re-run detection
mkdir -p /etc/openafs
echo "lan.example.com" > /etc/openafs/ThisCell
/usr/sbin/copyfail-redetect

# rxrpc drop should now be GONE; cf1 + cf2-xfrm preserved.
test ! -f /etc/modprobe.d/99-copyfail-defense-rxrpc.conf \
    || fail "rxrpc drop persisted after redetect on AFS host"
test -f /etc/modprobe.d/99-copyfail-defense-cf1.conf \
    || fail "cf1 drop removed by redetect (should be always-on)"
jq -e '.detected.afs.present == true' \
       /var/lib/copyfail-defense/auto-detect.json >/dev/null \
    || fail "auto-detect.json not updated by redetect"
ok "redetect: AFS signal newly applied; rxrpc suppressed"
echo "=== REDETECT OK ==="
INNER
}

# v2.0.1 fixup M-2 canary: install -systemd WITHOUT -modprobe.
# detect.sh + /usr/libexec/copyfail-defense/ + /var/lib/copyfail-defense/
# moved from -modprobe %files to meta %files. Both -modprobe and
# -systemd hard-Require meta. This test asserts that installing
# -systemd alone still pulls meta (and its detect.sh), so the
# %posttrans actually fires and produces auto-detect.json + 12-/15-*
# drop-ins. Pre-fixup, this scenario silently no-op'd because
# detect.sh did not land on disk.
run_systemd_only_test_in() {
    local image="$1"
    podman run --rm -i --network=host \
        -e REPO_URL="$REPO_URL" -e KEY_URL="$KEY_URL" \
        "$image" /bin/bash <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }

curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/copyfail.repo
dnf install -y python3 jq >/dev/null 2>&1 || true

# Install ONLY -systemd (and let dnf pull meta as a hard Require).
# We deliberately do NOT pull -modprobe/-shim/-auditor.
dnf install -y copyfail-defense-systemd 2>&1 | tail -10

# Meta must have been pulled (hard Requires).
rpm -q copyfail-defense >/dev/null 2>&1 \
    || fail "meta package not pulled by -systemd alone (Requires chain broken)"
# -modprobe must NOT be installed (we didn't ask for it).
if rpm -q copyfail-defense-modprobe >/dev/null 2>&1; then
    fail "-modprobe was pulled despite installing only -systemd (test invalid)"
fi
ok "rpm topology: meta + -systemd installed; -modprobe absent"

# detect.sh must be present (meta-owned).
test -x /usr/libexec/copyfail-defense/detect.sh \
    || fail "detect.sh missing on -systemd-only install (M-2 regression)"
ok "detect.sh present (meta-owned)"

# auto-detect.json must have been written by -systemd's %posttrans.
test -f /var/lib/copyfail-defense/auto-detect.json \
    || fail "auto-detect.json missing on -systemd-only install (%posttrans no-op'd?)"
jq -e '.schema_version == "2"' /var/lib/copyfail-defense/auto-detect.json >/dev/null \
    || fail "auto-detect.json malformed on -systemd-only install"
ok "auto-detect.json written and parses"

# 10-* always-on drop-ins for all 5 tenant units.
for u in user@ sshd cron crond atd; do
    test -f "/etc/systemd/system/${u}.service.d/10-copyfail-defense.conf" \
        || fail "10-* drop missing for ${u} on -systemd-only install"
done
ok "10-* always-on drops applied for all 5 tenant units"

# 12-/15-* conditional drop-ins land on a clean host (no IPsec/AFS/rootless).
for u in user@ sshd cron crond atd; do
    test -f "/etc/systemd/system/${u}.service.d/12-copyfail-defense-rxrpc-af.conf" \
        || fail "12-rxrpc-af missing for ${u} on -systemd-only install (M-2 canary)"
    test -f "/etc/systemd/system/${u}.service.d/15-copyfail-defense-userns.conf" \
        || fail "15-userns missing for ${u} on -systemd-only install (M-2 canary)"
done
ok "12-/15-* conditional drop-ins applied via meta-owned detect.sh"

# Modprobe drop files must NOT be present (we did not install -modprobe).
for f in cf1 cf2-xfrm rxrpc; do
    test ! -f "/etc/modprobe.d/99-copyfail-defense-${f}.conf" \
        || fail "modprobe ${f} drop present despite -modprobe NOT being installed"
done
ok "modprobe drops absent (correct: -modprobe not installed)"

echo "=== SYSTEMD-ONLY (M-2) OK ==="
INNER
}

run_split_upgrade_test_in() {
    local image="$1"
    podman run --rm -i --network=host \
        -e REPO_URL="$REPO_URL" -e KEY_URL="$KEY_URL" \
        "$image" /bin/bash <<'INNER'
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "ok:   $*"; }

curl -sSfL "$REPO_URL" -o /etc/yum.repos.d/copyfail.repo
dnf install -y python3 jq >/dev/null 2>&1 || true

# Install v2.0.0 explicitly. If the repo no longer has v2.0.0, SKIP.
if dnf install -y 'copyfail-defense-2.0.0*' 2>&1 | tail -5; then
    test -f /etc/modprobe.d/99-copyfail-defense.conf \
        || fail "v2.0.0 monolithic modprobe file missing"
    test -f /etc/systemd/system/sshd.service.d/10-copyfail-defense.conf \
        || fail "v2.0.0 sshd drop missing"
    ok "v2.0.0 baseline installed"
else
    echo "SKIP: copyfail-defense-2.0.0 not in repo (one-cycle expired)"
    exit 77
fi

# Upgrade to 2.0.1
dnf upgrade -y copyfail-defense 2>&1 | tail -10

# v2.0.0 monolithic file MUST be gone from its original path
# (pretrans renamed it to .rpmsave-v2.0.1 per rev 2 D-37).
test ! -f /etc/modprobe.d/99-copyfail-defense.conf \
    || fail "v2.0.0 monolithic modprobe file still at original path after upgrade"
# And the .rpmsave-v2.0.1 SHOULD exist (rev 2 preserves operator
# hand-edits via rename; the file is inert / RPM doesn't consult it).
test -f /etc/modprobe.d/99-copyfail-defense.conf.rpmsave-v2.0.1 \
    || fail "v2.0.0 monolithic file not renamed to .rpmsave-v2.0.1 (D-37 broken)"
# All v2.0.1 split files present (clean host = no suppression)
for f in cf1 cf2-xfrm rxrpc; do
    test -f "/etc/modprobe.d/99-copyfail-defense-${f}.conf" \
        || fail "v2.0.1 split file ${f} missing post-upgrade"
done
for u in user@ sshd cron crond atd; do
    test -f "/etc/systemd/system/${u}.service.d/10-copyfail-defense.conf" \
        || fail "10-* drop for ${u} missing post-upgrade"
    test -f "/etc/systemd/system/${u}.service.d/12-copyfail-defense-rxrpc-af.conf" \
        || fail "12-rxrpc-af drop for ${u} missing post-upgrade"
    test -f "/etc/systemd/system/${u}.service.d/15-copyfail-defense-userns.conf" \
        || fail "15-* drop for ${u} missing post-upgrade"
    # Rev 2: the .rpmsave-v2.0.1 from systemd %pretrans should also exist.
    test -f "/etc/systemd/system/${u}.service.d/10-copyfail-defense.conf.rpmsave-v2.0.1" \
        || fail "${u} v2.0.0 monolithic systemd drop not renamed to .rpmsave-v2.0.1"
done
test -f /var/lib/copyfail-defense/auto-detect.json \
    || fail "auto-detect.json missing post-upgrade"
ok "v2.0.0 -> v2.0.1 split-file upgrade clean"
echo "=== SPLIT-UPGRADE OK ==="
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

    # v2.0.1: detection scenario tests (rev 2: + subuid_no_storage;
    # fixup pass: + systemd_only for M-2 canary).
    for scenario_name in clean_host ipsec_host afs_host rootless_host \
                         subuid_no_storage \
                         force_full redetect split_upgrade \
                         systemd_only; do
        echo
        step "${scenario_name} test"
        scenario_rc=0
        "run_${scenario_name}_test_in" "$image" || scenario_rc=$?
        case "$scenario_rc" in
            0)  RESULT[$el]="${RESULT[$el]} +${scenario_name}$(c_green OK)" ;;
            77) RESULT[$el]="${RESULT[$el]} +${scenario_name}$(c_dim SKIP)" ;;
            *)  RESULT[$el]="${RESULT[$el]} +${scenario_name}$(c_red FAIL)"
                overall_rc=1 ;;
        esac
    done
    echo
done

echo "============================================================"
echo "summary"
echo "============================================================"
for el in "${ELS[@]}"; do
    printf '  EL%-3s  %s\n' "$el" "${RESULT[$el]:-unknown}"
done

exit "$overall_rc"
