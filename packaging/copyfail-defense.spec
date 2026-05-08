%global         _hardened_build         1
%global         debug_package           %{nil}

# We deliberately do NOT byte-compile or strip the python script - it is
# distributed as plain text so an operator can read it before running.
%global         __os_install_post       %{nil}

# Upstream project tarball is named copyfail-VERSION.tar.gz - that is the
# project name in README/source. The RPM family was previously named
# afalg-defense; v2.0.0 renames to copyfail-defense for cf-class coverage
# (cf1 = CVE-2026-31431, cf2, Dirty Frag).
%global         upstream_name           copyfail

Name:           copyfail-defense
Epoch:          1
Version:        2.0.0
Release:        1%{?dist}
Summary:        Defense-in-depth toolkit for the Copy Fail bug class

License:        GPLv2
URL:            https://www.rfxn.com/
Source0:        %{upstream_name}-%{version}.tar.gz
# Auxiliary files maintained alongside the spec rather than in the upstream
# tarball - declaring them as Source1..N is what gets them into the SRPM
# (only declared Source* entries make it past `rpmbuild -bs`).
Source1:        copyfail-shim-enable
Source2:        copyfail-shim-disable
Source3:        copyfail-modprobe.conf
Source4:        copyfail-systemd-dropin.conf
Source5:        copyfail-systemd-dropin-containers.conf

# x86_64 only: no-afalg.c has an explicit #error for non-x86_64. The auditor
# is portable, but the shim is a load-bearing primitive of this package
# family and we do not ship a half-package.
ExclusiveArch:  x86_64

BuildRequires:  gcc
BuildRequires:  glibc-devel
# The auditor is plain Python 3 stdlib at runtime, but %build runs a
# py_compile syntax check against it as a build-time gate (catches mismerged
# patches before they reach a server). EL8/EL10 minimal buildroots do not
# include python3 by default - hence BuildRequires.
BuildRequires:  python3

# Meta package ties the four subpackages together. Most operators install
# `copyfail-defense` and get all four halves.
Requires:       %{name}-shim     = %{epoch}:%{version}-%{release}
Requires:       %{name}-modprobe = %{epoch}:%{version}-%{release}
Requires:       %{name}-systemd  = %{epoch}:%{version}-%{release}
Requires:       %{name}-auditor  = %{epoch}:%{version}-%{release}

# v2.0.0 rename: afalg-defense -> copyfail-defense. Compat retained
# through the 2.0.x release line; dropped in 2.1.0.
Obsoletes:      afalg-defense    < %{epoch}:%{version}-%{release}
Provides:       afalg-defense    = %{epoch}:%{version}-%{release}

%description
Defense-in-depth toolkit covering the Copy Fail bug class:
  - cf1 (CVE-2026-31431) - algif_aead AEAD scratch-write
  - cf2 ("Electric Boogaloo") - xfrm-ESP skip_cow path
  - Dirty Frag - xfrm-ESP and RxRPC pcbc(fcrypt) on splice'd frag

This metapackage installs four subpackages:
  - copyfail-defense-shim      - LD_PRELOAD AF_ALG block
  - copyfail-defense-modprobe  - kernel-module entry-point cuts
  - copyfail-defense-systemd   - per-unit RestrictAddressFamilies/Namespaces
  - copyfail-defense-auditor   - read-only host posture auditor

The shim is INSTALLED but NOT enabled by this package. To enable it
system-wide:

    /usr/sbin/copyfail-shim-enable

To disable:

    /usr/sbin/copyfail-shim-disable

Refer to /usr/share/doc/copyfail-defense/README.md for the defense-in-depth
ladder, the per-class coverage table, and the override paths for
operator workflows that conflict with default cuts (rootless podman,
IPsec, AFS).

# ---------------------------------------------------------------------------
%package shim
Summary:        LD_PRELOAD shim that blocks AF_ALG socket creation
Obsoletes:      afalg-defense-shim < %{epoch}:%{version}-%{release}
Provides:       afalg-defense-shim = %{epoch}:%{version}-%{release}

%description shim
no-afalg.so: small libdl-based interposer that wraps libc socket(2) and
socketpair(2), denying AF_ALG (domain=38) with EPERM and logging the
attempt to LOG_AUTHPRIV. Intended for /etc/ld.so.preload.

The shim DOES NOT prevent direct-syscall bypass (syscall(SYS_socket,
AF_ALG, ...) or inline asm). Pair with the systemd subpackage's
RestrictAddressFamilies=~AF_ALG ~AF_RXRPC drop-ins for kernel-enforced
coverage, and with the kernel patch for full coverage.

THIS SUBPACKAGE INSTALLS no-afalg.so BUT DOES NOT WIRE IT INTO
/etc/ld.so.preload. To activate:

    /usr/sbin/copyfail-shim-enable

The activation helper smoke-tests the .so against /bin/true before
modifying /etc/ld.so.preload, refusing to brick the system if the .so
is broken.

# ---------------------------------------------------------------------------
%package modprobe
Summary:        Modprobe blacklist for cf-class kernel sinks
BuildArch:      noarch
Requires(post): kmod
Requires(post): util-linux

%description modprobe
Modprobe blacklist + install-redirect for kernel modules used by the
Copy Fail bug-class entry points:
  - cf1 (CVE-2026-31431): algif_aead, authenc, authencesn, af_alg
  - cf2 / Dirty Frag-ESP:  esp4, esp6, xfrm_user, xfrm_algo
  - Dirty Frag-RxRPC:      rxrpc

Drops /etc/modprobe.d/99-copyfail-defense.conf (config noreplace,
operator-override safe).

WILL BREAK workloads that legitimately use IPsec (strongSwan, libreswan,
FRRouting), AFS (openafs, kafs), or kernel crypto via AF_ALG (some QEMU
configs, dm-crypt-via-AF_ALG userspace). Confirm posture before
installing on hosts that run any of these.

# ---------------------------------------------------------------------------
%package systemd
Summary:        systemd drop-ins blocking cf-class primitives on tenant units
BuildArch:      noarch
Requires:       systemd
Requires(post): systemd

%description systemd
systemd unit drop-ins applying RestrictAddressFamilies=~AF_ALG ~AF_RXRPC,
RestrictNamespaces=~user ~net, SystemCallFilter=~@swap, and
SystemCallArchitectures=native to: user@.service, sshd.service,
cron.service, crond.service, atd.service.

These cuts block the userspace prerequisites for cf2 / Dirty Frag-ESP
(unprivileged user namespace creation) and the AF_RXRPC socket required
by Dirty Frag-RxRPC, kernel-enforced at the unit level (uncircumventable
from userspace).

Container-runtime drop-ins (containerd, docker, podman) are shipped
as examples under /usr/share/doc/copyfail-defense/examples/ for
operators who do NOT run rootless or userns-remapped containers and
want to extend coverage. The default install does NOT activate
container-runtime drop-ins.

May break rootless podman/buildah running under user@.service.
Override: drop a 20-*.conf with empty directive values per unit;
see README.

# ---------------------------------------------------------------------------
%package auditor
Summary:        cf-class host posture auditor (cf1, cf2, Dirty Frag — read-only)
BuildArch:      noarch
Requires:       python3
Obsoletes:      afalg-defense-auditor < %{epoch}:%{version}-%{release}
Provides:       afalg-defense-auditor = %{epoch}:%{version}-%{release}
# The following are used opportunistically by the auditor and degrade
# gracefully when missing (every external command is wrapped in
# run_cmd which returns rc=-1 on FileNotFoundError). We list them as
# Recommends so a minimal install still gets the auditor working even
# when the recommendations cannot be satisfied (e.g. EL8 minimal).
Recommends:     coreutils
Recommends:     systemd
Recommends:     audit
Recommends:     libcap

%description auditor
copyfail-local-check: comprehensive read-only auditor that scores the host
across five attack-chain layers (ENV, KERNEL, MITIGATION, HARDENING,
DETECTION) for the Copy Fail bug class:
  - cf1 (CVE-2026-31431) - algif_aead
  - cf2 - xfrm-ESP skip_cow
  - Dirty Frag - xfrm-ESP and RxRPC pcbc(fcrypt)

SAFE BY DESIGN: writes only to mkdtemp() sentinel files, never modifies
/usr/bin or /etc, runs unprivileged (some checks degrade gracefully
without root). The optional trigger probe targets a freshly-created
sentinel file - it does not corrupt /usr/bin/su or anything else.

JSON output (--json) is fleet-rollout friendly; consume the
posture.verdict, posture.bug_classes_covered (array), and
posture.bug_classes (per-class map) fields, not the human report.

# ===========================================================================
%prep
%setup -q -n %{upstream_name}-%{version}

# Sanity-check that the source files we expect actually exist. Fail the
# build loud and early if the tarball is malformed rather than packaging
# a half-empty RPM.
test -f no-afalg.c
test -f copyfail-local-check.py
test -f README.md
test -f LICENSE

%build
# Single-translation-unit build, deterministic flags. We deliberately do
# not pull in distro-default LDFLAGS that include --as-needed late in the
# arg list - placement here matches upstream README and is known-good
# across el7/el8/el9/el10.
# SONAME deliberately omitted: an LD_PRELOAD shim is not linked against,
# only dlopen'd by ld.so via /etc/ld.so.preload. Adding -Wl,-soname for
# a non-lib*.so.N filename trips rpmlint's invalid-soname check.
%{__cc} -shared -fPIC -O2 -Wall -Wextra \
    %{?_hardening_cflags} %{optflags} \
    -o no-afalg.so no-afalg.c -ldl

# We disable the debug-info subpackage (debug_package=nil) so an explicit
# strip is needed - RPM's automatic strip is part of the same machinery.
# Without strip, rpmlint flags the .so as unstripped-binary-or-object and
# we ship 30k+ of unnecessary symbol info to every server.
strip --strip-unneeded no-afalg.so

# Smoke-test: confirm the shim we just built (and stripped) actually loads
# and does not break /bin/true under LD_PRELOAD on the build host. This
# catches an entire class of broken builds (missing -fPIC, undefined
# dlsym, over-aggressive strip, etc.) before the file ever reaches a
# server.
LD_PRELOAD=$PWD/no-afalg.so /bin/true

# Confirm the auditor is parseable Python 3 on the build host.
python3 -c "import py_compile; py_compile.compile('copyfail-local-check.py', doraise=True)"

%install
rm -rf %{buildroot}

# --- shim subpackage layout ---
install -d -m 0755 %{buildroot}%{_libdir}
install -m 0755 no-afalg.so %{buildroot}%{_libdir}/no-afalg.so

install -d -m 0755 %{buildroot}%{_sbindir}
install -m 0755 %{SOURCE1} %{buildroot}%{_sbindir}/copyfail-shim-enable
install -m 0755 %{SOURCE2} %{buildroot}%{_sbindir}/copyfail-shim-disable

# --- auditor subpackage layout ---
install -m 0755 copyfail-local-check.py \
    %{buildroot}%{_sbindir}/copyfail-local-check
sed -i '1s|^#!/usr/bin/env python3|#!/usr/bin/python3|' \
    %{buildroot}%{_sbindir}/copyfail-local-check

# --- modprobe subpackage layout ---
install -d -m 0755 %{buildroot}/etc/modprobe.d
install -m 0644 %{SOURCE3} \
    %{buildroot}/etc/modprobe.d/99-copyfail-defense.conf

# --- systemd subpackage layout ---
# Active drop-ins for tenant units (login + cron family). Drop-ins
# on units that don't exist on a given host are silently ignored at
# daemon-reload time (cron.service vs crond.service is the canonical
# Debian-vs-RHEL divergence; both listed for cross-distro safety).
for u in user@ sshd cron crond atd; do
    install -d -m 0755 \
        %{buildroot}/etc/systemd/system/${u}.service.d
    install -m 0644 %{SOURCE4} \
        %{buildroot}/etc/systemd/system/${u}.service.d/10-copyfail-defense.conf
done

# Container-runtime drop-ins ship as opt-in examples (NOT active).
install -d -m 0755 %{buildroot}%{_docdir}/%{name}/examples
install -m 0644 %{SOURCE5} \
    %{buildroot}%{_docdir}/%{name}/examples/containers-dropin.conf

# ===========================================================================
# Scriptlets - safety-first.
#
# We do NOT modify /etc/ld.so.preload from %post. A bad shim on every
# dynamic-linked binary would lock the operator out before they could
# log in to fix it. The activation helper exists for explicit operator
# action.
#
# We DO scrub /etc/ld.so.preload from %preun on full uninstall ($1=0),
# because the alternative is removing the .so file out from under a
# live preload entry, which is the same brick condition.
# ===========================================================================

%post shim
cat <<'EOF'

copyfail-defense-shim installed but NOT yet enabled.

To activate the AF_ALG block on this host:
    /usr/sbin/copyfail-shim-enable

To remove later:
    /usr/sbin/copyfail-shim-disable
    dnf remove copyfail-defense

Verify after enabling:
    python3 -c 'import socket; socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)'
    # expect: PermissionError [Errno 1] Operation not permitted

EOF
exit 0

%preun shim
# Only run on full uninstall, not upgrade.  $1==0 means erase.
if [ "$1" -eq 0 ]; then
    if [ -f /etc/ld.so.preload ] && \
       grep -Fxq /usr/lib64/no-afalg.so /etc/ld.so.preload; then
        # Remove our line atomically before rpm deletes the .so. If we
        # let rpm remove the .so first, every dynamic-linked invocation
        # of /bin/sh, sed, etc. tries to dlopen a missing file and
        # fails - including the very scripts running this teardown.
        tmp=$(mktemp /etc/ld.so.preload.XXXXXX 2>/dev/null) || tmp=""
        if [ -n "$tmp" ]; then
            grep -Fxv /usr/lib64/no-afalg.so /etc/ld.so.preload > "$tmp" || true
            if [ -s "$tmp" ]; then
                chmod 0644 "$tmp"
                mv -f "$tmp" /etc/ld.so.preload
            else
                rm -f "$tmp" /etc/ld.so.preload
            fi
        else
            # mktemp failed (RO /etc, partition full, etc). Fall back
            # to in-place sed scrub to avoid leaving the .so referenced
            # in /etc/ld.so.preload after rpm deletes it (would brick
            # every dyn-linked exec on the host).
            sed -i '\|^/usr/lib64/no-afalg\.so$|d' /etc/ld.so.preload \
                2>/dev/null || true
            # If file is now empty, remove it (preload-empty is fine,
            # preload-with-only-blank-lines logs a warning per exec).
            if [ -f /etc/ld.so.preload ] && \
               [ ! -s /etc/ld.so.preload ]; then
                rm -f /etc/ld.so.preload
            fi
        fi
    fi
fi
exit 0

%posttrans shim
if [ -f /etc/ld.so.preload ] && \
   grep -Fxq /usr/lib64/no-afalg.so /etc/ld.so.preload; then
    if [ ! -f /usr/lib64/no-afalg.so ]; then
        cat <<'EOF' >&2
WARNING: /etc/ld.so.preload references /usr/lib64/no-afalg.so but the
file is missing. Every dynamic-linked process on this host will log a
preload error. Run: /usr/sbin/copyfail-shim-disable
EOF
    fi
fi
exit 0

# ---------------------------------------------------------------------------
%post modprobe
# Best-effort rmmod of any cf-class entry-point module already loaded.
# Failures (module-in-use, not-loaded) are both fine and silenced.
# Emits a per-attempt syslog audit trail to authpriv (visible in
# /var/log/secure on RHEL, /var/log/auth.log on Debian) so an operator
# investigating a fleet-wide install has a paper trail of which modules
# the package actually unloaded vs which were absent or in-use.
{
    for m in algif_aead authenc authencesn af_alg \
             esp4 esp6 xfrm_user xfrm_algo rxrpc; do
        if /sbin/rmmod "$m" 2>/dev/null; then
            printf 'rmmod %s: unloaded\n' "$m"
        elif [ -d "/sys/module/$m" ]; then
            printf 'rmmod %s: still loaded (in-use or builtin)\n' "$m"
        fi
    done
} | logger -t copyfail-defense -p authpriv.info 2>/dev/null || true
exit 0

%preun modprobe
# Only on full erase. Remove drop file. Do NOT rmmod - taking modules
# down on uninstall could break a host that depends on them.
if [ "$1" -eq 0 ]; then
    rm -f /etc/modprobe.d/99-copyfail-defense.conf
fi
exit 0

%posttrans modprobe
loaded=$(grep -E '^(algif_aead|authenc|authencesn|af_alg|esp4|esp6|xfrm_user|xfrm_algo|rxrpc) ' /proc/modules 2>/dev/null | awk '{print $1}' | tr '\n' ' ')
if [ -n "$loaded" ]; then
    cat <<EOF >&2
NOTICE: copyfail-defense-modprobe installed but the following listed
modules are still loaded in the running kernel: $loaded
They will be blocked on next load attempt; reboot to clear running state.
EOF
fi
exit 0

# ---------------------------------------------------------------------------
%post systemd
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl try-reload-or-restart sshd.service 2>/dev/null || true
fi
exit 0

%postun systemd
# Run AFTER rpm removes the drop-in files so daemon-reload + reload
# pick up the absence of the restrictions. (Putting this in %preun
# would reload while the files still exist - operator's running sshd
# would keep the restrictions in memory until the next manual reload.)
# $1==0 means full erase (not upgrade).
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl try-reload-or-restart sshd.service 2>/dev/null || true
fi
exit 0

# ===========================================================================
%files
%license LICENSE
%doc README.md

%files shim
%license LICENSE
%doc README.md
%{_libdir}/no-afalg.so
%{_sbindir}/copyfail-shim-enable
%{_sbindir}/copyfail-shim-disable

%files modprobe
%license LICENSE
%doc README.md
%config(noreplace) /etc/modprobe.d/99-copyfail-defense.conf

%files systemd
%license LICENSE
%doc README.md
%dir /etc/systemd/system/user@.service.d
%dir /etc/systemd/system/sshd.service.d
%dir /etc/systemd/system/cron.service.d
%dir /etc/systemd/system/crond.service.d
%dir /etc/systemd/system/atd.service.d
%config(noreplace) /etc/systemd/system/user@.service.d/10-copyfail-defense.conf
%config(noreplace) /etc/systemd/system/sshd.service.d/10-copyfail-defense.conf
%config(noreplace) /etc/systemd/system/cron.service.d/10-copyfail-defense.conf
%config(noreplace) /etc/systemd/system/crond.service.d/10-copyfail-defense.conf
%config(noreplace) /etc/systemd/system/atd.service.d/10-copyfail-defense.conf
# Note: the docdir is implicitly owned via %%doc README.md in every
# subpackage; do not redeclare with %%dir here (rpm warns on duplicate
# ownership).
%dir %{_docdir}/%{name}/examples
%{_docdir}/%{name}/examples/containers-dropin.conf

%files auditor
%license LICENSE
%doc README.md
%{_sbindir}/copyfail-local-check

# ===========================================================================
%changelog
* Fri May 08 2026 rfxn.com <proj@rfxn.com> - 1:2.0.0-1
- v2.0.0: rename afalg-defense -> copyfail-defense umbrella, expand to
  cover the full Copy Fail bug class:
    cf1 (CVE-2026-31431) - algif_aead AEAD scratch-write
    cf2 ("Electric Boogaloo") - xfrm-ESP skip_cow path
    Dirty Frag - xfrm-ESP and RxRPC pcbc(fcrypt) on splice'd frag
- New subpackage copyfail-defense-modprobe: ships
  /etc/modprobe.d/99-copyfail-defense.conf with the cf-class
  kernel-module entry-point cuts (algif_aead/authenc/authencesn/af_alg,
  esp4/esp6/xfrm_user/xfrm_algo, rxrpc). Best-effort rmmod on install.
- New subpackage copyfail-defense-systemd: ships drop-ins for
  user@/sshd/cron/crond/atd applying RestrictAddressFamilies=~AF_ALG
  ~AF_RXRPC, RestrictNamespaces=~user ~net, SystemCallFilter=~@swap,
  SystemCallArchitectures=native. Container-runtime drop-ins ship as
  opt-in examples under /usr/share/doc/copyfail-defense/examples/.
- copyfail-defense-shim: pure rename of afalg-defense-shim. No
  behavioural change. Obsoletes/Provides afalg-defense-shim.
- copyfail-defense-auditor: pure rename of afalg-defense-auditor with
  expanded checks for cf2/Dirty Frag (xfrm-ESP and RxRPC reachability,
  modprobe extended coverage, systemd RestrictNamespaces, PAM nullok
  scan, page-cache integrity for /usr/bin/su and PAM stacks). New JSON
  output: posture.bug_classes_covered (SIEM array) and
  posture.bug_classes (granular map). Exit codes unchanged.
- Epoch: 1 introduced. Compat metadata (Obsoletes/Provides
  afalg-defense*) retained through 2.0.x; dropped in 2.1.0.

* Thu Apr 30 2026 R-fx Networks <proj@rfxn.com> - 1.0.1-1
- Signed release. RPMs and repodata are GPG-signed with the
  Copyfail Project Signing Key (fingerprint 6001 1CDC EA2F F52D 975A
  FDEE 6D30 F32C D5E8 0F80). The published .repo file enforces
  gpgcheck=1 / repo_gpgcheck=1; the public key is published as
  /RPM-GPG-KEY-copyfail at the gh-pages root and as a release asset.
- Initial RPM packaging of the AF_ALG defensive primitives.
- Package family renamed from copyfail-* to afalg-defense-* to track the
  defensive primitive rather than a single CVE.
- Subpackages: afalg-defense-shim (LD_PRELOAD AF_ALG block) and
  afalg-defense-auditor (read-only host posture auditor).
- Shim is installed but not auto-enabled - operator runs
  copyfail-shim-enable to wire it into /etc/ld.so.preload, after a
  pre-flight LD_PRELOAD smoke-test against /bin/true.
- preun on full erase scrubs /etc/ld.so.preload before the .so is
  removed to avoid bricking dynamic-linked binaries during teardown.
