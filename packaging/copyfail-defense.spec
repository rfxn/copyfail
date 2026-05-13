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
Version:        2.0.2
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
Source3:        copyfail-modprobe-cf1.conf
Source4:        copyfail-systemd-dropin.conf
Source5:        copyfail-systemd-dropin-containers.conf
Source6:        copyfail-modprobe-cf2-xfrm.conf
Source7:        copyfail-modprobe-rxrpc.conf
Source8:        copyfail-systemd-dropin-userns.conf
Source9:        copyfail-defense-detect.sh
Source10:       copyfail-redetect
Source11:       copyfail-systemd-dropin-rxrpc-af.conf
Source12:       copyfail-sysctl-userns.conf
Source13:       copyfail-defense-audit.rules

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

# Meta package ties the six subpackages together. Most operators install
# `copyfail-defense` and get the full set (with -audit as a soft dep so
# minimal hosts without auditd installed don't pull it in by default).
Requires:       %{name}-shim     = %{epoch}:%{version}-%{release}
Requires:       %{name}-modprobe = %{epoch}:%{version}-%{release}
Requires:       %{name}-systemd  = %{epoch}:%{version}-%{release}
Requires:       %{name}-auditor  = %{epoch}:%{version}-%{release}
Requires:       %{name}-sysctl   = %{epoch}:%{version}-%{release}
# Soft dep: -audit pulls auditd transitively; minimal hosts can skip it
# via `--setopt=install_weak_deps=false` or `dnf install <subpackages>`
# selectively.
Recommends:     %{name}-audit    = %{epoch}:%{version}-%{release}

# v2.0.0 rename: afalg-defense -> copyfail-defense. Compat retained
# through the 2.0.x release line; dropped in 2.1.0.
Obsoletes:      afalg-defense    < %{epoch}:%{version}-%{release}
Provides:       afalg-defense    = %{epoch}:%{version}-%{release}

%description
Defense-in-depth toolkit covering the Copy Fail bug class:
  - cf1 (CVE-2026-31431) - algif_aead AEAD scratch-write
  - cf2 (CVE-2026-43284) - xfrm-ESP skip_cow path / Dirty Frag-ESP
  - Dirty Frag-RxRPC (CVE-2026-43500) - rxrpc pcbc(fcrypt) on splice'd frag
  - Fragnesia (no CVE yet, same surface as CVE-2026-43284) - ESP-in-TCP

This metapackage installs six subpackages:
  - copyfail-defense-shim      - LD_PRELOAD AF_ALG block
  - copyfail-defense-modprobe  - kernel-module entry-point cuts
  - copyfail-defense-systemd   - per-unit RestrictAddressFamilies/Namespaces
  - copyfail-defense-auditor   - read-only host posture auditor
  - copyfail-defense-sysctl    - host-wide unprivileged userns sysctl (v2.0.2)
  - copyfail-defense-audit     - auditd tripwire rules (v2.0.2; soft-dep)

The shim is INSTALLED but NOT enabled by this package. To enable it
system-wide:

    /usr/sbin/copyfail-shim-enable

To disable:

    /usr/sbin/copyfail-shim-disable

v2.0.1 introduced auto-detection of IPsec / AFS / rootless-container
workloads at install time, suppressing the conflicting drop-ins.
v2.0.2 extends auto-detection to userns consumers (Flatpak, firejail,
desktop browsers) for the new host-wide sysctl drop-in. The detection
report at /var/lib/copyfail-defense/auto-detect.json shows what ran
and what was suppressed; /usr/sbin/copyfail-redetect re-runs detection
on demand. Override the auto-detection by creating
/etc/copyfail/force-full before install.

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
RestrictAddressFamilies=~AF_ALG ~AF_KEY ~AF_RXRPC drop-ins for
kernel-enforced coverage, and with the kernel patch for full coverage.

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
Requires:       /usr/bin/python3
# Meta package owns detect.sh under /usr/libexec/copyfail-defense/
# (called from this subpackage's %posttrans), so -modprobe must pull
# meta even when the operator installs -modprobe alone. Hard Require
# (not Recommends) so --setopt=install_weak_deps=false still pulls it.
Requires:       %{name} = %{epoch}:%{version}-%{release}

%description modprobe
Modprobe blacklist + install-redirect for kernel modules used by the
Copy Fail bug-class entry points:
  - cf1 (CVE-2026-31431):           algif_aead, authenc, authencesn, af_alg
  - cf2 / Dirty Frag-ESP (CVE-2026-43284):
                                    esp4, esp6, xfrm_user, xfrm_algo
  - Dirty Frag-RxRPC (CVE-2026-43500):
                                    rxrpc
  - Fragnesia (no CVE yet, same surface as CVE-2026-43284):
                                    covered by the esp4/esp6 blacklist

Drops /etc/modprobe.d/99-copyfail-defense-cf1.conf (always-on, config
noreplace, operator-override safe) plus conditional drop files for
cf2-xfrm and rxrpc managed by /usr/libexec/copyfail-defense/detect.sh.

NOTE: on RHEL-family kernels algif_aead is built-in
(CRYPTO_USER_API_AEAD=y), so the cf1 modprobe drop is a no-op there;
the LD_PRELOAD shim and systemd RestrictAddressFamilies=~AF_ALG are
the real cf1 cuts on those kernels. The supported escape is the
kernel command line: `grubby --update-kernel ALL --args
"initcall_blacklist=algif_aead_init"` followed by a reboot. The
auditor reports this state under MITIGATION.

WILL BREAK workloads that legitimately use IPsec (strongSwan, libreswan,
FRRouting), AFS (openafs, kafs), or kernel crypto via AF_ALG (some QEMU
configs, dm-crypt-via-AF_ALG userspace). Auto-detection suppresses the
conflicting drop file on detected hosts; confirm posture before
installing on hosts that run any of these.

# ---------------------------------------------------------------------------
%package systemd
Summary:        systemd drop-ins blocking cf-class primitives on tenant units
BuildArch:      noarch
Requires:       systemd
Requires(post): systemd
Requires:       /usr/bin/python3
# Meta package owns detect.sh under /usr/libexec/copyfail-defense/
# (called from this subpackage's %posttrans), so -systemd must pull
# meta even when the operator installs -systemd alone (the case the
# v2.0.1 hotfix's M-2 review caught). Hard Require so
# --setopt=install_weak_deps=false still pulls it.
Requires:       %{name} = %{epoch}:%{version}-%{release}

%description systemd
systemd unit drop-ins applying RestrictAddressFamilies=~AF_ALG ~AF_KEY
~AF_RXRPC, RestrictNamespaces=~user ~net, SystemCallFilter=~@swap, and
SystemCallArchitectures=native to: user@.service, sshd.service,
cron.service, crond.service, atd.service.

v2.0.2 adds ~AF_KEY to RestrictAddressFamilies: the legacy PF_KEYv2
socket is one of the two SA-config paths used by the Dirty Frag /
Fragnesia chain (the other, XFRM netlink, still requires
CAP_NET_ADMIN). Modern userland uses XFRM netlink; AF_KEY is legacy
with negligible compatibility risk on the five tenant units.

These cuts block the userspace prerequisites for cf2 / Dirty Frag-ESP
(unprivileged user namespace creation, AF_KEY SA install) and the
AF_RXRPC socket required by Dirty Frag-RxRPC, kernel-enforced at the
unit level (uncircumventable from userspace).

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
  - cf2 (CVE-2026-43284) - xfrm-ESP skip_cow / Dirty Frag-ESP
  - Dirty Frag-RxRPC (CVE-2026-43500) - rxrpc pcbc(fcrypt) on splice'd frag
  - Fragnesia (no CVE yet) - ESP-in-TCP, same surface as CVE-2026-43284

SAFE BY DESIGN: writes only to mkdtemp() sentinel files, never modifies
/usr/bin or /etc, runs unprivileged (some checks degrade gracefully
without root). The optional trigger probe targets a freshly-created
sentinel file - it does not corrupt /usr/bin/su or anything else.

JSON output (--json) is fleet-rollout friendly; consume the
posture.verdict, posture.bug_classes_covered (array), and
posture.bug_classes (per-class map) fields, not the human report.

# ---------------------------------------------------------------------------
%package sysctl
Summary:        Host-wide sysctl drop-in disabling unprivileged user namespaces
BuildArch:      noarch
Requires:       procps-ng
# Meta package owns detect.sh under /usr/libexec/copyfail-defense/
# (called from this subpackage's %posttrans); hard Requires so
# --setopt=install_weak_deps=false still pulls it.
Requires:       %{name} = %{epoch}:%{version}-%{release}

%description sysctl
Host-wide sysctl drop-in to /etc/sysctl.d/99-copyfail-defense-userns.conf
disabling unprivileged user-namespace creation:
  - user.max_user_namespaces                     = 0
  - kernel.unprivileged_userns_clone             = 0
  - kernel.apparmor_restrict_unprivileged_userns = 1

The cf2 / Dirty Frag-ESP / Fragnesia chains need CLONE_NEWUSER to
acquire CAP_NET_ADMIN-in-namespace, which gates the xfrm SA install.
The systemd RestrictNamespaces=~user drop-in only protects the five
tenant units; this sysctl closes the same gap host-wide for any
unprivileged process not started by those units.

Keys are prefixed with '-' so unknown keys on a given kernel are
silently skipped (sysctl.d(5)) - the three keys above are not all
defined on every distro.

WILL BREAK workloads that legitimately need unprivileged userns:
rootless containers (rootless podman/buildah), Flatpak runtimes,
firejail sandboxes, and desktop browser renderer sandboxes
(Chromium/Chrome/Firefox). Auto-detection suppresses the drop file
when these are present; the drop-in is removed if any of
   - rootless container storage (existing v2.0.1 detector)
   - Flatpak apps/runtimes
   - firejail binary
   - desktop browser binaries
is detected. See /var/lib/copyfail-defense/auto-detect.json for the
decision trace.

# ---------------------------------------------------------------------------
%package audit
Summary:        auditd tripwire rules for cf-class userspace prep
BuildArch:      noarch
Requires:       audit

%description audit
auditd tripwire rules dropped to /etc/audit/rules.d/99-copyfail-defense.rules
catching the userspace prep steps of the Copy Fail bug class:
  - socket(AF_ALG,  ...) - cf1 (CVE-2026-31431)        - tag copyfail_afalg
  - socket(AF_KEY,  ...) - cf2 / DF-ESP / Fragnesia    - tag copyfail_afkey
  - socket(AF_RXRPC,...) - Dirty Frag-RxRPC (CVE-2026-43500)
                                                       - tag copyfail_afrxrpc

Filters auid>=1000 + auid!=-1 to skip unattended system services;
unprivileged-user exploitation is the precise case these rules catch.

Real value is on hosts where the modprobe blacklist is suppressed
(IPsec / AFS workloads) and the kernel sink is intentionally
reachable - the rules become the residual tripwire.

Query examples:
    ausearch -k copyfail_afalg     --start today
    ausearch -k copyfail_afkey     --start today
    ausearch -k copyfail_afrxrpc   --start today

x86_64 native ABI only (b64); i386-compat socket() rides socketcall()
on b32 and is intentionally out of scope.

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
# cf1 always-on; cf2-xfrm + rxrpc as templates under /usr/share/.
install -d -m 0755 %{buildroot}/etc/modprobe.d
install -m 0644 %{SOURCE3} \
    %{buildroot}/etc/modprobe.d/99-copyfail-defense-cf1.conf

install -d -m 0755 %{buildroot}/usr/share/copyfail-defense/conditional/modprobe
install -m 0644 %{SOURCE6} \
    %{buildroot}/usr/share/copyfail-defense/conditional/modprobe/99-copyfail-defense-cf2-xfrm.conf
install -m 0644 %{SOURCE7} \
    %{buildroot}/usr/share/copyfail-defense/conditional/modprobe/99-copyfail-defense-rxrpc.conf

# --- systemd subpackage layout ---
# 10-* always-on body installed for all 5 tenant units.
for u in user@ sshd cron crond atd; do
    install -d -m 0755 \
        %{buildroot}/etc/systemd/system/${u}.service.d
    install -m 0644 %{SOURCE4} \
        %{buildroot}/etc/systemd/system/${u}.service.d/10-copyfail-defense.conf
done

# Conditional drop-in templates (rev 2): 12-rxrpc-af + 15-userns.
install -d -m 0755 %{buildroot}/usr/share/copyfail-defense/conditional/systemd
install -m 0644 %{SOURCE11} \
    %{buildroot}/usr/share/copyfail-defense/conditional/systemd/12-copyfail-defense-rxrpc-af.conf
install -m 0644 %{SOURCE8} \
    %{buildroot}/usr/share/copyfail-defense/conditional/systemd/15-copyfail-defense-userns.conf

# Container-runtime drop-ins ship as opt-in examples (NOT active).
install -d -m 0755 %{buildroot}%{_docdir}/%{name}/examples
install -m 0644 %{SOURCE5} \
    %{buildroot}%{_docdir}/%{name}/examples/containers-dropin.conf

# --- sysctl subpackage layout (v2.0.2) ---
# Ships as a template under /usr/share/...; detect.sh copies to
# /etc/sysctl.d/ in %posttrans iff no userns-consumer is detected
# (rootless containers, Flatpak, firejail, desktop browser).
install -d -m 0755 %{buildroot}/usr/share/copyfail-defense/conditional/sysctl
install -m 0644 %{SOURCE12} \
    %{buildroot}/usr/share/copyfail-defense/conditional/sysctl/99-copyfail-defense-userns.conf

# --- audit subpackage layout (v2.0.2) ---
# Rules drop directly into /etc/audit/rules.d/. Mode 0640 matches the
# convention shipped by the audit package itself (root-only readability).
install -d -m 0755 %{buildroot}/etc/audit/rules.d
install -m 0640 %{SOURCE13} \
    %{buildroot}/etc/audit/rules.d/99-copyfail-defense.rules

# --- detection helper + meta layout ---
install -d -m 0755 %{buildroot}/usr/libexec/copyfail-defense
install -m 0755 %{SOURCE9} \
    %{buildroot}/usr/libexec/copyfail-defense/detect.sh

install -d -m 0755 %{buildroot}%{_sbindir}
install -m 0755 %{SOURCE10} \
    %{buildroot}%{_sbindir}/copyfail-redetect

# State directory (auto-detect.json gets written here at first %posttrans).
install -d -m 0755 %{buildroot}/var/lib/copyfail-defense

# Sentinel directory (operator drops force-full file here pre-install).
install -d -m 0755 %{buildroot}/etc/copyfail

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
# %pretrans modprobe - v2.0.0 -> v2.0.1 upgrade cleanup (D-37).
# Rename the v2.0.0 monolithic %config file to .rpmsave-v2.0.1 so:
#   1. RPM's default .rpmsave-then-skip-new behavior is bypassed
#      (new split files land cleanly on unpack).
#   2. Operator hand-edits to the v2.0.0 file are preserved on disk
#      for inspection/recovery (C-4: same-day v2.0.0 -> v2.0.1 ship
#      means hand-edits are plausible).
# Conditional on the v2.0.0 RPM having been installed.
%pretrans modprobe
old=/etc/modprobe.d/99-copyfail-defense.conf
if [ -f "$old" ] && \
   rpm -q copyfail-defense-modprobe --qf '%%{version}' 2>/dev/null \
       | grep -q '^2\.0\.0$'; then
    mv -f "$old" "${old}.rpmsave-v2.0.1"
    logger -t copyfail-defense -p authpriv.info \
        "pretrans: renamed v2.0.0 monolithic modprobe drop file to ${old}.rpmsave-v2.0.1" \
        2>/dev/null || true
fi
exit 0

# %pretrans systemd - same logic, five files.
%pretrans systemd
if rpm -q copyfail-defense-systemd --qf '%%{version}' 2>/dev/null \
       | grep -q '^2\.0\.0$'; then
    for u in user@ sshd cron crond atd; do
        f="/etc/systemd/system/${u}.service.d/10-copyfail-defense.conf"
        if [ -f "$f" ]; then
            mv -f "$f" "${f}.rpmsave-v2.0.1"
        fi
    done
    logger -t copyfail-defense -p authpriv.info \
        'pretrans: renamed v2.0.0 monolithic systemd drop-in files to .rpmsave-v2.0.1' \
        2>/dev/null || true
fi
exit 0

# ---------------------------------------------------------------------------
%post modprobe
# %post fires before %posttrans - we don't yet know whether to apply
# cf2-xfrm or rxrpc (detect.sh runs in %posttrans). So %post only
# rmmods cf1 modules unconditionally; %posttrans handles cf2/rxrpc
# rmmod conditionally based on whether the drop-in landed.
{
    for m in algif_aead authenc authencesn af_alg; do
        if /sbin/rmmod "$m" 2>/dev/null; then
            printf 'rmmod %s: unloaded\n' "$m"
        elif [ -d "/sys/module/$m" ]; then
            printf 'rmmod %s: still loaded (in-use or builtin)\n' "$m"
        fi
    done
} | logger -t copyfail-defense -p authpriv.info 2>/dev/null || true
exit 0

%postun modprobe -p /bin/bash
# On full erase, remove conditional /etc/ files via detect.sh
# teardown. RPM has already removed the always-on cf1 file by this
# point. detect.sh ships in the META package (/usr/libexec/copyfail-defense/)
# and is called from both -modprobe and -systemd %posttrans/%postun.
# Both subpackages have a hard Requires on meta, so detect.sh is
# normally available throughout this scriptlet. The fallback inline
# teardown remains for the corner case where dnf removes meta in the
# same transaction (rare but possible if meta itself is being erased).
if [ "$1" -eq 0 ]; then
    if [ -x /usr/libexec/copyfail-defense/detect.sh ]; then
        /usr/libexec/copyfail-defense/detect.sh teardown modprobe \
            2> >(tee /dev/stderr \
                | logger -t copyfail-defense -p authpriv.info 2>/dev/null) \
            || true
    else
        rm -f /etc/modprobe.d/99-copyfail-defense-cf2-xfrm.conf
        rm -f /etc/modprobe.d/99-copyfail-defense-rxrpc.conf
    fi
fi
exit 0

%posttrans modprobe -p /bin/bash
# v2.0.1 rev 2: run detect.sh in modprobe scope only. Per D-56 the
# scope arg prevents this %posttrans from creating orphan
# /etc/systemd/system/<unit>.service.d/12-* or 15-* files when
# -systemd is not installed. detect.sh writes auto-detect.json
# regardless of scope. stderr tees to dnf output (D-55) so
# operator sees warnings during install.
/usr/libexec/copyfail-defense/detect.sh apply modprobe 2> >(tee /dev/stderr \
    | logger -t copyfail-defense -p authpriv.info 2>/dev/null) \
    || true

# cf2 / rxrpc rmmod (conditional - only modules the drop file applies).
{
    if [ -f /etc/modprobe.d/99-copyfail-defense-cf2-xfrm.conf ]; then
        for m in esp4 esp6 xfrm_user xfrm_algo; do
            if /sbin/rmmod "$m" 2>/dev/null; then
                printf 'rmmod %s: unloaded\n' "$m"
            elif [ -d "/sys/module/$m" ]; then
                printf 'rmmod %s: still loaded (in-use or builtin)\n' "$m"
            fi
        done
    fi
    if [ -f /etc/modprobe.d/99-copyfail-defense-rxrpc.conf ]; then
        if /sbin/rmmod rxrpc 2>/dev/null; then
            printf 'rmmod rxrpc: unloaded\n'
        elif [ -d "/sys/module/rxrpc" ]; then
            printf 'rmmod rxrpc: still loaded (in-use or builtin)\n'
        fi
    fi
} | logger -t copyfail-defense -p authpriv.info 2>/dev/null || true

# Existing "still loaded" warning, scoped to whatever module set is
# actually applied on this host.
applied_mods="algif_aead authenc authencesn af_alg"
[ -f /etc/modprobe.d/99-copyfail-defense-cf2-xfrm.conf ] && \
    applied_mods="$applied_mods esp4 esp6 xfrm_user xfrm_algo"
[ -f /etc/modprobe.d/99-copyfail-defense-rxrpc.conf ] && \
    applied_mods="$applied_mods rxrpc"
loaded=""
for m in $applied_mods; do
    grep -qE "^$m " /proc/modules 2>/dev/null && loaded="$loaded $m"
done
if [ -n "$loaded" ]; then
    cat <<EOF >&2
NOTICE: copyfail-defense-modprobe installed but the following listed
modules are still loaded in the running kernel:$loaded
They will be blocked on next load attempt; reboot to clear running state.
EOF
fi
exit 0

# ---------------------------------------------------------------------------
%post systemd
# Defer daemon-reload to %posttrans so we reload after detect.sh has
# applied/suppressed the 15-*.conf userns drop-ins. %post runs before
# %posttrans; reloading here would reload-without the conditional
# drop-ins on first install, then again with them in %posttrans -
# cosmetically wasteful and racy.
exit 0

%posttrans systemd -p /bin/bash
# v2.0.1 rev 2: scope=systemd per D-56. -modprobe %posttrans uses
# scope=modprobe and never touches /etc/systemd/system/...d/. This
# %posttrans only manages systemd drop-ins. Both write
# auto-detect.json (idempotent rewrite). stderr tees to dnf
# scriptlet output per D-55.
/usr/libexec/copyfail-defense/detect.sh apply systemd 2> >(tee /dev/stderr \
    | logger -t copyfail-defense -p authpriv.info 2>/dev/null) \
    || true
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl try-reload-or-restart sshd.service 2>/dev/null || true
fi
exit 0

%postun systemd -p /bin/bash
if [ "$1" -eq 0 ]; then
    if [ -x /usr/libexec/copyfail-defense/detect.sh ]; then
        /usr/libexec/copyfail-defense/detect.sh teardown systemd \
            2> >(tee /dev/stderr \
                | logger -t copyfail-defense -p authpriv.info 2>/dev/null) \
            || true
    else
        # Fallback: detect.sh removed by -modprobe %postun before this
        # ran. Inline the teardown so /etc/... is clean regardless.
        for u in user@ sshd cron crond atd; do
            rm -f "/etc/systemd/system/${u}.service.d/12-copyfail-defense-rxrpc-af.conf"
            rm -f "/etc/systemd/system/${u}.service.d/15-copyfail-defense-userns.conf"
        done
    fi
    if [ -d /run/systemd/system ]; then
        systemctl daemon-reload || true
        systemctl try-reload-or-restart sshd.service 2>/dev/null || true
    fi
fi
exit 0

# ---------------------------------------------------------------------------
# sysctl subpackage scriptlets (v2.0.2)
%post sysctl
cat <<'EOF'

copyfail-defense-sysctl installed.

Detection-driven activation runs in %posttrans below; the host-wide
userns sysctl drop file lands at /etc/sysctl.d/99-copyfail-defense-userns.conf
only if no rootless containers, Flatpak runtimes, firejail, or
desktop browsers are present on this host.

Inspect the decision:
    sudo cat /var/lib/copyfail-defense/auto-detect.json

EOF
exit 0

%posttrans sysctl -p /bin/bash
# Detection-driven file placement first, then sysctl --system to load
# whatever landed. detect.sh emits the same proc-sub stderr-tee idiom
# as the modprobe/systemd %posttrans (D-55); requires -p /bin/bash.
/usr/libexec/copyfail-defense/detect.sh apply sysctl 2> >(tee /dev/stderr \
    | logger -t copyfail-defense -p authpriv.info 2>/dev/null) \
    || true

if [ -f /etc/sysctl.d/99-copyfail-defense-userns.conf ]; then
    # Use -p <file> instead of --system to avoid re-applying every other
    # sysctl.d drop-in (noisy + unrelated). The '-' prefix on our keys
    # silences "unknown key" errors on kernels where one of the three
    # keys is undefined (sysctl.d(5)).
    sysctl -p /etc/sysctl.d/99-copyfail-defense-userns.conf 2>&1 \
        | logger -t copyfail-defense -p authpriv.info 2>/dev/null \
        || true
fi
exit 0

%postun sysctl -p /bin/bash
if [ "$1" -eq 0 ]; then
    if [ -x /usr/libexec/copyfail-defense/detect.sh ]; then
        /usr/libexec/copyfail-defense/detect.sh teardown sysctl \
            2> >(tee /dev/stderr \
                | logger -t copyfail-defense -p authpriv.info 2>/dev/null) \
            || true
    else
        rm -f /etc/sysctl.d/99-copyfail-defense-userns.conf
    fi
    # Reload from the remaining sysctl.d set. user.max_user_namespaces
    # stays at whatever value the kernel's last sysctl --system pass left
    # it at; if no other drop-in sets it, the running-kernel value
    # persists until reboot. Document this in the README "Remove" section.
    sysctl --system 2>&1 \
        | logger -t copyfail-defense -p authpriv.info 2>/dev/null \
        || true
fi
exit 0

# ---------------------------------------------------------------------------
# audit subpackage scriptlets (v2.0.2)
%posttrans audit -p /bin/bash
# augenrules compiles /etc/audit/rules.d/*.rules to /etc/audit/audit.rules
# and applies via auditctl. Idempotent; safe on install + upgrade.
# On hosts without auditd running, augenrules will compile the rules
# file but auditctl --load will fail - that's acceptable. Errors tee
# to dnf scriptlet output per D-55.
if command -v augenrules >/dev/null 2>&1; then
    augenrules --load 2> >(tee /dev/stderr \
        | logger -t copyfail-defense -p authpriv.info 2>/dev/null) \
        | logger -t copyfail-defense -p authpriv.info 2>/dev/null \
        || true
fi
exit 0

%postun audit -p /bin/bash
# On full erase, RPM has already removed /etc/audit/rules.d/99-copyfail-defense.rules
# by the time this scriptlet fires - reload augenrules so the running
# auditd no longer carries our keys.
if [ "$1" -eq 0 ]; then
    if command -v augenrules >/dev/null 2>&1; then
        augenrules --load 2> >(tee /dev/stderr \
            | logger -t copyfail-defense -p authpriv.info 2>/dev/null) \
            | logger -t copyfail-defense -p authpriv.info 2>/dev/null \
            || true
    fi
fi
exit 0

%postun
# Meta package %postun: remove auto-detect.json when all three
# detection-managed subpackages (-modprobe, -systemd, -sysctl) are
# gone. -audit is unconditional and does not consume the detect.sh
# state file. rpm -q returncodes (D-45 / M-9) determine subpackage
# presence, not file existence.
if [ "$1" -eq 0 ]; then
    if ! rpm -q copyfail-defense-modprobe >/dev/null 2>&1 && \
       ! rpm -q copyfail-defense-systemd  >/dev/null 2>&1 && \
       ! rpm -q copyfail-defense-sysctl   >/dev/null 2>&1; then
        rm -f /var/lib/copyfail-defense/auto-detect.json
    fi
fi
exit 0

# ===========================================================================
%files
%license LICENSE
%doc README.md
%dir /etc/copyfail
%{_sbindir}/copyfail-redetect
# Detection helper (called from -modprobe + -systemd %posttrans/%postun
# and from copyfail-redetect). Owned here in meta so a single copy
# exists regardless of which subpackages are installed; both -modprobe
# and -systemd hard-Require meta to guarantee this binary is present
# before their scriptlets fire.
%dir /usr/libexec/copyfail-defense
/usr/libexec/copyfail-defense/detect.sh
# State directory (auto-detect.json lives here). Owned by meta so
# it exists from first install regardless of which subpackages are
# present; -modprobe and -systemd no longer need to %dir-claim it.
%dir /var/lib/copyfail-defense

%files shim
%license LICENSE
%doc README.md
%{_libdir}/no-afalg.so
%{_sbindir}/copyfail-shim-enable
%{_sbindir}/copyfail-shim-disable

%files modprobe
%license LICENSE
%doc README.md
# Always-on cf1 cut - operator-editable, RPM-tracked.
%config(noreplace) /etc/modprobe.d/99-copyfail-defense-cf1.conf
# Conditional cut templates - copied to /etc/ by %posttrans
# detect.sh per /var/lib/copyfail-defense/auto-detect.json.
%dir /usr/share/copyfail-defense
%dir /usr/share/copyfail-defense/conditional
%dir /usr/share/copyfail-defense/conditional/modprobe
/usr/share/copyfail-defense/conditional/modprobe/99-copyfail-defense-cf2-xfrm.conf
/usr/share/copyfail-defense/conditional/modprobe/99-copyfail-defense-rxrpc.conf
# detect.sh + /usr/libexec/copyfail-defense + /var/lib/copyfail-defense
# moved to meta package %files in v2.0.1 fixup pass (M-2): they were
# only listed here, so installing -systemd without -modprobe missed
# detect.sh and the %posttrans silently no-op'd.

%files systemd
%license LICENSE
%doc README.md
%dir /etc/systemd/system/user@.service.d
%dir /etc/systemd/system/sshd.service.d
%dir /etc/systemd/system/cron.service.d
%dir /etc/systemd/system/crond.service.d
%dir /etc/systemd/system/atd.service.d
# Always-on (10-) drop-ins: RestrictAddressFamilies=~AF_ALG +
# SystemCallArchitectures + SystemCallFilter (rev 2: ~AF_RXRPC moved
# to conditional 12-* drop-in).
%config(noreplace) /etc/systemd/system/user@.service.d/10-copyfail-defense.conf
%config(noreplace) /etc/systemd/system/sshd.service.d/10-copyfail-defense.conf
%config(noreplace) /etc/systemd/system/cron.service.d/10-copyfail-defense.conf
%config(noreplace) /etc/systemd/system/crond.service.d/10-copyfail-defense.conf
%config(noreplace) /etc/systemd/system/atd.service.d/10-copyfail-defense.conf
# Conditional drop-in templates (rev 2):
#   12-* RestrictAddressFamilies=~AF_RXRPC: copied to /etc/...d/12-*.conf
#        by %posttrans detect.sh; suppressed on AFS hosts.
#   15-* RestrictNamespaces=~user ~net: copied to /etc/...d/15-*.conf;
#        suppressed for user@.service.d when rootless containers detected.
%dir /usr/share/copyfail-defense/conditional/systemd
/usr/share/copyfail-defense/conditional/systemd/12-copyfail-defense-rxrpc-af.conf
/usr/share/copyfail-defense/conditional/systemd/15-copyfail-defense-userns.conf
# %dir /var/lib/copyfail-defense moved to meta %files (v2.0.1 fixup M-2).
# Existing example doc unchanged.
%dir %{_docdir}/%{name}/examples
%{_docdir}/%{name}/examples/containers-dropin.conf

%files auditor
%license LICENSE
%doc README.md
%{_sbindir}/copyfail-local-check

%files sysctl
%license LICENSE
%doc README.md
# Conditional sysctl drop-in template - copied to /etc/sysctl.d/ by
# %posttrans detect.sh per /var/lib/copyfail-defense/auto-detect.json
# (suppressed when rootless containers, Flatpak, firejail, or a
# desktop browser is detected on the host).
%dir /usr/share/copyfail-defense/conditional/sysctl
/usr/share/copyfail-defense/conditional/sysctl/99-copyfail-defense-userns.conf

%files audit
%license LICENSE
%doc README.md
# auditd rules drop directly to /etc/audit/rules.d/. Marked
# %config(noreplace) so an operator hand-edit survives upgrade
# (the rule set is small and well-defined; if you have a tuned
# set, you want yours preserved).
%dir /etc/audit/rules.d
%config(noreplace) %attr(0640, root, root) /etc/audit/rules.d/99-copyfail-defense.rules

# ===========================================================================
%changelog
* Wed May 13 2026 rfxn.com <proj@rfxn.com> - 1:2.0.2-1
- v2.0.2 broadens cf2 / Dirty Frag / Fragnesia coverage along three
  axes informed by the Fragnesia advisory and the Red Hat / AWS /
  Wiz / Sysdig mitigation guidance published the week of 2026-05-08.
- New subpackage copyfail-defense-sysctl: ships a host-wide sysctl
  drop-in at /etc/sysctl.d/99-copyfail-defense-userns.conf that
  disables unprivileged user-namespace creation
  (user.max_user_namespaces=0, kernel.unprivileged_userns_clone=0,
  kernel.apparmor_restrict_unprivileged_userns=1). Keys are
  '-'-prefixed so unknown keys on a given kernel are silently
  skipped (sysctl.d(5)). Closes the CLONE_NEWUSER prerequisite that
  the cf2 / DF-ESP / Fragnesia chain needs for
  CAP_NET_ADMIN-in-namespace and the subsequent xfrm SA install,
  on processes NOT covered by the per-tenant-unit systemd
  RestrictNamespaces drop-in (a shell-user running an exploit
  binary).
- detect.sh extends with detect_userns_consumers() that flags
  Flatpak (system+user installs), firejail, and desktop browsers
  (Chromium/Chrome/Firefox). The sysctl drop-in is suppressed when
  EITHER the existing rootless-container signal OR the new
  userns-consumer signal fires. Per-unit systemd RestrictNamespaces
  is unaffected - still applies to all five tenant units regardless
  of userns-consumer detection. New `apply sysctl` and `teardown
  sysctl` scopes (plus `all` covering modprobe+systemd+sysctl).
  TOOL_VERSION bumped 2.0.1 -> 2.0.2.
- New subpackage copyfail-defense-audit (Requires: audit, Recommends
  from meta so minimal hosts can skip the auditd pull-in): ships
  /etc/audit/rules.d/99-copyfail-defense.rules with three -k-tagged
  rules detecting socket(AF_ALG/AF_KEY/AF_RXRPC) syscalls from
  unprivileged users (auid>=1000 + auid!=-1). Real value is on hosts
  where modprobe blacklist is suppressed by auto-detection
  (IPsec / AFS workloads) and the kernel sink is intentionally
  reachable - the rules become the residual tripwire. Query via
  `ausearch -k copyfail_afalg` / `copyfail_afkey` /
  `copyfail_afrxrpc`. x86_64 native ABI only (b64); i386-compat
  socketcall is intentionally out of scope.
- systemd drop-in 10-copyfail-defense.conf adds ~AF_KEY to
  RestrictAddressFamilies, closing the legacy PF_KEYv2 SA-config
  path used by the Dirty Frag / Fragnesia chain (the other,
  XFRM netlink, still requires CAP_NET_ADMIN). Modern userland
  uses XFRM netlink; AF_KEY is legacy with negligible
  compatibility risk on the five tenant units. Same change
  applied to the containers-dropin.conf example.
- auto-detect.json schema: backward-compatible additions of
  detected.userns_consumers (present + signals array),
  suppressed.sysctl_userns, applied.sysctl_userns. schema_version
  stays at "2" - consumers ignore unknown keys.
- %description modprobe now documents the RHEL builtin case
  (CRYPTO_USER_API_AEAD=y makes the cf1 modprobe drop a no-op) and
  the supported workaround: `grubby --update-kernel ALL --args
  "initcall_blacklist=algif_aead_init"` followed by reboot. The
  cf1 modprobe drop-in itself is unchanged from v2.0.1; this is
  documentation only.
- CVE cross-stamping in subpackage %descriptions:
  cf2 / Dirty Frag-ESP = CVE-2026-43284,
  Dirty Frag-RxRPC = CVE-2026-43500,
  Fragnesia = no CVE yet (same surface as CVE-2026-43284, per Wiz
  and oss-sec disclosure). Previously only CVE-2026-31431 (cf1)
  was pinned inline.

* Fri May 08 2026 rfxn.com <proj@rfxn.com> - 1:2.0.1-2
- 2.0.1-2 packaging hotfix (no functional change): declare
  `-p /bin/bash` on the four scriptlets that use bash process
  substitution (`2> >(tee /dev/stderr | logger ...)`):
  %posttrans modprobe, %posttrans systemd, %postun modprobe,
  %postun systemd. RPM scriptlets default to /bin/sh; on EL/Alma 8
  /bin/sh is bash invoked in POSIX mode, where process substitution
  is rejected as a syntax error. 2.0.1-1 added the proc-sub idiom
  per D-55 (surface detect.sh stderr to dnf output) without a
  matching `-p /bin/bash` on the scriptlet headers, causing
  %posttrans/%postun to abort with `syntax error near unexpected
  token \`>'\` on EL8 hosts. detect.sh never ran, so auto-detect.json
  was never written and conditional drop-ins (cf2-xfrm/rxrpc/userns)
  were never suppressed - the install appeared to succeed but the
  detection-driven hardening was inert. Reported by Jamie Sexton on
  AlmaLinux 8 stage hosts (2026-05-08).
- packaging/test-repo.sh adds a scriptlet-failure regression guard:
  every dnf install/upgrade/remove now greps the captured output
  for `scriptlet failed`, `Error in (POST|PRE)*`, and `syntax error`
  markers and fails loudly if any appear. Closes the gap that let
  2.0.1-1 ship without a final dnf-from-gh-pages canary catching
  this class of bug.
- spec: %pretrans modprobe and %pretrans systemd were querying
  `rpm -q ... --qf '%{version}'` with an unescaped %{version} - RPM
  expanded the macro at build time to the literal new-package
  version (e.g. '2.0.1'), so the rpm-q always returned that string
  regardless of what was installed, and the v2.0.0 -> v2.0.1
  monolithic-file rename guard never fired. Switched to '%%{version}'
  so RPM emits a literal %{version} into the scriptlet body and the
  rpm-q queries the *currently-installed* version. Bug present in
  2.0.1-1; only surfaced on this hotfix's gh-pages-staging canary.
- packaging/test-repo.sh fixes: (a) `mp_count=$(grep -ch ... 3 files)`
  produced a multi-line per-file count, breaking `[ -eq 9 ]` - swap
  to cat-then-grep for a single integer; (b) the systemd_only
  scenario asserted -modprobe was NOT pulled, but the meta package
  Requires all four subpackages (umbrella semantics for
  `dnf install copyfail-defense`), so -modprobe IS always pulled
  transitively - removed the inverted assertion and assert presence
  instead.

* Fri May 08 2026 rfxn.com <proj@rfxn.com> - 1:2.0.1-1
- v2.0.1 hotfix: auto-detect IPsec / AFS / rootless-container
  workloads at install time and suppress the conflicting drop-ins.
  The README's "Override paths" section is now package-driven via
  /usr/libexec/copyfail-defense/detect.sh and reported in
  /var/lib/copyfail-defense/auto-detect.json. Operators can re-run
  detection on demand via /usr/sbin/copyfail-redetect, and force
  full-install (skip detection) by creating /etc/copyfail/force-full
  before %posttrans.
- File-layout split: 99-copyfail-defense.conf becomes three files
  (-cf1 always-on, -cf2-xfrm suppressible-on-IPsec, -rxrpc
  suppressible-on-AFS). Per-tenant-unit systemd drop-ins split into
  10-copyfail-defense.conf (always-on RestrictAddressFamilies +
  SystemCallFilter) and 15-copyfail-defense-userns.conf (suppressible
  on user@.service.d when rootless containers are detected;
  unconditional on sshd/cron/crond/atd).
- %pretrans removes v2.0.0 monolithic %config files before v2.0.1
  unpacks (avoids RPM's default .rpmsave-then-skip-new behavior).
  Conditional on the v2.0.0 RPM having been the source of those
  files - operator-pre-staged files are preserved.
- Auditor reads auto-detect.json and surfaces the detection state
  under posture.auto_detect; new check_auto_detect_state() under
  MITIGATION reports OK / INFO / WARN per detection posture.
- test-repo.sh extends to 25 per-EL checks (was 18 in v2.0.0): clean
  host, IPsec host, AFS host, rootless host, force-full, redetect
  helper, v2.0.0->v2.0.1 split-file upgrade.

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
