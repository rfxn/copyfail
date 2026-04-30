%global         _hardened_build         1
%global         debug_package           %{nil}

# We deliberately do NOT byte-compile or strip the python script - it is
# distributed as plain text so an operator can read it before running.
%global         __os_install_post       %{nil}

# Upstream project tarball is named copyfail-VERSION.tar.gz - that is the
# project name in README/source. The RPM package family is named after the
# defensive primitive (afalg-defense) so it survives any future AF_ALG-family
# bug, not just CVE-2026-31431. Filenames installed into /usr/lib64 and
# /usr/sbin still match upstream source naming.
%global         upstream_name           copyfail

Name:           afalg-defense
Version:        1.0.1
Release:        1%{?dist}
Summary:        Userspace AF_ALG defensive primitives (LD_PRELOAD shim + auditor)

License:        GPLv2
URL:            https://www.rfxn.com/
Source0:        %{upstream_name}-%{version}.tar.gz
# Auxiliary files maintained alongside the spec rather than in the upstream
# tarball - declaring them as Source1..N is what gets them into the SRPM
# (only declared Source* entries make it past `rpmbuild -bs`).
Source1:        copyfail-shim-enable
Source2:        copyfail-shim-disable
Source3:        no-afalg-modprobe.conf
Source4:        no-afalg-systemd-dropin.conf

# x86_64 only: no-afalg.c has an explicit #error for non-x86_64. The auditor
# is portable, but the shim is the load-bearing primitive of this package
# and we do not ship a half-package.
ExclusiveArch:  x86_64

BuildRequires:  gcc
BuildRequires:  glibc-devel
# The auditor is plain Python 3 stdlib at runtime, but %build runs a
# py_compile syntax check against it as a build-time gate (catches mismerged
# patches before they reach a server). EL8/EL10 minimal buildroots do not
# include python3 by default - hence BuildRequires.
BuildRequires:  python3

# Empty meta package ties the two components together. Most operators will
# install just `afalg-defense` and get both halves.
Requires:       %{name}-shim    = %{version}-%{release}
Requires:       %{name}-auditor = %{version}-%{release}

%description
Userspace defensive primitives against AF_ALG / authencesn page-cache
corruption (CVE-2026-31431, "Copy Fail") and the broader AF_ALG attack
surface.

This metapackage installs the LD_PRELOAD shim that blocks AF_ALG socket
creation (afalg-defense-shim) and the comprehensive read-only host posture
auditor (afalg-defense-auditor).

The shim is INSTALLED but NOT enabled by this package. To enable it
system-wide:

    /usr/sbin/copyfail-shim-enable

To disable:

    /usr/sbin/copyfail-shim-disable

Refer to /usr/share/doc/afalg-defense/README.md for the defense-in-depth
ladder this package fits into and the layers it explicitly does not
replace (kernel patch, modprobe blacklist, systemd RestrictAddressFamilies,
seccomp).

# ---------------------------------------------------------------------------
%package shim
Summary:        LD_PRELOAD shim that blocks AF_ALG socket creation
# Upstream contains shim + auditor. We split into subpackages to allow
# operators who only want the auditor on hot infrastructure (where they
# do not yet trust an LD_PRELOAD on every dynamic-linked process) to
# install just afalg-defense-auditor.

%description shim
no-afalg.so: small libdl-based interposer that wraps libc socket(2) and
socketpair(2), denying AF_ALG (domain=38) with EPERM and logging the
attempt to LOG_AUTHPRIV. Intended for /etc/ld.so.preload.

The shim DOES NOT prevent direct-syscall bypass (syscall(SYS_socket,
AF_ALG, ...) or inline asm). Pair with seccomp at the systemd or
container-runtime level for that surface, and with the kernel patch
for full coverage.

THIS SUBPACKAGE INSTALLS no-afalg.so BUT DOES NOT WIRE IT INTO
/etc/ld.so.preload. To activate:

    /usr/sbin/copyfail-shim-enable

The activation helper smoke-tests the .so against /bin/true before
modifying /etc/ld.so.preload, refusing to brick the system if the .so
is broken.

# ---------------------------------------------------------------------------
%package auditor
Summary:        AF_ALG host posture auditor (CVE-2026-31431, read-only)
BuildArch:      noarch
Requires:       python3
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
DETECTION) for CVE-2026-31431 ("Copy Fail") and the AF_ALG attack
surface in general.

SAFE BY DESIGN: writes only to mkdtemp() sentinel files, never modifies
/usr/bin or /etc, runs unprivileged (some checks degrade gracefully
without root). The optional trigger probe targets a freshly-created
sentinel file - it does not corrupt /usr/bin/su or anything else.

JSON output (--json) is fleet-rollout friendly; consume the
posture.verdict field, not the human report.

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
# server. Build host arch must match the package arch (ExclusiveArch:
# x86_64), so this is meaningful.
LD_PRELOAD=$PWD/no-afalg.so /bin/true

# Confirm the auditor is parseable Python 3 on the build host.
python3 -c "import py_compile; py_compile.compile('copyfail-local-check.py', doraise=True)"

%install
rm -rf %{buildroot}

# --- shim subpackage layout ---
# Shared libraries ship 0755 by convention even when nothing exec's them
# directly (Fedora packaging guideline, and rpmlint enforces it).
install -d -m 0755 %{buildroot}%{_libdir}
install -m 0755 no-afalg.so %{buildroot}%{_libdir}/no-afalg.so

install -d -m 0755 %{buildroot}%{_sbindir}
install -m 0755 %{SOURCE1} %{buildroot}%{_sbindir}/copyfail-shim-enable
install -m 0755 %{SOURCE2} %{buildroot}%{_sbindir}/copyfail-shim-disable

# --- auditor subpackage layout ---
# Drop the .py extension on the installed name, in keeping with how
# system tools are typically invoked (mkpasswd, semanage, etc.).
install -m 0755 copyfail-local-check.py \
    %{buildroot}%{_sbindir}/copyfail-local-check
# Replace `#!/usr/bin/env python3` with the absolute interpreter path:
# Fedora packaging guideline (env-based shebangs are non-deterministic
# under restricted PATH and rpmlint flags them as errors).
sed -i '1s|^#!/usr/bin/env python3|#!/usr/bin/python3|' \
    %{buildroot}%{_sbindir}/copyfail-local-check

# --- shared docs / examples ---
install -d -m 0755 %{buildroot}%{_docdir}/%{name}/examples
install -m 0644 %{SOURCE3} %{buildroot}%{_docdir}/%{name}/examples/no-afalg-modprobe.conf
install -m 0644 %{SOURCE4} %{buildroot}%{_docdir}/%{name}/examples/no-afalg-systemd-dropin.conf

# License and README go into the meta package's docdir; subpackages get
# them too via %license / %doc directives so rpm -ql works the way an
# operator expects.

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
# Print actionable guidance, do not modify the system.
cat <<'EOF'

afalg-defense-shim installed but NOT yet enabled.

To activate the AF_ALG block on this host:
    /usr/sbin/copyfail-shim-enable

To remove later:
    /usr/sbin/copyfail-shim-disable
    dnf remove afalg-defense afalg-defense-shim afalg-defense-auditor

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
        tmp=$(mktemp /etc/ld.so.preload.XXXXXX) || exit 0
        grep -Fxv /usr/lib64/no-afalg.so /etc/ld.so.preload > "$tmp" || true
        if [ -s "$tmp" ]; then
            chmod 0644 "$tmp"
            mv -f "$tmp" /etc/ld.so.preload
        else
            rm -f "$tmp" /etc/ld.so.preload
        fi
    fi
fi
exit 0

# %posttrans runs after all %post / %preun in the transaction, so it is
# the right place for any "advise the operator about state" messaging
# that should fire even on upgrade. Keep it informational only.
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
%dir %{_docdir}/%{name}
%dir %{_docdir}/%{name}/examples
%{_docdir}/%{name}/examples/no-afalg-modprobe.conf
%{_docdir}/%{name}/examples/no-afalg-systemd-dropin.conf

%files auditor
%license LICENSE
%doc README.md
%{_sbindir}/copyfail-local-check

# ===========================================================================
%changelog
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
