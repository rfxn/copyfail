# PLAN — `copyfail-defense` v2.0.0

**Source:** `SPEC.md` rev 3 (drafted 2026-05-08).
**Status:** Implementation in progress. Phases 1–6 (source-only changes)
will be executed autonomously. Phases 7–9 (mock builds, signing, gh-pages
push, GH release) **stop at the build/publish boundary** — they require
the build host's signing key and externally-visible state changes that
should not be triggered headless.

All decisions reference `SPEC.md` §9 by **[D-NN]**. None of them are
reopened here.

---

## Dependency graph

```
                    ┌──────────────────────┐
                    │ Phase 1              │
                    │ Spec restructure     │  (foundational)
                    └──────────┬───────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
        ▼                      ▼                      ▼
┌───────────────┐      ┌───────────────┐      ┌───────────────┐
│ Phase 2       │      │ Phase 3       │      │ Phase 4       │
│ -modprobe pkg │      │ -systemd pkg  │      │ -shim rename  │
└───────┬───────┘      └───────┬───────┘      └───────┬───────┘
        │                      │                      │
        │              ┌───────────────┐              │
        │              │ Phase 5       │              │
        │              │ -auditor      │              │
        │              │ expansion     │              │
        │              └───────┬───────┘              │
        └──────────────┐       │       ┌──────────────┘
                       ▼       ▼       ▼
                    ┌──────────────────────┐
                    │ Phase 6              │
                    │ test-repo.sh extend  │
                    └──────────┬───────────┘
                               │
                    ═══════════╪═══════════════════
                    ║ BUILD/PUBLISH BOUNDARY ║
                    ═══════════╪═══════════════════
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Phase 7              │
                    │ Mock + sign + repo   │  (needs signing key)
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Phase 8              │
                    │ Docs (README, gh-pg) │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Phase 9              │
                    │ Release v2.0.0       │  (gh release / push)
                    └──────────────────────┘
```

---

## Phase 1 — Spec restructure (foundational)

**Goal.** Rename `packaging/afalg-defense.spec` → `packaging/copyfail-defense.spec`.
Introduce `Epoch: 1` + Obsoletes/Provides chains. Add stanzas for the
new `-modprobe` and `-systemd` subpackages (bodies filled in Phases 2/3).
No behavioural change to shim/auditor in this phase.

**Files.**
- `packaging/copyfail-defense.spec` (new, derived from existing)
- `packaging/afalg-defense.spec` (deleted)
- `packaging/copyfail.repo` (`name=` field updated)
- `packaging/copyfail-modprobe.conf` (new — populated in Phase 2)
- `packaging/copyfail-systemd-dropin.conf` (new — populated in Phase 3)
- `packaging/no-afalg-modprobe.conf` (deleted — replaced by above)
- `packaging/no-afalg-systemd-dropin.conf` (deleted — replaced by above)

**Acceptance.**
- `rpm --specfile packaging/copyfail-defense.spec --qf '%{name}-%{epoch}:%{version}\n' | sort -u`
  shows `copyfail-defense-1:2.0.0`, `copyfail-defense-shim-1:2.0.0`,
  `copyfail-defense-modprobe-1:2.0.0`, `copyfail-defense-systemd-1:2.0.0`,
  `copyfail-defense-auditor-1:2.0.0`.
- `rpm --specfile packaging/copyfail-defense.spec --provides | grep ^afalg-defense`
  shows `Provides:` lines for the three renamed subpackages.
- `rpm --specfile packaging/copyfail-defense.spec --obsoletes | grep ^afalg-defense`
  shows three `Obsoletes:` lines pinning to `< 1:2.0.0`.

---

## Phase 2 — `-modprobe` subpackage   `parallel:`

**Goal.** Per **[D-06], [D-07], [D-08], [D-24]**.

**Files.**
- `packaging/copyfail-modprobe.conf` (new) — the full cf-class drop file.
- `packaging/copyfail-defense.spec` — fill `%package modprobe` body.

**Spec block** (drop into Phase 1's stub):

```spec
%package modprobe
Summary:        Modprobe blacklist for cf-class kernel sinks
BuildArch:      noarch
Requires(post): kmod
Requires(post): util-linux
%description modprobe
Modprobe blacklist + install-redirect for kernel modules used by the
Copy Fail bug-class entry points: AF_ALG (cf1, CVE-2026-31431),
xfrm-ESP (cf2 / Dirty Frag-ESP), and RxRPC (Dirty Frag-RxRPC).

This subpackage will break workloads that legitimately use IPsec
(strongSwan, libreswan, FRRouting), AFS (openafs, kafs), or kernel
crypto via AF_ALG (some QEMU configs, dm-crypt-via-AF_ALG userspace).
Confirm posture before installing on hosts that run any of these.

%files modprobe
%license LICENSE
%doc README.md
%config(noreplace) /etc/modprobe.d/99-copyfail-defense.conf

%post modprobe
for m in algif_aead authenc authencesn af_alg esp4 esp6 \
         xfrm_user xfrm_algo rxrpc; do
    /sbin/rmmod "$m" 2>/dev/null || true
done | logger -t copyfail-defense || true
exit 0

%preun modprobe
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
They will be blocked on next load attempt; reboot to clear.
EOF
fi
exit 0
```

**Modprobe drop file** (`packaging/copyfail-modprobe.conf` →
`/etc/modprobe.d/99-copyfail-defense.conf` per **[D-06]**) — full content
in spec section §4.2.

**Acceptance.**
- `rpm -qpl rpmbuild/RPMS/noarch/copyfail-defense-modprobe-2.0.0-1.*.noarch.rpm`
  contains `/etc/modprobe.d/99-copyfail-defense.conf`.
- File mode `0644 root:root`. `%config(noreplace)` flagged.
- All 9 module lines present (algif_aead, authenc, authencesn,
  af_alg, esp4, esp6, xfrm_user, xfrm_algo, rxrpc).

---

## Phase 3 — `-systemd` subpackage   `parallel:`

**Goal.** Per **[D-09], [D-09a], [D-10], [D-11], [D-12], [D-12a], [D-13], [D-24], [D-25]**.

**Files.**
- `packaging/copyfail-systemd-dropin.conf` (new) — single body
  replicated across units.
- `packaging/copyfail-defense.spec` — fill `%package systemd` body.

**Drop-in body** (`packaging/copyfail-systemd-dropin.conf`):

```ini
# /etc/systemd/system/<unit>.service.d/10-copyfail-defense.conf
# Owned by copyfail-defense-systemd; do not hand-edit.
# Override per-host: drop a 20-*.conf in the same directory with empty
# values for any directive you need to relax.
[Service]
RestrictAddressFamilies=~AF_ALG ~AF_RXRPC
RestrictNamespaces=~user ~net
SystemCallArchitectures=native
SystemCallFilter=~@swap
```

**Container-runtime example body** (`packaging/examples/copyfail-systemd-dropin-containers.conf` —
shipped as doc-only, NOT installed as active drop-in):

```ini
# Optional drop-in for containerd/docker/podman service units.
# Copy to /etc/systemd/system/<runtime>.service.d/10-copyfail-defense.conf
# ONLY if your fleet does NOT run rootless or userns-remapped
# containers via the runtime daemons.
[Service]
RestrictAddressFamilies=~AF_ALG ~AF_RXRPC
RestrictNamespaces=~user ~net
SystemCallArchitectures=native
SystemCallFilter=~@swap
```

**Spec block**:

```spec
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
Override: drop a 20-*.conf with empty directive values per unit.
See README.

%install systemd
for u in user@ sshd cron crond atd; do
    install -d -m 0755 \
        %{buildroot}/etc/systemd/system/${u}.service.d
    install -m 0644 %{SOURCE5} \
        %{buildroot}/etc/systemd/system/${u}.service.d/10-copyfail-defense.conf
done
# Container-runtime drop-ins ship as opt-in examples
install -d -m 0755 %{buildroot}%{_docdir}/%{name}/examples
install -m 0644 %{SOURCE6} \
    %{buildroot}%{_docdir}/%{name}/examples/containers-dropin.conf

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
%dir %{_docdir}/%{name}
%dir %{_docdir}/%{name}/examples
%{_docdir}/%{name}/examples/containers-dropin.conf

%post systemd
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl try-reload-or-restart sshd.service 2>/dev/null || true
fi
exit 0

%preun systemd
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl try-reload-or-restart sshd.service 2>/dev/null || true
fi
exit 0
```

Add `Source5: copyfail-systemd-dropin.conf` and
`Source6: copyfail-systemd-dropin-containers.conf` to spec preamble.

**Acceptance.**
- `rpm -qpl rpmbuild/RPMS/noarch/copyfail-defense-systemd-2.0.0-1.*.noarch.rpm`
  lists 5 active drop files under
  `/etc/systemd/system/{user@,sshd,cron,crond,atd}.service.d/`.
- Container-runtime example file ships under
  `/usr/share/doc/copyfail-defense/examples/containers-dropin.conf`.
- Each active drop file marked `%config(noreplace)`.
- Drop file body contains all four directives.

---

## Phase 4 — `-shim` rename   `parallel:`

**Goal.** Pure rename of `afalg-defense-shim` → `copyfail-defense-shim`.
Behaviour, files, scriptlets all unchanged. Per **[D-05]**, drop the
v1.0.1 example dropin doc-files from `-shim`.

**Changes**:
- `%package shim` metadata: update `Obsoletes:`/`Provides:`.
- `%files shim`: remove `%dir %{_docdir}/%{name}/examples` and the
  two `examples/no-afalg-*.conf` entries — those concerns now owned
  by `-modprobe` and `-systemd`.
- `%post shim` cat-heredoc: replace `afalg-defense*` package names
  with `copyfail-defense*`.
- `%posttrans shim` warning text: same name swap.
- docdir literal `afalg-defense` → `copyfail-defense` (the spec uses
  `%{name}` so this comes for free with the rename).

**Acceptance.**
- `%build` LD_PRELOAD smoke test still passes:
  `LD_PRELOAD=$PWD/no-afalg.so /bin/true`.
- No file collision between `copyfail-defense-shim` and the legacy
  `afalg-defense-shim` (the Obsoletes drives the swap on upgrade).

---

## Phase 5 — `-auditor` expansion

**Goal.** Per **[D-14], [D-15], [D-16], [D-17], [D-18], [D-26]**.

**Files**:
- `copyfail-local-check.py` — additions only, no signature breaks
  on existing functions.
- `packaging/copyfail-defense.spec` — `%package auditor` already
  exists; just rename Obsoletes/Provides.

### 5.1 New checks (each one new function)

| Function | Category | Returns |
|---|---|---|
| `check_xfrm_modules()` | KERNEL | OK if esp4/esp6/xfrm_user/xfrm_algo all blocked (modprobe -n -v fails or returns `install /bin/false`); WARN if any loadable; INFO with builtin-vs-modular detection from `/proc/modules` |
| `check_rxrpc_module()` | KERNEL | OK if rxrpc not present in `/proc/net/protocols` AND modprobe blocked; WARN if reachable; uses `/proc/net/protocols` parse first to avoid autoload side-effect |
| `check_modprobe_blacklist_extended()` | MITIGATION | aggregates the existing modprobe check across the new module list; OK iff all of {algif_aead, authenc, authencesn, af_alg, esp4, esp6, xfrm_user, xfrm_algo, rxrpc} have `install /bin/false` or blacklist directive |
| `check_systemd_restrict_namespaces()` | MITIGATION | per-unit `RestrictNamespaces=` containing both `user` and `net` for sshd, user@, cron/crond, atd. Container runtimes (containerd/docker/podman) checked but reported as INFO not WARN if missing — those are opt-in extensions. |
| `check_pam_nullok()` | DETECTION | scans `/etc/pam.d/{system,password,common}-auth`, `/etc/pam.d/login`, `/etc/pam.d/sshd`, `/etc/pam.d/passwd`, `/etc/pam.d/su`, plus glob `/etc/pam.d/cpanel*` and `/etc/pam.d/plesk*`; WARN per occurrence of `pam_unix.so` + `nullok` |
| `check_unprivileged_userns_sysctl()` | HARDENING | reads `/proc/sys/user/max_user_namespaces` and `/proc/sys/kernel/unprivileged_userns_clone`; INFO posture only — do not WARN by default per **[D-01]** |
| `check_apparmor_userns_restrict()` | ENV | Ubuntu/Debian only; reads `/proc/sys/kernel/apparmor_restrict_unprivileged_userns` if present; INFO with value |
| `check_su_target_hardening()` | HARDENING | `stat /usr/bin/su`; suppresses recommendation when `/etc/passwd` analysis shows non-wheel non-system users with login shells (cPanel-shaped fleet); WARN otherwise per **[D-26]** |
| `check_page_cache_extended()` | DETECTION | extends existing page-cache integrity probe to include `/usr/bin/su`, `/etc/pam.d/system-auth`, `/etc/pam.d/password-auth`, `/etc/pam.d/common-auth` (in addition to existing PRIV_CONFIG_FILES list) |
| `check_auditd_rules_extended()` | DETECTION | adds detection of `cf_userns` and `cf_addkey` rule keys to existing auditd rule check |

### 5.2 JSON `posture.bug_classes_covered` + `bug_classes`

New function `_aggregate_bug_classes(results)` runs after the existing
`determine_posture()`. Returns `(covered_array, classes_map)`:

```python
covered_array = ["cf1", "cf2"]   # only classes where mitigated:true
classes_map = {
  "cf1":             {"applicable": True,  "mitigated": True},
  "cf2":             {"applicable": True,  "mitigated": True},
  "dirtyfrag-esp":   {"applicable": True,  "mitigated": False},
  "dirtyfrag-rxrpc": {"applicable": False, "mitigated": None},
}
```

Embedded under `posture.bug_classes_covered` (array) and
`posture.bug_classes` (map) in JSON output. Human output gets a
one-line summary at the end of the report.

### 5.3 Remediation emitter extensions

Append to `emit_remediation_script`:

1. modprobe: write `/etc/modprobe.d/99-copyfail-defense.conf` content.
2. systemd: write five drop-ins via heredoc; `systemctl daemon-reload`.
3. auditd: append two rule lines to
   `/etc/audit/rules.d/copyfail.rules`; `augenrules --load`.

### 5.4 Documentation surface in the auditor

The `--help` output's category list mentions cf2 + dirtyfrag.
The opening banner gains `(covers cf1, cf2, Dirty Frag — see
/usr/share/doc/copyfail-defense/README.md)`.

**Acceptance.**
- `python3 -c 'import py_compile; py_compile.compile("copyfail-local-check.py", doraise=True)'` passes.
- `./copyfail-local-check --json | jq '.posture.bug_classes_covered'` returns
  a JSON array on every test environment.
- `./copyfail-local-check --json | jq '.posture.bug_classes | keys | length == 4'` returns true.
- Existing exit code matrix preserved: 0/1/2/3/4 unchanged from v1.0.1.
- `--category MITIGATION,DETECTION` still filters correctly.

---

## Phase 6 — Test harness extension

**Goal.** Per **[D-23]**: extend `packaging/test-repo.sh` with new
checks (per-EL container).

**New tests** (preserved 12 existing + 6 new = 18 total per EL):

13. `dnf install -y copyfail-defense` succeeds; pulls all four subs.
14. `/etc/modprobe.d/99-copyfail-defense.conf` exists, contains 9 module lines.
15. `/etc/systemd/system/sshd.service.d/10-copyfail-defense.conf`
    exists and parses.
16. `copyfail-local-check --json | jq -e '.posture.bug_classes_covered'` exits 0.
17. `copyfail-local-check` exits 0/3/4 (never 2 — fresh install has
    shim disabled but kernel sinks are still reachable).
18. **Upgrade-path test.** Pre-stage `afalg-defense-1.0.1*` from
    `rpmbuild/upgrade-fixture/`; `dnf install` it; `dnf upgrade -y
    copyfail-defense`; assert `rpm -qa | grep '^afalg-defense' | wc -l == 0`
    AND `rpm -qa | grep '^copyfail-defense' | wc -l == 5`.

**Acceptance.**
- Script syntactically valid: `bash -n packaging/test-repo.sh`.
- New test functions defined and called from main matrix loop.
- Live container run is deferred to Phase 7 (needs built RPMs).

---

## ═══ BUILD/PUBLISH BOUNDARY ═══

The phases below require the build host's specific environment
(mock chroots, signing key in `/root/.gnupg/`, gh CLI auth, network
access to push gh-pages). They are **NOT** executed autonomously.
Documented for Ryan's return.

## Phase 7 — Build, sign, repo refresh   *(manual)*

```sh
# 1. SRPMs
rpmbuild --define "_topdir /home/copyfail/rpmbuild" \
    -ba packaging/copyfail-defense.spec

# 2. Per-EL mock rebuild
for el in 8 9 10; do
    mock -r centos-stream+epel-${el}-x86_64 \
        --rebuild /home/copyfail/rpmbuild/SRPMS/copyfail-defense-2.0.0-1.el${el}.src.rpm
done

# 3. Sign every binary RPM and SRPM
rpmsign --addsign \
    /home/copyfail/rpmbuild/mock-out/centos-stream+epel-{8,9,10}-x86_64/result/*.rpm \
    /home/copyfail/rpmbuild/SRPMS/*.src.rpm

# 4. Repo metadata
for el in 8 9 10; do
    createrepo_c --general-compress-type=gz \
        /home/copyfail/rpmbuild/gh-pages-staging/repo/${el}/x86_64/
done

# 5. Detach-sign repodata
for el in 8 9 10; do
    pushd /home/copyfail/rpmbuild/gh-pages-staging/repo/${el}/x86_64/repodata
    gpg --detach-sign --armor -o repomd.xml.asc repomd.xml
    popd
done
```

## Phase 8 — Documentation surface   *(manual)*

- `README.md` — full rewrite (cf-class framing, action-first, override
  block for rootless podman).
- `STATE.md` — bump to v2.0.0 snapshot.
- `BRIEF.md` — extend with cf2 + Dirty Frag sections.
- `FOLLOWUPS.md` — close v1.0.2 entry; open v2.1.0 items.
- `gh-pages-staging/index.html` — refresh package list.

## Phase 9 — Release v2.0.0   *(manual)*

```sh
git add -A
git commit -m "v2.0.0: copyfail-defense umbrella — cf1 + cf2 + Dirty Frag coverage"
git tag -a v2.0.0 -m "..."
git push origin main --tags
gh release create v2.0.0 --notes-file <release-notes> [15 RPMs] [3 SRPMs] copyfail.repo RPM-GPG-KEY-copyfail
# gh-pages branch: merge gh-pages-staging
bash packaging/test-repo.sh   # against live published repo
```

---

## Self-review (challenge pass)

- **Coherence with SPEC §9 decisions** — every D-NN referenced is
  consistent. No silent reopening.
- **Container-runtime drop-in risk (D-09)** — applying
  `RestrictNamespaces=~user` to containerd/docker/podman service
  units WILL break rootless containers AND user-namespace-remapped
  containers. The user's directive is explicit; override path is
  documented.
- **`SystemCallFilter=~@mount` risk (D-12)** — breaks rootless podman
  under user@.service. User's directive is explicit. Override path
  documented.
- **Phase 5 size** — auditor expansion is the largest single phase.
  ~10 new functions + JSON aggregator + remediation emitter
  extensions + help-text updates. Single phase keeps related changes
  atomic.
- **Phase 6 fixture** — needs `rpmbuild/upgrade-fixture/` with
  v1.0.1 RPMs checked in. Fixture is ~150KB binary. Acceptable for
  a packaging repo. Will be added inside Phase 6 implementation.
- **Operator who hand-edited v1.0.1 inline-doc modprobe file**:
  different filename (was `99-no-afalg.conf` example, now shipped
  `99-copyfail.conf`). No collision; new file's contents are a
  strict superset of the old.

Plan is shippable. Phases 1–6 will be executed.

---

## Handoff notes for Ryan on return

If you arrive mid-phase:
- `git status` shows what changed; `git diff packaging/copyfail-defense.spec`
  is the canonical source of truth for the new spec.
- The build/publish boundary in this plan is intentional — Phases 7–9
  are documented but **not** executed. The signing key is on freedom
  and externally-visible state changes (gh-pages, GH release) need
  your sign-off.
- Run `bash -n packaging/test-repo.sh` to syntax-check the harness
  before mock builds. The full live test happens after Phase 7
  produces signed RPMs against staging.
- `SPEC.md` §9 holds every **[D-NN]** decision; §10 lists the rev1→rev2
  deltas where I integrated your explicit directives.
