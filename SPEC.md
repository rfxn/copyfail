# SPEC — `copyfail-defense` v2.0.0

**Status:** Drafted autonomously 2026-05-08 (rev 3). Optimized for **maximum
protection without disrupting the business**. Every decision in §9 was made
on Ryan's behalf — return review is the **[D-NN]** index.

Rev history:
- rev 1 — initial draft after cf2 + Dirty Frag assessment.
- rev 2 — misread context as user directive; over-tightened systemd cuts.
- rev 3 (this) — re-evaluated each decision against business-disruption cost
  vs cf-class defense gain. Container-runtime drop-ins demoted to examples;
  `SystemCallFilter` narrowed to `@swap` only.

---

## 1. Problem

The shipped toolkit (`afalg-defense` v1.0.1) is laser-focused on AF_ALG /
`algif_aead` (CVE-2026-31431). Two follow-on disclosures sit in the same
vulnerability class but use completely different kernel sinks:

- **cf2 ("Copy Fail 2: Electric Boogaloo")** — `esp_input` skip_cow path,
  4-byte STORE via xfrm SA `seq_hi`. AF_INET socket. Patch: upstream
  `f4c50a4034`.
- **Dirty Frag** (V4bel) — vulnerability *class*, chains two distinct
  bugs: (a) the same xfrm-ESP bug as cf2, (b) RxRPC `rxkad_verify_packet_1`
  in-place `pcbc(fcrypt)` on splice'd frag. RxRPC leg has **no upstream
  patch yet**; embargo broken; affects kernel 4.11–7.1.

The author's own framing: *"even on systems where the publicly known Copy
Fail mitigation (algif_aead blacklist) is applied, your Linux is still
vulnerable to Dirty Frag."* The current package name has aged poorly —
the defensive primitives we ship are a superset of bug-class entry-point
cuts, not specifically AF_ALG.

## 2. Goal

Pivot the project to a **`copyfail-defense`** umbrella covering cf1, cf2,
and Dirty Frag (both legs) through additive subpackages. Clean RPM rename
path. Auditor reports per-class coverage for SIEM consumption. Ship as
v2.0.0.

## 3. Scope

### In v2.0.0
- Rename meta package `afalg-defense` → `copyfail-defense`.
- New subpackage `copyfail-defense-modprobe` (was inline doc).
- New subpackage `copyfail-defense-systemd` (was inline doc).
- Existing `afalg-defense-shim` → `copyfail-defense-shim` (renamed only).
- Existing `afalg-defense-auditor` → `copyfail-defense-auditor` (renamed
  + expanded with cf2 + dirtyfrag coverage).
- Backward-compat metadata (`Obsoletes:` / `Provides:`) so `dnf upgrade`
  is a single-command path from v1.0.1.
- README rewrite framing the toolkit as cf-class coverage.
- `packaging/test-repo.sh` extended for new subpackages + upgrade path.
- gh-pages `index.html` + `.repo` description updated; URL paths
  unchanged.

### Defined but deferred (2.1.0)
- **`copyfail-defense-userns`** — sysctl drop for
  `user.max_user_namespaces=0` (RHEL/Fedora) and
  `kernel.unprivileged_userns_clone=0` (Debian/Ubuntu). **Opt-in only.**
  NOT pulled by meta. **[D-01]** The blast radius (rootless podman,
  flatpak, browser sandboxes) needs operator-side feedback before
  auto-pulling.

### Out of scope
- arm64 port — pre-existing follow-up.
- kpatch wrapping — each upstream patch is per-CVE.
- PAM `nullok` auto-fix — auditor reports, operator acts. **[D-02]**
- Splice-syscall blocking — every bypass class is reachable via inline
  asm. **[D-03]**

## 4. Architecture

### 4.1 Package layout

```
copyfail-defense                 (meta — Obsoletes: afalg-defense)
├── copyfail-defense-shim        (Obsoletes: afalg-defense-shim)
│     LD_PRELOAD no-afalg.so + copyfail-shim-{enable,disable}
│     Coverage: cf1 (primary), dirtyfrag-RxRPC PoC cksum (incidental)
│
├── copyfail-defense-modprobe    (NEW — was inline doc in v1.0.1)
│     /etc/modprobe.d/99-copyfail.conf:
│       install algif_aead /bin/false   # cf1 (no-op on RHEL builtin)
│       install authenc    /bin/false
│       install authencesn /bin/false
│       install esp4       /bin/false   # dirtyfrag-ESP, cf2
│       install esp6       /bin/false
│       install xfrm_user  /bin/false   # cuts xfrm netlink autoload
│       install xfrm_algo  /bin/false
│       install rxrpc      /bin/false   # dirtyfrag-RxRPC (Ubuntu critical)
│     %post: best-effort `rmmod` of any loaded
│     %preun: remove the file (do NOT auto-rmmod on uninstall)
│     Coverage: cf2 + both dirtyfrag legs on hosting nodes
│
├── copyfail-defense-systemd     (NEW — was inline doc in v1.0.1)
│     drop-ins for user@.service, sshd.service, cron.service,
│     crond.service, atd.service:
│       RestrictAddressFamilies=~AF_ALG ~AF_RXRPC
│       RestrictNamespaces=~user ~net
│       SystemCallArchitectures=native
│       SystemCallFilter=~@swap
│     Coverage: ALL THREE — RestrictNamespaces blocks unshare path used
│              by cf2 + dirtyfrag-ESP; ~AF_ALG keeps cf1 cut;
│              ~AF_RXRPC kills dirtyfrag-RxRPC at the kernel-enforced
│              seccomp layer (not LD_PRELOAD)
│     Container-runtime drop-ins (containerd, docker, podman) shipped
│     as examples/ for opt-in only — NOT active by default. Operator
│     installs per-fleet after confirming no rootless/userns-remapped
│     workloads run on those runtimes.
│
└── copyfail-defense-auditor     (Obsoletes: afalg-defense-auditor)
      copyfail-local-check expanded with new checks per category;
      JSON gains bug_classes_covered + per-class boolean.
```

### 4.2 Subpackage details

#### `copyfail-defense-shim`
- **No behavioural change** from `afalg-defense-shim`. Pure rename.
- Files unchanged: `/usr/lib64/no-afalg.so`,
  `/usr/sbin/copyfail-shim-{enable,disable}`.
- `%post` / `%preun` / `%posttrans` scriptlets unchanged (text updated
  to reference new package family names).
- docdir rebased: `/usr/share/doc/copyfail-defense/` (was
  `afalg-defense`).
- Example modprobe + systemd snippets removed from this subpackage —
  the new `-modprobe` and `-systemd` subpackages own those concerns.
  **[D-05]**

#### `copyfail-defense-modprobe`
- **New.** Single drop file: `/etc/modprobe.d/99-copyfail-defense.conf`. **[D-06]**
  *(Keeps `-defense` suffix for namespace hygiene — avoids collision with
  any future `copyfail-checker.conf` or third-party `copyfail*` configs.
  Modprobe drop directories are flat, so namespacing matters.)*
- Content:

  ```
  # /etc/modprobe.d/99-copyfail-defense.conf
  # Owned by copyfail-defense-modprobe; do not hand-edit.

  # cf1 — CVE-2026-31431 algif_aead family
  install algif_aead   /bin/false
  install authenc      /bin/false
  install authencesn   /bin/false
  install af_alg       /bin/false
  blacklist algif_aead
  blacklist authenc
  blacklist authencesn
  blacklist af_alg

  # cf2 / Dirty Frag-ESP — xfrm IPsec ESP family
  install esp4         /bin/false
  install esp6         /bin/false
  install xfrm_user    /bin/false
  install xfrm_algo    /bin/false
  blacklist esp4
  blacklist esp6
  blacklist xfrm_user
  blacklist xfrm_algo

  # Dirty Frag-RxRPC — Andrew File System RPC
  install rxrpc        /bin/false
  blacklist rxrpc
  ```

- `%config(noreplace)` so operator hand-edits survive package upgrade.
- `%post`: best-effort `rmmod` of any of the above already loaded;
  ignore failures; log to `LOG_AUTHPRIV` for paper trail. **[D-07]**
- `%preun` on full erase: remove drop file; do **not** rmmod. **[D-08]**
- `%posttrans`: warn if any of the listed modules is loaded *and*
  the conf file disagrees with running state.
- **Conflict path:** if operator legitimately runs IPsec or AFS,
  this subpackage will break those workloads. README must surface
  the warning loudly.

#### `copyfail-defense-systemd`
- **New.** Drop-in tree under `/etc/systemd/system/`. **[D-09]**

  Default units covered (active drop-ins):

  ```
  user@.service.d/10-copyfail-defense.conf
  sshd.service.d/10-copyfail-defense.conf
  cron.service.d/10-copyfail-defense.conf
  crond.service.d/10-copyfail-defense.conf
  atd.service.d/10-copyfail-defense.conf
  ```

  Rationale: these are the units that spawn tenant work — login
  sessions (user@/sshd), scheduled jobs (cron/crond/atd). The drop-in
  body's `RestrictNamespaces=~user` prevents `unshare(CLONE_NEWUSER)`
  from any process the unit roots, which is the prerequisite for
  cf2/dirtyfrag-ESP. Drop-ins on units that don't exist on a given
  host are silently skipped at daemon-reload time (cron.service vs
  crond.service is a Debian-vs-RHEL divergence; both are listed for
  cross-distro coverage even though only one will exist per host).

  Container-runtime drop-ins (`containerd.service`, `docker.service`,
  `podman.service`) are shipped as **`examples/`** under
  `/usr/share/doc/copyfail-defense/examples/`, NOT installed as active
  drop-ins. Applying `RestrictNamespaces=~user` to those service units
  breaks rootless containers AND user-namespace-remapped containers
  comprehensively — that's infrastructure disruption beyond tenant
  blast-radius reduction. Operators on hosting nodes that don't run
  rootless/remapped containers can opt in by copying the example into
  the active drop-in directory. **[D-09a]**

- Drop-in body (identical across units):

  ```ini
  # /etc/systemd/system/<unit>.service.d/10-copyfail-defense.conf
  # Owned by copyfail-defense-systemd; do not hand-edit.
  # Override per-host: drop a 20-*.conf in the same directory.
  [Service]
  RestrictAddressFamilies=~AF_ALG ~AF_RXRPC
  RestrictNamespaces=~user ~net
  SystemCallArchitectures=native
  SystemCallFilter=~@swap
  ```

- **Why `RestrictNamespaces=~user ~net`** (not `~user ~net ~uts`):
  UTS removal not required for cf2/dirtyfrag-ESP defense (the exploit
  chain doesn't touch the UTS namespace); adding it would buy zero
  cf-class protection at minor cost to niche workloads
  (`unshare -u` for hostname-isolated test runners, some flatpak
  configs). Stay surgical. **[D-10]**
- **Why `SystemCallFilter=~@swap` only** (not `~@mount @swap`):
  `@swap` blocks `swapon`/`swapoff` — no tenant has legitimate use,
  zero-cost cut. `@mount` was considered and **rejected**: blocking
  `mount`/`umount2`/`pivot_root` would break rootless podman/buildah
  container creation under `user@.service` AND adds zero cf-class
  defense (the exploit chain doesn't require `mount` syscalls — it
  uses `unshare(CLONE_NEWUSER|CLONE_NEWNET)` which is already cut
  by `RestrictNamespaces=~user`). Keeping `@swap` only is the
  protection-without-business-disruption pick. **[D-12]**
- **Why `~AF_ALG ~AF_RXRPC`:** kernel-enforced seccomp filter,
  uncircumventable from userspace. Pairs with shim (which is
  bypassable) for layered defense. AF_RXRPC drop is the load-bearing
  cut against dirtyfrag-RxRPC since the bug primitive itself is
  unprivileged. **[D-12a]**
- All drop files marked `%config(noreplace)`.
- `%post`: `systemctl daemon-reload` always; `try-reload-or-restart
  sshd.service` only (others handle drop-ins via reload alone).
  Skip in container builds via `if [ -d /run/systemd/system ]`.
  **[D-13]**
- `%preun` on full erase: remove drop files; daemon-reload;
  try-reload sshd. Do **not** stop services.
- **Operator override path** (surfaced in README):

  ```sh
  # Drop a 20-override.conf with empty values to neutralize per-unit.
  # Most common case: rootless podman/buildah under user@.service.
  mkdir -p /etc/systemd/system/user@.service.d
  cat >/etc/systemd/system/user@.service.d/20-override.conf <<'EOF'
  [Service]
  RestrictNamespaces=
  RestrictAddressFamilies=
  EOF
  systemctl daemon-reload
  # No service restart needed — user@<UID>.service instances pick this
  # up on next login session.
  ```

- **Container-runtime opt-in path** (surfaced in README):

  ```sh
  # If your fleet does NOT run rootless or userns-remapped containers
  # under containerd/docker/podman, you can extend coverage:
  for u in containerd docker podman; do
      sudo install -d /etc/systemd/system/${u}.service.d
      sudo cp /usr/share/doc/copyfail-defense/examples/${u}-dropin.conf \
              /etc/systemd/system/${u}.service.d/10-copyfail-defense.conf
  done
  sudo systemctl daemon-reload
  ```

#### `copyfail-defense-auditor`
- Existing five categories preserved. Internal additions only. **[D-14]**

  | Category | New checks |
  |---|---|
  | `ENV` | apparmor userns posture (Ubuntu/Debian only — `/proc/sys/kernel/apparmor_restrict_unprivileged_userns`); rxrpc/esp4/esp6/xfrm_user/xfrm_algo `/proc/modules` state and builtin-vs-modular classification |
  | `KERNEL` | xfrm-ESP module presence + reachable probe (read-only — opens AF_INET/UDP, attempts `setsockopt(UDP_ENCAP, ESPINUDP)` without registering an SA); RxRPC reachable probe (`/proc/net/protocols` parse for `RXRPC` row, then optional `socket(AF_RXRPC, ...)` confirm) |
  | `MITIGATION` | modprobe drop coverage of new entries; per-unit `RestrictAddressFamilies` + `RestrictNamespaces` for sshd/user@/containerd/docker/podman; `user.max_user_namespaces` and `kernel.unprivileged_userns_clone` sysctl posture (informational) |
  | `HARDENING` | `/usr/bin/su` mode/ownership (cf2/df-ESP target); recommend `chmod 4750` **only when** a wheel/admin group exists AND no non-wheel non-system users have legitimate su use (heuristic: scan `/etc/passwd` for users with shells in standard list) **[D-26]** |
  | `DETECTION` | page-cache integrity probe extended to `/usr/bin/su`, `/etc/pam.d/system-auth`, `/etc/pam.d/password-auth`, `/etc/pam.d/common-auth`; PAM `nullok` scan in `pam.d/{system,password,common}-auth` plus glob `/etc/pam.d/cpanel*` and `/etc/pam.d/plesk*`; auditd-rule presence checks for `unshare(CLONE_NEWUSER)`, `add_key("rxrpc",...)`, xfrm-netlink SA add (XFRM_MSG_NEWSA = netlink type filter, documented as best-effort given kauditd's limited netlink filtering) |

- **Exit code semantics:** unchanged (`0/1/2/3/4`). Per-class
  coverage reported in JSON only; the human verdict still distills
  to existing values. **[D-15]**
- **JSON schema additions** (per Ryan's directive — array form):

  ```json
  "posture": {
    ...existing fields...,
    "bug_classes_covered": ["cf1", "cf2", "dirtyfrag-esp"],
    "bug_classes": {
      "cf1":              { "applicable": true, "mitigated": true },
      "cf2":              { "applicable": true, "mitigated": true },
      "dirtyfrag-esp":    { "applicable": true, "mitigated": false },
      "dirtyfrag-rxrpc":  { "applicable": false, "mitigated": null }
    }
  }
  ```

  `bug_classes_covered` is a flat array of class IDs where
  `mitigated: true` — Ryan's directive form, tailored for SIEM
  ingestion (a single field to filter on). The map under
  `bug_classes` retains the per-class booleans for finer-grained
  consumption. `applicable: false` means the kernel sink isn't
  reachable on this host (e.g., rxrpc.ko not present and not
  loadable). **[D-16]**
- **Human-readable summary line**: `Bug-class coverage:
  cf1=mitigated cf2=mitigated dirtyfrag-esp=vulnerable
  dirtyfrag-rxrpc=n/a` appears at end of report.
- **New auditd remediation snippets** emitted by `--remediate`:

  ```
  -a always,exit -F arch=b64 -S unshare -F auid>=1000 -k cf_userns
  -a always,exit -F arch=b64 -S add_key -F auid>=1000 -k cf_addkey
  ```

  Plus a documented best-effort note for the xfrm-netlink rule
  (kauditd cannot filter netlink message types per-protocol;
  documented as known gap rather than emitted as a non-functional
  rule). **[D-17]**
- Auditor binary path unchanged: `/usr/sbin/copyfail-local-check`. **[D-18]**

### 4.3 RPM rename mechanics

Spec file moves: `packaging/afalg-defense.spec` →
`packaging/copyfail-defense.spec`. Old filename removed cleanly. **[D-19]**

Per-subpackage metadata:

```
Name:      copyfail-defense
Epoch:     1
Version:   2.0.0
Release:   1%{?dist}
Obsoletes: afalg-defense          < 1:2.0.0
Provides:  afalg-defense          = %{epoch}:%{version}-%{release}

%package shim
Obsoletes: afalg-defense-shim     < 1:2.0.0
Provides:  afalg-defense-shim     = %{epoch}:%{version}-%{release}

%package auditor
Obsoletes: afalg-defense-auditor  < 1:2.0.0
Provides:  afalg-defense-auditor  = %{epoch}:%{version}-%{release}

# (-modprobe and -systemd are new; no Obsoletes/Provides)
```

- `Epoch: 1` introduced. Once present, every future release must
  carry it. **[D-20]**
- Obsoletes/Provides retained through 2.0.x release line. Drop in
  2.1.0. **[D-21]**

### 4.4 gh-pages and `.repo`

- URL paths unchanged: `https://rfxn.github.io/copyfail/repo/{8,9,10}/x86_64/`.
- `packaging/copyfail.repo`: `name=` updated.
- `index.html` description rewritten for cf-class coverage; URLs
  untouched.
- Old `afalg-defense-1.0.1*` RPMs **kept** in repo trees for one
  release cycle so v1.0.1 hosts see a clean Obsolete-driven upgrade
  path on `dnf upgrade`. Removed in v2.0.1. **[D-22]**

### 4.5 Test harness

`packaging/test-repo.sh` extended:

- Replace per-EL container check `dnf install -y afalg-defense`
  with `dnf install -y copyfail-defense`.
- Add a sub-test that pre-stages `afalg-defense-1.0.1*` from
  `rpmbuild/upgrade-fixture/`, then runs `dnf upgrade -y
  copyfail-defense`, asserting:
  - `rpm -qa | grep '^copyfail-defense' | wc -l == 5` (meta + 4 subs).
  - `rpm -qa | grep '^afalg-defense' | wc -l == 0` (clean obsolete).
  - `/etc/modprobe.d/99-copyfail-defense.conf` present.
  - `/etc/systemd/system/sshd.service.d/10-copyfail-defense.conf` present.
  - `/usr/sbin/copyfail-local-check --json | jq -e '.posture.bug_classes_covered'` non-null.
- Existing 12-check matrix preserved per EL → 18 checks total. **[D-23]**

## 5. Decisions deliberately *not* made (need Ryan's call on return)

These are reasonable defaults; flagged for your review:

- **[D-09a] Container-runtime drop-ins shipped as opt-in examples**:
  default install does NOT touch containerd/docker/podman service
  units. Operator opts in via the documented copy-from-examples
  workflow. Flag if your fleet should default to active drop-ins
  on these (i.e., you've confirmed no rootless workloads).
- **[D-26] Conditional `chmod 4750 /usr/bin/su` recommendation**: the
  auditor's heuristic checks for non-wheel non-system users with
  shells in `/etc/passwd`. cPanel hosting boxes have many such users
  by design — the recommendation will be **suppressed by default**
  on those hosts. Operator can force it via `--recommend-aggressive`.
  Verify this matches your intent.

## 6. Rollback plan

If 2.0.0 ships with a broken subpackage:

1. Operator: `dnf downgrade copyfail-defense afalg-defense`. The
   `Provides:` clause keeps the old name resolvable through 2.0.x.
2. We: tag `v2.0.0-yanked`, rebuild a `2.0.1` with the bad
   subpackage gated off, push.
3. Signing key unchanged — no key-trust rollback needed.

## 7. Out-of-band dependencies

- **GPG signing key** unchanged (fingerprint
  `6001 1CDC EA2F F52D 975A FDEE 6D30 F32C D5E8 0F80`, expires
  2028-04-29). Still valid.
- **Build hosts:** same `mock` chroots
  (`centos-stream+epel-{8,9,10}-x86_64`).
- **Backup:** new spec file replicates to forge ZFS via existing
  rsync convention; no backup runbook change.

## 8. Documentation surface

- `README.md` — full rewrite (cf-class framing). Action-first.
  Rootless-podman override block included.
- `STATE.md` — bumped to v2.0.0 snapshot.
- `BRIEF.md` — extended with cf2 + Dirty Frag sections.
- `FOLLOWUPS.md` — close v1.0.2 entry; open v2.1.0 items
  (`-userns` opt-in, drop Obsoletes/Provides, repo cleanup,
  rfxn.com article).

## 9. Decision index

- **D-01** Defer `-userns` subpackage to 2.1.0; opt-in only.
- **D-02** No PAM `nullok` auto-fix — auditor reports only.
- **D-03** No splice-syscall blocking.
- **D-04** Meta `Requires:` exact-match VR on shim/modprobe/systemd/auditor.
- **D-05** Remove example dropins from `-shim`.
- **D-06** Modprobe drop file at `/etc/modprobe.d/99-copyfail-defense.conf`
  *(keeps `-defense` suffix for namespace hygiene)*.
- **D-07** `%post modprobe` rmmod best-effort, log to LOG_AUTHPRIV.
- **D-08** `%preun modprobe` removes drop file; no rmmod on uninstall.
- **D-09** systemd drop-in default unit list: user@, sshd, cron,
  crond, atd. Container-runtime drop-ins shipped as `examples/`,
  NOT active — opt-in only.
- **D-09a** containerd/docker/podman drop-ins ship as
  `/usr/share/doc/copyfail-defense/examples/<runtime>-dropin.conf`
  with documented opt-in path in README.
- **D-10** `RestrictNamespaces=~user ~net` *(no UTS — adds zero
  cf-class defense, minor collateral on niche workloads)*.
- **D-11** Leave mount/ipc/pid/cgroup namespaces alone.
- **D-12** `SystemCallFilter=~@swap` *(NOT `@mount @swap`; @mount
  breaks rootless podman/buildah and adds zero cf-class defense
  since the exploit chain doesn't need mount syscalls)*.
- **D-12a** `RestrictAddressFamilies=~AF_ALG ~AF_RXRPC`.
- **D-13** `%post systemd` daemon-reload + try-reload sshd only.
- **D-14** Auditor categories unchanged; checks added inside.
- **D-15** Exit code semantics unchanged.
- **D-16** New JSON `bug_classes_covered` array + `bug_classes` map
  *(array form per Ryan's directive, map retained for granular consumers)*.
- **D-17** auditd remediation: unshare + add_key only; xfrm-netlink
  documented as gap.
- **D-18** Auditor binary path unchanged.
- **D-19** Spec file renamed; old removed cleanly.
- **D-20** `Epoch: 1` introduced.
- **D-21** Obsoletes/Provides retained through 2.0.x; dropped in 2.1.0.
- **D-22** Keep old RPMs in repo for one release cycle.
- **D-23** test-repo.sh upgrade-path test added.
- **D-24** All shipped conf files marked `%config(noreplace)`.
- **D-25** Override pattern documented in README (20-override.conf).
- **D-26** `chmod 4750 /usr/bin/su` recommendation conditional on
  `/etc/passwd` analysis; suppressed by default on cPanel-shaped hosts.

## 10. Decision evolution (rev 1 → rev 2 → rev 3)

| Decision | Rev 1 | Rev 2 (over-tightened) | Rev 3 (this — final) | Source of rev 3 |
|---|---|---|---|---|
| Modprobe filename | `99-copyfail-defense.conf` | `99-copyfail.conf` | `99-copyfail-defense.conf` | namespace hygiene; rev 2 saved 8 chars at cost of collision risk |
| `RestrictNamespaces` | `~user net uts` | `~user ~net` | `~user ~net` | UTS adds zero cf-class defense |
| `SystemCallFilter` | rejected | `~@mount @swap` | `~@swap` only | `@mount` breaks rootless containers, no cf-class defense gain |
| systemd unit list | user@/sshd/cron/crond/atd | user@/sshd + container runtimes (active) | user@/sshd/cron/crond/atd default; container runtimes shipped as **examples** | applying `~user` to runtime daemons breaks every rootless deployment |
| JSON shape | map only | array + map | array + map | array is SIEM-ergonomic, map is granular — keep both |
| `chmod 4750 /usr/bin/su` | unconditional flag | conditional on user inventory | conditional on user inventory | rev 2 self-review fix carried forward |

---

## 11. Self-review (challenge pass — rev 3)

The rev 2 → rev 3 reset corrected over-tightening. Re-running the
challenge pass on rev 3:

- **Default systemd unit list (user@/sshd/cron/crond/atd)** covers the
  tenant blast radius (login shells + scheduled jobs) without touching
  infrastructure daemons. Drop-ins on units that don't exist are
  silently ignored at daemon-reload — `cron.service` (Debian) and
  `crond.service` (RHEL) are both listed for cross-distro coverage.
- **Container-runtime drop-ins as examples**: operators who legitimately
  run rootless or userns-remapped containers under containerd/docker/
  podman are NOT broken by default install. Operators who don't can
  opt in via the documented copy-from-examples step. Tenant-on-tenant
  cf2/df-ESP from inside a container is still blocked by the
  user@.service drop-in (the container's userspace process is rooted
  at the host's user@ unit if launched via login shell), and from a
  daemon-launched container path the `~user` cut at the runtime would
  block useful workflow. Net: this default protects the high-value
  case without the high-cost collateral.
- **`SystemCallFilter=~@swap`** is a zero-cost cut. `@swap` blocks
  `swapon`/`swapoff` — no tenant has legitimate use, and these
  syscalls only matter to administrators. Adding it costs nothing,
  catches accidental misconfiguration, and provides a small additional
  hardening layer beyond the cf-class scope.
- **`RestrictNamespaces=~user ~net`** is the surgical pair: `~user`
  breaks the cf2/df-ESP unshare prerequisite; `~net` independently
  blocks netns creation (also part of the chain). UTS is left alone.
- **Modprobe filename `99-copyfail-defense.conf`**: namespace-clean.
  `99-` prefix puts it after the system defaults but before any
  numerically-late operator config; `-defense` suffix avoids collision
  with hypothetical future copyfail-* tooling.
- **`bug_classes_covered` array + `bug_classes` map**: dual
  representation kept. The array is one-field-filter ergonomic for
  SIEM/Ansible; the map is finer-grained for dashboards. JSON byte
  cost is trivial.
- **Untouched concerns from rev 1**: `%config(noreplace)` on conf
  files, README override docs, auditd rule limitations, `Epoch: 1`
  permanence — all carried into this rev.

**No outstanding fixes.** Rev 3 is the protection-without-disruption
optimum I can produce without operator-fleet-specific signal. Proceed.
