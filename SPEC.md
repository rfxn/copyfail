# SPEC — `copyfail-defense` v2.0.0

**Status:** Drafted autonomously 2026-05-08 (rev 3). Optimized for **maximum
protection without disrupting the business**. Every decision in §9 was made
on Ryan's behalf — return review is the **[D-NN]** index.

**v2.0.1 hotfix appended in §12** (drafted 2026-05-08; rev 2 after
reviewer fixup pass). The §1–§11 body documents the v2.0.0 baseline and
is preserved unchanged for history. New work for v2.0.1 lives in §12
with decisions D-27..D-58 continuing the existing index (D-51..D-58
added in the fixup pass). Conflict: where §12 contradicts §1–§11
(file-layout split, auto-detection scriptlet additions), §12 wins for
v2.0.1+ builds.

Rev history:
- rev 1 — initial draft after cf2 + Dirty Frag assessment.
- rev 2 — misread context as user directive; over-tightened systemd cuts.
- rev 3 (this) — re-evaluated each decision against business-disruption cost
  vs cf-class defense gain. Container-runtime drop-ins demoted to examples;
  `SystemCallFilter` narrowed to `@swap` only.
- v2.0.1 hotfix — auto-detect IPsec / AFS / rootless-container workloads
  at install time and suppress the conflicting drop-ins. Replaces the
  README's "Override paths" section with package-driven behavior.
- v2.0.1 fixup (rev 2, 2026-05-08) — incorporates reviewer findings
  C-1..C-8 + M-1..M-12. Key changes: storage-tree-based rootless
  detection (replacing the cPanel-FP-prone `/etc/subuid` signal),
  conditional `~AF_RXRPC` (was unconditional; AFS aklog opens
  AF_RXRPC sockets), `.rpmsave-v2.0.1` rename (not delete) on
  `%pretrans`, per-subpackage `detect.sh apply <scope>`, cmp-and-skip
  on operator-edited conditional files, `20-override` /
  `25-additions` documented patterns (NOT chattr +i). Decisions
  D-51..D-58 added for these.

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

---

# 12. v2.0.1 hotfix — auto-detect conflicting workloads

**Status:** drafted 2026-05-08, awaiting Ryan's review. Builds on
v2.0.0 §1–§11. New decisions D-27..D-50 continue the index.

## 12.1 Problem

v2.0.0 ships three suppressible mitigations that break legitimate
workloads:

| Mitigation | Conflicts with |
|---|---|
| modprobe `esp4 esp6 xfrm_user xfrm_algo` blacklist | IPsec (strongSwan, libreswan, openswan, FRRouting VTI) |
| modprobe `rxrpc` blacklist | AFS (openafs, kafs) |
| `user@.service.d` `RestrictNamespaces=~user ~net` | rootless podman/buildah |

The current README's "Override paths" section pushes the resolution
onto the operator: skip the subpackage, hand-edit `%config(noreplace)`
files, write 20-override drop-ins. **Operators who don't read the
README break their fleet on first install.** That's a lot to ask for
a hotfix-class default.

v2.0.1 replaces operator-driven override with package-driven
auto-detection: at install time, inspect the host for IPsec / AFS /
rootless-container fingerprints, suppress only the conflicting
drop-ins, log the decision to LOG_AUTHPRIV, and write a versioned
JSON report the auditor consumes.

## 12.2 Goal (v2.0.1 only)

- **Suppress + log + report.** When a conflict is detected, the
  conflicting drop-in/blacklist is **not installed** on the host. The
  always-on cuts continue to apply. The decision is logged to
  `LOG_AUTHPRIV` and surfaced in `/var/lib/copyfail-defense/auto-detect.json`
  for the auditor. **[D-27]**
- **Sentinel override.** A pre-existing `/etc/copyfail/force-full`
  file makes `%posttrans` skip detection and install everything.
  This is the operator's "I know better than your detector" lever.
  **[D-28]**
- **Re-detect helper.** `/usr/sbin/copyfail-redetect` re-runs detection
  on demand (operator enabled IPsec post-install; reboot or fleet
  config change). Same logic as `%posttrans`. **[D-29]**
- **No changes to v2.0.0 always-on cuts:**
  - cf1 modprobe stanza (`algif_aead authenc authencesn af_alg`) —
    always installed.
  - systemd `RestrictAddressFamilies=~AF_ALG` —
    always installed (no realistic legitimate userspace consumer).
  - systemd `RestrictAddressFamilies=~AF_RXRPC` —
    **conditional on AFS detection** (rev 2 fixup per reviewer C-3:
    aklog/kinit -A open AF_RXRPC sockets to vlserver/ptserver, so
    leaving this unconditional breaks AFS userspace tooling on
    `user@.service`). The `~AF_RXRPC` directive ships in a separate
    drop-in (`12-copyfail-defense-rxrpc-af.conf`) gated by the same
    AFS signal that gates the `rxrpc` modprobe blacklist. **[D-30]**

## 12.3 Out of scope

- The deferred `copyfail-defense-userns` subpackage (D-01) stays
  deferred.
- Dropping `Obsoletes:`/`Provides:` for `afalg-defense*` (D-21) stays
  deferred.
- Removing legacy `afalg-defense-1.0.1*` RPMs from gh-pages (D-22)
  stays deferred. v2.0.1 ships into the same repo trees alongside
  v2.0.0; v1.0.1 RPMs remain for the upgrade-path test.
- runtime-state checks (`ip xfrm policy list`, `mount`, `docker
  info`) — explicitly rejected. They're flaky inside `mock` build
  environments and unreliable during scriptlet execution. **[D-31]**

## 12.4 File-layout split

The `%posttrans` scriptlet must be able to install OR not-install each
mitigation independently. v2.0.0 ships them as monolithic files; v2.0.1
splits them. **[D-32]**

### 12.4.1 modprobe split (3 files)

| File | Contents | Suppressible |
|---|---|---|
| `99-copyfail-defense-cf1.conf` | algif_aead, authenc, authencesn, af_alg | NO — always-on |
| `99-copyfail-defense-cf2-xfrm.conf` | esp4, esp6, xfrm_user, xfrm_algo | YES — IPsec conflict |
| `99-copyfail-defense-rxrpc.conf` | rxrpc | YES — AFS conflict |

**Numbering:** all three keep the `99-` prefix so any operator
`100-*` drop overrides ours. The shared `-copyfail-defense-` prefix
preserves namespace hygiene from D-06.

### 12.4.2 systemd drop-in split (3 files per unit)

The single `10-copyfail-defense.conf` body splits into three (rev 2
fixup per reviewer C-3 / D-30):

| File | Contents | Suppressible |
|---|---|---|
| `10-copyfail-defense.conf` | `RestrictAddressFamilies=~AF_ALG` + `SystemCallArchitectures=native` + `SystemCallFilter=~@swap` | NO — always-on |
| `12-copyfail-defense-rxrpc-af.conf` | `RestrictAddressFamilies=~AF_RXRPC` | YES — AFS conflict (aklog/kinit -A open userspace AF_RXRPC sockets to vlserver/ptserver) |
| `15-copyfail-defense-userns.conf` | `RestrictNamespaces=~user ~net` | YES — rootless container conflict (only on `user@.service.d`) |

**Why split at `10-` / `12-` / `15-` instead of one `10-` and one
`20-override`:** a numerically-low prefix lets all three of our
drop-ins sit *before* any operator override. systemd drop-ins are
merged in lexicographic order; `10` < `12` < `15` < `20`. The two
suppressible drop-ins each have a distinct prefix so detect.sh can
remove one independently of the other. The operator override patterns
documented in v2.0.1 README (`20-override.conf` to empty-value any
directive; `25-additions.conf` to add new directives) continue to work
because they sort after our 15-* in every directory. **[D-33]**

`RestrictAddressFamilies` is mergeable — systemd unions the value
across drop-ins, so the `~AF_RXRPC` token in the `12-` file extends
the `~AF_ALG` token from the `10-` file when both are present. When
the `12-` is suppressed, only `~AF_ALG` applies. **[D-33a]**

**Per-unit suppression matrix:**

- **`10-` always installed** on all 5 tenant units (user@/sshd/cron/crond/atd).
- **`12-rxrpc-af` suppressed when AFS detected**, on all 5 units (since
  AFS userspace tooling can be invoked from any of those service
  contexts — login shell, cron job, at job).
- **`15-userns` suppressed for `user@.service.d` ONLY** when rootless
  containers are detected. `RestrictNamespaces=~user ~net` on
  sshd/cron/crond/atd is INTENDED defense (those don't legitimately
  need user namespaces). **[D-34]**

### 12.4.3 Templates under `/usr/share/`

The conditional drop-ins ship as **package-owned templates** under
`/usr/share/copyfail-defense/conditional/`:

```
/usr/share/copyfail-defense/conditional/
├── modprobe/
│   ├── 99-copyfail-defense-cf2-xfrm.conf
│   └── 99-copyfail-defense-rxrpc.conf
└── systemd/
    ├── 12-copyfail-defense-rxrpc-af.conf   # AF_RXRPC family cut, gated on AFS
    └── 15-copyfail-defense-userns.conf     # userns cut, gated on rootless
```

`%posttrans` copies templates to `/etc/...` only when no conflict is
detected. `/etc/...` files are **not RPM-owned** — they're created and
removed by the scriptlet. `%config(noreplace)` doesn't apply because
RPM doesn't track them. The always-on files stay RPM-owned with
`%config(noreplace)` per D-24. **[D-35]**

**Trade-off vs alternative pattern (commented-out `install` lines or
ship-everything-then-blank):** rejected. Both alternatives put a
file at the same path that *would have applied* the cut, then mute
it. Operators inspecting `/etc/modprobe.d/` to understand state see a
file that looks like the mitigation is active but isn't. Splitting +
copy-on-detect leaves `/etc/...` empty when the mitigation isn't
applied — operator's mental model matches reality. **[D-36]**

### 12.4.4 What v2.0.0 → v2.0.1 RPM upgrade does to existing files

Operators who already installed v2.0.0 have:
- `/etc/modprobe.d/99-copyfail-defense.conf` (the monolithic file)
- `/etc/systemd/system/<unit>.service.d/10-copyfail-defense.conf` (monolithic body)

Both are `%config(noreplace)`. RPM upgrade rules: when a `%config`
file's path is removed from a new package (because we split it), RPM
moves the existing file to `<path>.rpmsave` and does NOT install the
new file. That breaks v2.0.0 → v2.0.1 upgrade silently — the host
keeps the old monolithic file (still applying the unconditional cut)
and gets none of the new split files (no cf1 cut, no userns cut, no
detection).

**Mitigation:** `%pretrans` for `-modprobe` and `-systemd`
**renames** the v2.0.0 monolithic files to `<path>.rpmsave-v2.0.1`
**before** the new RPM is installed, so the new split files land
cleanly AND any operator hand-edits to the v2.0.0 monolithic file
are preserved on disk for inspection. The rename is conditional on
the v2.0.0 file existing AND the v2.0.0 RPM having been installed
(avoid renaming files an operator hand-placed before installing
v2.0.0). The RPM does NOT consult `.rpmsave-v2.0.1` files — they're
inert audit-trail artifacts the operator can review/restore by hand
or delete with `rm`. **[D-37]**

Rev 2 rationale (reviewer C-4): v2.0.0 shipped 2026-05-08 and v2.0.1
ships same-day, so an operator with a hand-edit to the monolithic
file is plausible. Aggressive `rm -f` would silently destroy that
edit. Renaming preserves it.

```sh
# %pretrans modprobe — runs before v2.0.1 unpacks
old=/etc/modprobe.d/99-copyfail-defense.conf
if [ -f "$old" ] && \
   rpm -q copyfail-defense-modprobe --qf '%{version}' 2>/dev/null \
       | grep -q '^2\.0\.0'; then
    mv -f "$old" "${old}.rpmsave-v2.0.1"
fi
exit 0
```

Same shape for `-systemd` against the five `10-copyfail-defense.conf`
drop-ins (each file gets its own `.rpmsave-v2.0.1` next to it).

## 12.5 Detection signals

Strict signals only — no false positives from package presence alone.
**Detection runs in `%posttrans`**, after all subpackages are unpacked
but before scriptlets close, so the host's persistent state is what
gets inspected (NOT the freshly-installed package's state). Helper
script `/usr/libexec/copyfail-defense/detect.sh` owns the logic;
`%posttrans` and `copyfail-redetect` both call it. **[D-38]**

### 12.5.1 IPsec

Detected if **any** of:

1. `systemctl is-enabled <unit>` returns `enabled` (exit 0, output
   `enabled`) for any of: `strongswan`, `strongswan-starter`,
   `strongswan-swanctl`, `ipsec`, `libreswan`, `openswan`, `pluto`.
   Stopped-but-enabled counts; only masked or disabled passes.

   Rev 2 fixup (reviewer M-1, M-2):
   - **Added `strongswan-starter`**: Fedora/EPEL strongswan packaging
     (verified against `repoquery --list strongswan` on Fedora 40)
     ships *both* `strongswan.service` and
     `strongswan-starter.service` in `/usr/lib/systemd/system/`. The
     `-starter` unit is the legacy `ipsec` daemon entry-point and is
     the active unit on a non-trivial subset of EPEL hosts. EPEL 10
     strongswan packaging follows the same Fedora-derived layout.
   - **Added `pluto.service`**: some libreswan downstream rebuilds
     ship the daemon as `pluto.service` rather than `libreswan` /
     `ipsec`. Cheap inclusion.
   - **Removed `frr`**: FRRouting's BGP-only deployments dominate
     real-world FRR usage (BGP route reflectors, edge routers). The
     FP cost of suppressing the IPsec mitigation across a whole BGP
     fleet (which has no IPsec attack surface to begin with) is much
     larger than the FN cost of the rare FRR-with-IPsec-VTI
     deployment, who can use `force-full` or hand-edit a
     `20-override.conf`. **[D-51]**
2. `/etc/ipsec.conf` exists AND grep finds at least one line matching
   `^[[:space:]]*conn[[:space:]]+[^[:space:]]` (a real `conn` stanza,
   not just commented-out templates).
3. `/etc/swanctl/conf.d/` exists and contains at least one `*.conf`
   file (non-empty: any file with non-whitespace content).
4. `/etc/ipsec.d/*.conf` matches at least one file with non-whitespace
   content.
5. `/etc/strongswan/conf.d/*.conf` or `/etc/strongswan.d/*.conf` —
   distro-divergent strongSwan layout. Same non-empty rule.

**No runtime-state checks.** `ip xfrm policy list` and similar are
rejected per D-31.

**Edge cases handled:**

- Stopped-but-enabled IPsec daemon (maintenance window) — `is-enabled`
  still returns `enabled`. Detection trips. Correct. **[D-39]**
- Comments-only `ipsec.conf` — `conn` stanza grep skips comments via
  `^[[:space:]]*conn[[:space:]]+`. Correct.
- Debian-vs-RHEL service name divergence — alias list (1) catches
  Fedora/EPEL `strongswan.service` + `strongswan-starter.service`
  (both ship in `/usr/lib/systemd/system/` per Fedora packaging),
  Debian `strongswan.service`, EPEL `strongswan-swanctl.service`,
  the legacy `ipsec.service` symlink, libreswan / pluto rebuilds.
- FRRouting: NOT a signal in rev 2 — see D-51. BGP-only FRR
  deployments dominate; FRR-with-IPsec-VTI operators can use
  `force-full` or hand-edit a `20-override.conf`.

### 12.5.2 AFS

Detected if **any** of:

1. `systemctl is-enabled` returns `enabled` for any of:
   `openafs-client`, `openafs-server`, `kafs`, `afsd`.
2. `/etc/openafs/CellServDB` exists.
3. `/etc/openafs/ThisCell` exists (small text file, present on every
   AFS-configured host).
4. `/etc/krb5.conf.d/openafs*` matches any file (RHEL-style).
5. `/proc/fs/afs/` exists as a directory (already-loaded kafs;
   shouldn't apply on a fresh install but catches re-detect cases
   where the operator just configured AFS).

### 12.5.3 Rootless containers

**Rev 2 fixup (reviewer C-1, M-4, L-7):** the original signal set
included `/etc/subuid` cross-referenced against `UID>=1000` users.
shadow-utils' `useradd` populates `/etc/subuid` for every regular
user regardless of container intent, which produces a near-100%
false-positive rate on cPanel hosts (the project's primary target
audience). cPanel routinely creates 100s-1000s of regular users —
on those fleets the signal trips on first install, suppressing the
`user@.service` userns cut and inverting the v2.0.0 → v2.0.1
protection guarantee. The signal is dropped entirely. The
docker-group signal is also dropped (per L-7: docker group
membership signals access to the *rootful* docker daemon, not
rootless usage; FP cost > FN cost). The `/etc/subgid` file is
likewise not consulted.

Detected if **any** of these *storage-tree* signals:

1. **Per-user rootless podman storage tree (canonical marker)**:
   `/home/*/.local/share/containers/storage/overlay-containers/`
   exists for any user (this is podman's default rootless storage
   path; presence means some user has actually run a rootless
   container at least once). Per `containers/storage` upstream
   defaults — see <https://github.com/containers/storage/blob/main/storage.conf>
   ("rootless\_storage\_path" defaults to
   `$HOME/.local/share/containers/storage`).
2. **Rootful container storage tree with recent activity**:
   `/var/lib/containers/storage/` exists, is non-empty, AND its
   `mtime` is within the last 90 days. The mtime gate avoids
   tripping on long-stale podman installs that haven't been used
   (operator may have purged rootless workflows but left the
   directory). Recent mtime indicates the runtime is still
   producing state.
3. **Per-user runtime tmpfs tree**:
   `/run/user/<UID>/containers/` exists for any UID >= 1000. This
   is podman's per-user runtime root, populated when a rootless
   podman command is currently active or recently was (tmpfs is
   cleared on logout, so this is a strong "live rootless usage"
   signal).
4. **`podman.socket` enabled** for any user (system or per-user
   instance). Detected via `systemctl is-enabled podman.socket`
   AND `loginctl list-users --no-legend` enumeration with
   `systemctl --user --machine=<user>@.host is-enabled
   podman.socket`. Failure to query a user's session bus is
   silently treated as "not enabled" (mock-chroot safe). **[D-40]**

**Why these signals are the right primary set** (reviewer C-1
adoption rationale):

- **Storage tree presence is the canonical podman rootless
  fingerprint** — it's literally the directory podman creates the
  first time `podman run` succeeds rootlessly. Operators who set up
  the rootless prerequisite (`useradd`, `loginctl enable-linger`)
  but never invoked podman do not trip these signals. This
  inverts the FP/FN cost calculus correctly: signaling intent is
  not enough; signaling *activity* is required.
- **The cPanel false-positive is eliminated.** cPanel creates
  many regular users with auto-populated `/etc/subuid`, but those
  users almost never run podman. The storage trees stay empty.
  The rootless signal stays false. The userns cut applies.
- **The `90-day mtime` gate on `/var/lib/containers/storage/`**
  catches operators who used rootful podman and then stopped, vs
  ongoing usage. Stale state is suppressed; live state suppresses
  the cut.

**Edge cases handled:**

- **Operator pre-stages `/var/lib/containers/storage/` via image
  pull from an init script, then never runs containers**: signal
  (2) trips initially, mtime gate ages out within 90 days, signal
  goes false at next `copyfail-redetect` run. Acceptable.
- **Operator runs rootless podman exactly once a year**: signal
  (1) stays true (storage tree persists across logout). Signal
  (3) goes false during quiet periods. Either signal alone is
  enough to suppress; operator gets the safe default.
- **Future-user setup: operator pre-populates `useradd` for users
  not yet running containers**: NO false positive. The dropped
  `/etc/subuid` signal was the only intent-based trigger. With
  storage-tree-only signals, the rootless cut applies until users
  actually run a rootless container. Operator can `force-full` if
  they want eager opt-out. **[D-41]**
- **`/home` is on a separate mount that's slow to traverse**: signal
  (1) uses `find /home -maxdepth 5 -type d -name overlay-containers`
  with a `-mtime -180` gate to bound traversal. Performance concerns
  for very-large-`/home` fleets are tracked as M-5 in FOLLOWUPS.md
  v2.0.2 watch list.

**Storage path correction (reviewer M-4):** the prior draft cited
`/home/*/.config/containers/storage.conf` as a rootless signal.
That path is the *config file* (XDG\_CONFIG\_HOME), not the storage
tree. The actual rootless storage tree default is
`/home/*/.local/share/containers/storage/` (XDG\_DATA\_HOME). The
storage.conf file alone does not indicate active rootless use
(many distros ship it as a packaged default).

### 12.5.4 What about AF_ALG and AF_RXRPC RestrictAddressFamilies?

**Rev 2 fixup (reviewer C-3): the AF_RXRPC half of this section is
revised.** AF_ALG remains unconditional; AF_RXRPC moves to a
*conditional* drop-in gated on the same AFS detection signal as
`rxrpc` modprobe blacklist. The original draft's "no userspace
consumer" claim was wrong: `aklog` and `kinit -A` (openafs-tools,
shipped on every AFS-configured host) open userspace AF_RXRPC
sockets to communicate with vlserver/ptserver. Leaving
`~AF_RXRPC` unconditional on `user@.service` breaks `aklog`-based
token acquisition for any tenant on an AFS-configured host.

The conditional file lives at
`12-copyfail-defense-rxrpc-af.conf` per §12.4.2 and ships under
`/usr/share/copyfail-defense/conditional/systemd/` per §12.4.3.
detect.sh's apply scope copies it to all 5 tenant unit drop-in
directories *only when AFS is not detected*. When AFS is
detected, the file is removed from `/etc/...` and the tenant's
AF_RXRPC use survives.

The reviewer's specific code-example (`add_key("rxrpc",...)`) was
technically wrong (keyctl is not a socket family restriction —
that's a separate `add_key` keyring API), but the broader concern
about AF_RXRPC userspace consumers stands and drives this fix.

- **AF_ALG legitimate userspace consumers** are exotic: some QEMU
  configs that offload AES-XTS to the kernel crypto API, niche
  `dm-crypt-via-AF_ALG` userspace tooling, the cryptodev kernel-API
  tests. None of these run as systemd-managed services that are
  affected by `user@.service` drop-ins; they run as either root
  daemons (unaffected by user@) or as one-shot CLI invocations from
  a login shell (which is rooted at `user@<UID>.service`). Operators
  with this workload installed copyfail-defense intentionally.
- **AF_RXRPC userspace consumers (corrected per reviewer C-3)**:
  AFS userspace tooling (openafs-tools' `aklog`, `kinit -A` from
  some Kerberos-AFS integrations, `pts`, `vos`) opens AF_RXRPC
  sockets to talk to vlserver/ptserver from userspace. Kernel
  kafs uses the in-kernel rxrpc API, but the userspace tooling is
  the AFS-token-acquisition path — breaking it leaves authenticated
  AFS access broken for every tenant on the host. The earlier
  draft's claim that "no production workload reaches user-space
  AF_RXRPC" was incorrect for AFS hosts.

`~AF_ALG` stays unconditional in v2.0.1; `~AF_RXRPC` becomes
conditional on AFS detection (signals identical to those gating
the `rxrpc` modprobe blacklist — §12.5.2). If an AF_ALG
counter-example surfaces post-ship, add it to v2.0.2 detection.
**[D-30]**

## 12.6 Detection report (`auto-detect.json`)

Schema versioned for forward compatibility. The auditor reads it.
Path: `/var/lib/copyfail-defense/auto-detect.json` (mode 0644 root:root,
created by `%posttrans` if not present). **[D-42]**

```json
{
  "schema_version": "2",
  "tool": "copyfail-defense-detect",
  "tool_version": "2.0.1",
  "timestamp": 1746700800,
  "hostname": "host.example.com",
  "force_full": false,
  "detected": {
    "ipsec":            { "present": false, "signals": [] },
    "afs":              { "present": false, "signals": [] },
    "rootless_containers": {
      "present": true,
      "signals": ["/home/alice/.local/share/containers/storage/overlay-containers: present"]
    }
  },
  "suppressed": {
    "modprobe_cf2_xfrm":      false,
    "modprobe_rxrpc":         false,
    "systemd_rxrpc_af":       false,
    "systemd_userns_user_at": true
  },
  "applied": {
    "modprobe_cf1":           true,
    "modprobe_cf2_xfrm":      true,
    "modprobe_rxrpc":         true,
    "systemd_always":         true,
    "systemd_rxrpc_af_user_at": true,
    "systemd_rxrpc_af_sshd":  true,
    "systemd_rxrpc_af_cron":  true,
    "systemd_rxrpc_af_crond": true,
    "systemd_rxrpc_af_atd":   true,
    "systemd_userns_sshd":    true,
    "systemd_userns_user_at": false,
    "systemd_userns_cron":    true,
    "systemd_userns_crond":   true,
    "systemd_userns_atd":     true
  }
}
```

Schema rules:
- `schema_version` is a string. **Schema rev 2** (rev 2 fixup): the
  field bumps from `"1"` to `"2"` because the suppressed/applied keys
  expanded for the new `12-rxrpc-af` drop-in. The rootless detection
  signal text format also changed (storage-tree based instead of
  subuid based).
- `signals` is a free-form list of human-readable strings — debugging
  aid, not a structured contract. Auditor reads `present` only.
- `force_full: true` means `/etc/copyfail/force-full` was present; all
  `suppressed.*` are `false`, all `applied.*` are `true`.
- Atomically written: detect.sh writes to `auto-detect.json.tmp`, then
  `mv -f` over the final path. No partial-state window.
- **JSON emission uses python3** (rev 2 fixup per reviewer M-6) —
  `python3 -c 'import json,sys; ...'` reads detect.sh's collected
  state via env-var marshalling and emits a properly-escaped JSON
  document. Bash heredoc emission is rejected because it cannot
  safely escape control characters or signals containing quotes.
  python3 is already a runtime requirement of the auditor; depending
  on it for detect.sh JSON emission introduces no new dependency.
  **[D-52]**

**Auditor schema rejection (rev 2 fixup per reviewer M-3):** the
auditor reads `schema_version` and compares against its own
`AUTO_DETECT_SCHEMA_VERSION` constant. On mismatch:

- The auditor's posture surface adds a structured field
  `posture.auto_detect.schema_unrecognized: true` so SIEM filtering
  on this signal is straightforward.
- The auditor's `check_auto_detect_state()` returns WARN (not OK or
  INFO) regardless of detected workloads, because the auditor cannot
  trust the file's contents.
- Exit code: WARN-emitting checks already escalate the auditor's
  exit code via existing logic — no NEW exit code value is added.
  This is the "keep at WARN but require the new field" branch of
  reviewer M-3's two options. **[D-53]**

## 12.7 Force-full sentinel

`/etc/copyfail/force-full` (path, content irrelevant — existence-based)
makes `%posttrans` skip detection entirely and install all
suppressible mitigations. Operator's "I know my host" lever.

- File presence test only — content is ignored. Empty file works.
- The `/etc/copyfail/` directory is RPM-owned by `copyfail-defense`
  (meta) at `%dir 0755 root:root` so it exists from first install.
  Sentinel is operator-created; package never writes it. **[D-43]**
- Logged: `auto-detect.json.force_full = true`.
- **Sentinel shape (v2.0.1 fixup M-4):** the sentinel must be a
  regular file. If `/etc/copyfail/force-full` exists as a directory,
  a broken symlink, or another non-regular form, detect.sh emits a
  `copyfail-defense: WARN: ... force-full sentinel IGNORED` line to
  stderr and authpriv.warning, then proceeds with normal auto-detect.
  This catches the `mkdir /etc/copyfail/force-full` operator typo
  that otherwise silently downgraded force-full to normal detection.

## 12.8 Helper: `/usr/sbin/copyfail-redetect`

Bash, ~30 lines. Re-runs `/usr/libexec/copyfail-defense/detect.sh`
with the same scriptlet semantics. Per the rev 2 fixup the helper
now passes an explicit scope (`both`) since detect.sh's CLI splits
into per-subpackage scopes (reviewer C-6):

```sh
#!/bin/bash
set -euo pipefail
test "$(id -u)" -eq 0 || { echo "must be run as root" >&2; exit 1; }
/usr/libexec/copyfail-defense/detect.sh apply both
echo "Detection refreshed. See /var/lib/copyfail-defense/auto-detect.json"
echo "Run: systemctl daemon-reload && systemctl try-reload sshd"
echo "to apply systemd drop-in changes."
```

`detect.sh apply <scope>` mode performs the %posttrans flow scoped to
modprobe / systemd / both subpackages: detect, copy templates / remove
conditional `/etc/...` files matching the scope, write
`auto-detect.json`, log to LOG_AUTHPRIV. The helper does NOT call
`daemon-reload` itself — operator decides when to take the reload hit.
**[D-44]**

**Rev 2 fixup (reviewer L-3):** detect.sh's `report` mode is **dropped
in v2.0.1**. It was originally specced as a "dry-run JSON to stdout"
for the auditor to consume, but the final auditor design (§12.9)
reads the on-disk `auto-detect.json` directly — there's no consumer
for the `report` mode. Removing it keeps detect.sh's CLI surface
minimal and removes dead code. If a future caller needs dry-run
output, add it back with a real consumer wired in the same change.
**[D-54]**

## 12.9 Auditor extension (auto-detect surface)

`copyfail-local-check.py` reads `auto-detect.json` (when present) and
reports detection state under `posture.auto_detect`:

```json
"posture": {
  ...
  "auto_detect": {
    "available": true,
    "force_full": false,
    "detected_workloads": ["rootless_containers"],
    "suppressed_mitigations": ["systemd_userns_user_at"],
    "schema_unrecognized": false
  }
}
```

Plus a new check `check_auto_detect_state()` under MITIGATION:

- `OK` if no workloads detected (or `force_full` set).
- `INFO` (not WARN) if workloads detected and corresponding
  mitigations suppressed — that's the package working as designed.
- `WARN` if `auto-detect.json` is missing on a host where
  `copyfail-defense-modprobe` or `-systemd` is installed (means
  scriptlets failed silently).
- `WARN` if `auto-detect.json`'s `schema_version` is unrecognized
  (rev 2 fixup per reviewer M-3 / D-53). The check sets
  `posture.auto_detect.schema_unrecognized: true` for SIEM
  filtering.

**SKIP behavior (rev 2 fixup per reviewer M-9):** the check uses
`rpm -q copyfail-defense-modprobe` and `rpm -q
copyfail-defense-systemd` (returncode-based) to determine whether
either subpackage is installed. SKIP when neither rpm-query
succeeds. The original draft used file-existence checks
(`/etc/modprobe.d/99-copyfail-defense-cf1.conf` etc.), which is
unreliable: an operator who hand-removed the file (or whose host
suffered a botched %posttrans) would get a misleading SKIP
(auditor-only install) when in fact a subpackage is installed but
its drop-in is missing. `rpm -q` is the authoritative source. **[D-45]**

**dnf surfacing of detect.sh failure (rev 2 fixup per reviewer M-11):**
the spec's `%posttrans` invocations of `detect.sh apply <scope>` send
detect.sh stderr to **both** `logger` AND `stderr` of the scriptlet
(via `tee`). dnf surfaces scriptlet stderr to the operator's terminal
during transaction execution. This means a detect.sh failure during
install is visible to the operator without requiring them to grep
journald. The exit code is unchanged (failures don't fail the dnf
transaction); only visibility changes. **[D-55]**

The human report adds one line:
```
Auto-detect: rootless_containers (suppressed: systemd_userns_user_at)
```

Or `Auto-detect: clean (no conflicts)` when nothing tripped.

## 12.10 Scriptlet flow (consolidated)

**Rev 2 fixup (reviewer C-6): `detect.sh apply` takes an explicit
scope argument** (`modprobe`, `systemd`, or `both`). Each
`%posttrans` passes its own scope so a `-modprobe`-only install
does not produce orphan systemd files (and vice-versa). The
`copyfail-redetect` helper passes `both`. detect.sh writes the same
`auto-detect.json` regardless of scope, but only mutates
`/etc/modprobe.d/` when scope is `modprobe` or `both`, and only
mutates `/etc/systemd/system/<unit>.service.d/` when scope is
`systemd` or `both`. **[D-56]**

### 12.10.1 `-modprobe` lifecycle

| Phase | Action |
|---|---|
| `%pretrans` | If v2.0.0 monolithic file present AND v2.0.0 RPM was installed, rename to `<path>.rpmsave-v2.0.1` (D-37 — preserves operator hand-edits) |
| `%files` | Always-on `99-copyfail-defense-cf1.conf` (RPM-owned, `%config(noreplace)`); templates under `/usr/share/copyfail-defense/conditional/modprobe/` (RPM-owned, no `%config`) |
| `%post` | Best-effort `rmmod` of cf1 modules only (cf2/rxrpc deferred to %posttrans because we don't yet know whether to apply them); existing LOG_AUTHPRIV trail preserved |
| `%posttrans` | Run `/usr/libexec/copyfail-defense/detect.sh apply modprobe`. Writes `auto-detect.json`, copies templates → `/etc/modprobe.d/` for non-conflicting cuts, removes any stale conditional files. Does NOT touch `/etc/systemd/system/` (scope is modprobe-only). Run rmmod for cf2/rxrpc if applied. |
| `%postun` (full erase) | `detect.sh teardown modprobe` removes conditional `/etc/modprobe.d/99-copyfail-defense-{cf2-xfrm,rxrpc}.conf` files; remove `auto-detect.json` if no other subpackage owns it |

### 12.10.2 `-systemd` lifecycle

| Phase | Action |
|---|---|
| `%pretrans` | If v2.0.0 monolithic drop-in files present AND v2.0.0 RPM was installed, rename each to `<path>.rpmsave-v2.0.1` (D-37) |
| `%files` | Always-on `10-copyfail-defense.conf` for all 5 units (RPM-owned, `%config(noreplace)`); templates `12-copyfail-defense-rxrpc-af.conf` and `15-copyfail-defense-userns.conf` under `/usr/share/copyfail-defense/conditional/systemd/` |
| `%post` | If `/run/systemd/system` exists: defer reload to %posttrans so we reload after detect.sh has placed the conditional drop-ins |
| `%posttrans` | Run `/usr/libexec/copyfail-defense/detect.sh apply systemd`. Copies `12-rxrpc-af.conf` to all 5 unit `.d/` dirs unless AFS detected. Copies `15-userns.conf` to user@/sshd/cron/crond/atd `.d/` unless rootless detected (user@ only). Does NOT touch `/etc/modprobe.d/` (scope is systemd-only). Final `daemon-reload` and `try-reload-or-restart sshd`. |
| `%postun` (full erase) | `detect.sh teardown systemd` removes conditional `12-*.conf` and `15-*.conf` from all five `*.service.d/` dirs; daemon-reload + try-reload sshd; remove `auto-detect.json` if no other subpackage owns it |

### 12.10.2a Conditional file overwrite policy (operator hand-edits)

**Rev 2 fixup (reviewer C-7).** The original draft made the
conditional `/etc/...` drop-ins overwrite-on-detect with `chattr +i`
documented as the operator's escape hatch. That policy is broken:
`chattr +i` on a `%config` file makes `install -m 0644 ...` fail
with EPERM on the next %posttrans, breaking dnf transactions.

Rev 2 policy: `detect.sh apply <scope>` uses `cmp -s` to compare
the deployed `/etc/...` file against the
`/usr/share/copyfail-defense/conditional/<scope>/` template.

- If `/etc/...` doesn't exist and the cut should apply: install template.
- If `/etc/...` exists and is identical to the template: no-op.
- If `/etc/...` exists and **differs** from the template: log a WARN
  to LOG_AUTHPRIV (and dnf-surface stderr per D-55) and **skip the
  overwrite**. The operator's hand-edits survive. The next install
  preserves their state.
- If `/etc/...` exists and the cut should be suppressed: remove
  it regardless of operator edits. Suppression is destructive by
  design (the operator who edited the file presumably wants the
  cut, but detection says it conflicts; suppression wins for
  safety).

The documented operator-edit pattern is NOT chattr-based; instead
operators use the standard systemd drop-in numerical-ordering rule
(see §12.12 / README rewrite per D-58 below).
**[D-57]**

### 12.10.3 Idempotence

`%posttrans` runs after every upgrade per RPM scriptlet semantics. The
helper script's apply mode is fully idempotent:

- Detection re-runs from scratch (no caching of previous result).
- Template copy uses `install -m 0644 -o root -g root <src> <dst>` —
  no diff/merge logic; if the file exists with matching content, copy
  is a no-op. **Rev 2 fixup (D-57): if content differs (operator
  hand-edited the file), detect.sh logs a WARN and SKIPS the
  overwrite — operator's edits are preserved.** Suppression-removal
  still proceeds regardless of hand-edits (suppression wins for
  safety).
- Conditional file removal (`rm -f`) is no-op when the file is absent.
- `auto-detect.json` is rewritten atomically every run.

Re-running `dnf reinstall copyfail-defense` produces identical state
to a fresh install. Same for `dnf upgrade`. **[D-46]**

### 12.10.4 Failure mode: `%posttrans` interrupted

If `detect.sh apply` is killed mid-execution (OOM, SIGKILL, power
loss):

- Templates may be partially copied to `/etc/...`.
- `auto-detect.json` may be missing or incomplete.

Recovery: operator runs `/usr/sbin/copyfail-redetect` to re-execute
the apply flow. The script is idempotent (D-46), so partial state
converges to the correct state on next run.

If `auto-detect.json` is missing entirely, the auditor's
`check_auto_detect_state()` reports WARN per §12.9 — the operator gets
a visible signal that re-detect is needed. **[D-47]**

### 12.10.5 Mock-build environment

`%post` and `%posttrans` run inside `mock` chroots during RPM
verification. Constraints:

- `/run/systemd/system` does not exist → existing v2.0.0 systemd
  scriptlet's `if [ -d /run/systemd/system ]` guard already handles
  this. Inherited unchanged.
- `systemctl is-enabled <unit>` may return rc=1 with no stdout, OR
  rc=4 with `Failed to connect to bus`, OR may not exist at all
  (`systemctl` binary absent on minimal mock chroots without
  `systemd`). detect.sh treats any non-zero return OR `enabled`
  output absent as "service not enabled" and continues.
- `/etc/passwd` exists in mock (provided by setup package) but
  populated with only system users. Rootless detection signal (1)
  has no UID>=1000 users → no false positive in mock. **[D-48]**
- `/etc/subuid`, `/etc/openafs/`, `/etc/ipsec.conf` all absent in
  vanilla mock chroots → all detection signals correctly return
  "no conflict detected", v2.0.1 RPMs build with all conditional
  drop-ins fully active by default in mock.

### 12.10.6 Bash safety

`detect.sh` uses `set -euo pipefail` per project conventions. Every
command that can legitimately fail (`is-enabled`, glob expansions,
`getent` calls) wraps with explicit `|| true` or `if … ; then` guards.
Output goes through `logger -t copyfail-defense-detect -p authpriv.info`
matching the existing v2.0.0 pattern (spec line 369). **[D-49]**

## 12.11 Test-harness extension

`packaging/test-repo.sh` extends to 25 checks per EL (was 18 in
v2.0.0). New scenarios:

| # | Scenario | Test |
|---|---|---|
| 19 | Clean host detection | Fresh container; `dnf install copyfail-defense`; assert all 3 modprobe files + 5 unit `10-` + 5 unit `12-rxrpc-af` + 5 unit `15-` present (15 systemd files total, 18 conf files total); `auto-detect.json` schema_version="2", reports no workloads, no suppressions. |
| 20 | IPsec host detection | Fresh container; pre-stage `/etc/ipsec.conf` with a real `conn home` stanza; `dnf install`; assert `99-copyfail-defense-cf2-xfrm.conf` ABSENT, `99-copyfail-defense-cf1.conf` and `99-copyfail-defense-rxrpc.conf` PRESENT; `auto-detect.json` flags ipsec=present, suppressed.modprobe_cf2_xfrm=true. |
| 21 | AFS host detection | Pre-stage `/etc/openafs/ThisCell`; install; assert `99-copyfail-defense-rxrpc.conf` ABSENT and all 5 unit `12-copyfail-defense-rxrpc-af.conf` ABSENT (rev 2 / D-30); cf1+cf2-xfrm present; JSON flags afs and suppressed.systemd_rxrpc_af=true. |
| 22 | Rootless host detection (rev 2: storage-tree fixture per C-1) | Pre-stage `/home/alice/.local/share/containers/storage/overlay-containers/` (the canonical podman rootless fingerprint), useradd alice with UID 1000; `dnf install`; assert `user@.service.d/15-copyfail-defense-userns.conf` ABSENT, the other four units' `15-` files PRESENT, all `10-` and `12-rxrpc-af` files PRESENT. |
| 22b | cPanel-FP regression (rev 2 / C-1) | Pre-stage 5 regular users + populated `/etc/subuid` BUT NO podman storage tree, NO `/run/user/...` containers, NO `podman.socket`; `dnf install`; assert `user@.service.d/15-copyfail-defense-userns.conf` PRESENT (cut applies on cPanel-shaped host); `auto-detect.json` rootless=false. |
| 23 | Force-full override | Pre-stage all three conflict signals (IPsec + AFS + rootless storage tree) AND `touch /etc/copyfail/force-full`; install; assert ALL files present (no suppression); JSON `force_full: true`. |
| 24 | Re-detect helper | Install on clean host; verify all conditional files present; `touch /etc/openafs/ThisCell`; run `copyfail-redetect`; assert `99-copyfail-defense-rxrpc.conf` and all 5 `12-copyfail-defense-rxrpc-af.conf` removed and JSON updated. |
| 25 | v2.0.0 → v2.0.1 upgrade | Install v2.0.0 (from same repo per D-22 retention); verify monolithic files present; `dnf upgrade` to v2.0.1; assert monolithic files renamed to `.rpmsave-v2.0.1` (rev 2 D-37), split files installed per detection state. |

The existing v2.0.0 upgrade-path test (afalg-defense 1.0.1 →
copyfail-defense 2.0.0) is preserved as test #18. Per-EL test count
becomes 26 (was 18 in v2.0.0; rev 2 added 7 detection scenarios + 1
cPanel-FP regression). **[D-50]**

## 12.12 Documentation surface

- `README.md` — replace the "Override paths" section. New section:
  "Auto-detection of conflicting workloads" describing the three
  detection signals, the JSON report path, the `copyfail-redetect`
  helper, the `force-full` sentinel, and the **systemd-drop-in
  override patterns** for operators who need finer control than
  detection provides.

  **Override patterns documented (rev 2 fixup per reviewer C-8 /
  M-12). NO `chattr +i` recommendation.** The README documents
  these two standard systemd drop-in patterns:

  - **`20-override.conf` (empty-value to neutralize a directive)**
    — drop a `20-override.conf` next to our `10-`/`12-`/`15-` files
    with empty values for any directive you want to relax. systemd
    drop-ins merge in lex order; `20` > `10`/`12`/`15`, so the
    empty value wins and effectively disables the directive on
    that unit. Survives package upgrade because `20-override.conf`
    is operator-owned (RPM doesn't manage it).

    ```sh
    sudo mkdir -p /etc/systemd/system/user@.service.d
    sudo tee /etc/systemd/system/user@.service.d/20-override.conf <<'EOF'
    [Service]
    RestrictNamespaces=
    RestrictAddressFamilies=
    EOF
    sudo systemctl daemon-reload
    ```

  - **`25-additions.conf` (add a new directive)** — drop a
    `25-additions.conf` next to ours with directives you want to
    *add* (not override). The same lex-order merge applies, so
    `25-` lands after `20-`. Use this for adding fleet-wide cuts
    on top of ours.

    ```sh
    sudo tee /etc/systemd/system/sshd.service.d/25-additions.conf <<'EOF'
    [Service]
    NoNewPrivileges=true
    EOF
    sudo systemctl daemon-reload
    ```

  - **systemd numerical-ordering rule.** Within a single
    `<unit>.service.d/` directory, files are merged in
    lexicographic order. *Lower numbers lose to higher numbers
    for `=value` directives* (the latter override the former),
    but *list-valued directives concatenate* (every drop-in's
    value is added to the union). For
    `RestrictAddressFamilies=` and `RestrictNamespaces=`, the
    `=` (single equals) syntax is union/replace per systemd's
    rules — empty value clears the union entirely. The
    documented pattern works for the v2.0.1 directive set; for
    other directives consult `man 5 systemd.unit`.

  **NOT `chattr +i`.** The earlier draft proposed `chattr +i` on
  detect.sh-managed files as the escape hatch. That breaks dnf:
  the next `%posttrans` `install -m 0644` returns EPERM on an
  immutable file. Per reviewer C-7/C-8, this approach is dropped.
  Operators who need to fully prevent detect.sh from re-managing
  a file should use the `force-full` sentinel
  (`/etc/copyfail/force-full`) and treat detect.sh as a
  one-shot-disable lever rather than fighting per-file
  immutability flags. **[D-58]**

  **Conditional modprobe drop-ins** (`-cf2-xfrm`, `-rxrpc`) are
  managed by detect.sh and not RPM-owned. Operators wanting to
  pin one of these against detect.sh's decisions should hand-edit
  the file *and accept* that the cmp-and-skip policy (D-57) will
  preserve their edits — they'll get a WARN in the LOG_AUTHPRIV
  trail and a dnf-stderr notice on every %posttrans, but their
  edits survive.

- `STATE.md` — bump to v2.0.1.
- `BRIEF.md` — no changes (the bug-class story is unchanged).
- `FOLLOWUPS.md` — move "operator-side override docs" out of the
  open list (subsumed); add the "v2.0.2 watch list" with all
  reviewer-deferred items per the fixup directive (M-5, M-7, M-8,
  L-1, L-2, L-4, L-5, L-6, L-8) plus the v2.1.0 forward-cleanup
  obligation (M-10).

## 12.13 v2.0.1 decision index (continuation)

- **D-27** Detection action is suppress + log + report (not warn-only,
  not fail-install).
- **D-28** `/etc/copyfail/force-full` sentinel skips detection.
- **D-29** `/usr/sbin/copyfail-redetect` re-runs detection on demand.
- **D-30** `RestrictAddressFamilies=~AF_ALG` stays unconditional
  (no realistic legitimate-userspace consumer). `~AF_RXRPC` becomes
  **conditional** on AFS detection (rev 2 fixup per reviewer C-3:
  AFS userspace tooling — `aklog`, `kinit -A`, `pts`, `vos` —
  opens userspace AF_RXRPC sockets to vlserver/ptserver). The
  conditional `~AF_RXRPC` ships in the new
  `12-copyfail-defense-rxrpc-af.conf` drop-in, gated by the same
  AFS signals as the `rxrpc` modprobe blacklist.
- **D-31** No runtime-state checks (`ip xfrm`, `mount`, `docker info`)
  — flaky in mock and during scriptlets.
- **D-32** Split monolithic conf files: 3 modprobe + 2-per-unit
  systemd.
- **D-33** systemd userns drop-in numbered `15-` (between always-on
  `10-` and operator override `20-`).
- **D-34** systemd userns suppression is per-unit; only `user@`
  suppresses on rootless detection. sshd/cron/crond/atd always get
  the userns cut.
- **D-35** Conditional drop-ins ship as templates under
  `/usr/share/copyfail-defense/conditional/`; `/etc/...` not
  RPM-owned. Always-on files stay RPM-owned with `%config(noreplace)`.
- **D-36** Reject "ship-everything-then-blank" / commented-out
  alternative. Empty `/etc/...` directory is the truthful state.
- **D-37** `%pretrans` **renames** v2.0.0 monolithic files to
  `<path>.rpmsave-v2.0.1` before v2.0.1 unpacks (rev 2 fixup per
  reviewer C-4: preserves operator hand-edits). Conditional on file
  presence AND v2.0.0 RPM being installed.
- **D-38** Detection logic lives in
  `/usr/libexec/copyfail-defense/detect.sh`; `%posttrans` and
  `copyfail-redetect` both invoke it via explicit scope arg
  (per D-56).
- **D-39** Stopped-but-enabled IPsec daemon counts as detected.
- **D-40** Rootless container signals (rev 2 fixup per reviewer C-1
  / M-4 / L-7): storage-tree based — per-user
  `~/.local/share/containers/storage/overlay-containers/`,
  `/var/lib/containers/storage/` non-empty + recent mtime,
  `/run/user/<UID>/containers/`, `podman.socket` enabled
  (system or per-user). Earlier `/etc/subuid` cross-ref (cPanel FP)
  and docker-group (rootful, not rootless) signals dropped.
- **D-41** Storage-tree-only rootless detection (D-40) makes
  D-41's stale-subuid concern moot. Operators who pre-stage user
  accounts but never run rootless containers no longer trip the
  signal at all.
- **D-42** `auto-detect.json` schema v2 (rev 2 bump from v1 — keys
  expanded for `12-rxrpc-af`); auditor consumes it; rejects
  unknown schema versions with WARN + structured field
  `posture.auto_detect.schema_unrecognized: true` (D-53).
- **D-43** `/etc/copyfail/` directory is RPM-owned by meta package;
  sentinel is operator-created.
- **D-44** `copyfail-redetect` does NOT auto daemon-reload; operator
  decides reload timing.
- **D-45** Auditor `check_auto_detect_state()`: OK on clean / INFO on
  detected+suppressed / WARN on missing-JSON-but-installed / SKIP on
  auditor-only install.
- **D-46** `detect.sh apply` is fully idempotent.
- **D-47** Interrupted `%posttrans` recovery: operator runs
  `copyfail-redetect`. Auditor reports WARN if JSON missing.
- **D-48** Mock-build chroots: vanilla state has no workload signals;
  RPMs build with all conditional cuts active by default.
- **D-49** detect.sh logs to `LOG_AUTHPRIV` matching v2.0.0
  pattern.
- **D-50** test-repo.sh extends to 25 per-EL checks; existing
  upgrade-path (#18) preserved; v2.0.0 → v2.0.1 split-file upgrade
  added as #25.

### Rev 2 fixup additions (D-51..D-58)

- **D-51** IPsec detection unit list updated: ADD
  `strongswan-starter` (Fedora/EPEL packaging ships it alongside
  `strongswan.service`) and `pluto` (some libreswan downstream
  rebuilds); REMOVE `frr` (BGP-only deployments dominate FRR; FP
  cost greater than FN cost). Reviewer M-1 / M-2.
- **D-52** detect.sh JSON emission uses `python3 -c 'import
  json,sys; ...'` not bash heredoc — properly escapes control
  chars and signal text containing quotes. python3 is already a
  runtime dep of the auditor. Reviewer M-6.
- **D-53** auditor schema-rejection adds
  `posture.auto_detect.schema_unrecognized: true` field; check
  returns WARN (existing behavior, no new exit code).
  Reviewer M-3.
- **D-54** detect.sh `report` mode dropped — was unused by the
  final auditor design (auditor reads the on-disk file directly).
  Trim dead code. Reviewer L-3.
- **D-55** detect.sh failure surfaces to dnf stderr (via tee) so
  the operator sees scriptlet warnings during transaction
  execution, not just in journald. Exit code unchanged.
  Reviewer M-11.
- **D-56** `detect.sh apply <scope>` takes explicit scope arg
  (`modprobe` / `systemd` / `both`); each `%posttrans` passes
  its own scope to avoid orphan files when only one subpackage
  is installed; `copyfail-redetect` passes `both`.
  Reviewer C-6.
- **D-57** detect.sh uses `cmp -s` against the
  `/usr/share/copyfail-defense/conditional/` template before
  overwriting `/etc/...` conditional files. If the deployed
  file differs (operator hand-edited), log WARN and skip the
  overwrite; suppression-removal still proceeds regardless of
  hand-edits. Replaces the broken `chattr +i` policy.
  Reviewer C-7.
- **D-58** README documents `20-override.conf` (empty values to
  neutralize a directive) and `25-additions.conf` (add new
  directives) as the operator escape hatches — both are standard
  systemd drop-in patterns and survive package upgrade.
  Removes the `chattr +i` recommendation entirely. Includes the
  systemd numerical-ordering rule (lower numbers lose to higher
  numbers for `=value` directives within the same directory).
  Reviewer C-8 / M-12.

**Schema bump:** `auto-detect.json` schema_version moves from `"1"`
to `"2"` because the suppressed/applied keys expanded to
accommodate the new `12-rxrpc-af` drop-ins (5 unit positions). The
auditor's `AUTO_DETECT_SCHEMA_VERSION` constant is updated to match
in the same release.

**Reviewer items not folded here (deferred to v2.0.2 watch list per
fixup directive):** M-5 (find /home perf + auditd noise), M-7
(conditional daemon-reload optimization), M-8 (test fixture
redundant write), L-1, L-2, L-4, L-5, L-6, L-8. See FOLLOWUPS.md
for the deferral list.

## 12.14 Self-review (challenge pass — v2.0.1)

- **Does the split survive `dnf reinstall`?** Yes. `%pretrans` only
  fires on upgrade (RPM passes `$1 == 2`). On reinstall, the v2.0.1
  RPM's own files are removed and re-installed; the always-on files
  flow through `%config(noreplace)` correctly; conditional files in
  `/etc/...` are removed by detect.sh's idempotent apply on
  `%posttrans` and re-created based on detection. Verified
  mentally; needs PLAN test coverage.
- **Does the split survive `dnf downgrade copyfail-defense afalg-defense`?**
  Hypothetical operator-recovery path from v2.0.0 §6 rollback. v2.0.1
  → v2.0.0 downgrade hits the same `%config` rename-on-removal logic
  in reverse: v2.0.1 conditional `/etc/...` files are removed
  cleanly by `%preun`, the always-on `10-` files are renamed to
  `.rpmsave` because v2.0.0 has `10-copyfail-defense.conf` at the
  same path. Operator picks up `.rpmsave` files in v2.0.0; they're
  identical content, no harm. Acceptable rollback semantics.
- **What if `/proc` is restricted (paranoid container)?** The `/proc/fs/afs/`
  signal returns "not present" (degraded gracefully); other AFS
  signals (CellServDB, ThisCell) are filesystem-based and unaffected.
  IPsec / rootless detection don't touch `/proc`. Mock chroots have
  fully readable `/proc/`. No problem.
- **What if `getent` is missing?** `getent` ships with `glibc-common`
  on RHEL and is present in every mock chroot. detect.sh wraps with
  `if command -v getent >/dev/null 2>&1; then ... fi`; absent
  `getent`, signal (4) for rootless degrades to false (acceptable;
  signals 1-3 are sufficient).
- **Does `%pretrans` running before `%pre` cause any issue?** RPM
  scriptlet order: `%pretrans` (all packages, before any unpack) →
  `%pre` (per-package, before unpack) → unpack → `%post` (per-package,
  after unpack) → `%posttrans` (all packages, after all unpacks).
  Removing the v2.0.0 monolithic file in `%pretrans` happens before
  RPM tries to handle the same path during unpack of v2.0.1, which
  doesn't list it. Clean.
- **Are detection signals stable across distros?** Tested per-distro
  (in test-repo.sh): EL8 (AlmaLinux 8), EL9 (CentOS Stream 9),
  EL10 (CentOS Stream 10). systemctl `is-enabled` semantics identical;
  `/etc/openafs/`, `/etc/subuid`, `/etc/ipsec.conf` paths are all
  upstream-Linux conventional, present on all three.
- **Race between detect.sh and concurrent dnf?** RPM serializes
  scriptlets — only one transaction at a time. `auto-detect.json`
  atomic-writes via tmpfile + `mv -f`. No race.
- **Operator runs `copyfail-redetect` while a `%posttrans` from a
  separate dnf is in progress?** Both invoke the same detect.sh; the
  second one waits-or-overwrites depending on filesystem timing. The
  atomic `mv -f` means the JSON is always either the old or new
  state, never a blend. Acceptable.

**Reviewer's three open questions — resolved in rev 2 fixup:**

1. **Operator-edit policy for conditional `15-*` files
   (overwrite-on-detect vs cmp-and-skip)?** **Resolved: cmp-and-skip
   per D-57.** detect.sh compares the deployed `/etc/...` file
   against the `/usr/share/...conditional/` template using `cmp -s`
   and skips the install (with a WARN) if they differ. The
   `chattr +i` workaround is dropped because it breaks dnf via
   EPERM on subsequent `install -m 0644`. Reviewer C-7.
2. **README override pattern documentation?** **Resolved:
   `20-override.conf` (empty values to neutralize) +
   `25-additions.conf` (add new directives) per D-58.** Both are
   standard systemd drop-in patterns and survive package upgrade.
   `chattr +i` is removed from the README entirely. Reviewer
   C-8 / M-12.
3. **detect.sh location: `/usr/libexec/` (FHS) vs
   `/usr/share/`?** **Acked-deferred for v2.0.2 (reviewer L-2,
   `%{_libexecdir}` macro use).** Current plan keeps the path
   string `/usr/libexec/copyfail-defense/detect.sh` hard-coded
   per FHS. v2.0.2 may convert to the macro form for cleanliness.

**Rev 2 fixup challenge re-pass (after C-1..C-8 + M-1..M-12 fold-in):**

- **Storage-tree-based rootless detection vs cPanel false-positives.**
  The rev 1 `/etc/subuid` signal was the load-bearing FP source.
  Rev 2 drops it entirely; rootless is now signaled only by *active
  storage tree presence*, which cPanel hosts do not produce by
  default. Verified mentally; needs Phase 6 test coverage on a
  cPanel-shaped fixture (many regular users, no podman storage
  trees → rootless=false).
- **AF_RXRPC conditionalization vs AFS userspace tooling.** With
  the `12-rxrpc-af.conf` drop-in gated on AFS detection, an AFS
  host with `aklog` retains AF_RXRPC userspace socket access. A
  non-AFS host still gets the cut. Edge case: a host that runs
  the kernel selftest suite for AF_RXRPC (as the rev 1 draft
  cited as the only userspace consumer) — rev 2 still applies
  the cut on those hosts (no AFS signal trips). Acceptable;
  selftest is a developer workflow, not a production deployment.
- **Per-subpackage detect.sh scope vs orphan files.** With
  `apply modprobe` / `apply systemd` / `apply both`, each
  `%posttrans` mutates only its own subpackage's territory.
  Operator who installs `-modprobe` alone gets clean
  `/etc/modprobe.d/` state and no `/etc/systemd/system/...d/`
  drop-ins (because `-systemd` was never installed). detect.sh
  still writes `auto-detect.json` regardless of scope (it's a
  shared report). Edge case: operator installs `-modprobe`,
  later installs `-systemd` — `-systemd` `%posttrans apply
  systemd` adds the systemd files; the modprobe state is
  unchanged (correct, idempotent). Verified.
- **`.rpmsave-v2.0.1` rename vs operator hand-edits.** Rename
  preserves any operator hand-edits to v2.0.0 monolithic files
  for inspection/recovery. Operator can `rm` the
  `.rpmsave-v2.0.1` files at their leisure. RPM doesn't track
  these files. Acceptable.
- **Rev 2 cmp-and-skip on conditional files vs new edge cases.**
  An operator who hand-edits `/etc/modprobe.d/99-copyfail-defense-cf2-xfrm.conf`
  in rev 2 gets their edits preserved. If detect.sh later
  decides to *suppress* that cut (operator added IPsec
  post-install), the file is removed (suppression wins over
  hand-edit). Counter-edge: operator who edited the file to
  *strengthen* the cut and then enabled IPsec — they lose the
  edit on next %posttrans, which is correct because the cut
  conflicts with their now-enabled IPsec. Documented in
  README "Manual override (finer than detection)" subsection.
- **Schema v2 bump vs v2.0.0 → v2.0.1 upgrade.** v2.0.0 never
  shipped `auto-detect.json`, so there's no schema-v1 file in
  the wild to migrate. Schema-v2 is what every v2.0.1 host
  produces. The auditor's WARN-on-unrecognized-schema (D-53)
  protects against future v2.0.x ships that bump schema again.
- **Did rev 2 introduce any new high-risk mechanism?** Two
  candidates worth flagging for the next reviewer pass:
  - **`find /home -maxdepth 5` performance**: see M-5 (deferred
    v2.0.2). The bound is reasonable for typical /home layouts
    but pathological on 100k-user cPanel hosts. Mitigation
    options: timeout the find, parallel-walk, or invert to a
    "loginctl list-users" enumeration that only checks
    actually-active users. Tracked.
  - **python3 dependency in detect.sh's JSON emission**: detect.sh
    runs in `%posttrans`. If python3 is absent (extreme minimal
    chroot), JSON emission fails. Tradeoff: python3 is already
    a runtime dep of `copyfail-defense-auditor`; the meta package
    `Requires: python3-libs` is a small new dep cost on the
    `-modprobe` and `-systemd` subpackages. PLAN Phase 3 must add
    `Requires: /usr/bin/python3` (path dep) to those subpackages.
    Documented in PLAN file map.

**Verdict:** rev 2 is shippable. The three reviewer open questions
are resolved (C-7→cmp-and-skip; C-8/M-12→20-override+25-additions;
L-2 ack-deferred). All in-scope CRITICALs and MEDIUMs are folded.
The two new mechanisms flagged above (find perf, python3 dep) are
documented for the next reviewer pass to inspect.
