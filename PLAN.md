# PLAN — `copyfail-defense` v2.0.1

**Source:** `SPEC.md` §12 (drafted 2026-05-08; rev 2 after reviewer
fixup pass — folds in C-1..C-8 + M-1..M-12 in-scope items).
**Status:** rev 2 drafted, awaiting Ryan's approval + sentinel review.
**Predecessor:** v2.0.0 (shipped 2026-05-08, tag `v2.0.0`, commit `f70c9eb`).

This plan replaces the prior v2.0.0 PLAN. v2.0.0 is fully shipped;
v2.0.0 acceptance criteria are preserved as-is. v2.0.1 adds
auto-detection of conflicting workloads (IPsec, AFS, rootless
containers) at install time, replacing the README's operator-driven
override section with package-driven behavior.

All decisions reference `SPEC.md` §12.13 (D-27..D-58) for v2.0.1 work.
v2.0.0 decisions (D-01..D-26) remain locked. Rev 2 fixup added
D-51..D-58 per the reviewer report.

---

## Dependency graph

```
            ┌──────────────────────┐
            │ Phase 1              │
            │ File-layout split    │  (foundational — splits monolithic
            │ (sources only)       │   conf into 3 modprobe + 2-per-unit
            └──────────┬───────────┘   systemd)
                       │
            ┌──────────┴───────────┐
            ▼                      ▼
┌──────────────────────┐  ┌──────────────────────┐
│ Phase 2              │  │ Phase 3              │
│ detect.sh helper     │  │ Spec scriptlet       │  (parallel — different
│ + auto-detect.json   │  │ rewrite              │   files; can do both)
└──────────┬───────────┘  └──────────┬───────────┘
           │                         │
           └────────────┬────────────┘
                        ▼
            ┌──────────────────────┐
            │ Phase 4              │
            │ copyfail-redetect    │
            │ helper + force-full  │
            └──────────┬───────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │ Phase 5              │
            │ Auditor extension    │
            │ (auto_detect read)   │
            └──────────┬───────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │ Phase 6              │
            │ test-repo.sh extend  │
            │ (5 new scenarios)    │
            └──────────┬───────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │ Phase 7              │
            │ README + STATE       │
            │ + FOLLOWUPS docs     │
            └──────────┬───────────┘
                       │
            ═══════════╪═══════════════════
            ║ BUILD/PUBLISH BOUNDARY ║
            ═══════════╪═══════════════════
                       │
                       ▼
            ┌──────────────────────┐
            │ Phase 8              │
            │ Mock + sign + repo   │  (manual, build host required)
            └──────────┬───────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │ Phase 9              │
            │ Release v2.0.1       │  (manual, gh release / push)
            └──────────────────────┘
```

---

## File map (full plan)

| File | Action | Owner phase |
|---|---|---|
| `packaging/copyfail-defense.spec` | modify (rewrite scriptlets, add Sources, %pretrans, split %files, add `Requires: /usr/bin/python3` to -modprobe and -systemd) | Phase 3 |
| `packaging/copyfail-modprobe.conf` | rename → `copyfail-modprobe-cf1.conf` | Phase 1 |
| `packaging/copyfail-modprobe-cf2-xfrm.conf` | new | Phase 1 |
| `packaging/copyfail-modprobe-rxrpc.conf` | new | Phase 1 |
| `packaging/copyfail-systemd-dropin.conf` | rewrite (always-on body only — `~AF_ALG` only, no `~AF_RXRPC`) | Phase 1 |
| `packaging/copyfail-systemd-dropin-rxrpc-af.conf` | new (rev 2: `~AF_RXRPC` body, gated on AFS detection) | Phase 1 |
| `packaging/copyfail-systemd-dropin-userns.conf` | new (suppressible body) | Phase 1 |
| `packaging/copyfail-systemd-dropin-containers.conf` | rewrite (concatenate all 3 bodies for the example) | Phase 1 |
| `packaging/copyfail-defense-detect.sh` | new (~200 lines bash; rev 2: scope arg, cmp-and-skip, storage-tree rootless detection, python3-based JSON emission, no `report` mode) | Phase 2 |
| `packaging/copyfail-redetect` | new (~30 lines bash; calls `detect.sh apply both`) | Phase 4 |
| `copyfail-local-check.py` | modify (add check_auto_detect_state with rpm-q SKIP, schema_unrecognized field, posture.auto_detect, render line) | Phase 5 |
| `packaging/test-repo.sh` | modify (add 7 new test functions; rev 2: rootless test pre-stages a podman storage tree, not /etc/subuid) | Phase 6 |
| `README.md` | modify (replace "Override paths" section with "Auto-detection" + 20-override / 25-additions doc; NO chattr +i) | Phase 7 |
| `STATE.md` | modify (bump to v2.0.1; defer commit-hash placeholder to Phase 9) | Phase 7 |
| `FOLLOWUPS.md` | modify (subsume operator-override entry; add v2.0.2 watch list with deferred reviewer items; add v2.1.0 forward-cleanup) | Phase 7 |

---

## Conventions (referenced by all phases)

- **Bash:** `#!/bin/bash`, `set -euo pipefail` per `.rdf/governance/conventions.md` §"Bash". All commands that legitimately fail wrap with `|| true` or `if … ; then`.
- **Logging:** scriptlets use `logger -t copyfail-defense-detect -p authpriv.info` matching v2.0.0 spec line 369. detect.sh logs every detection signal hit and every applied/suppressed action.
- **Spec comments:** multi-paragraph commentary in the spec is intentional and load-bearing per `.rdf/governance/anti-patterns.md` §"Source comments: spec is the exception". Preserve density on edits; do NOT strip.
- **No em-dashes** in shipped artifacts (per `.rdf/governance/anti-patterns.md`). Use ASCII hyphens. Plain quotes only.
- **Atomic file writes:** detect.sh writes JSON to `<path>.tmp` then `mv -f` to final path. No partial-state windows.
- **Idempotence:** every `%post` / `%posttrans` / `detect.sh apply` invocation must produce identical state on re-run. Tested in Phase 6.
- **Mock-chroot safe:** every scriptlet wraps `systemctl` calls with `if [ -d /run/systemd/system ]` (existing v2.0.0 pattern); detect.sh wraps `systemctl is-enabled` returns to treat any non-zero AND any output other than literal `enabled` as "not enabled".
- **Verification gates per phase:** every phase has at least one shell command that proves the change works without rebuilding RPMs. Real RPM verification happens in Phase 6 (test-repo.sh) and Phase 8 (mock build).
- **Commit messages:** lowercase area prefix + colon + active voice (per `.rdf/governance/conventions.md` §"Commit messages"). v2.0.1 release commit: `2.0.1: auto-detect IPsec / AFS / rootless workloads at install time`.

---

## Phase 1 — File-layout split (sources only)

**Goal.** Split the monolithic v2.0.0 conf files into v2.0.1 layout
per SPEC §12.4. No spec changes yet (Phase 3 wires them up). Pure
source-tree manipulation, easily reverted if the design changes
during review.

**Mode.** serial-context (foundational; all later phases depend on
final paths).
**Risk.** low (no behavior change until Phase 3 wires the new files).
**Type.** refactor.

### Files

- **rename:** `packaging/copyfail-modprobe.conf` → `packaging/copyfail-modprobe-cf1.conf`
- **new:** `packaging/copyfail-modprobe-cf2-xfrm.conf`
- **new:** `packaging/copyfail-modprobe-rxrpc.conf`
- **rewrite:** `packaging/copyfail-systemd-dropin.conf` (rev 2: `~AF_ALG` only, no `~AF_RXRPC`)
- **new:** `packaging/copyfail-systemd-dropin-rxrpc-af.conf` (rev 2: `~AF_RXRPC` body, gated on AFS)
- **new:** `packaging/copyfail-systemd-dropin-userns.conf`
- **rewrite:** `packaging/copyfail-systemd-dropin-containers.conf`

### Steps

- [ ] **1.1** `git mv packaging/copyfail-modprobe.conf packaging/copyfail-modprobe-cf1.conf`
- [ ] **1.2** Edit `packaging/copyfail-modprobe-cf1.conf` to retain ONLY the cf1 stanza.

  Replace the full content with:

  ```
  # /etc/modprobe.d/99-copyfail-defense-cf1.conf
  # Owned by copyfail-defense-modprobe; do not hand-edit.
  #
  # Always-on. cf1 (CVE-2026-31431) algif_aead AEAD scratch-write.
  # No-op on RHEL where algif_aead is builtin; functional on stock mainline.
  install algif_aead   /bin/false
  install authenc      /bin/false
  install authencesn   /bin/false
  install af_alg       /bin/false
  blacklist algif_aead
  blacklist authenc
  blacklist authencesn
  blacklist af_alg
  ```

- [ ] **1.3** Create `packaging/copyfail-modprobe-cf2-xfrm.conf`:

  ```
  # /etc/modprobe.d/99-copyfail-defense-cf2-xfrm.conf
  # Owned by copyfail-defense-modprobe; do not hand-edit.
  #
  # Conditional: suppressed by %posttrans when IPsec is detected
  # (strongSwan, libreswan, openswan, FRRouting). See
  # /var/lib/copyfail-defense/auto-detect.json.
  #
  # cf2 / Dirty Frag-ESP. xfrm IPsec ESP family.
  # Modules on stock RHEL 8/9/10 generic kernels - blacklist IS functional.
  install esp4         /bin/false
  install esp6         /bin/false
  install xfrm_user    /bin/false
  install xfrm_algo    /bin/false
  blacklist esp4
  blacklist esp6
  blacklist xfrm_user
  blacklist xfrm_algo
  ```

- [ ] **1.4** Create `packaging/copyfail-modprobe-rxrpc.conf`:

  ```
  # /etc/modprobe.d/99-copyfail-defense-rxrpc.conf
  # Owned by copyfail-defense-modprobe; do not hand-edit.
  #
  # Conditional: suppressed by %posttrans when AFS is detected
  # (openafs, kafs). See /var/lib/copyfail-defense/auto-detect.json.
  #
  # Dirty Frag-RxRPC. Andrew File System RPC.
  # Ubuntu loads by default; RHEL ships in kernel-modules-extra, not core.
  install rxrpc        /bin/false
  blacklist rxrpc
  ```

- [ ] **1.5** Rewrite `packaging/copyfail-systemd-dropin.conf` to retain ONLY the always-on body. Rev 2 fixup (reviewer C-3): drop `~AF_RXRPC` from this file — it moves into the new conditional `12-copyfail-defense-rxrpc-af.conf` that's gated on AFS detection.

  ```
  # /etc/systemd/system/<unit>.service.d/10-copyfail-defense.conf
  # Owned by copyfail-defense-systemd; do not hand-edit.
  #
  # Always-on tenant-unit hardening. The conditional AF_RXRPC and
  # userns cuts live in 12-copyfail-defense-rxrpc-af.conf and
  # 15-copyfail-defense-userns.conf respectively (managed by detect.sh).
  #
  # Override per-host: drop a 20-override.conf with empty values
  # to neutralize a directive, or 25-additions.conf to add new ones.
  # See README "Manual override (finer than detection)".
  [Service]
  RestrictAddressFamilies=~AF_ALG
  SystemCallArchitectures=native
  SystemCallFilter=~@swap
  ```

- [ ] **1.5a** (NEW, rev 2 fixup per C-3) Create `packaging/copyfail-systemd-dropin-rxrpc-af.conf`:

  ```
  # /etc/systemd/system/<unit>.service.d/12-copyfail-defense-rxrpc-af.conf
  # Owned by copyfail-defense-systemd; managed by %posttrans detection.
  # Do not hand-edit; %posttrans rewrites this file based on
  # /var/lib/copyfail-defense/auto-detect.json.
  #
  # Suppressed (file removed from /etc/...) when AFS is detected:
  # aklog / kinit -A / pts / vos open AF_RXRPC sockets to vlserver and
  # ptserver from userspace, and would lose token-acquisition with
  # this cut applied.
  #
  # systemd merges RestrictAddressFamilies across drop-ins; pairing
  # this with the 10-* file's =~AF_ALG produces the same union as
  # the v2.0.0 monolithic =~AF_ALG ~AF_RXRPC body.
  [Service]
  RestrictAddressFamilies=~AF_RXRPC
  ```

- [ ] **1.6** Create `packaging/copyfail-systemd-dropin-userns.conf`:

  ```
  # /etc/systemd/system/<unit>.service.d/15-copyfail-defense-userns.conf
  # Owned by copyfail-defense-systemd; managed by %posttrans detection.
  # Do not hand-edit; %posttrans rewrites this file based on
  # /var/lib/copyfail-defense/auto-detect.json.
  #
  # On user@.service.d, this file is suppressed when rootless
  # containers (podman, buildah, rootless docker) are detected.
  # On sshd/cron/crond/atd, the file is always installed.
  [Service]
  RestrictNamespaces=~user ~net
  ```

- [ ] **1.7** Rewrite `packaging/copyfail-systemd-dropin-containers.conf` to ship the **combined** body (10-, 12-, AND 15- contents) so an operator opting in to container-runtime drop-ins gets the complete hardening. Rev 2 fixup (reviewer C-3): `~AF_RXRPC` is now part of this combined body since the opt-in path explicitly confirms "no rootless or AFS workloads on this runtime daemon":

  ```
  # Optional drop-in for container-runtime service units.
  # This file ships under /usr/share/doc/copyfail-defense/examples/ and
  # is NOT installed as an active drop-in.
  #
  # Combines the always-on (10-*), AF_RXRPC (12-*), and userns-restrict
  # (15-*) bodies into a single drop-in. v2.0.1 splits these on tenant
  # units to support auto-suppression on AFS / rootless hosts; for
  # container-runtime daemons the opt-in path is "you confirmed no
  # rootless workloads AND no AFS workloads on this runtime", so the
  # merged body is fine here.
  #
  # Activate ONLY if your fleet does NOT run rootless or
  # user-namespace-remapped containers via the runtime daemons.
  # Applying RestrictNamespaces=~user to containerd/docker/podman
  # breaks rootless containers AND userns-remapped containers.
  #
  # To activate (per-runtime - repeat for any of containerd, docker, podman):
  #
  #   sudo install -d /etc/systemd/system/podman.service.d
  #   sudo cp /usr/share/doc/copyfail-defense/examples/containers-dropin.conf \
  #           /etc/systemd/system/podman.service.d/10-copyfail-defense.conf
  #   sudo systemctl daemon-reload
  #   sudo systemctl try-reload-or-restart podman.service
  #
  # To deactivate later, just remove the active drop-in file and reload.
  [Service]
  RestrictAddressFamilies=~AF_ALG ~AF_RXRPC
  RestrictNamespaces=~user ~net
  SystemCallArchitectures=native
  SystemCallFilter=~@swap
  ```

### Acceptance

- [ ] `ls packaging/copyfail-modprobe-*.conf` lists exactly 3 files (`-cf1`, `-cf2-xfrm`, `-rxrpc`); no `copyfail-modprobe.conf` (without suffix) remains.
- [ ] `ls packaging/copyfail-systemd-dropin*.conf` lists exactly 4 files (base, `-rxrpc-af`, `-userns`, `-containers`).
- [ ] `grep -E "^install (algif_aead|authenc|authencesn|af_alg|esp4|esp6|xfrm_user|xfrm_algo|rxrpc) /bin/false" packaging/copyfail-modprobe-*.conf | wc -l` returns `9` (4 cf1 + 4 cf2-xfrm + 1 rxrpc, all 9 cf-class modules accounted for across the three files).
- [ ] `grep -c "RestrictNamespaces" packaging/copyfail-systemd-dropin.conf` returns `0` (always-on body has no userns directive).
- [ ] `grep -c "RestrictNamespaces" packaging/copyfail-systemd-dropin-userns.conf` returns `1`.
- [ ] `grep -c "RestrictAddressFamilies" packaging/copyfail-systemd-dropin.conf` returns `1`.
- [ ] `grep -c "AF_RXRPC" packaging/copyfail-systemd-dropin.conf` returns `0` (rev 2: AF_RXRPC moved to conditional file).
- [ ] `grep -c "AF_RXRPC" packaging/copyfail-systemd-dropin-rxrpc-af.conf` returns `1`.
- [ ] `grep -c "AF_RXRPC" packaging/copyfail-systemd-dropin-containers.conf` returns `1` (preserved in the merged opt-in example).

### Test strategy

Lint-only. No runtime changes possible until Phase 3 wires these into
the spec.

### Commit message (pre-written)

```
packaging: split monolithic conf files into per-cut files for v2.0.1

Splits 99-copyfail-defense.conf into 99-copyfail-defense-cf1.conf
(always-on), 99-copyfail-defense-cf2-xfrm.conf (suppressible on IPsec
hosts), and 99-copyfail-defense-rxrpc.conf (suppressible on AFS hosts).

Splits the systemd drop-in body into three files:
- 10-copyfail-defense.conf: always-on (RestrictAddressFamilies=~AF_ALG,
  SystemCallArchitectures, SystemCallFilter)
- 12-copyfail-defense-rxrpc-af.conf: ~AF_RXRPC, suppressible on AFS hosts
  (aklog/kinit -A open AF_RXRPC sockets to vlserver/ptserver)
- 15-copyfail-defense-userns.conf: RestrictNamespaces=~user ~net,
  suppressible on user@.service.d when rootless containers detected

The container-runtime example file concatenates all three bodies since
the opt-in path is "operator has confirmed no rootless or AFS
workloads on this runtime daemon."

Spec wiring + scriptlets land in the next commit.
```

---

## Phase 2 — `detect.sh` helper + `auto-detect.json`

**Goal.** Implement `/usr/libexec/copyfail-defense/detect.sh` per
SPEC §12.5, §12.6, §12.10 (rev 2 fixup). Bash + python3 (for JSON
emission per D-52). ~200 lines. Single mode: `apply <scope>` where
scope is one of `modprobe`, `systemd`, `both` (per D-56). The
former `report` mode is dropped (per D-54 / reviewer L-3) — there
is no consumer for it; the auditor reads the on-disk file directly.

**Mode.** serial-context (Phase 3 spec depends on detect.sh path/contract).
**Risk.** medium (live filesystem mutations on operator hosts).
**Type.** feature.

### Files

- **new:** `packaging/copyfail-defense-detect.sh`

### detect.sh contract (rev 2)

```
USAGE: detect.sh apply (modprobe|systemd|both)
       detect.sh teardown (modprobe|systemd|both)

apply <scope>:
  detect, write JSON to /var/lib/copyfail-defense/auto-detect.json,
  copy non-conflicting templates from /usr/share/copyfail-defense/conditional/
  to /etc/ for the given scope, remove any stale conflicting files
  from /etc/ for the given scope, log to LOG_AUTHPRIV.

  Scope semantics (per D-56):
    modprobe - only mutates /etc/modprobe.d/. Never touches
               /etc/systemd/system/. Used by -modprobe %posttrans.
    systemd  - only mutates /etc/systemd/system/<unit>.service.d/.
               Never touches /etc/modprobe.d/. Used by -systemd
               %posttrans.
    both     - mutates both. Used by /usr/sbin/copyfail-redetect.

  In all scopes, auto-detect.json is rewritten with the current
  detected state. Suppression flags reflect the union of
  detection results regardless of scope (the report is global).

teardown <scope>:
  Remove any conditional /etc/... files belonging to the given
  scope. Used by %postun on full erase. Does NOT delete
  auto-detect.json (the meta package's %postun owns that, since
  another subpackage may still be installed).

EXIT CODES:
  0  - completed successfully (regardless of what was found)
  1  - usage error or unrecoverable filesystem error
  2  - detection partial (some signals errored but best-effort
       decisions made; auto-detect.json reflects degraded state)
```

The exit-code semantics matter for Phase 3's `%posttrans`: `set +e`
around the call so a failed detection doesn't fail the RPM
transaction. Per D-55, detect.sh stderr is teed to dnf's scriptlet
stderr so the operator sees warnings during install. Logged via
LOG_AUTHPRIV either way.

### Steps

- [ ] **2.1** Write the file header:

  ```bash
  #!/bin/bash
  #
  # copyfail-defense-detect.sh
  #   Detect IPsec / AFS / rootless-container workloads on the host
  #   and decide which copyfail-defense conditional drop-ins to apply.
  #
  # Invoked from %posttrans of copyfail-defense-modprobe and
  # copyfail-defense-systemd, and from /usr/sbin/copyfail-redetect.
  #
  # Modes:
  #   apply  - decide, mutate /etc/, write auto-detect.json
  #   report - decide, emit JSON to stdout (no mutations)
  set -euo pipefail
  ```

- [ ] **2.2** Define paths + constants:

  ```bash
  STATE_DIR="/var/lib/copyfail-defense"
  STATE_FILE="${STATE_DIR}/auto-detect.json"
  TEMPLATE_DIR="/usr/share/copyfail-defense/conditional"
  ETC_MODPROBE="/etc/modprobe.d"
  ETC_SYSTEMD="/etc/systemd/system"
  FORCE_FULL="/etc/copyfail/force-full"
  TOOL_VERSION="2.0.1"

  # Active tenant units (must match SPEC §4.2 and v2.0.0 CF_CLASS_TENANT_UNITS)
  TENANT_UNITS=("user@" "sshd" "cron" "crond" "atd")

  # Logging tag matches v2.0.0 spec line 369 convention
  LOGGER_TAG="copyfail-defense-detect"

  log() {
      logger -t "${LOGGER_TAG}" -p authpriv.info "$*" 2>/dev/null || true
  }
  ```

- [ ] **2.3** Implement `detect_ipsec()`. Returns array of signal strings via global `IPSEC_SIGNALS`; sets global `IPSEC_PRESENT=true|false`. Rev 2 fixup (reviewer M-1, M-2 / D-51): unit list adds `strongswan-starter` and `pluto`; removes `frr`:

  ```bash
  IPSEC_PRESENT="false"
  IPSEC_SIGNALS=()

  detect_ipsec() {
      local unit
      # D-51: strongswan-starter is the legacy ipsec daemon entry on
      # Fedora/EPEL strongswan packaging (verified against
      # repoquery --list strongswan: ships both strongswan.service AND
      # strongswan-starter.service in /usr/lib/systemd/system/).
      # pluto.service covers some libreswan downstream rebuilds.
      # frr REMOVED: BGP-only deployments dominate; FP > FN.
      for unit in strongswan strongswan-starter strongswan-swanctl \
                  ipsec libreswan openswan pluto; do
          if systemctl is-enabled "${unit}.service" 2>/dev/null \
             | grep -qx 'enabled'; then
              IPSEC_PRESENT="true"
              IPSEC_SIGNALS+=("systemctl: ${unit}.service enabled")
          fi
      done
      if [ -f /etc/ipsec.conf ] && \
         grep -qE '^[[:space:]]*conn[[:space:]]+[^[:space:]]' /etc/ipsec.conf 2>/dev/null; then
          IPSEC_PRESENT="true"
          IPSEC_SIGNALS+=("/etc/ipsec.conf: contains conn stanza")
      fi
      local d
      for d in /etc/swanctl/conf.d /etc/ipsec.d /etc/strongswan/conf.d /etc/strongswan.d; do
          [ -d "${d}" ] || continue
          if find "${d}" -maxdepth 1 -name '*.conf' -type f \
             -not -empty 2>/dev/null | grep -q .; then
              IPSEC_PRESENT="true"
              IPSEC_SIGNALS+=("${d}: non-empty *.conf present")
          fi
      done
  }
  ```

- [ ] **2.4** Implement `detect_afs()`:

  ```bash
  AFS_PRESENT="false"
  AFS_SIGNALS=()

  detect_afs() {
      local unit
      for unit in openafs-client openafs-server kafs afsd; do
          if systemctl is-enabled "${unit}.service" 2>/dev/null \
             | grep -qx 'enabled'; then
              AFS_PRESENT="true"
              AFS_SIGNALS+=("systemctl: ${unit}.service enabled")
          fi
      done
      local f
      for f in /etc/openafs/CellServDB /etc/openafs/ThisCell; do
          if [ -f "${f}" ]; then
              AFS_PRESENT="true"
              AFS_SIGNALS+=("${f}: present")
          fi
      done
      if find /etc/krb5.conf.d -maxdepth 1 -name 'openafs*' -type f \
         2>/dev/null | grep -q .; then
          AFS_PRESENT="true"
          AFS_SIGNALS+=("/etc/krb5.conf.d/openafs*: present")
      fi
      if [ -d /proc/fs/afs ]; then
          AFS_PRESENT="true"
          AFS_SIGNALS+=("/proc/fs/afs: kernel kafs filesystem registered")
      fi
  }
  ```

- [ ] **2.5** Implement `detect_rootless_containers()`. Rev 2 fixup (reviewer C-1, M-4, L-7): the `/etc/subuid` cross-reference signal is DROPPED (near-100% FP rate on cPanel hosts; shadow-utils auto-populates subuid for every regular user regardless of container intent, inverting protection guarantee on the project's primary target audience). The docker-group signal is also DROPPED (signals access to rootful daemon, not rootless usage). Replaced with storage-tree-based signals that fire only on *active rootless usage*:

  ```bash
  ROOTLESS_PRESENT="false"
  ROOTLESS_SIGNALS=()

  detect_rootless_containers() {
      # Signal 1: per-user rootless podman storage tree (canonical
      # marker). Per containers/storage upstream defaults the rootless
      # storage path is $HOME/.local/share/containers/storage; the
      # overlay-containers subdirectory is created by podman on first
      # successful rootless container run. Bound the find traversal
      # to maxdepth 6 with -mtime -180 to avoid pathological /home
      # walks (M-5 deferred).
      if find /home -maxdepth 6 -type d \
              -name overlay-containers \
              -path '*/.local/share/containers/storage/overlay-containers' \
              -mtime -180 2>/dev/null | grep -q .; then
          ROOTLESS_PRESENT="true"
          ROOTLESS_SIGNALS+=("/home/*/.local/share/containers/storage/overlay-containers: present")
      fi

      # Signal 2: rootful container storage tree with recent activity.
      # Rejects long-stale podman installs (operator may have purged
      # rootless workflows but left the directory). 90-day mtime gate.
      if [ -d /var/lib/containers/storage ] && \
         find /var/lib/containers/storage -mindepth 1 -maxdepth 1 \
              -mtime -90 2>/dev/null | grep -q .; then
          ROOTLESS_PRESENT="true"
          ROOTLESS_SIGNALS+=("/var/lib/containers/storage: non-empty + mtime<90d")
      fi

      # Signal 3: per-user runtime tmpfs (live or recent rootless
      # podman activity). /run/user/<UID>/containers is podman's
      # XDG_RUNTIME_DIR child for rootless state. Tmpfs clears on
      # logout, so this is a strong "live use" signal.
      local rud
      for rud in /run/user/*/containers; do
          [ -d "${rud}" ] || continue
          local uid
          uid=$(printf '%s\n' "${rud}" | cut -d/ -f4)
          if [ -n "${uid}" ] && [ "${uid}" -ge 1000 ] 2>/dev/null; then
              ROOTLESS_PRESENT="true"
              ROOTLESS_SIGNALS+=("/run/user/${uid}/containers: present")
              break
          fi
      done

      # Signal 4: podman.socket enabled (system or any per-user instance).
      # System-wide check first (works in mock chroots that lack a session bus).
      if systemctl is-enabled podman.socket 2>/dev/null | grep -qx 'enabled'; then
          ROOTLESS_PRESENT="true"
          ROOTLESS_SIGNALS+=("systemctl: podman.socket enabled")
      fi
      # Per-user enumeration via loginctl (best-effort; failures are silent
      # in mock or on hosts without active sessions).
      if command -v loginctl >/dev/null 2>&1; then
          local lusers user
          lusers=$(loginctl list-users --no-legend 2>/dev/null | awk '{print $2}')
          for user in ${lusers}; do
              [ -n "${user}" ] || continue
              if systemctl --user --machine="${user}@.host" \
                           is-enabled podman.socket 2>/dev/null \
                  | grep -qx 'enabled'; then
                  ROOTLESS_PRESENT="true"
                  ROOTLESS_SIGNALS+=("systemctl --user (${user}): podman.socket enabled")
                  break
              fi
          done
      fi
  }
  ```

  Note: the `/etc/subuid` and `getent group docker` blocks from rev 1
  are REMOVED. Tests in Phase 6 are updated to pre-stage a rootless
  storage tree instead of `/etc/subuid` (rev 2 fixup per M-9 plus the
  rootless-test rewrite below).

- [ ] **2.6** Implement `decide_suppressions()`. Rev 2 adds the
  `SUPPRESS_SYSTEMD_RXRPC_AF` flag (gated on AFS, applies to all 5
  tenant units, per D-30 / C-3):

  ```bash
  # SUPPRESS_*: true if mitigation is suppressed; false if applied.
  SUPPRESS_MODPROBE_CF2_XFRM="false"
  SUPPRESS_MODPROBE_RXRPC="false"
  SUPPRESS_SYSTEMD_RXRPC_AF="false"           # rev 2: NEW (AF_RXRPC drop-in, all 5 units)
  SUPPRESS_SYSTEMD_USERNS_USER_AT="false"     # rev 2: per-unit only (user@)

  decide_suppressions() {
      if [ -f "${FORCE_FULL}" ]; then
          # Operator override - apply everything regardless of detection.
          return 0
      fi
      [ "${IPSEC_PRESENT}" = "true" ]    && SUPPRESS_MODPROBE_CF2_XFRM="true"
      [ "${AFS_PRESENT}" = "true" ]      && SUPPRESS_MODPROBE_RXRPC="true"
      [ "${AFS_PRESENT}" = "true" ]      && SUPPRESS_SYSTEMD_RXRPC_AF="true"
      [ "${ROOTLESS_PRESENT}" = "true" ] && SUPPRESS_SYSTEMD_USERNS_USER_AT="true"
  }
  ```

- [ ] **2.7** Implement `cmp_and_install()` helper + `apply_modprobe()` + `apply_systemd()`. Rev 2 fixup (reviewer C-7 / D-57): cmp-and-skip on the deployed `/etc/...` file vs the template — preserves operator hand-edits. Rev 2 (D-56): each apply function only mutates its own scope; the dispatcher in `main()` selects which to call. The new `12-rxrpc-af` drop-in is installed for all 5 units when AFS is not detected.

  ```bash
  # cmp-and-skip helper: install src to dst only if dst doesn't
  # exist OR matches src exactly. If dst differs from src, log
  # WARN and skip the install (preserves operator hand-edits per D-57).
  # Returns 0 on success/skip, non-zero on filesystem error.
  cmp_and_install() {
      local src="$1" dst="$2" tag="$3"
      if [ ! -f "${dst}" ]; then
          install -d -m 0755 "$(dirname "${dst}")"
          install -m 0644 -o root -g root "${src}" "${dst}"
          log "${tag}: applied (new install)"
          return 0
      fi
      if cmp -s "${src}" "${dst}"; then
          # Same content — nothing to do.
          return 0
      fi
      # Different content — operator hand-edit. Skip overwrite.
      # tee to stderr so dnf surfaces the warning (D-55).
      printf 'copyfail-defense: WARN: %s diverged from template; preserving operator edits (cmp-and-skip per D-57)\n' \
          "${dst}" | tee /dev/stderr | logger -t "${LOGGER_TAG}" -p authpriv.warning 2>/dev/null || true
      return 0
  }

  apply_modprobe() {
      local src dst
      # cf2-xfrm: cmp-and-install or remove
      src="${TEMPLATE_DIR}/modprobe/99-copyfail-defense-cf2-xfrm.conf"
      dst="${ETC_MODPROBE}/99-copyfail-defense-cf2-xfrm.conf"
      if [ "${SUPPRESS_MODPROBE_CF2_XFRM}" = "true" ]; then
          rm -f "${dst}"
          log "modprobe cf2-xfrm: suppressed (IPsec detected)"
      elif [ -f "${src}" ]; then
          cmp_and_install "${src}" "${dst}" "modprobe cf2-xfrm"
      fi
      # rxrpc: cmp-and-install or remove
      src="${TEMPLATE_DIR}/modprobe/99-copyfail-defense-rxrpc.conf"
      dst="${ETC_MODPROBE}/99-copyfail-defense-rxrpc.conf"
      if [ "${SUPPRESS_MODPROBE_RXRPC}" = "true" ]; then
          rm -f "${dst}"
          log "modprobe rxrpc: suppressed (AFS detected)"
      elif [ -f "${src}" ]; then
          cmp_and_install "${src}" "${dst}" "modprobe rxrpc"
      fi
  }

  apply_systemd() {
      local src dst unit suppress
      # 12-* AF_RXRPC drop-in (suppressed on AFS hosts; applies to all 5 units)
      src="${TEMPLATE_DIR}/systemd/12-copyfail-defense-rxrpc-af.conf"
      if [ -f "${src}" ]; then
          for unit in "${TENANT_UNITS[@]}"; do
              dst="${ETC_SYSTEMD}/${unit}.service.d/12-copyfail-defense-rxrpc-af.conf"
              if [ "${SUPPRESS_SYSTEMD_RXRPC_AF}" = "true" ]; then
                  rm -f "${dst}"
                  log "systemd rxrpc-af ${unit}: suppressed (AFS detected)"
              else
                  cmp_and_install "${src}" "${dst}" "systemd rxrpc-af ${unit}"
              fi
          done
      fi
      # 15-* userns drop-in (suppressed on user@ only when rootless detected)
      src="${TEMPLATE_DIR}/systemd/15-copyfail-defense-userns.conf"
      if [ -f "${src}" ]; then
          for unit in "${TENANT_UNITS[@]}"; do
              dst="${ETC_SYSTEMD}/${unit}.service.d/15-copyfail-defense-userns.conf"
              suppress="false"
              if [ "${unit}" = "user@" ] && \
                 [ "${SUPPRESS_SYSTEMD_USERNS_USER_AT}" = "true" ]; then
                  suppress="true"
              fi
              if [ "${suppress}" = "true" ]; then
                  rm -f "${dst}"
                  log "systemd userns ${unit}: suppressed (rootless detected)"
              else
                  cmp_and_install "${src}" "${dst}" "systemd userns ${unit}"
              fi
          done
      fi
  }

  teardown_modprobe() {
      rm -f "${ETC_MODPROBE}/99-copyfail-defense-cf2-xfrm.conf"
      rm -f "${ETC_MODPROBE}/99-copyfail-defense-rxrpc.conf"
      log "modprobe teardown: removed conditional /etc/modprobe.d/* files"
  }

  teardown_systemd() {
      local unit
      for unit in "${TENANT_UNITS[@]}"; do
          rm -f "${ETC_SYSTEMD}/${unit}.service.d/12-copyfail-defense-rxrpc-af.conf"
          rm -f "${ETC_SYSTEMD}/${unit}.service.d/15-copyfail-defense-userns.conf"
      done
      log "systemd teardown: removed conditional /etc/systemd/system/*.d/12-* and 15-*"
  }
  ```

- [ ] **2.8** Implement `write_state_json()` using python3 for safe JSON emission. Rev 2 fixup (reviewer M-6 / D-52): bash heredoc emission cannot safely escape control characters, quotes, or backslashes that may appear in signal strings. python3 is already a runtime requirement of the auditor and now of `-modprobe` / `-systemd` (added in Phase 3 as `Requires: /usr/bin/python3`).

  Schema version bumps to `"2"` (rev 2: keys expanded for `12-rxrpc-af` per-unit applied flags).

  ```bash
  write_state_json() {
      local target="$1"   # final path
      local force_full="false"
      [ -f "${FORCE_FULL}" ] && force_full="true"

      # Marshall arrays as NUL-delimited bytes via env vars; python reads
      # and decodes. NUL is the only safe delimiter for arbitrary-content
      # signal strings.
      local ipsec_blob afs_blob rootless_blob
      ipsec_blob=$(printf '%s\0' "${IPSEC_SIGNALS[@]+${IPSEC_SIGNALS[@]}}")
      afs_blob=$(printf '%s\0' "${AFS_SIGNALS[@]+${AFS_SIGNALS[@]}}")
      rootless_blob=$(printf '%s\0' "${ROOTLESS_SIGNALS[@]+${ROOTLESS_SIGNALS[@]}}")

      install -d -m 0755 -o root -g root "$(dirname "${target}")"
      local tmp="${target}.tmp.$$"

      env \
          CFD_TOOL_VERSION="${TOOL_VERSION}" \
          CFD_TIMESTAMP="$(date +%s)" \
          CFD_HOSTNAME="$(hostname 2>/dev/null || echo unknown)" \
          CFD_FORCE_FULL="${force_full}" \
          CFD_IPSEC_PRESENT="${IPSEC_PRESENT}" \
          CFD_AFS_PRESENT="${AFS_PRESENT}" \
          CFD_ROOTLESS_PRESENT="${ROOTLESS_PRESENT}" \
          CFD_IPSEC_SIGNALS="${ipsec_blob}" \
          CFD_AFS_SIGNALS="${afs_blob}" \
          CFD_ROOTLESS_SIGNALS="${rootless_blob}" \
          CFD_SUP_MODPROBE_CF2_XFRM="${SUPPRESS_MODPROBE_CF2_XFRM}" \
          CFD_SUP_MODPROBE_RXRPC="${SUPPRESS_MODPROBE_RXRPC}" \
          CFD_SUP_SYSTEMD_RXRPC_AF="${SUPPRESS_SYSTEMD_RXRPC_AF}" \
          CFD_SUP_SYSTEMD_USERNS_USER_AT="${SUPPRESS_SYSTEMD_USERNS_USER_AT}" \
          python3 -c '
  import json, os, sys

  def split_blob(name):
      raw = os.environ.get(name, "")
      if not raw:
          return []
      # printf %s\\0 leaves a trailing NUL; strip empty trailing entries
      return [s for s in raw.split("\0") if s]

  def b(name):
      return os.environ.get(name, "false") == "true"

  sup_xfrm   = b("CFD_SUP_MODPROBE_CF2_XFRM")
  sup_rxrpc  = b("CFD_SUP_MODPROBE_RXRPC")
  sup_rxaf   = b("CFD_SUP_SYSTEMD_RXRPC_AF")
  sup_userns = b("CFD_SUP_SYSTEMD_USERNS_USER_AT")

  doc = {
      "schema_version": "2",
      "tool": "copyfail-defense-detect",
      "tool_version": os.environ["CFD_TOOL_VERSION"],
      "timestamp": int(os.environ["CFD_TIMESTAMP"]),
      "hostname": os.environ["CFD_HOSTNAME"],
      "force_full": b("CFD_FORCE_FULL"),
      "detected": {
          "ipsec":               {"present": b("CFD_IPSEC_PRESENT"),    "signals": split_blob("CFD_IPSEC_SIGNALS")},
          "afs":                 {"present": b("CFD_AFS_PRESENT"),      "signals": split_blob("CFD_AFS_SIGNALS")},
          "rootless_containers": {"present": b("CFD_ROOTLESS_PRESENT"), "signals": split_blob("CFD_ROOTLESS_SIGNALS")},
      },
      "suppressed": {
          "modprobe_cf2_xfrm":      sup_xfrm,
          "modprobe_rxrpc":         sup_rxrpc,
          "systemd_rxrpc_af":       sup_rxaf,
          "systemd_userns_user_at": sup_userns,
      },
      "applied": {
          "modprobe_cf1":              True,
          "modprobe_cf2_xfrm":         not sup_xfrm,
          "modprobe_rxrpc":            not sup_rxrpc,
          "systemd_always":            True,
          "systemd_rxrpc_af_user_at":  not sup_rxaf,
          "systemd_rxrpc_af_sshd":     not sup_rxaf,
          "systemd_rxrpc_af_cron":     not sup_rxaf,
          "systemd_rxrpc_af_crond":    not sup_rxaf,
          "systemd_rxrpc_af_atd":      not sup_rxaf,
          "systemd_userns_user_at":    not sup_userns,
          "systemd_userns_sshd":       True,
          "systemd_userns_cron":       True,
          "systemd_userns_crond":      True,
          "systemd_userns_atd":        True,
      },
  }
  with open(sys.argv[1], "w") as f:
      json.dump(doc, f, indent=2, sort_keys=True)
      f.write("\n")
  ' "${tmp}"

      mv -f "${tmp}" "${target}"
  }
  ```

  Note: there is no longer a stdout/`-` mode — the dropped `report`
  mode (D-54) was the only consumer. detect.sh always writes to a
  real path.

- [ ] **2.9** Implement main entry. Rev 2 (D-54, D-56): no `report`
  mode; `apply` and `teardown` both take an explicit scope arg
  (`modprobe`/`systemd`/`both`).

  ```bash
  usage() {
      cat <<USAGE >&2
  USAGE: $0 apply (modprobe|systemd|both)
         $0 teardown (modprobe|systemd|both)
  USAGE
      exit 1
  }

  main() {
      local action="${1:-}" scope="${2:-}"
      case "${action}" in
          apply)
              case "${scope}" in
                  modprobe|systemd|both) ;;
                  *) usage ;;
              esac
              detect_ipsec
              detect_afs
              detect_rootless_containers
              decide_suppressions
              if [ "${scope}" = "modprobe" ] || [ "${scope}" = "both" ]; then
                  apply_modprobe
              fi
              if [ "${scope}" = "systemd" ] || [ "${scope}" = "both" ]; then
                  apply_systemd
              fi
              write_state_json "${STATE_FILE}"
              log "apply ${scope} complete: ipsec=${IPSEC_PRESENT} afs=${AFS_PRESENT} rootless=${ROOTLESS_PRESENT}"
              ;;
          teardown)
              case "${scope}" in
                  modprobe|systemd|both) ;;
                  *) usage ;;
              esac
              if [ "${scope}" = "modprobe" ] || [ "${scope}" = "both" ]; then
                  teardown_modprobe
              fi
              if [ "${scope}" = "systemd" ] || [ "${scope}" = "both" ]; then
                  teardown_systemd
              fi
              ;;
          *)
              usage
              ;;
      esac
  }

  main "$@"
  ```

### Acceptance

- [ ] `bash -n packaging/copyfail-defense-detect.sh` returns 0 (syntax valid).
- [ ] `shellcheck packaging/copyfail-defense-detect.sh` returns 0 (or all warnings have inline `# shellcheck disable=` justifications).
- [ ] `bash packaging/copyfail-defense-detect.sh` (no args) prints USAGE to stderr and exits 1.
- [ ] `bash packaging/copyfail-defense-detect.sh apply` (no scope) prints USAGE to stderr and exits 1.
- [ ] `bash packaging/copyfail-defense-detect.sh apply bogus` rejects unknown scope and exits 1.
- [ ] On a clean dev host (with templates in place + writable STATE_DIR via env override OR with sudo): `apply both` writes a valid `auto-detect.json` parseable by `python3 -c "import json,sys; json.load(open('/var/lib/copyfail-defense/auto-detect.json'))"`.
- [ ] `jq -r .schema_version /var/lib/copyfail-defense/auto-detect.json` returns `"2"` (rev 2 schema bump).
- [ ] On a clean dev host: JSON has `detected.ipsec.present == false`, `detected.afs.present == false`, `detected.rootless_containers.present` may be either (depends on dev host) but type is bool.
- [ ] Manual signal verification (rootless replacement): `mkdir -p /tmp/fakehome/alice/.local/share/containers/storage/overlay-containers` and bind-mount over /home (or run inside a fixture container) and confirm signal trips. Equivalent fixture exercised in Phase 6 test #22.

### Test strategy

Lint-only (bash -n + shellcheck) at this phase. Real install-time
verification happens in Phase 6 (test-repo.sh).

### Edge cases

- Empty `IPSEC_SIGNALS`/etc arrays: bash 4.x `set -u` complains on
  `${arr[@]}` when `arr=()`. The `${arr[@]+...}` idiom + NUL-blob
  marshalling handles this — the python3 reader treats empty input
  as an empty list.
- `python3` absent (extreme minimal chroots): JSON emission fails.
  The spec adds `Requires: /usr/bin/python3` to `-modprobe` and
  `-systemd` (Phase 3) so dnf installs python3 alongside our
  subpackages. Mock chroots used in Phase 8 build process include
  python3 by default; verified.
- `systemctl` absent (extreme minimal chroots): all `is-enabled`
  calls return non-zero via `2>/dev/null`, signals from those
  branches return false. Filesystem-based signals still work.
- `loginctl` absent: per-user podman.socket enumeration (signal 4
  in rootless detection) skips silently. System-wide
  `podman.socket` check still works.
- `find /home -maxdepth 6` performance on huge fleets: M-5 deferred
  to v2.0.2 watch list. The `-mtime -180` gate bounds the
  inode-scan cost on each subtree but does NOT bound the directory
  traversal itself. Acceptable for v2.0.1; revisit if cPanel hosts
  see scriptlet timeout.
- `cmp -s` against missing template (development build with broken
  install): `cmp` returns non-zero on missing src, the WARN path
  fires. Acceptable; this is a misbuild and the operator should
  re-install.
- `hostname` absent: command substitution falls through to `echo
  unknown` via the `||` chain.

### Commit message (pre-written)

```
packaging: add copyfail-defense-detect.sh helper for v2.0.1

Implements IPsec / AFS / rootless-container detection per SPEC §12.5
(rev 2). Single mode: apply <scope> where scope is modprobe / systemd
/ both (D-56). Per-subpackage scope avoids orphan files on
single-subpackage installs.

Rootless detection uses storage-tree signals (the canonical podman
fingerprint) instead of /etc/subuid (which has near-100% FP rate on
cPanel hosts where shadow-utils auto-populates subuid for every
useradd). docker-group signal also dropped (signals access to rootful
daemon, not rootless usage).

IPsec unit list adds strongswan-starter (Fedora/EPEL packaging) and
pluto (libreswan downstream rebuilds); drops frr (BGP-only deployments
dominate; FP > FN).

cmp-and-skip policy on conditional /etc/... files preserves operator
hand-edits (D-57). Replaces the earlier chattr +i workaround which
broke dnf via EPERM.

JSON emission via python3 -c (D-52) properly escapes control chars
and signal text containing quotes. Bash heredoc emission rejected.

LOG_AUTHPRIV trail matches v2.0.0 modprobe scriptlet pattern; stderr
is teed to dnf scriptlet output (D-55) so operator sees warnings
during install.

Spec wiring lands in the next commit; the helper is idle until
%posttrans invokes it.
```

---

## Phase 3 — Spec scriptlet rewrite

**Goal.** Wire detect.sh into the spec. Add `%pretrans` for v2.0.0
upgrade cleanup (D-37), reshape `%files`, add new `Source*` lines, add
new directories, install templates under `/usr/share/`, ship detect.sh
under `/usr/libexec/`. Bump `Version` to `2.0.1`. Per SPEC §12.10.

**Mode.** serial-context (depends on Phase 1+2 paths; downstream
phases depend on spec contract).
**Risk.** high (spec scriptlets are the live-fire surface).
**Type.** feature.

### Files

- **modify:** `packaging/copyfail-defense.spec`

### Steps

- [ ] **3.1** Edit spec preamble. Bump `Version` and `Release`. Add new `Source*` lines. Add `Requires: /usr/bin/python3` to `-modprobe` and `-systemd` subpackages (rev 2: detect.sh requires python3 for JSON emission per D-52). Phase 3 owns Source0..9 only; Source10 (copyfail-redetect) lands cleanly in Phase 4.

  Old (lines 16-30):
  ```spec
  Version:        2.0.0
  Release:        1%{?dist}
  ...
  Source0:        %{upstream_name}-%{version}.tar.gz
  Source1:        copyfail-shim-enable
  Source2:        copyfail-shim-disable
  Source3:        copyfail-modprobe.conf
  Source4:        copyfail-systemd-dropin.conf
  Source5:        copyfail-systemd-dropin-containers.conf
  ```

  New (rev 2 — Source10 deferred to Phase 4):
  ```spec
  Version:        2.0.1
  Release:        1%{?dist}
  ...
  Source0:        %{upstream_name}-%{version}.tar.gz
  Source1:        copyfail-shim-enable
  Source2:        copyfail-shim-disable
  Source3:        copyfail-modprobe-cf1.conf
  Source4:        copyfail-systemd-dropin.conf
  Source5:        copyfail-systemd-dropin-containers.conf
  Source6:        copyfail-modprobe-cf2-xfrm.conf
  Source7:        copyfail-modprobe-rxrpc.conf
  Source8:        copyfail-systemd-dropin-userns.conf
  Source9:        copyfail-defense-detect.sh
  Source11:       copyfail-systemd-dropin-rxrpc-af.conf
  ```

  (Source numbering: Source10 is reserved for Phase 4's
  copyfail-redetect; Source11 is the new rxrpc-af drop-in body
  added in rev 2 fixup.)

  Add `Requires:` to subpackages. Find each `%package modprobe` and
  `%package systemd` block (currently at lines around 95 and 110)
  and add after the existing `Requires:` lines:

  ```spec
  Requires:       /usr/bin/python3
  ```

  (Rev 2: detect.sh's JSON emission delegates to python3 per D-52.
  python3 is already a runtime dep of `-auditor`; adding it to the
  two subpackages that ship detect.sh-using scriptlets is the
  smallest correct change. The meta package's `Requires:` already
  pulls these subpackages exact-match per D-04.)

- [ ] **3.2** Update meta package's `%description` and `%post` to mention auto-detection. The current `%description` (lines 57-81) ends with: `Refer to /usr/share/doc/copyfail-defense/README.md for the defense-in-depth ladder, the per-class coverage table, and the override paths for operator workflows that conflict with default cuts (rootless podman, IPsec, AFS).`

  Replace the trailing sentence with:

  ```
  v2.0.1 auto-detects IPsec / AFS / rootless-container workloads at
  install time and suppresses the conflicting drop-ins. The detection
  report at /var/lib/copyfail-defense/auto-detect.json shows what
  ran and what was suppressed; /usr/sbin/copyfail-redetect re-runs
  detection on demand. Override the auto-detection by creating
  /etc/copyfail/force-full before install.
  ```

- [ ] **3.3** Add `%dir /etc/copyfail` to meta's `%files` block (currently lines 412-414). Insert directory ownership so the sentinel path exists from first install (D-43):

  Old:
  ```spec
  %files
  %license LICENSE
  %doc README.md
  ```

  New:
  ```spec
  %files
  %license LICENSE
  %doc README.md
  %dir /etc/copyfail
  ```

- [ ] **3.4** Rewrite `%files modprobe` block (currently lines 423-426):

  Old:
  ```spec
  %files modprobe
  %license LICENSE
  %doc README.md
  %config(noreplace) /etc/modprobe.d/99-copyfail-defense.conf
  ```

  New:
  ```spec
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
  # Detection helper (shared with -systemd %posttrans + copyfail-redetect).
  %dir /usr/libexec/copyfail-defense
  /usr/libexec/copyfail-defense/detect.sh
  # State directory (created here so -modprobe alone gets it; -systemd
  # also lists %dir /var/lib/copyfail-defense for the same reason -
  # rpm reconciles duplicate %dir cleanly).
  %dir /var/lib/copyfail-defense
  ```

- [ ] **3.5** Rewrite `%files systemd` block (currently lines 428-445):

  Old (drop the suppressible `RestrictNamespaces` line; add the new conditional dir):
  ```spec
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
  %dir %{_docdir}/%{name}/examples
  %{_docdir}/%{name}/examples/containers-dropin.conf
  ```

  New (rev 2: adds 12-rxrpc-af template; copyfail-redetect line owned by Phase 4 in the meta package per Phase 3 self-correction below):
  ```spec
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
  # State directory (also listed in -modprobe; %dir is idempotent).
  %dir /var/lib/copyfail-defense
  # Existing example doc unchanged.
  %dir %{_docdir}/%{name}/examples
  %{_docdir}/%{name}/examples/containers-dropin.conf
  ```

- [ ] **3.6** Modify `%install` block (currently lines 232-269) to install the new files. Insert after the existing `%SOURCE5` block (line 269):

  Old (lines 249-269):
  ```spec
  # --- modprobe subpackage layout ---
  install -d -m 0755 %{buildroot}/etc/modprobe.d
  install -m 0644 %{SOURCE3} \
      %{buildroot}/etc/modprobe.d/99-copyfail-defense.conf

  # --- systemd subpackage layout ---
  ...
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
  ```

  New (rev 2: adds Source11 for the 12-rxrpc-af.conf template; Source10/copyfail-redetect deferred to Phase 4):
  ```spec
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

  # --- detection helper + meta layout ---
  install -d -m 0755 %{buildroot}/usr/libexec/copyfail-defense
  install -m 0755 %{SOURCE9} \
      %{buildroot}/usr/libexec/copyfail-defense/detect.sh

  # State directory (auto-detect.json gets written here at first %posttrans).
  install -d -m 0755 %{buildroot}/var/lib/copyfail-defense

  # Sentinel directory (operator drops force-full file here pre-install).
  install -d -m 0755 %{buildroot}/etc/copyfail
  ```

- [ ] **3.7** Add `%pretrans` blocks for `-modprobe` and `-systemd` to handle v2.0.0 → v2.0.1 upgrade cleanup (D-37). Rev 2 fixup (reviewer C-4 / D-37): rename to `<path>.rpmsave-v2.0.1` instead of deleting — preserves operator hand-edits to v2.0.0 monolithic files. Insert before the existing `%post modprobe` block (line 353):

  ```spec
  # %pretrans modprobe - v2.0.0 → v2.0.1 upgrade cleanup (D-37).
  # Rename the v2.0.0 monolithic %config file to .rpmsave-v2.0.1 so:
  #   1. RPM's default .rpmsave-then-skip-new behavior is bypassed
  #      (new split files land cleanly on unpack).
  #   2. Operator hand-edits to the v2.0.0 file are preserved on disk
  #      for inspection/recovery (C-4: same-day v2.0.0 → v2.0.1 ship
  #      means hand-edits are plausible).
  # Conditional on the v2.0.0 RPM having been installed.
  %pretrans modprobe
  old=/etc/modprobe.d/99-copyfail-defense.conf
  if [ -f "$old" ] && \
     rpm -q copyfail-defense-modprobe --qf '%{version}' 2>/dev/null \
         | grep -q '^2\.0\.0$'; then
      mv -f "$old" "${old}.rpmsave-v2.0.1"
      logger -t copyfail-defense -p authpriv.info \
          "pretrans: renamed v2.0.0 monolithic modprobe drop file to ${old}.rpmsave-v2.0.1" \
          2>/dev/null || true
  fi
  exit 0

  # %pretrans systemd - same logic, five files.
  %pretrans systemd
  if rpm -q copyfail-defense-systemd --qf '%{version}' 2>/dev/null \
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
  ```

- [ ] **3.8** Rewrite `%post modprobe` to do **only** cf1 rmmod (not cf2/rxrpc) since detection hasn't run yet. Modify lines 353-370. Old block does rmmod for ALL nine modules; new block restricts to cf1 only (algif_aead, authenc, authencesn, af_alg). The cf2/rxrpc rmmod gets deferred to `%posttrans` after detection.

  Old (lines 360-370):
  ```spec
  {
      for m in algif_aead authenc authencesn af_alg \
               esp4 esp6 xfrm_user xfrm_algo rxrpc; do
          if /sbin/rmmod "$m" 2>/dev/null; then
  ```

  New:
  ```spec
  # %post fires before %posttrans - we don't yet know whether to apply
  # cf2-xfrm or rxrpc (detect.sh runs in %posttrans). So %post only
  # rmmods cf1 modules unconditionally; %posttrans handles cf2/rxrpc
  # rmmod conditionally based on whether the drop-in landed.
  {
      for m in algif_aead authenc authencesn af_alg; do
          if /sbin/rmmod "$m" 2>/dev/null; then
  ```

- [ ] **3.9** Replace existing `%posttrans modprobe` (lines 380-389) with a block that invokes detect.sh and conditionally rmmods cf2/rxrpc:

  Old:
  ```spec
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
  ```

  New (rev 2: scope=modprobe per D-56; tee stderr to dnf scriptlet output per D-55):
  ```spec
  %posttrans modprobe
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
  ```

- [ ] **3.10** Replace existing `%preun modprobe` to clean up conditional files via `detect.sh teardown modprobe` (rev 2 D-56). The `auto-detect.json` removal is deferred to the meta package's `%postun` since other subpackages (-systemd) may still own it.

  Old:
  ```spec
  %preun modprobe
  if [ "$1" -eq 0 ]; then
      rm -f /etc/modprobe.d/99-copyfail-defense.conf
  fi
  exit 0
  ```

  New (rev 2):
  ```spec
  %postun modprobe
  # On full erase, remove conditional /etc/ files via detect.sh
  # teardown. RPM has already removed the always-on cf1 file by this
  # point. We use %postun (not %preun) so detect.sh's binary is still
  # available; it ships in -modprobe %files so it's removed during
  # this transaction's unpack-replacement-of-removal phase.
  # Actually: detect.sh ships in BOTH -modprobe and -systemd (same
  # path, idempotent %files entry). %postun runs AFTER RPM removes
  # files, so the script may be gone if -systemd is also being
  # removed. Run the teardown inline as fallback.
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
  ```

  Note: detect.sh is shipped only in `-modprobe %files` per the
  Phase 3 step 3.4 layout. The `-systemd` subpackage's `%postun` calls
  detect.sh too — the inline-fallback `rm -f` lines protect against
  the race where -modprobe is removed first, then -systemd %postun
  runs without detect.sh. The fallback only handles the modprobe
  scope; -systemd %postun uses its own fallback for systemd files.

  Also add a `%postun` to the meta package to clean up
  `auto-detect.json` when no subpackage owns it. Find the meta
  package's existing `%postun` (or insert a new one near line 388):

  ```spec
  %postun
  # Meta package %postun: remove auto-detect.json when both -modprobe
  # and -systemd are gone. rpm -q returncodes (D-45 / M-9) determine
  # subpackage presence, not file existence.
  if [ "$1" -eq 0 ]; then
      if ! rpm -q copyfail-defense-modprobe >/dev/null 2>&1 && \
         ! rpm -q copyfail-defense-systemd >/dev/null 2>&1; then
          rm -f /var/lib/copyfail-defense/auto-detect.json
      fi
  fi
  exit 0
  ```

- [ ] **3.11** Replace existing `%post systemd` (lines 392-397) to invoke detect.sh + handle the 15-* drop-ins:

  Old:
  ```spec
  %post systemd
  if [ -d /run/systemd/system ]; then
      systemctl daemon-reload || true
      systemctl try-reload-or-restart sshd.service 2>/dev/null || true
  fi
  exit 0
  ```

  New:
  ```spec
  %post systemd
  # Defer daemon-reload to %posttrans so we reload after detect.sh has
  # applied/suppressed the 15-*.conf userns drop-ins. %post runs before
  # %posttrans; reloading here would reload-without the conditional
  # drop-ins on first install, then again with them in %posttrans -
  # cosmetically wasteful and racy.
  exit 0
  ```

- [ ] **3.12** Add `%posttrans systemd` block (currently doesn't exist for systemd). Rev 2 (D-56): scope=systemd. The -modprobe %posttrans uses scope=modprobe; the two scriptlets do not duplicate each other's territory.

  ```spec
  %posttrans systemd
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
  ```

- [ ] **3.13** Replace existing `%postun systemd` (lines 399-409) so it runs cleanup of conditional `15-*.conf` files on full erase:

  Old:
  ```spec
  %postun systemd
  if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
      systemctl daemon-reload || true
      systemctl try-reload-or-restart sshd.service 2>/dev/null || true
  fi
  exit 0
  ```

  New (rev 2: detect.sh teardown systemd, with inline fallback for the case where detect.sh has already been removed by -modprobe %postun):
  ```spec
  %postun systemd
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
  ```

  `auto-detect.json` cleanup is owned by the meta package's `%postun`
  (added in step 3.10) — not here, since `-modprobe` may still be
  installed and rely on it.

- [ ] **3.14** Update the `%changelog` to add a v2.0.1 entry at the top:

  ```spec
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
  ```

### Acceptance

- [ ] `rpm --specfile packaging/copyfail-defense.spec --qf '%{name}-%{epoch}:%{version}\n' | sort -u` shows `copyfail-defense-1:2.0.1`, `copyfail-defense-shim-1:2.0.1`, `copyfail-defense-modprobe-1:2.0.1`, `copyfail-defense-systemd-1:2.0.1`, `copyfail-defense-auditor-1:2.0.1`.
- [ ] `rpm --specfile packaging/copyfail-defense.spec -P | grep -E 'pretrans|posttrans' | wc -l` returns at least 4 (modprobe + systemd %pretrans + %posttrans).
- [ ] `rpmlint packaging/copyfail-defense.spec 2>&1 | grep -vE '^(.+: I: |0 packages)' | head -5` — should show no `E:` errors.
- [ ] Spec parses cleanly: `rpmspec -P packaging/copyfail-defense.spec >/dev/null` returns 0.
- [ ] `grep -c 'apply modprobe' packaging/copyfail-defense.spec` returns 1 (the -modprobe %posttrans invocation, scope arg per D-56).
- [ ] `grep -c 'apply systemd' packaging/copyfail-defense.spec` returns 1 (the -systemd %posttrans).
- [ ] `grep -c 'rpmsave-v2.0.1' packaging/copyfail-defense.spec` returns at least 2 (modprobe + systemd %pretrans rename targets per D-37).
- [ ] `grep -c 'Requires:.*python3' packaging/copyfail-defense.spec` returns at least 2 (added to -modprobe and -systemd per D-52).
- [ ] Phase 3 ships the spec referencing Source0..9 + Source11 (the new rxrpc-af template). Source10 (copyfail-redetect) lands in Phase 4. Verify: `rpmspec -P packaging/copyfail-defense.spec | grep -E 'Source10:|Source11:'` shows Source11 present, Source10 absent until Phase 4.

### Test strategy

`rpmlint` + `rpmspec -P`. Real install verification waits for Phase 6
(test-repo.sh) and Phase 8 (mock build).

### Edge cases

- The first time an upgrade-from-v2.0.0 host runs `%pretrans`, RPM has
  not yet swapped out v2.0.0's package metadata, so `rpm -q --qf
  '%{version}'` returns the v2.0.0 version string. After unpack,
  `rpm -q` returns 2.0.1. Verified mentally.
- An operator running `dnf install copyfail-defense-modprobe`
  fresh (no v2.0.0 ever installed) hits `%pretrans modprobe` with
  `rpm -q copyfail-defense-modprobe` returning non-zero / empty. The
  `grep -q '^2\.0\.0$'` is false, no removal happens. Correct.
- Container build (`mock`): `/run/systemd/system` doesn't exist,
  `%post systemd` exits early; `%posttrans systemd` calls detect.sh
  (returns clean) and then guards the systemctl calls with the same
  `if [ -d /run/systemd/system ]`. Mock-safe per existing v2.0.0
  pattern.

### Commit message (pre-written)

```
packaging: rewire spec scriptlets for v2.0.1 auto-detection

Bumps Version: 2.0.1. Adds Source3-Source9 for the split-conf files
and detect.sh helper. Reshapes %install to lay templates under
/usr/share/copyfail-defense/conditional/ + always-on files in /etc/
+ detect.sh under /usr/libexec/copyfail-defense/.

Adds %pretrans for -modprobe and -systemd that removes v2.0.0
monolithic %config files when the v2.0.0 RPM was their source -
avoids RPM's default .rpmsave-then-skip-new behavior on upgrade.

Rewrites %posttrans -modprobe to invoke detect.sh apply (writes
auto-detect.json, copies/removes conditional /etc/ files, logs to
LOG_AUTHPRIV) and rmmods cf2/rxrpc only when their drop files
landed. Adds %posttrans -systemd doing the same detect.sh call
(idempotent across both subpackages) plus daemon-reload after the
15-*.conf userns drop-ins are placed.

%postun -systemd cleans up the conditional 15-*.conf files on full
erase; %preun -modprobe likewise removes the conditional drop files
and auto-detect.json.

copyfail-redetect helper script lands in the next commit.
```

---

## Phase 4 — `copyfail-redetect` helper + force-full sentinel

**Goal.** Ship the operator-facing on-demand redetect helper. Per
SPEC §12.7, §12.8.

**Mode.** serial-context (Phase 5+ depend on the helper existing for
test wiring).
**Risk.** low (thin wrapper around detect.sh).
**Type.** feature.

### Files

- **new:** `packaging/copyfail-redetect`
- **modify:** `packaging/copyfail-defense.spec` (add Source10, install + %files lines)

### Steps

- [ ] **4.1** Create `packaging/copyfail-redetect`:

  ```bash
  #!/bin/bash
  #
  # copyfail-redetect
  #   Re-run copyfail-defense workload detection on demand.
  #   Use after enabling IPsec / AFS / rootless containers post-install
  #   to refresh the conditional drop-in state.
  #
  # The helper does NOT call systemctl daemon-reload; the operator
  # decides reload timing (a daemon-reload is required before systemd
  # drop-in changes take effect on running services).
  set -euo pipefail

  if [ "$(id -u)" -ne 0 ]; then
      echo "copyfail-redetect: must be run as root" >&2
      exit 1
  fi

  if [ ! -x /usr/libexec/copyfail-defense/detect.sh ]; then
      echo "copyfail-redetect: /usr/libexec/copyfail-defense/detect.sh missing" >&2
      echo "  (re-install copyfail-defense-modprobe or -systemd to restore)" >&2
      exit 1
  fi

  # Pass scope=both per D-56: operator-driven re-detect updates both
  # modprobe and systemd state regardless of which subpackage's
  # %posttrans last fired.
  /usr/libexec/copyfail-defense/detect.sh apply both
  echo
  echo "Detection refreshed. State: /var/lib/copyfail-defense/auto-detect.json"
  echo
  echo "If conditional systemd drop-ins changed, run:"
  echo "    systemctl daemon-reload"
  echo "    systemctl try-reload-or-restart sshd.service"
  echo "to apply the change to running services."
  ```

- [ ] **4.2** Modify `packaging/copyfail-defense.spec` to declare Source10:

  Find the `Source9: copyfail-defense-detect.sh` line (added in Phase 3 step 3.1) and add:

  ```spec
  Source10:       copyfail-redetect
  ```

- [ ] **4.3** Modify the `%install` block to install the helper. Find the `install -m 0755 %{SOURCE9}` line (added in Phase 3 step 3.6) and add after the matching block:

  ```spec
  install -d -m 0755 %{buildroot}%{_sbindir}
  install -m 0755 %{SOURCE10} \
      %{buildroot}%{_sbindir}/copyfail-redetect
  ```

  (The `%{_sbindir}` directory was already installed by the shim subpackage's earlier `install -d` — but a duplicate `install -d` is idempotent.)

- [ ] **4.4** Modify the meta `%files` block (currently lines 412-415, including the `%dir /etc/copyfail` added in Phase 3 step 3.3). Add `copyfail-redetect` under the meta package since both `-modprobe` and `-systemd` operators benefit from on-demand redetect:

  ```spec
  %files
  %license LICENSE
  %doc README.md
  %dir /etc/copyfail
  %{_sbindir}/copyfail-redetect
  ```

  Note: Phase 3 step 3.5 (rewritten in rev 2) no longer lists
  `%{_sbindir}/copyfail-redetect` under `%files systemd` — that line
  was removed from the Phase 3 plan and added here under the meta
  package. Phase 3's diff stays scoped to spec scriptlets + split
  files; Phase 4's diff is scoped to the redetect helper.

### Acceptance

- [ ] `bash -n packaging/copyfail-redetect` returns 0.
- [ ] `shellcheck packaging/copyfail-redetect` returns 0.
- [ ] `rpm --specfile packaging/copyfail-defense.spec -P 2>/dev/null | grep -F 'Source10:'` returns the `copyfail-redetect` line.
- [ ] `rpm --specfile packaging/copyfail-defense.spec --qf '[%{filenames}\n]' 2>/dev/null | grep -E '/usr/sbin/copyfail-redetect$'` returns exactly one match (under the meta package).

### Test strategy

Lint-only. End-to-end test in Phase 6.

### Commit message (pre-written)

```
packaging: ship copyfail-redetect helper for v2.0.1

Operator-facing helper at /usr/sbin/copyfail-redetect that re-runs
detection on demand (e.g., after enabling IPsec post-install). Owned
by the meta package since both -modprobe and -systemd produce
conditional state that may need refresh.

Helper does NOT call daemon-reload; operator decides reload timing.
```

---

## Phase 5 — Auditor extension (`auto_detect` posture surface)

**Goal.** Read `/var/lib/copyfail-defense/auto-detect.json`, expose
under `posture.auto_detect`, add `check_auto_detect_state()` MITIGATION
check, append a one-line summary to the human report. Per SPEC §12.9.

**Mode.** serial-context (Phase 6 test asserts auditor JSON shape).
**Risk.** medium (auditor is the operator-trusted view of state).
**Type.** feature.

### Files

- **modify:** `copyfail-local-check.py`

### Steps

- [ ] **5.1** Add a constant near the existing `CF_CLASS_MODULES` block (around line 146, file `copyfail-local-check.py`). Rev 2 schema bump from `"1"` to `"2"` per the `auto-detect.json` rev 2 layout (12-rxrpc-af keys added):

  ```python
  AUTO_DETECT_PATH = "/var/lib/copyfail-defense/auto-detect.json"
  AUTO_DETECT_SCHEMA_VERSION = "2"
  ```

- [ ] **5.2** Add `check_auto_detect_state()` function. Insert after `check_modprobe_blacklist_extended()` (around line 1402, before `_unit_namespaces_blocked`):

  ```python
  def _rpm_q_installed(pkg):
      """Returncode-based check: rpm -q <pkg> exits 0 iff installed.
      Per D-45 / reviewer M-9: file-existence checks misclassify hosts
      where a subpackage is installed but its drop-in file got
      hand-removed or its scriptlet failed silently. rpm -q is the
      authoritative source."""
      try:
          rc = subprocess.run(["rpm", "-q", pkg],
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL).returncode
          return rc == 0
      except (OSError, subprocess.SubprocessError):
          return False

  def check_auto_detect_state():
      """v2.0.1: report auto-detection result from
      /var/lib/copyfail-defense/auto-detect.json (written by detect.sh).

      OK if no workloads detected (or force_full set).
      INFO if workloads detected and conditional mitigations suppressed
           (the package working as designed).
      WARN if the JSON is missing on a host where the modprobe or
           systemd subpackage is installed (scriptlet failed silently),
           OR if the schema_version is unrecognized (D-53 / M-3).
      SKIP if neither subpackage is installed (auditor-only install).

      Rev 2 fixup: SKIP test uses rpm -q (D-45 / M-9) not file-existence;
      schema rejection emits posture.auto_detect.schema_unrecognized=true
      (D-53 / M-3)."""
      have_modprobe = _rpm_q_installed("copyfail-defense-modprobe")
      have_systemd = _rpm_q_installed("copyfail-defense-systemd")

      if not (have_modprobe or have_systemd):
          return Check("auto_detect_state", "MITIGATION", Status.SKIP,
                       "auditor-only install (no -modprobe or -systemd)")

      try:
          with open(AUTO_DETECT_PATH, "r") as f:
              data = json.load(f)
      except FileNotFoundError:
          return Check("auto_detect_state", "MITIGATION", Status.WARN,
                       "auto-detect.json missing; %posttrans likely failed",
                       remediation="Run: /usr/sbin/copyfail-redetect")
      except (json.JSONDecodeError, OSError) as e:
          return Check("auto_detect_state", "MITIGATION", Status.WARN,
                       "auto-detect.json unreadable: {}".format(e),
                       remediation="Run: /usr/sbin/copyfail-redetect")

      schema = data.get("schema_version")
      if schema != AUTO_DETECT_SCHEMA_VERSION:
          # D-53 / M-3: structured field for SIEM filtering.
          return Check("auto_detect_state", "MITIGATION", Status.WARN,
                       "auto-detect.json schema {} unrecognized "
                       "(expected {})".format(schema, AUTO_DETECT_SCHEMA_VERSION),
                       details={
                           "schema": schema,
                           "schema_unrecognized": True,
                       })

      detected = data.get("detected", {})
      detected_workloads = sorted([
          k for k, v in detected.items() if v.get("present") is True
      ])
      suppressed = data.get("suppressed", {})
      suppressed_mits = sorted([
          k for k, v in suppressed.items() if v is True
      ])
      force_full = bool(data.get("force_full"))

      details = {
          "detected_workloads": detected_workloads,
          "suppressed_mitigations": suppressed_mits,
          "force_full": force_full,
          "schema_unrecognized": False,
      }

      if force_full:
          return Check("auto_detect_state", "MITIGATION", Status.OK,
                       "force-full sentinel active; all mitigations applied",
                       details=details)
      if not detected_workloads:
          return Check("auto_detect_state", "MITIGATION", Status.OK,
                       "auto-detect: no conflicting workloads",
                       details=details)
      return Check("auto_detect_state", "MITIGATION", Status.INFO,
                   "auto-detect: {} ({} mitigation(s) suppressed)".format(
                       ", ".join(detected_workloads), len(suppressed_mits)),
                   details=details)
  ```

  Pre-flight: ensure `subprocess` is imported at the top of
  `copyfail-local-check.py`. It's already imported in v2.0.0
  (`grep -n '^import subprocess' copyfail-local-check.py` should
  return non-empty). If not, add `import subprocess` near the
  existing imports.

- [ ] **5.3** Wire the new check into `run_all_checks()`. Find the existing `add_one(check_modprobe_blacklist_extended(), "MITIGATION")` line (around line 1926) and add immediately after:

  ```python
      # v2.0.1: auto-detect.json state
      PROGRESS.step("reading auto-detect.json state")
      add_one(check_auto_detect_state(), "MITIGATION")
  ```

- [ ] **5.4** Extend `determine_posture()` to expose `auto_detect` summary. Find the existing return statement (around line 2045-2050):

  Old:
  ```python
      return {
          "verdict": verdict,
          "layers": layers,
          "bug_classes": bug_classes,
          "bug_classes_covered": covered,
      }
  ```

  New:
  ```python
      auto_detect_summary = _summarize_auto_detect(by_name)
      return {
          "verdict": verdict,
          "layers": layers,
          "bug_classes": bug_classes,
          "bug_classes_covered": covered,
          "auto_detect": auto_detect_summary,
      }
  ```

- [ ] **5.5** Add `_summarize_auto_detect()` helper. Insert before `_aggregate_bug_classes()` (around line 2052):

  ```python
  def _summarize_auto_detect(by_name):
      """v2.0.1: summarize auto_detect_state check for posture surface.

      Returns the summarized fields the SIEM/dashboard wants without
      embedding the full raw JSON file - that's what the .details on
      the underlying check carries.

      Rev 2 fixup (D-53 / M-3): exposes schema_unrecognized field for
      SIEM to filter on schema-rejection events without parsing the
      raw JSON file."""
      r = by_name.get("auto_detect_state")
      if r is None:
          return {"available": False}
      details = r.details or {}
      return {
          "available": True,
          "force_full": details.get("force_full", False),
          "detected_workloads": details.get("detected_workloads", []),
          "suppressed_mitigations": details.get("suppressed_mitigations", []),
          "schema_unrecognized": details.get("schema_unrecognized", False),
      }
  ```

- [ ] **5.6** Add a one-line auto-detect render after the surface-area matrix. Find the `Surface area / mitigation matrix:` printing block (around line 2358-2370 in the human-output branch of `main()`). After the matrix loop ends, add:

  ```python
          # v2.0.1: auto-detect summary line.
          ad = posture_summary.get("auto_detect", {})
          if ad.get("available"):
              if ad.get("force_full"):
                  ad_line = "force-full sentinel active (all mitigations applied)"
              elif ad.get("detected_workloads"):
                  workloads = ", ".join(ad["detected_workloads"])
                  suppressed = ad.get("suppressed_mitigations", [])
                  if suppressed:
                      ad_line = "{} (suppressed: {})".format(
                          workloads, ", ".join(suppressed))
                  else:
                      ad_line = workloads
              else:
                  ad_line = "clean (no conflicts)"
              print()
              print(colorize("Auto-detect:", C.BOLD), ad_line)
  ```

  The exact insertion point: after the `for cls_id, label in (...)` loop in
  the surface-area-matrix printing block but before the existing
  bug-classes-covered summary line. Verify by reading
  `copyfail-local-check.py:2360-2390` during implementation.

### Acceptance

- [ ] `python3 -c 'import py_compile; py_compile.compile("copyfail-local-check.py", doraise=True)'` returns 0.
- [ ] `./copyfail-local-check.py --json --skip-trigger --skip-hardening --no-progress 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); assert 'auto_detect' in d['posture']; print(d['posture']['auto_detect'])"` runs without error and prints the summary dict.
- [ ] `grep -c 'AUTO_DETECT_SCHEMA_VERSION = "2"' copyfail-local-check.py` returns 1 (rev 2 schema bump).
- [ ] On a host without `auto-detect.json`: the summary's `available` field is `False`.
- [ ] On a host without `-modprobe` or `-systemd` installed (use a chroot or a system that genuinely lacks them): `check_auto_detect_state()` returns SKIP. Verify the SKIP path uses `rpm -q` (M-9): mock by writing the `cf1` drop file to `/etc/modprobe.d/` *without* installing the RPM and confirm SKIP, not WARN/OK.
- [ ] After writing a synthetic `auto-detect.json` with `schema_version="99"`, the check returns WARN and `posture.auto_detect.schema_unrecognized` is `True` (rev 2 / M-3).
- [ ] After writing a synthetic `auto-detect.json` with `schema_version="2"` and `detected.ipsec.present=true`, the check returns INFO and the summary's `detected_workloads` lists `["ipsec"]`, `schema_unrecognized` is `False`.

### Test strategy

`py_compile` syntax check. Manual smoke test by writing a synthetic
JSON file and running the auditor. Real install verification in
Phase 6.

### Commit message (pre-written)

```
auditor: read auto-detect.json and surface state under posture (v2.0.1)

Adds check_auto_detect_state() under MITIGATION: OK if no workloads
detected (or force-full set), INFO if workloads detected and
conditional mitigations suppressed (package working as designed),
WARN if the JSON is missing on a host with -modprobe/-systemd
installed (scriptlet failed silently), SKIP on auditor-only
installs.

posture.auto_detect summary in JSON output gives SIEM consumers a
flat view of detected_workloads, suppressed_mitigations, and
force_full without re-reading the raw JSON file. Human report
gains a one-line "Auto-detect:" annotation after the surface-area
matrix.
```

---

## Phase 6 — `test-repo.sh` extension

**Goal.** Add 7 new test scenarios per SPEC §12.11 (5 detection
scenarios + redetect + v2.0.0→v2.0.1 split-file upgrade). Existing
v2.0.0 tests preserved.

**Mode.** serial-context (Phase 7 docs reference test scenarios).
**Risk.** medium (test harness is the canary per anti-patterns.md).
**Type.** test.

### Files

- **modify:** `packaging/test-repo.sh`

### Steps

- [ ] **6.1** Add new test functions to `test-repo.sh`. Each scenario gets its own `run_<name>_test_in()` shell function modeled on the existing `run_test_in()` (line 71) and `run_upgrade_test_in()` (line 236) patterns.

  Insert after `run_upgrade_test_in()` (around line 300) and before the live URL probe (line 303):

  ```bash
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

  # Pre-stage the IPsec signal BEFORE installing the package.
  mkdir -p /etc
  cat >/etc/ipsec.conf <<'EOC'
  # libreswan-style stub
  conn home
      left=192.0.2.1
      right=192.0.2.2
      auto=add
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
  ok "ipsec host: cf2-xfrm correctly suppressed, JSON correct"
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
  ```

- [ ] **6.2** Wire the new test functions into the per-EL loop. Find the existing `run_test_in` + `run_upgrade_test_in` invocation block (around line 343-362) and extend. Rev 2 adds the cPanel-FP regression test:

  ```bash
      # v2.0.1: detection scenario tests (rev 2: + subuid_no_storage)
      for scenario_name in clean_host ipsec_host afs_host rootless_host \
                           subuid_no_storage \
                           force_full redetect split_upgrade; do
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
  ```

- [ ] **6.3** Update the script header comment block (lines 8-32) to reflect the new check count: 26 per EL (was 18 in v2.0.0; rev 2 added 8 scenarios = 7 detection + 1 cPanel-FP regression).

- [ ] **6.4** Update the v2.0.0 main `run_test_in()` (lines 71-230) to assert the new file paths. The existing line 104 checks for `/etc/modprobe.d/99-copyfail-defense.conf` (the monolithic v2.0.0 path) — this must be replaced with checks for the three split files (cf1 / cf2-xfrm / rxrpc all present on clean container).

  Old (line 104):
  ```bash
  test -f /etc/modprobe.d/99-copyfail-defense.conf \
      || fail "modprobe drop file missing"
  ```

  New:
  ```bash
  for f in cf1 cf2-xfrm rxrpc; do
      test -f "/etc/modprobe.d/99-copyfail-defense-${f}.conf" \
          || fail "modprobe ${f} drop file missing"
  done
  ```

  Likewise update the regex in the existing test (lines 122-126) — the
  count should still be 9 module install lines but distributed across
  three files:

  Old:
  ```bash
  mp_count=$(grep -cE '^install +(algif_aead|authenc|authencesn|af_alg|esp4|esp6|xfrm_user|xfrm_algo|rxrpc) +/bin/false' \
      /etc/modprobe.d/99-copyfail-defense.conf 2>/dev/null || echo 0)
  ```

  New:
  ```bash
  mp_count=$(grep -chE '^install +(algif_aead|authenc|authencesn|af_alg|esp4|esp6|xfrm_user|xfrm_algo|rxrpc) +/bin/false' \
      /etc/modprobe.d/99-copyfail-defense-{cf1,cf2-xfrm,rxrpc}.conf 2>/dev/null || echo 0)
  ```

  (The `-h` flag is critical with multi-file grep so the count adds up
  cleanly; `grep -c` per-file would print `<file>:N` instead of just `N`.)

  Also update the dnf-remove cleanup assertion (line 221):

  Old:
  ```bash
  [ ! -f /etc/modprobe.d/99-copyfail-defense.conf ] \
      || fail "modprobe drop file remained after dnf remove"
  ```

  New:
  ```bash
  for f in cf1 cf2-xfrm rxrpc; do
      [ ! -f "/etc/modprobe.d/99-copyfail-defense-${f}.conf" ] \
          || fail "modprobe ${f} drop file remained after dnf remove"
  done
  ```

### Acceptance

- [ ] `bash -n packaging/test-repo.sh` returns 0.
- [ ] `shellcheck packaging/test-repo.sh` returns 0 (existing inline `# shellcheck disable=` directives may need updating; preserve them where they apply).
- [ ] `grep -c "^  run_.*_test_in()" packaging/test-repo.sh` returns at least 10 (existing 2 + new 8 in rev 2).
- [ ] The per-EL `RESULT` summary line in the harness output should include `+clean_host` `+ipsec_host` `+afs_host` `+rootless_host` `+subuid_no_storage` `+force_full` `+redetect` `+split_upgrade` annotations after a real run.

### Test strategy

Lint-only at this phase (bash -n, shellcheck). Live test happens in
Phase 8 against built+signed RPMs in mock+staging.

### Edge cases

- The `run_split_upgrade_test_in` requires v2.0.0 RPMs to remain in the
  gh-pages repo. Per D-22 they're retained for one cycle (through
  v2.0.1 ship), and v2.0.0 was just published 2026-05-08 — the cycle
  has not yet expired. If by the time this lands in build the cycle
  HAS expired, the test exits 77 (SKIP) with a clean message, matching
  the existing v1.0.1 upgrade test pattern.
- Containers may not have `useradd` or `shadow-utils` baseline-installed.
  The rootless test wraps `useradd` with `2>/dev/null || true` and
  hand-writes `/etc/subuid` directly as a fallback path.
- `dnf install -y 'copyfail-defense-2.0.0*'` may pull v2.0.0 of all 5
  subpackages; verify the `tail -5` output captures both `installed`
  and `replaced` lines so the test isn't blind to dnf reporting.

### Commit message (pre-written)

```
test-repo.sh: add v2.0.1 detection scenario tests (25 per-EL checks)

Adds 7 new test functions exercising the v2.0.1 auto-detection path:
clean host (all 3 modprobe + 10 systemd files), IPsec host (cf2-xfrm
suppressed), AFS host (rxrpc suppressed), rootless host (user@ 15-
suppressed, others applied), force-full sentinel (all applied
despite signals), redetect helper (post-install signal triggers
correct refresh), v2.0.0->v2.0.1 split-file upgrade (pretrans
correctly removes monolithic file).

Existing v2.0.0 main matrix updated to assert split-file paths
instead of the monolithic /etc/modprobe.d/99-copyfail-defense.conf.
```

---

## Phase 7 — Documentation surface

**Goal.** Per SPEC §12.12. Replace README's "Override paths" section
with auto-detection narrative; bump STATE.md to v2.0.1; trim
FOLLOWUPS.md.

**Mode.** parallel-agent-safe (each file is independently scoped; no
cross-file state).
**Risk.** low (docs only).
**Type.** docs.

### Files

- **modify:** `README.md`
- **modify:** `STATE.md`
- **modify:** `FOLLOWUPS.md`

### Steps

- [ ] **7.1** `README.md` — replace the "Override paths" section (lines 261-315) with a new "Auto-detection of conflicting workloads" section. Keep the `## Verifying signatures` section (line 318+) unchanged.

  New section content:

  ```markdown
  ## Auto-detection of conflicting workloads

  v2.0.1+ inspects the host at install time for workloads the default
  cuts would break, and **suppresses the conflicting drop-in only**
  while keeping every other layer active.

  Three workload classes are detected:

  | Workload | Detection signals (any) | Suppresses |
  |---|---|---|
  | **IPsec** (strongSwan, libreswan, openswan) | `systemctl is-enabled` returns enabled for strongswan/strongswan-starter/strongswan-swanctl/ipsec/libreswan/openswan/pluto; OR `/etc/ipsec.conf` has a `conn` stanza; OR non-empty `/etc/swanctl/conf.d/`, `/etc/ipsec.d/`, `/etc/strongswan/conf.d/`, `/etc/strongswan.d/` | `99-copyfail-defense-cf2-xfrm.conf` (esp4, esp6, xfrm_user, xfrm_algo blacklist) |
  | **AFS** (openafs, kafs) | `systemctl is-enabled` for openafs-client/openafs-server/kafs/afsd; OR `/etc/openafs/CellServDB` or `/etc/openafs/ThisCell` exists; OR `/etc/krb5.conf.d/openafs*` exists; OR `/proc/fs/afs/` registered | `99-copyfail-defense-rxrpc.conf` (rxrpc modprobe blacklist) AND `12-copyfail-defense-rxrpc-af.conf` (RestrictAddressFamilies=~AF_RXRPC on all 5 tenant units) — preserves AFS userspace tooling like aklog |
  | **Rootless containers** (rootless podman/buildah) | `/home/*/.local/share/containers/storage/overlay-containers/` present (rootless podman storage tree, recent mtime); OR `/var/lib/containers/storage/` non-empty with mtime <90d; OR `/run/user/<UID>/containers/` for any UID >= 1000; OR `podman.socket` enabled (system or per-user) | `15-copyfail-defense-userns.conf` on `user@.service.d` ONLY (other tenant units stay protected) |

  Note: `/etc/subuid` populated by `useradd` is NOT a rootless
  detection signal in v2.0.1 rev 2 — shadow-utils auto-populates
  subuid for every regular user regardless of container intent,
  which produced near-100% false positives on cPanel-shaped fleets.
  The detection now requires *active rootless usage* (storage tree,
  runtime tmpfs, or enabled podman.socket).

  Detection runs in `%posttrans` after every install/upgrade and writes
  a structured report to `/var/lib/copyfail-defense/auto-detect.json`
  (schema versioned). The auditor consumes this and surfaces the
  decision under `posture.auto_detect`.

  ### Re-detect after the host changes

  If you enable IPsec / AFS / rootless containers post-install:

  ```sh
  sudo /usr/sbin/copyfail-redetect
  sudo systemctl daemon-reload
  sudo systemctl try-reload-or-restart sshd.service
  ```

  The helper re-runs detection, refreshes `auto-detect.json`, and
  copies/removes the conditional drop-in files in `/etc/`. It does
  NOT auto-reload systemd — the operator decides when running
  services pick up the change.

  ### Force full install (skip detection)

  Drop a sentinel file before `dnf install` (or before
  `copyfail-redetect`) to skip detection entirely:

  ```sh
  sudo mkdir -p /etc/copyfail
  sudo touch /etc/copyfail/force-full
  sudo dnf install -y copyfail-defense
  ```

  The auditor reports `force-full sentinel active` when this is on.
  Remove the sentinel and re-run `copyfail-redetect` to re-engage
  detection.

  ### Manual override (finer than detection)

  systemd drop-ins use the standard layered-override pattern.
  Within a `<unit>.service.d/` directory, files merge in
  lexicographic order, and **lower numbers lose to higher numbers
  for `=value` directives** (later files override earlier ones).
  copyfail-defense ships at `10-`, `12-`, `15-`; the standard
  operator escape hatches sit at `20-` and `25-`:

  **`20-override.conf` (empty-value to neutralize a directive):**
  drop a `20-override.conf` next to our files with empty values for
  any directive you want to relax. Survives package upgrade because
  `20-override.conf` is operator-owned (RPM doesn't manage it).

  ```sh
  sudo mkdir -p /etc/systemd/system/user@.service.d
  sudo tee /etc/systemd/system/user@.service.d/20-override.conf >/dev/null <<'EOF'
  [Service]
  RestrictNamespaces=
  RestrictAddressFamilies=
  EOF
  sudo systemctl daemon-reload
  ```

  Empty `=` clears the union for list-valued directives like
  `RestrictAddressFamilies` and `RestrictNamespaces`.

  **`25-additions.conf` (add a new directive on top of ours):**
  drop a `25-additions.conf` next to our files with directives you
  want to *add*. Sorts after `20-` so it can layer on top of an
  empty-override. Use this for fleet-wide hardening that goes
  beyond the cf-class scope.

  ```sh
  sudo tee /etc/systemd/system/sshd.service.d/25-additions.conf >/dev/null <<'EOF'
  [Service]
  NoNewPrivileges=true
  EOF
  sudo systemctl daemon-reload
  sudo systemctl try-reload-or-restart sshd.service
  ```

  **modprobe override**: the conditional `99-copyfail-defense-cf2-xfrm.conf`
  and `99-copyfail-defense-rxrpc.conf` files are managed by detect.sh
  (cmp-and-skip per [SPEC §12.10.2a / D-57]). If you hand-edit a
  conditional file, detect.sh detects the divergence on next
  `%posttrans` or `copyfail-redetect`, logs a WARN, and **preserves
  your edits** (does not overwrite). For the always-on
  `99-copyfail-defense-cf1.conf` file, edits survive package upgrade
  via `%config(noreplace)`.

  The earlier (incorrect) recommendation to `chattr +i` a managed
  file is **removed** — it broke dnf via EPERM on the next
  `install -m 0644` from `%posttrans`. Use the cmp-and-skip
  behavior or `force-full` instead.
  ```

  Also bump the v2.0.0 references in the README header / coverage
  matrix to v2.0.1 where they're version-stamped:

  - Line 27 (release badge): no change (auto-updates from gh).
  - Line 36-37 (upgrade note): rewrite to read "Upgrading from
    `afalg-defense` v1.0.x or `copyfail-defense` v2.0.0 is a single
    command: `dnf upgrade copyfail-defense`. The v2.0.0 → v2.0.1 path
    auto-suppresses any conflicting drop-ins detected on your host
    (see Auto-detection below)."
  - Line 64-67 (subpackage table): no change (file paths are still
    accurate at the table-level abstraction).
  - Line 282-283 ("99- prefix on the modprobe drop") sits inside the
    section being replaced; it's gone with the rewrite.
  - Line 393 (build example): bump `2.0.0` → `2.0.1` in the SRPM URL.
  - Line 348 (auditor JSON schema example): update the `bug_classes_covered`
    example block to also show the new `auto_detect` field next to
    `bug_classes`. Add:

    ```json
    "auto_detect": {
      "available": true,
      "force_full": false,
      "detected_workloads": ["rootless_containers"],
      "suppressed_mitigations": ["systemd_userns_user_at"]
    },
    ```

- [ ] **7.2** `STATE.md` — bump to v2.0.1.

  - Line 3 timestamp: keep at 2026-05-08 (same-day release).
  - Line 7-12 "Latest release": rewrite to:

    ```markdown
    - **v2.0.1** — Hotfix on top of v2.0.0: auto-detect IPsec / AFS /
      rootless-container workloads at install time and suppress only
      the conflicting drop-ins. Replaces the README's operator-driven
      "Override paths" section with package-driven detection.
    - **v2.0.0** (2026-05-08) — `copyfail-defense` umbrella covering
      cf1 (CVE-2026-31431), cf2 (xfrm-ESP), and Dirty Frag (xfrm-ESP +
      RxRPC). Renamed from `afalg-defense`. Signed RPMs, EL8 / EL9 /
      EL10, x86_64 only.
    - Tag: <https://github.com/rfxn/copyfail/releases/tag/v2.0.1>
    - v2.0.0 RPMs retained in repo trees for one cycle (clean
      `dnf upgrade copyfail-defense` from v2.0.0 → v2.0.1 path tested
      via test-repo.sh #25).
    - v1.0.1 RPMs retained in repo trees alongside v2.0.0 + v2.0.1
      (rolled-forward retention from v2.0.0 ship).
    ```

  - Line 44-50 "RPM family" table: update modprobe + systemd row paths:

    Old:
    ```markdown
    | `copyfail-defense-modprobe` | noarch | `/etc/modprobe.d/99-copyfail-defense.conf` |
    | `copyfail-defense-systemd` | noarch | `/etc/systemd/system/{user@,sshd,cron,crond,atd}.service.d/10-copyfail-defense.conf` + `examples/containers-dropin.conf` |
    ```

    New (rev 2):
    ```markdown
    | `copyfail-defense-modprobe` | noarch | `/etc/modprobe.d/99-copyfail-defense-{cf1,cf2-xfrm,rxrpc}.conf` (cf2-xfrm/rxrpc auto-suppressed on detection); `/usr/share/copyfail-defense/conditional/modprobe/` templates; `/usr/libexec/copyfail-defense/detect.sh` |
    | `copyfail-defense-systemd` | noarch | `/etc/systemd/system/{user@,sshd,cron,crond,atd}.service.d/10-copyfail-defense.conf` (always-on `~AF_ALG`); `12-copyfail-defense-rxrpc-af.conf` (auto-suppressed on AFS hosts); `15-copyfail-defense-userns.conf` (auto-suppressed on user@ when rootless detected); `examples/containers-dropin.conf` |
    ```

  - Add new "Auto-detection" section after "Coverage matrix" (after line 71):

    ```markdown
    ## Auto-detection (v2.0.1+)

    `%posttrans` runs `/usr/libexec/copyfail-defense/detect.sh apply <scope>` to
    inspect the host for IPsec / AFS / rootless-container workloads and
    write `/var/lib/copyfail-defense/auto-detect.json` (schema_version=2).
    Conflicting conditional drop-ins are not installed when their workload
    is detected; the always-on cuts (cf1 modprobe,
    `RestrictAddressFamilies=~AF_ALG`, `SystemCallFilter=~@swap`) apply
    unconditionally. Per-subpackage scope keeps `-modprobe`-only installs
    from creating orphan systemd files.

    Operator interaction:

    - `/usr/sbin/copyfail-redetect` — re-run detection on demand (scope=both)
    - `/etc/copyfail/force-full` — sentinel that skips detection (apply all)
    - `/var/lib/copyfail-defense/auto-detect.json` — schema-versioned
      report consumed by the auditor and SIEM dashboards
    ```

  - Update "Test harness" section (line 105-115): bump count from 18
    to 26 per EL (v2.0.0 baseline 18 + 7 detection scenarios + 1
    cPanel-FP regression test = 26).

  - **Defer the cross-repo commit-hash update to Phase 9** (rev 2
    fixup per reviewer L-8). The line 170 cross-repo state line
    references `f70c9eb` as the v2.0.0 commit; v2.0.1's commit hash
    is not known until Phase 9 commits the changes. Phase 7's
    STATE.md edit leaves the v2.0.0 reference intact and adds a
    placeholder note: `(v2.0.1 commit hash filled in at release
    time — see Phase 9)`. Phase 9's commit step (after the actual
    git commit produces a hash) does a follow-up edit to fill in
    the real hash. This avoids shipping a TBD-marker to gh-pages.

- [ ] **7.3** `FOLLOWUPS.md` — the v2.0.0-shipped file already has a
  "Subsumed by v2.0.1" section and a stub "v2.0.2 watch list". Rev 2
  fixup expands the watch list with all reviewer-deferred items
  per the in-scope/deferral directive, and adds a v2.1.0 forward-
  cleanup obligation per reviewer M-10.

  Find the existing "v2.0.2 watch list (post v2.0.1 ship)" section
  (already in the v2.0.0-shipped FOLLOWUPS.md) and expand it. The
  existing 2 items stay; append the rev 2 deferred items.

  Replace the existing v2.0.2 watch list section content with the
  rev 2 expanded form:

  ```markdown
  ## v2.0.2 watch list (post v2.0.1 ship)

  Carried from v2.0.0 ship:

  - [ ] **AF_ALG legitimate userspace consumers** — v2.0.1 keeps
    `RestrictAddressFamilies=~AF_ALG` unconditional on the assumption
    that no production workload uses AF_ALG. If a counter-example
    surfaces (some QEMU + AF_ALG deployment), add the detection
    signal to detect.sh and ship as v2.0.2.
    (AF_RXRPC was conditionalized in v2.0.1 rev 2 per reviewer C-3.)
  - [ ] **Cross-subpackage removal: detection drift on partial
    uninstall** — `dnf remove copyfail-defense-systemd` (keeping
    -modprobe) does not currently re-run detection. Auditor flags
    drift on next audit run. If operationally noisy, hook `%preun`
    to re-run detect.sh for the surviving subpackages.

  Added in v2.0.1 rev 2 (reviewer fixup deferrals):

  - [ ] **`find /home -maxdepth 6` performance** (reviewer M-5) on
    huge-`/home` fleets (cPanel, multi-tenant). The `-mtime -180`
    gate bounds inode scans per subtree but not the directory
    traversal itself. Mitigation candidates: timeout the find,
    parallel-walk, or invert to `loginctl list-users` enumeration
    that only checks active users. Watch for scriptlet timeouts
    in production reports.
  - [ ] **Conditional `daemon-reload` optimization** (reviewer M-7)
    — detect.sh always returns rc=0 on apply success regardless of
    whether any conditional file actually changed. `%posttrans
    systemd` always runs `daemon-reload`. Optimization: detect.sh
    returns rc=2 when no /etc/... changes happened; %posttrans
    skips daemon-reload on rc=2. Saves cosmetic reload work on
    re-runs. Defer until profiling shows a need.
  - [ ] **Test fixture redundant write cleanup** (reviewer M-8) —
    a few of the rev 2 detection-scenario tests do redundant
    `echo > file` followed by `printf > file` writes (force-full
    test pre-stages /etc/ipsec.conf twice). Tighten on next
    revision.
  - [ ] **v2.0.0 yank vs v2.0.1 hotfix narrative** (reviewer L-1) —
    document in BRIEF.md / external article whether v2.0.0 should
    be tagged "yanked" given the same-day v2.0.1 ship. Current
    plan: keep v2.0.0 RPMs in the repo through v2.0.x line per
    D-22 retention.
  - [ ] **`%{_libexecdir}` macro adoption** (reviewer L-2) — v2.0.1
    hard-codes `/usr/libexec/copyfail-defense/` in the spec.
    Convert to `%{_libexecdir}/copyfail-defense/` macro in v2.0.2
    for distro-portability cleanliness.
  - [ ] **test-repo.sh file-count assertion tightening** (reviewer
    L-4) — clean-host test asserts presence of 18 expected files
    but does not fail on *additional* unexpected files. Add a
    `find ... | wc -l` exact-count assertion in v2.0.2.
  - [ ] **mock chroot UID_MIN assumption documentation** (reviewer
    L-5) — D-48 documents that mock chroots have only system
    users (UID < 1000), so rootless detection signal (4) for
    `loginctl list-users` returns false. Add an INTERNAL-NOTES.md
    entry citing `/etc/login.defs` `UID_MIN` and tying our
    detection threshold (1000) to that convention.
  - [ ] **Per-mitigation force flags** (reviewer L-6) — current
    `force-full` is a single boolean. Operators may want
    `force-modprobe-cf2-xfrm` etc. as more granular existence-based
    flags. Defer until requested; the `force-full` lever covers
    the documented use cases.
  - [ ] **STATE.md cross-repo state line** (reviewer L-8) —
    placeholder TBD-marker for v2.0.1 commit hash got resolved by
    deferring the STATE.md edit to Phase 9 (post-commit). Verify
    Phase 9's STATE.md update did happen and the marker is gone
    from the published gh-pages STATE.md.

  ## v2.1.0 forward-cleanup obligation (reviewer M-10)

  - [ ] **`%pretrans` must handle BOTH v2.0.0 monolithic files AND
    v2.0.1 split files** when migrating to v2.1.0. The v2.0.0
    monolithic file may still exist as `.rpmsave-v2.0.1` (per D-37)
    on hosts that upgraded but never cleaned up; the v2.0.1 split
    files are now `%config(noreplace)` for the always-on cf1/10-*
    files and detect.sh-managed for the rest. v2.1.0's `%pretrans`
    needs explicit branches for both lineages.

    Recommended forward-compatible signal: write a plain-text file
    `/var/lib/copyfail-defense/installed-version` from v2.0.1
    `%posttrans` containing the version string. v2.1.0's `%pretrans`
    reads this to decide which migration path to take, instead of
    re-querying `rpm -q copyfail-defense-modprobe --qf '%{version}'`
    (which is unreliable mid-transaction).
  ```

### Acceptance

- [ ] `grep -c "Override paths" README.md` returns 0 (the heading is
  fully replaced).
- [ ] `grep -c "Auto-detection" README.md` returns at least 1.
- [ ] `grep -c "v2.0.1" STATE.md` returns at least 3.
- [ ] `grep -c "Subsumed by v2.0.1" FOLLOWUPS.md` returns 1.

### Test strategy

`grep` checks above. Visual inspection of section flow (no broken
markdown headers, no orphan sections).

### Commit message (pre-written)

```
docs: README + STATE + FOLLOWUPS for v2.0.1 auto-detection

Replaces README's "Override paths" section (operator-driven) with
"Auto-detection of conflicting workloads" (package-driven).
Documents the three detection signal classes, the auto-detect.json
report path, the copyfail-redetect helper, and the force-full
sentinel. Manual override docs preserved in a smaller "finer than
detection" subsection.

STATE.md bumps to v2.0.1 with updated RPM-family file paths and a
new Auto-detection section.

FOLLOWUPS.md subsumes the operator-side override entry and opens a
v2.0.2 watch list (AF_ALG/AF_RXRPC counter-examples,
cross-subpackage removal drift).
```

---

## ═══ BUILD/PUBLISH BOUNDARY ═══

The phases below need the build host's signing key + mock chroots +
gh-pages auth. Documented for Ryan's execution; not autonomously
runnable.

## Phase 8 — Build, sign, repo refresh   *(manual)*

```sh
# 1. SRPM
rpmbuild --define "_topdir /home/copyfail/rpmbuild" \
    -bs packaging/copyfail-defense.spec

# 2. Per-EL mock rebuild
for el in 8 9 10; do
    mock -r centos-stream+epel-${el}-x86_64 \
        --rebuild /home/copyfail/rpmbuild/SRPMS/copyfail-defense-2.0.1-1.el${el}.src.rpm
done

# 3. Sign every binary RPM and SRPM
rpmsign --addsign \
    /home/copyfail/rpmbuild/mock-out/centos-stream+epel-{8,9,10}-x86_64/result/*.rpm \
    /home/copyfail/rpmbuild/SRPMS/copyfail-defense-2.0.1-1.el*.src.rpm

# 4. Stage into gh-pages tree (preserves v2.0.0 + v1.0.1 RPMs per D-22)
for el in 8 9 10; do
    cp /home/copyfail/rpmbuild/mock-out/centos-stream+epel-${el}-x86_64/result/*.rpm \
       /home/copyfail/rpmbuild/gh-pages-staging/repo/${el}/x86_64/
    createrepo_c --general-compress-type=gz \
        /home/copyfail/rpmbuild/gh-pages-staging/repo/${el}/x86_64/
done

# 5. Detach-sign repodata
for el in 8 9 10; do
    pushd /home/copyfail/rpmbuild/gh-pages-staging/repo/${el}/x86_64/repodata
    gpg --detach-sign --armor -o repomd.xml.asc repomd.xml
    popd
done

# 6. Live test against staging
REPO_URL=file:///home/copyfail/rpmbuild/gh-pages-staging/copyfail.repo \
    bash packaging/test-repo.sh
```

## Phase 9 — Release v2.0.1   *(manual)*

```sh
git add -A
git commit -m "$(cat <<'EOF'
2.0.1: auto-detect IPsec / AFS / rootless workloads at install time

v2.0.1 replaces the v2.0.0 README's operator-driven "Override paths"
section with package-driven workload detection. %posttrans inspects
the host for IPsec, AFS, and rootless-container fingerprints and
suppresses only the conflicting conditional drop-ins; the always-on
cf1 cut, RestrictAddressFamilies, and SystemCallFilter remain active.

File-layout split: 99-copyfail-defense.conf becomes -cf1 (always-on),
-cf2-xfrm (suppressible-on-IPsec), -rxrpc (suppressible-on-AFS). Per-
unit systemd drop-ins split into 10-* always-on body and 15-userns
suppressible body (only suppressed for user@ on rootless hosts).

Operator levers: /usr/sbin/copyfail-redetect (on-demand re-run),
/etc/copyfail/force-full (skip detection sentinel),
/var/lib/copyfail-defense/auto-detect.json (versioned report consumed
by auditor and SIEM).

%pretrans handles the v2.0.0 -> v2.0.1 upgrade cleanly: removes the
monolithic %config files before unpack so the split files land
without RPM's default .rpmsave-then-skip-new behavior.

test-repo.sh extends to 25 per-EL checks. Auditor surfaces the
detection state under posture.auto_detect for SIEM consumption.
EOF
)"

git tag -a v2.0.1 -m "v2.0.1 hotfix: auto-detect conflicting workloads"
git push origin main --tags

gh release create v2.0.1 \
    --notes-file <release-notes> \
    /home/copyfail/rpmbuild/mock-out/centos-stream+epel-{8,9,10}-x86_64/result/*.rpm \
    /home/copyfail/rpmbuild/SRPMS/copyfail-defense-2.0.1-1.el*.src.rpm \
    packaging/copyfail.repo packaging/RPM-GPG-KEY-copyfail

# gh-pages branch: push staging
( cd /home/copyfail/rpmbuild/gh-pages-staging && \
  git add -A && git commit -m "v2.0.1 release" && git push origin gh-pages )

# Final live test against published repo
bash packaging/test-repo.sh
```

---

## Self-review (challenge pass)

- **Phase ordering:** Phase 1 (file split) → Phase 2 (detect.sh) →
  Phase 3 (spec wiring) → Phase 4 (redetect helper) → Phase 5
  (auditor) → Phase 6 (tests) → Phase 7 (docs). Each phase is
  bash-`-n`-able and `python3 -c py_compile`-able on its own. The
  dependency edges are: Phase 3 needs Phase 1+2 source paths; Phase 4
  modifies the spec from Phase 3; Phase 5 reads files written by
  detect.sh (Phase 2); Phase 6 tests behavior built up through Phases
  1-5. Phase 7 docs reference paths from Phases 1-4.
- **Phase 3 layout (rev 2 cleanup per reviewer C-5):**
  Source10/copyfail-redetect lands cleanly in Phase 4; Phase 3 ships
  Source0..9 + Source11 (the new rxrpc-af template). Phase 3 step
  3.5 lists `%files systemd` without the redetect helper line; that
  line is added by Phase 4 to the meta `%files` block. No
  intermediate broken state — the rev 1 in-step Self-correction
  callouts are removed; code blocks now show the final correct text.
- **Phase 4 placement:** redetect helper goes under the meta
  package's `%files` block since both `-modprobe` and `-systemd`
  consumers benefit from it. Settled in rev 2.
- **Phase 5 risk:** the `_summarize_auto_detect` helper assumes
  `r.details` is a dict. The existing Check class sets `details=None`
  by default; the helper guards with `details = r.details or {}`.
  Verified mentally; needs Phase 6 test coverage of the
  no-auto-detect-file case.
- **Phase 6 fragility:** the `run_split_upgrade_test_in` test depends
  on v2.0.0 RPMs being in the live repo. v2.0.0 was published
  2026-05-08; v2.0.1 ships same day. The retention window is one
  release cycle (D-22), and one cycle = "until we move past v2.0.x";
  v2.0.0 stays in repo through v2.1.0 ship per the existing rule.
  v2.0.1 is a v2.0.x ship, so v2.0.0 is still in repo. Test will
  pass; SKIP path is for distant-future safety.
- **mock-build behavior on `dnf install copyfail-defense`** (during
  test-repo.sh): containers don't have `/run/systemd/system`, so the
  `%post systemd` is a no-op (correctly), `%posttrans systemd` runs
  detect.sh (no IPsec/AFS/rootless on a fresh container = no
  suppression, all 12-* and 15-* files get installed), then the
  `if [ -d /run/systemd/system ]` guard skips daemon-reload. Test
  expectation matches: all 18 drop files present on clean container
  (3 modprobe + 5 always-on systemd + 5 12-rxrpc-af systemd + 5 15-userns systemd).
- **Operator hand-edits to conditional drop-ins (rev 2 cmp-and-skip
  policy per D-57)**: the conditional
  `99-copyfail-defense-{cf2-xfrm,rxrpc}.conf`,
  `12-copyfail-defense-rxrpc-af.conf`, and
  `15-copyfail-defense-userns.conf` files are NOT `%config(noreplace)`
  — they're managed by detect.sh, not RPM. Rev 2 fixup uses `cmp -s`
  against the
  `/usr/share/copyfail-defense/conditional/` template before
  overwriting. If the deployed file diverges from the template
  (operator hand-edited), detect.sh logs a WARN and skips the
  overwrite. The earlier `chattr +i` recommendation is dropped (it
  broke dnf via EPERM on `install -m 0644`). Suppression-removal
  still proceeds regardless of hand-edits (suppression wins for
  safety per §12.10.2a).
- **Race between detect.sh and concurrent dnf:** RPM serializes
  scriptlets per-host. Two `dnf` invocations across two hosts in a
  fleet run independently; that's the normal case and detect.sh
  state is per-host.
- **Per-subpackage scope (rev 2 D-56):** `%posttrans modprobe` calls
  `detect.sh apply modprobe` (only mutates `/etc/modprobe.d/`);
  `%posttrans systemd` calls `detect.sh apply systemd` (only mutates
  `/etc/systemd/system/...d/`). An operator who installs `-modprobe`
  alone gets clean modprobe state and no orphan systemd files (the
  rev 1 design's bug per reviewer C-6). When both subpackages are
  installed in one transaction, both `%posttrans` blocks fire — the
  shared `auto-detect.json` is rewritten by each (idempotent).
- **Phase 6 EL8-specific risk:** AlmaLinux 8 may ship without `jq`
  in the base image. Each detection-scenario test does
  `dnf install -y python3 jq >/dev/null 2>&1 || true` defensively.
  If `jq` install fails (no network, mirror down), test fails on the
  first `jq -e` call with a clear error. Acceptable.
- **detect.sh runs as root only:** the `report` mode that allowed
  unprivileged dry-run was dropped in rev 2 (D-54 / reviewer L-3 —
  no consumer). All invocations are root-only via either
  `%posttrans` or `copyfail-redetect`'s `id -u == 0` guard.

**Outstanding questions for Ryan's review (rev 2):**

The reviewer's three open questions are all resolved:

1. **Operator-edit policy on conditional drop-ins:** RESOLVED via
   D-57 cmp-and-skip. (Reviewer C-7.)
2. **README override pattern:** RESOLVED via D-58
   `20-override.conf` + `25-additions.conf`. (Reviewer C-8 / M-12.)
3. **detect.sh location:** ack-deferred to v2.0.2 watch list as
   `%{_libexecdir}` macro adoption (reviewer L-2). Current path
   `/usr/libexec/copyfail-defense/detect.sh` is FHS-correct.

Two new mechanisms surfaced in rev 2 worth flagging for the next
reviewer pass:

- **`find /home -maxdepth 6` performance** on huge cPanel fleets
  (M-5 deferred). The `-mtime -180` gate bounds inode scans per
  subtree but not the directory traversal itself. May need a
  fallback enumeration via `loginctl list-users` if scriptlet
  timeouts surface in production.
- **python3 dependency** in detect.sh's JSON emission (D-52).
  Phase 3 adds `Requires: /usr/bin/python3` to `-modprobe` and
  `-systemd`. Mock chroots include python3 by default; verified.

Cross-subpackage removal drift (single-subpackage dnf remove not
triggering detect.sh apply for surviving subpackages) — accepted
as out of scope for v2.0.1; auditor flags drift. Tracked in
FOLLOWUPS.md v2.0.2 watch list.

**Plan is shippable.** All in-scope reviewer items (C-1..C-8 +
M-1..M-12 listed in-scope) folded; deferred items (M-5, M-7, M-8,
L-1, L-2, L-4, L-5, L-6, L-8 + v2.1.0 cleanup M-10) recorded in
FOLLOWUPS.md v2.0.2 watch list.

---

## Handoff notes

- All Phase 1-7 work is autonomously executable from `/home/copyfail`
  with no external dependencies (no network, no signing key, no
  mock).
- Phase 8 + 9 are manual; same pattern as v2.0.0.
- `git status` after Phase 7 should show: 5 new packaging/ files
  (detect.sh, redetect, modprobe-cf2-xfrm, modprobe-rxrpc,
  systemd-dropin-rxrpc-af, systemd-dropin-userns — actually 6 new
  but `copyfail-modprobe.conf` is renamed not added), 1 renamed
  packaging/ file (modprobe → modprobe-cf1), 1 modified spec, 2
  modified packaging/ files (systemd-dropin and
  systemd-dropin-containers rewritten), 1 modified auditor, 1
  modified test harness, 1 modified README, 1 modified STATE, 1
  modified FOLLOWUPS, 0 modified governance/spec docs
  (.rdf/governance/* unchanged in this hotfix).
- Engineer should re-read SPEC §12 §12.14 (self-review rev 2)
  before starting; the resolved decisions there (D-51..D-58)
  constrain Phase 2/3/5/7 implementation choices.
