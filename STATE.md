# copyfail-defense — shipping state

Snapshot: **2026-05-08**

## Latest release

- **v2.0.1** — hotfix adding auto-detection of conflicting workloads
  (IPsec, AFS, rootless containers) at install time. Conditional
  modprobe/systemd drop-ins suppressed when a workload is detected.
  Adds `copyfail-redetect` helper and `check_auto_detect_state` auditor
  check. Signed RPMs, EL8 / EL9 / EL10, x86_64 only.
- Tag: <https://github.com/rfxn/copyfail/releases/tag/v2.0.1>
- v2.0.0 RPMs retained in repo trees for upgrade path
  (`dnf upgrade copyfail-defense`).
- v1.0.1 RPMs retained in repo trees for one cycle (clean
  `dnf upgrade afalg-defense -> copyfail-defense` path).
- v1.0.0 was rolled back (was unsigned baseline; deleted from GH releases).

## Distribution

| Surface | URL |
|---|---|
| Source repo (main) | <https://github.com/rfxn/copyfail> |
| GH Pages site | <https://rfxn.github.io/copyfail/> |
| DNF repo file | <https://rfxn.github.io/copyfail/copyfail.repo> |
| Public signing key | <https://rfxn.github.io/copyfail/RPM-GPG-KEY-copyfail> |
| Per-EL RPM trees | `https://rfxn.github.io/copyfail/repo/{8,9,10}/x86_64/` |
| Detached repodata sigs | `…/repo/{8,9,10}/x86_64/repodata/repomd.xml.asc` |
| Deep-dive article | <https://www.rfxn.com/research/copyfail-cve-2026-31431> |

## Operator one-liner

```sh
sudo curl -sSL https://rfxn.github.io/copyfail/copyfail.repo \
  -o /etc/yum.repos.d/copyfail.repo
sudo dnf install -y copyfail-defense
sudo /usr/sbin/copyfail-shim-enable
```

Upgrade from `afalg-defense` v1.0.x:

```sh
sudo dnf upgrade -y copyfail-defense
```

## RPM family

| Package | Arch | Path |
|---|---|---|
| `copyfail-defense` (meta) | x86_64 | requires shim + modprobe + systemd + auditor |
| `copyfail-defense-shim` | x86_64 | `/usr/lib64/no-afalg.so`, `/usr/sbin/copyfail-shim-{enable,disable}` |
| `copyfail-defense-modprobe` | noarch | `/etc/modprobe.d/99-copyfail-defense-cf1.conf` (always-on) + cf2-xfrm + rxrpc (conditional via detect.sh) |
| `copyfail-defense-systemd` | noarch | `/etc/systemd/system/{user@,sshd,cron,crond,atd}.service.d/10-copyfail-defense.conf` (always-on) + rxrpc-af (12-*, conditional) + userns (15-*, conditional) |
| `copyfail-defense-auditor` | noarch | `/usr/sbin/copyfail-local-check` |

`Epoch: 1` introduced in 2.0.0; `Obsoletes:` / `Provides: afalg-defense*`
metadata retained through 2.0.x release line. `/usr/sbin/copyfail-redetect`
added in 2.0.1 (ships in meta package).

Per-EL binary RPMs are independently compiled against each
distribution's glibc (EL8: 2.28; EL9/10: 2.34+).

Do **not** cross-install across ELs.

## Coverage matrix

| Layer | cf1 | cf2 | dirtyfrag-ESP | dirtyfrag-RxRPC |
|---|:---:|:---:|:---:|:---:|
| `-shim` (LD_PRELOAD AF_ALG) | ✅ primary | – | – | (incidental) |
| `-modprobe` (algif/authenc/af_alg) | ✅ (modular kernels) | – | – | – |
| `-modprobe` (esp4/esp6/xfrm_user/xfrm_algo) | – | ✅ | ✅ | – |
| `-modprobe` (rxrpc) | – | – | – | ✅ |
| `-systemd` (`~AF_ALG`) | ✅ | – | – | – |
| `-systemd` (`~AF_RXRPC`) | – | – | – | ✅ |
| `-systemd` (`~user ~net`) | – | ✅ | ✅ | – |
| Kernel patch | `a664bf3d` | `f4c50a4034` | `f4c50a4034` | (none upstream) |

## Signing

```
fingerprint:  6001 1CDC EA2F F52D 975A  FDEE 6D30 F32C D5E8 0F80
key id:       6D30F32CD5E80F80
algo:         RSA-4096 (signing only), no passphrase
created:      2026-04-30
expires:      2028-04-29  (rotate or extend before)
uid:          Copyfail Project Signing Key <proj@rfxn.com>
```

- Live private key: `/root/.gnupg/` on freedom (this box)
- Backed up at: `forge.lab.rpx.sh:/hdd-pool/backups/copyfail-signing-key/` (ZFS, lz4, snapshot `@20260430`)
- Backup runbook: `rfxn-infra/docs/runbooks/copyfail-signing-key-backup.md`
- Portable export: `/root/admin/secrets/copyfail-signing-key/`
- `/etc/yum.repos.d/copyfail.repo` enforces `gpgcheck=1` + `repo_gpgcheck=1`

## Build / package conventions

- Spec: `packaging/copyfail-defense.spec`
- Helper scripts: `packaging/copyfail-shim-{enable,disable}`
- Active dropins source: `packaging/copyfail-modprobe-{cf1,cf2-xfrm,rxrpc}.conf`, `packaging/copyfail-systemd-dropin{,-rxrpc-af,-userns}.conf`
- Container-runtime example dropin source: `packaging/copyfail-systemd-dropin-containers.conf`
- Workload detection helper: `packaging/copyfail-defense-detect.sh`
- Operator re-detect helper: `packaging/copyfail-redetect`
- `.repo` source: `packaging/copyfail.repo`
- Public key source: `packaging/RPM-GPG-KEY-copyfail`
- Build invocation: `rpmbuild --define "_topdir /home/copyfail/rpmbuild" -ba packaging/copyfail-defense.spec`
- Per-EL: `mock -r centos-stream+epel-{8,9,10}-x86_64 --rebuild SRPMS/...`
- Sign: `rpmsign --addsign <RPM>` (uses `/root/.rpmmacros`)
- Repo metadata: `createrepo_c --general-compress-type=gz <dir>/`
  - `gz` (not zstd) for older-dnf compatibility
- Detach-sign metadata: `gpg --detach-sign --armor -o repomd.xml.asc repomd.xml`

## Test harness

`packaging/test-repo.sh` — podman-driven, **26 checks per EL** (was 18 in
v2.0.0; v2.0.1 adds detection-scenario tests for IPsec/AFS/rootless/clean
host + redetect helper + auto_detect auditor JSON).

```sh
bash packaging/test-repo.sh           # all three ELs
bash packaging/test-repo.sh 9         # single EL
REPO_URL=... bash packaging/test-repo.sh   # override source
```

## Auditor

`/usr/sbin/copyfail-local-check` — 26 checks across ENV/KERNEL/MITIGATION/
HARDENING/DETECTION categories, stdlib-only Python 3.6+. Five-class
scoring:

```
ENV         : kernel_info, distro_info, privilege, apparmor_userns_restrict, lsm_stack
KERNEL      : af_alg_socket, authencesn_cipher, algif_aead_state, xfrm_modules, rxrpc_module, trigger_probe
MITIGATION  : ld_so_preload, shim_blocks_af_alg, modprobe_blacklist, modprobe_extended,
              modules_disabled, initcall_blacklist, systemd_restrict, systemd_restrict_namespaces,
              user_service_dropin, dropin_freshness
HARDENING   : suid_inventory, page_cache_integrity (extended), file_capabilities,
              su_target_hardening, userns_sysctl
DETECTION   : auditd, audit_rules_extended, seccomp_runtime, pam_nullok, af_alg_holders,
              kernel_log_iocs, recent_iocs
```

JSON output gains `posture.bug_classes_covered` (SIEM-ergonomic array)
and `posture.bug_classes` (per-class map with kernel_sink + per-layer
booleans). Exit codes unchanged from v1.0.1.

v2.0.1 adds `posture.auto_detect` with `available`, `suppressed_modprobe`,
and `suppressed_systemd` fields. Available only when
`/var/lib/copyfail-defense/auto-detect.json` schema version 2 is present.

## Auto-detection (v2.0.1+)

`/usr/libexec/copyfail-defense/detect.sh` runs during `%posttrans` for
modprobe and systemd subpackages. It writes
`/var/lib/copyfail-defense/auto-detect.json` (schema version 2) and
conditionally installs or suppresses drop files.

| Signal | Source | Suppresses |
|---|---|---|
| IPsec (xfrm/esp) | kernel modules loaded; ipsec.conf/nss db | cf2-xfrm modprobe conf |
| AFS | kafs module; afs mount | rxrpc modprobe conf + rxrpc-af systemd drop-in |
| rootless containers | storage-tree: `~/.local/share/containers/storage` | userns systemd drop-in (user@ only) |

`/usr/sbin/copyfail-redetect` — operator-callable wrapper; re-runs
`detect.sh apply both`. Required after enabling a workload post-install.
Does NOT call `systemctl daemon-reload` — operator decides reload timing.

`/etc/copyfail/force-full` — sentinel file; when present, detection is
skipped and all mitigations applied unconditionally.

## Safety properties enforced by the spec

- `%post` does **not** touch `/etc/ld.so.preload` — operator must run `copyfail-shim-enable`.
- `copyfail-shim-enable` smoke-tests the .so against `/bin/true` before writing the preload file.
- `%preun shim` on full erase scrubs `/etc/ld.so.preload` *before* RPM removes the .so (otherwise every dyn-linked binary fails to dlopen the missing preload — brick).
- `%posttrans shim` warns if the file ever ends up dangling.
- `%post modprobe` does best-effort `rmmod` of cf1 modules + LOG_AUTHPRIV trail; failures silenced.
- `%posttrans modprobe` calls `detect.sh apply modprobe`; best-effort rmmod of cf2/rxrpc if suppressed.
- `%postun modprobe` calls `detect.sh teardown modprobe` (or inline fallback); removes all drop files.
- `%posttrans systemd` calls `detect.sh apply systemd`; daemon-reload.
- `%postun systemd` calls `detect.sh teardown systemd` (or inline fallback); daemon-reload.
- All shipped conf files marked `%config(noreplace)` — operator hand-edits survive package upgrade.
- ExclusiveArch: x86_64 (the .c source has `#error` for non-x86_64).
- Both `gpgcheck=1` and `repo_gpgcheck=1` enforced in the published `.repo`.

## Defense-in-depth posture

The toolkit is a stack of independent layers:

1. **LD_PRELOAD shim** — works on every kernel, every dyn-linked process. cf1 primary defense.
2. **modprobe blacklist** of `algif_aead`/`authenc`/`authencesn`/`af_alg` (cf1; no-op on RHEL builtin) + `esp4`/`esp6`/`xfrm_user`/`xfrm_algo` (cf2/dirtyfrag-ESP) + `rxrpc` (dirtyfrag-RxRPC). Functional for the latter two on stock RHEL kernels (these are modules).
3. **systemd `RestrictAddressFamilies=~AF_ALG ~AF_RXRPC`** + **`RestrictNamespaces=~user ~net`** on tenant units (user@/sshd/cron/crond/atd). Kernel-enforced seccomp; uncircumventable from userspace.
4. **suid surface lockdown** (auditor recommends `chmod 4750 /usr/bin/su` only when `/etc/passwd` analysis shows no non-wheel interactive users).
5. **page-cache integrity probe** for `/etc/passwd`, PAM stacks, `/etc/ld.so.preload`, `/usr/bin/su`, dynamic linker.
6. **audit telemetry** — keys: `afalg_attempt`, `cf_userns`, `cf_addkey`, `cf_xfrm_nl`, `splice_tenant`.
7. **kernel patches** — cf1 `a664bf3d`, cf2/df-ESP `f4c50a4034`, df-RxRPC (none upstream).

The auditor scores all layers and reports per-class `applicable` /
`mitigated` / `active layers` so a fleet console can render per-host
posture without re-implementing verdict logic.

## Cross-repo state

- `rfxn/copyfail` main `<TBD-after-v2.0.1-commit>` — copyfail-defense v2.0.1 hotfix
- `rfxn/copyfail` gh-pages `<TBD>` — index.html refresh pending Phase 8
- `rfxn/copyfail` v2.0.0 tag — signed release (previous)
- `rfxn/copyfail` v2.0.1 tag — pending Phase 9 (manual)
- `rfxn/rfxn-infra` main `b86d9b7` — `docs/runbooks/copyfail-signing-key-backup.md` (unchanged)
- forge ZFS — `hdd-pool/backups/copyfail-signing-key/` populated, snapshot `@20260430` (unchanged)
