# Outstanding follow-ups

Snapshot: **2026-05-13** (post v2.0.2 ship)

## Shipped in v2.0.2 (2026-05-13)

Three Fragnesia / Dirty Frag bug-class hardening additions landed,
all driven by the 2026-05-08..2026-05-13 advisory wave (CloudLinux,
Wiz, Sysdig, Red Hat RHSB-2026-003, AWS, Microsoft, Tenable):

- New subpackage `copyfail-defense-sysctl` — host-wide
  `user.max_user_namespaces=0` (+ `kernel.unprivileged_userns_clone=0`,
  + `kernel.apparmor_restrict_unprivileged_userns=1`) drop-in to
  `/etc/sysctl.d/99-copyfail-defense-userns.conf`. Keys are
  `-`-prefixed so unknown keys silently skip (sysctl.d(5)). Closes
  the userns prerequisite of the cf2 / DF-ESP / Fragnesia chain
  host-wide, complementing the per-unit `RestrictNamespaces`. **This
  closes the "Open for v2.1.0" item below in v2.0.2 instead of v2.1.**
  Deviation from the original plan: meta hard-Requires `-sysctl`
  (not opt-in-only) because auto-detection suppresses the drop file
  on rootless containers, Flatpak, firejail, and desktop browsers —
  the "blast radius documented loudly" requirement is satisfied by
  detection rather than operator gating.
- New subpackage `copyfail-defense-audit` — auditd rules at
  `/etc/audit/rules.d/99-copyfail-defense.rules` catching
  `socket(AF_ALG/AF_KEY/AF_RXRPC)` syscalls from `auid>=1000`.
  Meta pulls it via `Recommends` (soft) so minimal hosts without
  auditd skip the auditd transitive pull. Real value on hosts where
  modprobe blacklists are auto-suppressed (IPsec/AFS workloads)
  and the kernel sink stays reachable.
- `RestrictAddressFamilies` extended with `~AF_KEY` on the always-on
  10-* drop-in and the containers-dropin.conf example. Closes the
  PF_KEYv2 SA-config path used by the Dirty Frag / Fragnesia chain
  (XFRM netlink — the other SA-config path — still requires
  `CAP_NET_ADMIN`, harder route).
- detect.sh extended: `detect_userns_consumers` (Flatpak / firejail
  / desktop browsers), new `sysctl` and `all` scopes,
  auto-detect.json schema gets backward-compat additions
  (`detected.userns_consumers`, `suppressed.sysctl_userns`,
  `applied.sysctl_userns`). TOOL_VERSION bumped 2.0.1 → 2.0.2.
- README: CVE cross-stamping (cf2 = CVE-2026-43284, DF-RxRPC =
  CVE-2026-43500, Fragnesia surface notation). Coverage matrix
  gets a Fragnesia column, sysctl userns row, audit tripwire row.
  Operator-applied table gets the `initcall_blacklist=algif_aead_init`
  + grubby + reboot row for the RHEL builtin algif_aead case.

## Documentation drift to apply elsewhere

- [ ] **rfxn.com research article** — extend the article at <https://www.rfxn.com/research/copyfail-cve-2026-31431> with cf2 (xfrm-ESP) and Dirty Frag (V4bel) sections, matching the cf-class framing now in README.md. Article source lives in `rfxn/rfxn-website-2026` (private). The full v2.0.1 coverage matrix from STATE.md should land in the article's mitigation section. Include a note on the v2.0.1 auto-detection feature (IPsec/AFS/rootless workload detection, `copyfail-redetect` helper).

## Cron entries from the backup runbook (documented but not installed)

`rfxn-infra/docs/runbooks/copyfail-signing-key-backup.md` documents these — the initial sync + snapshot are done, but the recurring schedule isn't installed yet.

- [ ] On freedom — nightly rsync to forge:
  ```
  5 3 * * * rsync -a --chmod=Du=rwx,Dgo=,Fo=,Fg= /root/admin/secrets/copyfail-signing-key/ \
      forge.lab.rpx.sh:/hdd-pool/backups/copyfail-signing-key/ 2>&1 | logger -t copyfail-key-backup
  ```
- [ ] On forge — daily snapshot:
  ```
  5 3 * * * zfs snapshot hdd-pool/backups/copyfail-signing-key@$(date +\%Y\%m\%d)
  ```

The bundle is durable as-is (one full sync + one snapshot already on forge); cron just keeps it fresh after future key edits.

## Subsumed by v2.0.0 (was: v1.0.2 queue)

The v1.0.2 modprobe-file-catchup queue is folded into v2.0.0 —
the new `-modprobe` subpackage owns
`/etc/modprobe.d/99-copyfail-defense.conf` with the full
cf-class entry-point list (algif_aead/authenc/authencesn/af_alg
+ esp4/esp6/xfrm_user/xfrm_algo + rxrpc). No separate v1.0.2
release.

## Subsumed by v2.0.1 (was: README operator-side overrides)

v2.0.0 README's "Override paths" section pushed conflict resolution
onto operators (skip subpackages, hand-edit `%config(noreplace)`
files, write `20-override.conf` drop-ins). v2.0.1 replaces that with
package-driven auto-detection of IPsec / AFS / rootless-container
workloads — operators get the right drop-ins by default. Manual
override paths remain documented for finer-grained needs but are no
longer the primary recommendation.

## v2.0.2 watch list (post v2.0.1 ship)

Carried from v2.0.0 ship:

- [ ] **AF_ALG legitimate userspace consumers** — v2.0.1 keeps
  `RestrictAddressFamilies=~AF_ALG` unconditional on the assumption
  that no production workload uses AF_ALG. If a counter-example
  surfaces (some QEMU + AF_ALG deployment), add the detection signal
  to `detect.sh` and ship as v2.0.2.
  (AF_RXRPC was conditionalized in v2.0.1 rev 2 per reviewer C-3 —
  AFS userspace tooling, `aklog` in particular, opens AF_RXRPC
  sockets to vlserver/ptserver.)
- [ ] **Cross-subpackage removal: detection drift on partial
  uninstall** — `dnf remove copyfail-defense-systemd` (keeping
  `-modprobe`) does not currently re-run detection. The auditor
  flags drift on next audit run. If this proves operationally
  noisy, hook `%preun` to re-run `detect.sh` for the surviving
  subpackages.

Added in v2.0.1 rev 2 (reviewer fixup deferrals; in-scope items
were folded into the v2.0.1 ship — see SPEC §12 D-51..D-58):

- [ ] **`find /home -maxdepth 6` performance** (reviewer M-5) on
  huge-`/home` fleets (cPanel, multi-tenant). The rev 2 rootless
  detection signal walks `/home/*/.local/share/containers/storage/`
  to find podman storage trees. The `-mtime -180` gate bounds inode
  scans per subtree but not the directory traversal itself. May
  need a fallback that enumerates only `loginctl list-users` active
  users instead of walking all of `/home`. Watch for scriptlet
  timeouts in production reports; auditd noise from filesystem
  watchers may also surface.
- [ ] **Conditional `daemon-reload` optimization** (reviewer M-7) —
  `detect.sh` always returns rc=0 on apply success regardless of
  whether any conditional file actually changed. `%posttrans
  systemd` always runs `daemon-reload`. Optimization: have
  `detect.sh` return rc=2 when no `/etc/...` changes happened;
  `%posttrans` skips `daemon-reload` on rc=2. Saves cosmetic reload
  work on re-runs. Defer until profiling shows a need.
- [ ] **Test fixture redundant write cleanup** (reviewer M-8) —
  a few of the rev 2 detection-scenario tests do redundant
  `echo > file` followed by `printf > file` writes (force-full
  test pre-stages `/etc/ipsec.conf` twice in a row). Tighten on
  next revision.
- [ ] **v2.0.0 yank vs v2.0.1 hotfix narrative** (reviewer L-1) —
  document in BRIEF.md / external article whether v2.0.0 should
  be tagged "yanked" given the same-day v2.0.1 ship. Current plan:
  keep v2.0.0 RPMs in the repo through the v2.0.x line per D-22
  retention. The narrative could read either way (hotfix vs yank);
  pick before the next blog post.
- [ ] **`%{_libexecdir}` macro adoption** (reviewer L-2) — v2.0.1
  hard-codes `/usr/libexec/copyfail-defense/` in the spec. Convert
  to `%{_libexecdir}/copyfail-defense/` macro form in v2.0.2 for
  distro-portability cleanliness. The hard-coded path is FHS-correct
  on EL but the macro is the conventional spec idiom.
- [ ] **test-repo.sh file-count assertion tightening** (reviewer
  L-4) — clean-host test asserts presence of 18 expected files but
  does not fail on *additional* unexpected files. Add a
  `find /etc/modprobe.d /etc/systemd/system/*.service.d -name '*copyfail*' | wc -l`
  exact-count assertion in v2.0.2.
- [ ] **mock chroot UID_MIN assumption documentation** (reviewer
  L-5) — D-48 documents that mock chroots have only system users
  (UID < 1000), so rootless detection signals never trip in mock.
  Add an INTERNAL-NOTES.md entry citing `/etc/login.defs` `UID_MIN`
  and tying our detection threshold (1000) to that convention.
- [ ] **Per-mitigation force flags** (reviewer L-6) — current
  `force-full` is a single boolean. Operators may want
  `force-modprobe-cf2-xfrm`, `force-systemd-rxrpc-af`, etc. as more
  granular existence-based flags. Defer until requested; the
  `force-full` lever covers the documented use cases.
- [ ] **STATE.md cross-repo state line** (reviewer L-8) — v2.0.1
  rev 2 deferred the placeholder commit-hash insertion to Phase 9
  (post-commit). Verify on next ship-cycle that Phase 9's STATE.md
  update happened and no `<TBD-after-v2.0.1-commit>` marker leaked
  to gh-pages.

## v2.1.0 forward-cleanup obligation (reviewer M-10)

- [ ] **`%pretrans` must handle BOTH v2.0.0 monolithic files AND
  v2.0.1 split files** when migrating forward to v2.1.0. The v2.0.0
  monolithic file may still exist as `.rpmsave-v2.0.1` on hosts
  that upgraded but never cleaned up the rename artifact; the
  v2.0.1 split files are `%config(noreplace)` for the always-on
  cf1/10-* files and detect.sh-managed for the rest. v2.1.0's
  `%pretrans` needs explicit branches for both lineages.

  Recommended forward-compatible signal: write a plain-text file
  `/var/lib/copyfail-defense/installed-version` from v2.0.1
  `%posttrans` containing the version string. v2.1.0's `%pretrans`
  reads this file to decide which migration path to take, instead
  of re-querying `rpm -q copyfail-defense-modprobe --qf '%{version}'`
  (which is unreliable mid-transaction). v2.0.1 rev 2 plan does
  NOT yet write this signal — adding the writer is itself a
  v2.1.0 prep task.

## Open for v2.1.0 (after v2.0.0 lands)

- [x] **DONE in v2.0.2 (2026-05-13)** — Shipped
  `copyfail-defense-sysctl` subpackage with
  `user.max_user_namespaces=0` /
  `kernel.unprivileged_userns_clone=0` /
  `kernel.apparmor_restrict_unprivileged_userns=1`. **Deviation:**
  meta hard-Requires it rather than opt-in-only; auto-detection
  suppresses the drop file on rootless containers / Flatpak /
  firejail / desktop browsers, so "blast radius documented loudly"
  becomes "blast radius auto-detected and avoided".
- [ ] Drop the `Obsoletes:`/`Provides:` for `afalg-defense*`
  names from the spec. The compat chain is retained through the
  2.0.x line per **[D-21]**.
- [ ] Cleanup: remove old `afalg-defense-1.0.1*` RPMs from the
  gh-pages repo trees (kept for one release cycle per **[D-22]**).
- [ ] **Fragnesia CVE pin** — when the upstream CVE assignment
  for the ESP-in-TCP variant lands, cross-stamp SPEC/README/PLAN.
  Current state: CloudLinux blog cited "CVE-2026-46300" but Wiz,
  Sysdig, Tenable, Red Hat, AlmaLinux, AWS, oss-sec all describe
  Fragnesia as a follow-on bug in the CVE-2026-43284 surface with
  no separate CVE assigned yet (as of 2026-05-13). Worth
  re-checking the cna/Red Hat tracker monthly until pinned.

## Architecture extension (not scheduled)

- [ ] arm64 support. The `no-afalg.c` source has `#error "no-afalg.so currently only supports x86_64"` and the auditor's trigger probe struct layout is x86_64-only. Spec has `ExclusiveArch: x86_64`. Patches welcome (mentioned in README "Limitations").

## Key lifecycle

- [ ] **2028-04-29 — signing key expires.** Either extend (`gpg --edit-key proj@rfxn.com expire`) or rotate (generate new key, ship 2.0.0 release whose `.repo` points at the new key URL, bump version so old signed RPMs aren't accidentally trusted). Re-run the backup procedure after either operation.
