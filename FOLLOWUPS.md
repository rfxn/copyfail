# Outstanding follow-ups

Snapshot: **2026-05-08** (post v2.0.0 ship)

## Documentation drift to apply elsewhere

- [ ] **rfxn.com research article** — extend the article at <https://www.rfxn.com/research/copyfail-cve-2026-31431> with cf2 (xfrm-ESP) and Dirty Frag (V4bel) sections, matching the cf-class framing now in README.md. Article source lives in `rfxn/rfxn-website-2026` (private). The full v2.0.0 coverage matrix from STATE.md should land in the article's mitigation section.

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

## Open for v2.1.0 (after v2.0.0 lands)

- [ ] Ship **`copyfail-defense-userns`** subpackage (sysctl drop
  for `user.max_user_namespaces=0` /
  `kernel.unprivileged_userns_clone=0`). Opt-in only — NOT pulled
  by meta. Document blast radius (rootless podman, browser
  sandboxes, flatpak) loudly.
- [ ] Drop the `Obsoletes:`/`Provides:` for `afalg-defense*`
  names from the spec. The compat chain is retained through the
  2.0.x line per **[D-21]**.
- [ ] Cleanup: remove old `afalg-defense-1.0.1*` RPMs from the
  gh-pages repo trees (kept for one release cycle per **[D-22]**).

## Architecture extension (not scheduled)

- [ ] arm64 support. The `no-afalg.c` source has `#error "no-afalg.so currently only supports x86_64"` and the auditor's trigger probe struct layout is x86_64-only. Spec has `ExclusiveArch: x86_64`. Patches welcome (mentioned in README "Limitations").

## Key lifecycle

- [ ] **2028-04-29 — signing key expires.** Either extend (`gpg --edit-key proj@rfxn.com expire`) or rotate (generate new key, ship 2.0.0 release whose `.repo` points at the new key URL, bump version so old signed RPMs aren't accidentally trusted). Re-run the backup procedure after either operation.
