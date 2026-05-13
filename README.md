<div align="center">

# copyfail-defense

**Defense-in-depth toolkit for the Copy Fail Linux kernel bug class.**
Covers three live LPE chains that share the same `splice()` →
`MSG_SPLICE_PAGES` → in-place page-cache write primitive:

| | CVE | Sink | Primitive |
|---|---|---|---|
| **cf1** | CVE-2026-31431 | `algif_aead` AEAD scratch-write | 4-byte STORE via `seqno_lo` |
| **cf2 / Dirty Frag-ESP** | CVE-2026-43284 | `esp_input` skip_cow | 4-byte STORE via `seq_hi` |
| **Dirty Frag-RxRPC** | CVE-2026-43500 | `rxkad_verify_packet_1` | 4-byte and 8-byte STORE |
| **Fragnesia** | (no CVE yet — same surface as CVE-2026-43284) | `espintcp` ULP after splice | byte STORE in cached page |

Userspace primitives stack into a single `dnf install`: an `LD_PRELOAD`
shim, a kernel-module-entry-point cut, kernel-enforced systemd
restrictions, and a read-only host posture auditor that reports
per-class coverage. Signed RPMs for EL8 / EL9 / EL10.

<a href="https://rfxn.github.io/copyfail/"><img src="https://img.shields.io/badge/%F0%9F%93%A6%20yum%2Fdnf%20repo-rfxn.github.io%2Fcopyfail-22d3ee?style=for-the-badge&labelColor=09090b" alt="copyfail-defense yum/dnf package repo"></a>
<a href="https://www.rfxn.com/research/copyfail-cve-2026-31431"><img src="https://img.shields.io/badge/%F0%9F%94%AC%20deep%20dive-rfxn.com%2Fresearch-d97757?style=for-the-badge&labelColor=09090b" alt="Deep-dive research article on rfxn.com"></a>

[![Bug class](https://img.shields.io/badge/Copy%20Fail%20bug%20class-cf1%20%2F%20cf2%20%2F%20Dirty%20Frag-d97757?labelColor=09090b)](#what-this-protects-against)
[![Severity](https://img.shields.io/badge/severity-LOCAL%20PRIVESC-d44d4d?labelColor=09090b)](#what-this-protects-against)
[![License](https://img.shields.io/badge/license-GPL--2.0-22d3ee?labelColor=09090b)](LICENSE)
[![EL8/9/10](https://img.shields.io/badge/EL-8%20%2F%209%20%2F%2010-4ade80?labelColor=09090b)](https://rfxn.github.io/copyfail/)
[![Latest release](https://img.shields.io/github/v/release/rfxn/copyfail?label=release&color=22d3ee&labelColor=09090b)](https://github.com/rfxn/copyfail/releases/latest)

[Install](#install) · [Verify](#verify) · [Coverage](#coverage-matrix) · [Defense in depth](#defense-in-depth) · [Audit](#audit-the-host) · [Subpackages](#subpackages) · [Overrides](#override-paths) · [Signatures](#verifying-signatures) · [Limitations](#limitations)

</div>

---

> [!NOTE]
> Upgrading from `afalg-defense` v1.0.x or any `copyfail-defense`
> 2.0.x release is a single command: `dnf upgrade copyfail-defense`.
> Auto-detection re-runs on every upgrade and suppresses any
> conflicting drop-ins detected on your host (IPsec, AFS, rootless
> containers, Flatpak, firejail, desktop browsers; see Auto-detection
> below).

---

## Install

```sh
sudo curl -sSL https://rfxn.github.io/copyfail/copyfail.repo \
  -o /etc/yum.repos.d/copyfail.repo
sudo dnf install -y copyfail-defense
sudo /usr/sbin/copyfail-shim-enable
```

One repo file works on EL8/EL9/EL10. RPMs are GPG-signed; dnf imports
the public key on first use. Cross-check the fingerprint when prompted:

```
6001 1CDC EA2F F52D 975A  FDEE 6D30 F32C D5E8 0F80
```

The meta package pulls six subpackages (with `-audit` as a soft dep so
minimal hosts without auditd skip the pull-in):

| Subpackage | Coverage |
|---|---|
| `copyfail-defense-shim` | LD_PRELOAD AF_ALG block (cf1 primary) |
| `copyfail-defense-modprobe` | kernel-module entry-point cuts (cf1 + cf2 + Dirty Frag) |
| `copyfail-defense-systemd` | per-unit `RestrictAddressFamilies=~AF_ALG ~AF_KEY ~AF_RXRPC` + `RestrictNamespaces=~user ~net` (all bug classes) |
| `copyfail-defense-sysctl` *(v2.0.2)* | host-wide `user.max_user_namespaces=0` sysctl (cf2 / DF-ESP / Fragnesia) |
| `copyfail-defense-auditor` | read-only host posture auditor with per-class coverage report |
| `copyfail-defense-audit` *(v2.0.2, soft-dep)* | auditd tripwire rules for `socket(AF_ALG/AF_KEY/AF_RXRPC)` syscalls |

Auditor only (no `LD_PRELOAD`, for hot infrastructure):

```sh
sudo dnf install -y copyfail-defense-auditor
```

## Verify

After install + activation:

```sh
# cf1: AF_ALG socket creation should fail
python3 -c 'import socket; socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)'
# expect: PermissionError [Errno 1] Operation not permitted

# Holistic per-class coverage report
sudo copyfail-local-check
```

The auditor renders a surface-area matrix at the bottom showing, per
bug-class, whether the kernel sink is reachable on this host AND which
mitigation layers are active:

```
Surface area / mitigation matrix:
  Class                Sink reachable?  Mitigated?  Active layers
  cf1 (CVE-2026-31431) YES              yes         ld_preload_shim, systemd_af_alg, modprobe_blacklist
  cf2 (xfrm-ESP)       YES              yes         modprobe_blacklist, systemd_restrict_ns
  Dirty Frag-ESP       YES              yes         modprobe_blacklist, systemd_restrict_ns
  Dirty Frag-RxRPC     YES              yes         modprobe_blacklist, systemd_af_rxrpc

Bug-class coverage: cf1=mitigated cf2=mitigated dirtyfrag-esp=mitigated dirtyfrag-rxrpc=mitigated
```

## Audit the host

```sh
sudo copyfail-local-check                # human-readable, only flags non-OK
sudo copyfail-local-check --json         # SIEM ingestion (posture.bug_classes_covered)
sudo copyfail-local-check --emit-remediation   # bash script of suggested fixes
```

Read-only by design: writes only to `mkdtemp()` sentinels, never modifies
`/usr/bin` or `/etc`, runs unprivileged (some checks degrade gracefully
without root). Five categories: `ENV`, `KERNEL`, `MITIGATION`,
`HARDENING`, `DETECTION`.

Exit codes (unchanged from v1.0.1): `0` clean · `2` **VULN**
(no userspace mitigation) · `3` VULN-but-mitigated · `4` hardening
recommendations only.

JSON output (`--json`) includes:
- `posture.bug_classes_covered`: array of class IDs where mitigation is
  active. Single SIEM filter for "is this host hardened against the cf
  class?"
- `posture.bug_classes`: per-class map with `applicable`, `mitigated`,
  `kernel_sink`, and per-layer activation booleans for dashboards.
- `posture.verdict`: headline string from v1.0.x, preserved for
  backwards compat.

## Remove

```sh
sudo /usr/sbin/copyfail-shim-disable
sudo dnf remove copyfail-defense
```

`%preun` scrubs `/etc/ld.so.preload` on full erase as a safety net,
and the modprobe drop file is removed; `%config(noreplace)` means the
operator's hand-edits to systemd drop-ins survive package upgrade.

---

## Coverage matrix

Which rung blocks which bug class. **✅** = primary mitigation; **·** =
not applicable; superscripts mark caveated coverage (notes below).

Rows below are mitigation rungs the package installs. Operator-applied
hardening (suid lockdown, auditd rules) is in its own table below
because no subpackage performs those actions; the auditor only
recommends them conditionally.

| Mitigation rung                                  | cf1 | cf2 | DF-ESP | DF-RxRPC | Fragnesia |
|---                                               |:---:|:---:|:---:   |:---:     |:---:      |
| LD_PRELOAD shim (`AF_ALG` hook)                  | ✅  |  ·  |   ·    |    ¹     |    ·      |
| modprobe `algif_aead` family                     | ²   |  ·  |   ·    |    ·     |    ·      |
| modprobe `esp4 esp6 xfrm_user xfrm_algo`         |  ·  | ✅  |  ✅    |    ·     |   ✅      |
| modprobe `rxrpc`                                 |  ·  |  ·  |   ·    |   ✅     |    ·      |
| systemd `RestrictAddressFamilies=~AF_ALG`        | ✅  |  ·  |   ·    |    ·     |    ·      |
| systemd `RestrictAddressFamilies=~AF_KEY` *(v2.0.2)* |  ·  | ✅  |  ✅    |    ·     |   ✅      |
| systemd `RestrictAddressFamilies=~AF_RXRPC`      |  ·  |  ·  |   ·    |   ✅     |    ·      |
| systemd `RestrictNamespaces=~user ~net`          |  ·  | ✅  |  ✅    |    ·     |   ✅      |
| sysctl `user.max_user_namespaces=0` *(v2.0.2)*   |  ·  | ✅  |  ✅    |    ·     |   ✅      |
| auditd tripwire rules *(v2.0.2)*                 | ³   | ³   |  ³     |   ³      |   ³       |

¹ Catches the `cksum` step in the public DF-RxRPC PoC, not the kernel
sink itself. Useful as defense-in-depth, not as a primary stop.
² No-op on RHEL stock kernels: `CRYPTO_USER_API*` is built-in, so the
blacklist line cannot prevent load. Listed for completeness on custom
or non-RHEL kernels where `algif_aead` ships modular. On RHEL the
supported workaround is `grubby --update-kernel ALL --args
"initcall_blacklist=algif_aead_init"` + reboot; the auditor reports
this state under MITIGATION.
³ Detection, not mitigation — telemetry for `socket(AF_ALG/AF_KEY/AF_RXRPC)`
syscalls from unprivileged users. Real value is on hosts where
modprobe blacklists are auto-suppressed (IPsec / AFS workloads) and
the kernel sink is intentionally reachable; rules become the
residual tripwire. Query via `ausearch -k copyfail_afalg` /
`copyfail_afkey` / `copyfail_afrxrpc`.

### Reference: kernel patches and detection signatures

| Class     | Upstream patch  | Audit signature                |
|---        |---              |---                             |
| cf1       | `a664bf3d`      | `socket(a0=38)` / `copyfail_afalg`   |
| cf2       | `f4c50a4034`    | `socket(a0=15)` / `copyfail_afkey` · `unshare(NEWUSER)` |
| DF-ESP    | `f4c50a4034`    | same as cf2                    |
| DF-RxRPC  | none upstream   | `socket(a0=33)` / `copyfail_afrxrpc` · `add_key("rxrpc",...)` |
| Fragnesia | netdev only (2026-05-13); not yet in stable trees | same as cf2 + `setsockopt(TCP_ULP="espintcp")` |

The auditor emits a page-cache integrity probe (cached IOC) for every
class; see `--json` `posture.bug_classes[*].kernel_sink`.

### Operator-applied (auditor-recommended)

These are surfaced via `--emit-remediation`. **No subpackage applies
them**, since each can break legitimate workloads on a busy fleet.
Review every line before pasting.

| Action                                                     | Targets       | When the auditor recommends it |
|---                                                         |---            |--- |
| `chmod 4750 /usr/bin/su && chgrp wheel /usr/bin/su`        | cf2, DF-ESP   | Suppressed when `/etc/passwd` shows non-wheel/admin interactive users (cPanel-style tenant fleets); chmod 4750 would break their `su` workflow. |
| `grubby --update-kernel ALL --args "initcall_blacklist=algif_aead_init"` + reboot | cf1 | RHEL kernels with `CRYPTO_USER_API_AEAD=y` (modprobe blacklist is a no-op on those); the supported escape per CIQ / Rocky Linux mitigation guidance. |
| `auditd` rule `cf_userns` (`unshare(CLONE_NEWUSER)`)       | cf2, DF-ESP   | Hosts where `auditd` is tuned for userns events (otherwise high alert noise). Pairs with the v2.0.2 `-audit` subpackage rules. |
| `auditd` rule `cf_addkey` (`add_key("rxrpc",...)`)         | DF-RxRPC      | Always; rxrpc keyring activity is rare enough that the false-positive rate stays low. The v2.0.2 `-audit` subpackage already installs the `socket(AF_RXRPC,...)` tripwire — `add_key` catches the next step in the chain. |

> 🔬 **Full writeup:** [Copy Fail (CVE-2026-31431) on rfxn.com/research](https://www.rfxn.com/research/copyfail-cve-2026-31431)
> covers cf1 kernel mechanics; cf2 and Dirty Frag extend the same
> primitive to two more sinks.

---

## What this protects against

The Copy Fail bug **class** is a deterministic page-cache-write
primitive: an unprivileged process uses `splice()` to plant a
read-only page-cache page (e.g., `/etc/passwd` or `/usr/bin/su`)
into a sender skb's `frag` slot, the receiver path performs in-place
crypto on top of that frag, and the resulting STORE writes
attacker-controlled bytes into the page cache. The on-disk file is
unchanged; the corruption lives in RAM until eviction.

| | Kernel sink | Privilege needed | Module |
|---|---|---|---|
| **cf1** (CVE-2026-31431) | `algif_aead` AEAD scratch-write | none | `algif_aead` (RHEL: builtin) |
| **cf2 / Dirty Frag-ESP** (CVE-2026-43284) | `esp_input` `skip_cow` path | `CAP_NET_ADMIN` via `unshare(NEWUSER\|NEWNET)` + SA install via `AF_KEY` or XFRM netlink | `esp4`, `xfrm_user` (RHEL: modules) |
| **Dirty Frag-RxRPC** (CVE-2026-43500) | `rxkad_verify_packet_1` in-place `pcbc(fcrypt)` | **none** | `rxrpc` (Ubuntu: loaded; RHEL: not in core) |
| **Fragnesia** (no CVE yet) | `espintcp` ULP after splice into TCP receive queue | same as cf2 | same as cf2 |

The same primitive shape, three different kernel sinks. Every layer in
this toolkit is independently useful; none is a silver bullet on its own.

---

## Defense in depth

Each rung defeats the bug by a **different mechanism**, so an attack
that defeats one doesn't necessarily defeat the next:

| Rung | Where it fails | What the next rung covers |
|---|---|---|
| **Kernel patch (vendor)** | EL7 EOL; EL8/9/10 patch rollout lags disclosure days-to-weeks; production reboot may not be available; **Dirty Frag-RxRPC has no upstream patch** | Userspace cuts close the window without a reboot |
| **modprobe blacklist** | No-op when the relevant module is **builtin** (RHEL `algif_aead` is); no effect on already-resident modules | Functional for `esp4`/`esp6`/`xfrm_user`/`xfrm_algo`/`rxrpc` on stock RHEL kernels (these are modules) |
| **systemd `RestrictAddressFamilies`/`RestrictNamespaces`** | Reaches only services systemd starts post-restriction. Misses cron-jobs running as root, sshd-pre-restriction, container payloads with their own pid 1 | LD_PRELOAD shim covers every dyn-linked process regardless of init |
| **LD_PRELOAD shim** | Static binaries; processes issuing `syscall` instruction directly; SUID binaries (kernel strips LD_PRELOAD for secure-exec) | seccomp at unit/runtime level catches direct-syscall path |
| **seccomp filter** | Per-service. Operationally heavy: each unit/runtime needs explicit policy | This package's systemd subpackage ships a one-line filter for the highest-leverage tenant units |

Where the shim itself fails (static binaries, direct `syscall`
instruction, SUID stripping) is **attacker engineering territory**.
The other rungs fail under **routine operator reality**: vendors
haven't shipped yet, the kernel was built with builtin crypto, the
threat surface includes a cron job. That asymmetry is the case for
deploying every rung this package ships.

---

## Subpackages

| Package | Arch | Contents |
|---|---|---|
| `copyfail-defense` | x86_64 | meta, pulls all six below (`-audit` as Recommends) |
| `copyfail-defense-shim` | x86_64 | `/usr/lib64/no-afalg.so` + `copyfail-shim-{enable,disable}` |
| `copyfail-defense-modprobe` | noarch | `/etc/modprobe.d/99-copyfail-defense-{cf1,cf2-xfrm,rxrpc}.conf` (cf-class entry-point cuts) |
| `copyfail-defense-systemd` | noarch | drop-ins for `user@`/`sshd`/`cron`/`crond`/`atd` + container-runtime examples |
| `copyfail-defense-sysctl` *(v2.0.2)* | noarch | `/etc/sysctl.d/99-copyfail-defense-userns.conf` (host-wide userns disable, suppressed on userns-consumer hosts) |
| `copyfail-defense-auditor` | noarch | `/usr/sbin/copyfail-local-check` (Python, stdlib-only, read-only) |
| `copyfail-defense-audit` *(v2.0.2)* | noarch | `/etc/audit/rules.d/99-copyfail-defense.rules` (syscall tripwires for AF_ALG / AF_KEY / AF_RXRPC) |

Per-EL binary RPMs are independently compiled against each
distribution's glibc (EL8: 2.28 with split `libdl`; EL9/EL10: 2.34+
with merged `libdl`). **Do not cross-install across ELs.** Direct
download links + sha256s:
[rfxn.github.io/copyfail](https://rfxn.github.io/copyfail/#direct-downloads).

---

## Auto-detection of conflicting workloads

v2.0.1+ inspects the host at install time for workloads the default
cuts would break, and **suppresses the conflicting drop-in only**
while keeping every other layer active. The intent is "do no harm to
running production"; nothing else relaxes.

### Why each workload triggers a carve-out

- **IPsec** — the kernel xfrm/ESP path *is* the cf2 / Dirty Frag-ESP
  kernel sink. Blacklisting `esp4`/`esp6`/`xfrm_user`/`xfrm_algo`
  disables IPsec tunnels entirely (no SA install, no encrypted
  traffic). Suppression keeps the modprobe drop off and leans on
  systemd `RestrictNamespaces=~user ~net` to block the unprivileged
  `unshare(NEWUSER|NEWNET)` step that gates the cf2 chain.
- **AFS** — `rxrpc` is both the DF-RxRPC kernel sink and the transport
  AFS itself rides on; blacklisting it breaks `openafs-client`. The
  per-unit `RestrictAddressFamilies=~AF_RXRPC` would also break AFS
  userspace tooling (`aklog`, `kinit`-style PAGs) when invoked from
  any of the five tenant units. Suppression drops both of those
  layers; every other rung still applies.
- **Rootless containers** — rootless `podman`/`buildah` needs
  `CLONE_NEWUSER` under the calling `user@.service`. Our default
  `RestrictNamespaces=~user ~net` on `user@.service` makes the
  `unshare(2)` return `EPERM`, which kills every rootless container.
  Suppression strips the userns drop-in **on `user@.service` only** —
  `sshd`/`cron`/`crond`/`atd` retain it.
- **Userns consumers** *(v2.0.2)* — Flatpak runtimes, firejail
  sandboxes, and desktop browser renderer sandboxes
  (Chromium/Chrome/Firefox) all rely on unprivileged user namespaces.
  Our v2.0.2 host-wide sysctl drop-in
  (`user.max_user_namespaces=0`) would break every one of them.
  Suppression strips **only the sysctl drop-in**; the per-tenant-unit
  `RestrictNamespaces=~user` cuts stay active. The same suppression
  also fires on rootless-container hosts (so the host-wide sysctl and
  the userns drop-in stay aligned).

### Detection signals

| Workload | Detection signals (any of) | Suppresses |
|---|---|---|
| **IPsec** (strongSwan, libreswan, openswan) | `systemctl is-enabled` returns enabled for strongswan/strongswan-starter/strongswan-swanctl/ipsec/libreswan/openswan/pluto; OR `/etc/ipsec.conf` has a `conn` stanza; OR non-empty `*.conf` in `/etc/swanctl/conf.d/`, `/etc/ipsec.d/`, `/etc/strongswan/conf.d/`, `/etc/strongswan.d/` | `99-copyfail-defense-cf2-xfrm.conf` (esp4, esp6, xfrm_user, xfrm_algo blacklist) |
| **AFS** (openafs, kafs) | `systemctl is-enabled` for openafs-client/openafs-server/kafs/afsd; OR `/etc/openafs/CellServDB` or `/etc/openafs/ThisCell` exists; OR `/etc/krb5.conf.d/openafs*` present; OR `/proc/fs/afs/` registered | `99-copyfail-defense-rxrpc.conf` (rxrpc modprobe blacklist) AND `12-copyfail-defense-rxrpc-af.conf` (`RestrictAddressFamilies=~AF_RXRPC` on all 5 tenant units) |
| **Rootless containers** (rootless podman/buildah) | `/home/*/.local/share/containers/storage/overlay-containers/` present with mtime within 180d (rootless podman storage tree); OR `/var/lib/containers/storage/` non-empty with mtime <90d; OR `/run/user/<UID>/containers/` present for any UID ≥ 1000 (live rootless tmpfs); OR `podman.socket` enabled (system-wide or any per-user instance) | `15-copyfail-defense-userns.conf` on `user@.service.d` **only** + `/etc/sysctl.d/99-copyfail-defense-userns.conf` (v2.0.2) |
| **Userns consumers** *(v2.0.2: Flatpak, firejail, desktop browser)* | non-empty `/var/lib/flatpak/{app,runtime}` OR per-user `~/.local/share/flatpak/app` within 180d; OR `/usr/bin/firejail` installed; OR `/usr/bin/{chromium,chromium-browser,google-chrome,firefox,firefox-esr}` present | `/etc/sysctl.d/99-copyfail-defense-userns.conf` (v2.0.2 host-wide userns sysctl) **only** — per-unit `RestrictNamespaces` stays active |

False-positive guards baked into the detector:

- `/etc/subuid` populated by `useradd` is **not** a rootless signal.
  shadow-utils auto-populates subuid for every regular user regardless
  of container intent, which produced near-100% FPs on cPanel-shaped
  fleets in v2.0.1 rev 1. Detection now requires *active* rootless
  usage (storage tree, runtime tmpfs, or enabled `podman.socket`).
- The rootful `/var/lib/containers/storage` signal is gated on
  `mtime < 90d` so a long-purged podman install doesn't keep
  triggering suppression.
- The `/home` walk is bounded (`maxdepth 6`, `mtime -180`) so a
  pathological tenant home tree can't stall `%posttrans`.
- The `/run/user/<UID>/containers` signal requires `UID ≥ 1000` so
  system-account artifacts under `/run/user/0` don't trip detection.

### What stays protected after a suppression

| Suppression triggered by | Layer dropped | Layers still active |
|---|---|---|
| **IPsec** | `99-cf2-xfrm.conf` modprobe blacklist | cf1 LD_PRELOAD shim · cf1 modprobe (`algif_aead` family) · `RestrictNamespaces=~user ~net` on all 5 tenant units (still blocks cf2/DF-ESP via the `unshare` gate) · `RestrictAddressFamilies=~AF_ALG ~AF_KEY ~AF_RXRPC` · `99-rxrpc.conf` blacklist · audit tripwire rules · host-wide userns sysctl (v2.0.2) |
| **AFS** | `99-rxrpc.conf` blacklist + `12-rxrpc-af.conf` (`AF_RXRPC` restrict) on all 5 tenant units | cf1 LD_PRELOAD shim · cf1 modprobe · `99-cf2-xfrm.conf` blacklist · `RestrictNamespaces=~user ~net` on all 5 units (cf2/DF-ESP) · `RestrictAddressFamilies=~AF_ALG ~AF_KEY` · audit tripwire rules (DF-RxRPC ausearch key still emits, gated by auid≥1000) · host-wide userns sysctl |
| **Rootless containers** | `15-userns.conf` on **`user@.service` only** + host-wide userns sysctl (v2.0.2) | All other layers; `sshd`/`cron`/`crond`/`atd` keep `RestrictNamespaces=~user ~net` (system-tier cf2/DF-ESP defense intact) · cf1 shim · all modprobe blacklists · `AF_ALG`/`AF_KEY`/`AF_RXRPC` restricts everywhere · audit tripwires |
| **Userns consumers** *(v2.0.2: Flatpak / firejail / desktop browser)* | Host-wide userns sysctl drop-in **only** | All per-unit drop-ins · all modprobe blacklists · cf1 shim · all `RestrictAddressFamilies` cuts · audit tripwires |

The cf1 shim and the auditor's tripwire layer are **never**
suppressed by auto-detection; CVE-2026-31431 coverage is unchanged on
every host.

### Inspect the decision

`%posttrans` writes a versioned JSON report. Read it any time:

```sh
sudo cat /var/lib/copyfail-defense/auto-detect.json
```

```json
{
  "schema_version": "2",
  "tool_version": "2.0.2",
  "force_full": false,
  "detected": {
    "ipsec":               { "present": true,  "signals": ["systemctl: strongswan.service enabled"] },
    "afs":                 { "present": false, "signals": [] },
    "rootless_containers": { "present": true,  "signals": ["systemctl --user (alice): podman.socket enabled"] },
    "userns_consumers":    { "present": true,  "signals": ["/usr/bin/firefox: desktop browser present"] }
  },
  "suppressed": {
    "modprobe_cf2_xfrm":      true,
    "modprobe_rxrpc":         false,
    "systemd_rxrpc_af":       false,
    "systemd_userns_user_at": true,
    "sysctl_userns":          true
  },
  "applied": { "modprobe_cf1": true, "systemd_userns_sshd": true, "sysctl_userns": false, "...": "..." }
}
```

Other inspection paths:

```sh
# Per-action log lines from %posttrans / copyfail-redetect
sudo journalctl -t copyfail-defense-detect --since today

# Auditor surface (SIEM-friendly)
sudo copyfail-local-check --json \
  | jq '.posture.auto_detect'
# {"available": true, "suppressed_modprobe": ["cf2_xfrm"], "suppressed_systemd": ["userns_user_at"]}
```

Detection runs in `%posttrans` after every install/upgrade and is
re-run on demand by `copyfail-redetect`. The auditor surfaces the
decision under `posture.auto_detect` for fleet dashboards.

### Re-detect after the host changes

If you enable IPsec / AFS / rootless containers / Flatpak / firejail
/ a desktop browser post-install:

```sh
sudo /usr/sbin/copyfail-redetect
sudo systemctl daemon-reload
sudo systemctl try-reload-or-restart sshd.service
sudo sysctl --system   # (v2.0.2) if the sysctl drop-in was added or removed
```

The helper re-runs detection, refreshes `auto-detect.json`, and
copies/removes the conditional drop-in files in `/etc/` (modprobe,
systemd, **and sysctl** in v2.0.2). It does NOT auto-reload systemd
or sysctl - the operator decides when running services pick up the
change.

**Removing the sysctl drop-in does not reset the running-kernel
value.** `user.max_user_namespaces` stays at `0` until either another
sysctl.d file sets it, or the host reboots. To restore the default
without reboot:

```sh
sudo sysctl -w user.max_user_namespaces=$(zcat /proc/config.gz \
    | grep -F CONFIG_USER_NS_DEFAULT_LIMIT \
    | cut -d= -f2 \
    || echo 31742)   # kernel default; 31742 on recent mainline
```

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
file is **removed** - it broke dnf via EPERM on the next
`install -m 0644` from `%posttrans`. Use the cmp-and-skip
behavior or `force-full` instead.

---
## Verifying signatures

1.0.1+ and 2.0.0+ are signed by the **Copyfail Project Signing Key**.
The `.repo` file enforces both `gpgcheck=1` (per-RPM) and
`repo_gpgcheck=1` (detached `repomd.xml.asc` over the metadata), so a
stock `dnf install` does end-to-end verification automatically.

```
fingerprint: 6001 1CDC EA2F F52D 975A  FDEE 6D30 F32C D5E8 0F80
uid:         Copyfail Project Signing Key <proj@rfxn.com>
key file:    https://rfxn.github.io/copyfail/RPM-GPG-KEY-copyfail
```

Out-of-band verification of a downloaded RPM:

```sh
curl -sSL https://rfxn.github.io/copyfail/RPM-GPG-KEY-copyfail \
  | sudo rpm --import /dev/stdin
rpm -K copyfail-defense-2.0.2-1.el9.x86_64.rpm
# expect: digests signatures OK
```

---

## Auditor JSON schema (v2.0)

`--json` emits a structured object. The headline fields:

```json
{
  "schema_version": "2.0",
  "covers": ["CVE-2026-31431", "cf2-xfrm-esp", "dirtyfrag-esp", "dirtyfrag-rxrpc"],
  "posture": {
    "verdict": "vulnerable_kernel_userspace_mitigated",
    "bug_classes_covered": ["cf1", "cf2", "dirtyfrag-esp"],
    "bug_classes": {
      "cf1":             { "applicable": true, "mitigated": true,  "kernel_sink": "...", "layers": {...} },
      "cf2":             { "applicable": true, "mitigated": true,  "kernel_sink": "...", "layers": {...} },
      "dirtyfrag-esp":   { "applicable": true, "mitigated": true,  "kernel_sink": "...", "layers": {...} },
      "dirtyfrag-rxrpc": { "applicable": true, "mitigated": false, "kernel_sink": "...", "layers": {...} }
    },
    "layers": { ... },
    "auto_detect": {
      "available": true,
      "suppressed_modprobe": [],
      "suppressed_systemd": []
    }
  }
}
```

`bug_classes_covered` is the SIEM-ergonomic single filter ("is this
host hardened?"). `bug_classes` map exposes per-layer breakdown for
finer dashboards. `verdict` and `layers` from v1.0.x are preserved for
backwards compatibility.

`--emit-remediation` prints a bash script aggregating per-check
remediation hints. Output is **fully commented** by default; review
every block before pasting (chmod on suid binaries, modprobe blacklist,
unprivileged-userns sysctl are policy-dependent or require a reboot to
undo).

---

## Build from source

`no-afalg.c` is single-file, no build system. Tested on EL7
(gcc 4.8 / glibc 2.17), EL8 (gcc 8.5 / glibc 2.28), EL9 (gcc 11.5 /
glibc 2.34), and EL10 (gcc 14 / glibc 2.39). x86_64 only.

```sh
gcc -shared -fPIC -O2 -Wall -Wextra \
    -o /usr/lib64/no-afalg.so no-afalg.c -ldl
```

To rebuild the RPMs from the published SRPM (under your own signing):

```sh
mock -r centos-stream+epel-9-x86_64 --rebuild \
  https://github.com/rfxn/copyfail/releases/download/v2.0.2/copyfail-defense-2.0.2-1.el9.src.rpm
```

The spec lives at `packaging/copyfail-defense.spec`.

---

## Limitations

- **x86_64 only.** The shim has architecture asserts; the auditor's
  trigger probe struct layout is x86_64. Patches welcome for arm64.
- The userspace shim is irrelevant to static binaries and
  syscall-instruction issuers. Other rungs (modprobe, systemd
  RestrictNamespaces, kernel patch) cover those.
- **Dirty Frag-RxRPC has no upstream patch** as of v2.0.0 ship date.
  Mitigation is the `rxrpc` modprobe blacklist + systemd
  `RestrictAddressFamilies=~AF_RXRPC` until upstream merges V4bel's
  proposed gate (`skb_cloned(skb) || skb->data_len`).
- modprobe blacklists do not unload already-resident modules. The
  package's `%post modprobe` does a best-effort `rmmod`; reboot to
  fully clear.
- Auditor's trigger probe is destructive *only* against its own
  sentinel; it will not corrupt anything you would notice. It will,
  however, briefly load `algif_aead` and friends if they aren't
  already loaded (which is the point).
- **v2.0.2:** the `-audit` subpackage installs three tripwire rules
  catching `socket(AF_ALG/AF_KEY/AF_RXRPC)` from unprivileged users
  (filtered to `auid>=1000`); installed by default via the meta
  `Recommends` (skip with `--setopt=install_weak_deps=false`). The
  auditor's `--emit-remediation` still surfaces additional rules
  (`cf_userns` for `unshare(CLONE_NEWUSER)`, `cf_addkey` for
  `add_key("rxrpc",...)`) that are out of scope for the default
  install because they depend on operator-tuned auditd context.
- **v2.0.2 sysctl drop-in:** removing `-sysctl` does NOT reset
  `user.max_user_namespaces` to the kernel default — the running
  kernel value persists until reboot or another sysctl.d drop-in
  overrides it. See "Re-detect after the host changes" above.

## License

GPL v2. See `LICENSE`.

---

[rfxn.com](https://www.rfxn.com/) | forged in prod | Ryan MacDonald
