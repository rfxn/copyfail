<div align="center">

# copyfail-defense

**Defense-in-depth toolkit for the Copy Fail Linux kernel bug class.**
Covers three live LPE chains that share the same `splice()` →
`MSG_SPLICE_PAGES` → in-place page-cache write primitive:

| | CVE | Sink | Primitive |
|---|---|---|---|
| **cf1** | CVE-2026-31431 | `algif_aead` AEAD scratch-write | 4-byte STORE via `seqno_lo` |
| **cf2** | (no CVE yet) | `esp_input` skip_cow | 4-byte STORE via `seq_hi` |
| **Dirty Frag** | (embargo broken, no CVE) | `esp_input` + `rxkad_verify_packet_1` | 4-byte and 8-byte STORE |

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
> Upgrading from `afalg-defense` v1.0.x is a single command:
> `dnf upgrade copyfail-defense`. The `Obsoletes:`/`Provides:` chain
> performs the rename swap automatically and pulls in the new
> subpackages. The shim is **still not auto-enabled**; activation
> remains an explicit operator step.

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

The meta package pulls four subpackages:

| Subpackage | Coverage |
|---|---|
| `copyfail-defense-shim` | LD_PRELOAD AF_ALG block (cf1 primary) |
| `copyfail-defense-modprobe` | kernel-module entry-point cuts (cf1 + cf2 + Dirty Frag) |
| `copyfail-defense-systemd` | per-unit `RestrictAddressFamilies=~AF_ALG ~AF_RXRPC` + `RestrictNamespaces=~user ~net` (all three classes) |
| `copyfail-defense-auditor` | read-only host posture auditor with per-class coverage report |

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

| Mitigation rung                                  | cf1 | cf2 | DF-ESP | DF-RxRPC |
|---                                               |:---:|:---:|:---:   |:---:     |
| LD_PRELOAD shim (`AF_ALG` hook)                  | ✅  |  ·  |   ·    |    ¹     |
| modprobe `algif_aead` family                     | ²   |  ·  |   ·    |    ·     |
| modprobe `esp4 esp6 xfrm_user xfrm_algo`         |  ·  | ✅  |  ✅    |    ·     |
| modprobe `rxrpc`                                 |  ·  |  ·  |   ·    |   ✅     |
| systemd `RestrictAddressFamilies=~AF_ALG`        | ✅  |  ·  |   ·    |    ·     |
| systemd `RestrictAddressFamilies=~AF_RXRPC`      |  ·  |  ·  |   ·    |   ✅     |
| systemd `RestrictNamespaces=~user ~net`          |  ·  | ✅  |  ✅    |    ·     |
| Suid lockdown (`chmod 4750 /usr/bin/su`)         |  ·  | ✅  |  ✅    |    ·     |

¹ Catches the `cksum` step in the public DF-RxRPC PoC, not the kernel
sink itself. Useful as defense-in-depth, not as a primary stop.
² No-op on RHEL stock kernels: `CRYPTO_USER_API*` is built-in, so the
blacklist line cannot prevent load. Listed for completeness on custom
or non-RHEL kernels where `algif_aead` ships modular.

### Reference: kernel patches and detection signatures

| Class    | Upstream patch  | Audit signature        |
|---       |---              |---                     |
| cf1      | `a664bf3d`      | `socket(a0=38)`        |
| cf2      | `f4c50a4034`    | `unshare(NEWUSER)`     |
| DF-ESP   | `f4c50a4034`    | `unshare(NEWUSER)`     |
| DF-RxRPC | none upstream   | `add_key("rxrpc",...)` |

The auditor emits a page-cache integrity probe (cached IOC) for every
class; see `--json` `posture.bug_classes[*].kernel_sink`.

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
| **cf2** ("Electric Boogaloo") | `esp_input` `skip_cow` path | `CAP_NET_ADMIN` via `unshare(NEWUSER\|NEWNET)` | `esp4`, `xfrm_user` (RHEL: modules) |
| **Dirty Frag-ESP** | same as cf2 | same as cf2 | same as cf2 |
| **Dirty Frag-RxRPC** | `rxkad_verify_packet_1` in-place `pcbc(fcrypt)` | **none** | `rxrpc` (Ubuntu: loaded; RHEL: not in core) |

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
| `copyfail-defense` | x86_64 | meta, pulls all four below |
| `copyfail-defense-shim` | x86_64 | `/usr/lib64/no-afalg.so` + `copyfail-shim-{enable,disable}` |
| `copyfail-defense-modprobe` | noarch | `/etc/modprobe.d/99-copyfail-defense.conf` (cf-class entry-point cuts) |
| `copyfail-defense-systemd` | noarch | drop-ins for `user@`/`sshd`/`cron`/`crond`/`atd` + container-runtime examples |
| `copyfail-defense-auditor` | noarch | `/usr/sbin/copyfail-local-check` (Python, stdlib-only, read-only) |

Per-EL binary RPMs are independently compiled against each
distribution's glibc (EL8: 2.28 with split `libdl`; EL9/EL10: 2.34+
with merged `libdl`). **Do not cross-install across ELs.** Direct
download links + sha256s:
[rfxn.github.io/copyfail](https://rfxn.github.io/copyfail/#direct-downloads).

---

## Override paths

Three workload classes legitimately need the surfaces this package
restricts: **rootless podman/buildah**, **IPsec**, and **AFS**. Each
has a per-unit opt-out below.

The default install applies `RestrictNamespaces=~user ~net` to
`user@.service` (and other tenant units). This **breaks rootless
podman/buildah** under `user@.service`. To opt out per-unit:

```sh
sudo install -d /etc/systemd/system/user@.service.d
sudo tee /etc/systemd/system/user@.service.d/20-override.conf >/dev/null <<'EOF'
[Service]
RestrictNamespaces=
RestrictAddressFamilies=
EOF
sudo systemctl daemon-reload
```

The `99-` prefix on the modprobe drop and the `10-` prefix on systemd
drop-ins are deliberate: any `20-*.conf` drop-in you add overrides
ours.

If your fleet legitimately uses **IPsec** (strongSwan, libreswan,
FRRouting), the modprobe subpackage's blacklist of `esp4`/`esp6`/
`xfrm_user`/`xfrm_algo` will break those workloads. Either skip the
modprobe subpackage:

```sh
sudo dnf install copyfail-defense-shim copyfail-defense-systemd \
                 copyfail-defense-auditor
# (omit copyfail-defense and copyfail-defense-modprobe)
```

…or remove the relevant entries from `/etc/modprobe.d/99-copyfail-defense.conf`
(the file is `%config(noreplace)`, so your edit survives package upgrade).

Same logic for **AFS** (`openafs`, `kafs`) and the `rxrpc` blacklist line.

If your fleet runs **rootless or userns-remapped containers** under
`containerd`/`docker`/`podman` service units, the default install does
NOT touch those by design. Container-runtime drop-ins ship as
opt-in examples under `/usr/share/doc/copyfail-defense/examples/` for
operators who have confirmed no rootless workloads:

```sh
for u in containerd docker podman; do
    sudo install -d /etc/systemd/system/${u}.service.d
    sudo cp /usr/share/doc/copyfail-defense/examples/containers-dropin.conf \
            /etc/systemd/system/${u}.service.d/10-copyfail-defense.conf
done
sudo systemctl daemon-reload
```

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
rpm -K copyfail-defense-2.0.0-1.el9.x86_64.rpm
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
    "layers": { ... }
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
  https://github.com/rfxn/copyfail/releases/download/v2.0.0/copyfail-defense-2.0.0-1.el9.src.rpm
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
- `auditd` rules (cf_userns, cf_addkey) are **emitted by
  `--emit-remediation`, not installed by the package**. Auditd
  rules cause unnecessary alerting on hosts where auditd is not
  tuned for them; operator action required.

## License

GPL v2. See `LICENSE`.

---

[rfxn.com](https://www.rfxn.com/) | forged in prod | Ryan MacDonald
