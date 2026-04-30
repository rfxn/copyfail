<div align="center">

# copyfail - CVE-2026-31431

**Local privilege escalation via the AF_ALG `authencesn` page-cache primitive.**
The kernel mis-bounds an AEAD decrypt and writes attacker-controlled bytes
into the page cache of any SUID binary or privileged config file.
No file on disk changes; the corruption lives in RAM until eviction.
No on-disk forensic artefacts.

Userspace defense-in-depth: an `LD_PRELOAD` shim that blocks `AF_ALG`
socket creation and a read-only host posture auditor.
Signed RPMs for EL8 / EL9 / EL10.

<a href="https://rfxn.github.io/copyfail/"><img src="https://img.shields.io/badge/%F0%9F%93%A6%20yum%2Fdnf%20repo-rfxn.github.io%2Fcopyfail-22d3ee?style=for-the-badge&labelColor=09090b" alt="copyfail yum/dnf package repo"></a>
<a href="https://www.rfxn.com/research/copyfail-cve-2026-31431"><img src="https://img.shields.io/badge/%F0%9F%94%AC%20deep%20dive-rfxn.com%2Fresearch-d97757?style=for-the-badge&labelColor=09090b" alt="Deep-dive research article on rfxn.com"></a>

[![CVE](https://img.shields.io/badge/CVE-2026--31431-d97757?labelColor=09090b)](#what-this-protects-against)
[![Severity](https://img.shields.io/badge/severity-LOCAL%20PRIVESC-d44d4d?labelColor=09090b)](#what-this-protects-against)
[![License](https://img.shields.io/badge/license-GPL--2.0-22d3ee?labelColor=09090b)](LICENSE)
[![EL8/9/10](https://img.shields.io/badge/EL-8%20%2F%209%20%2F%2010-4ade80?labelColor=09090b)](https://rfxn.github.io/copyfail/)
[![Latest release](https://img.shields.io/github/v/release/rfxn/copyfail?label=release&color=22d3ee&labelColor=09090b)](https://github.com/rfxn/copyfail/releases/latest)

[Install](#install) · [Audit](#audit-the-host) · [Defense-in-depth](#defense-in-depth-where-this-rung-carries-weight-on-its-own) · [Subpackages](#subpackages) · [Verify signatures](#verifying-signatures)

</div>

---

> [!NOTE]
> The shim is installed but **not auto-enabled** - activation is an explicit
> operator step (`copyfail-shim-enable`) so a broken upgrade can't brick a
> host. The auditor is read-only by design: writes only to `mkdtemp()`
> sentinels, never modifies `/usr/bin` or `/etc`.

---

## Install

```sh
sudo curl -sSL https://rfxn.github.io/copyfail/copyfail.repo \
  -o /etc/yum.repos.d/copyfail.repo
sudo dnf install -y afalg-defense
```

One repo file works on EL8/EL9/EL10 (dnf substitutes `$releasever`/`$basearch`
per host). RPMs are GPG-signed; dnf imports the public key on first use
— cross-check the fingerprint when prompted:

```
6001 1CDC EA2F F52D 975A  FDEE 6D30 F32C D5E8 0F80
```

Auditor only (no `LD_PRELOAD`, for hot infrastructure):

```sh
sudo dnf install -y afalg-defense-auditor
```

## Activate the shim

The shim is installed but **not auto-enabled**. Wiring
`/etc/ld.so.preload` from a `%post` would brick the host on any broken
upgrade — activation is an explicit operator step:

```sh
sudo /usr/sbin/copyfail-shim-enable      # smoke-tests, then writes /etc/ld.so.preload
sudo /usr/sbin/copyfail-shim-disable     # reverses it
```

The enable helper does `LD_PRELOAD=$shim /bin/true` first; if the .so
cannot be loaded the helper refuses to update the file rather than risk
locking you out.

## Also blacklist the AF_ALG modules (where loadable)

The package also ships an equally low-barrier mitigation: a `modprobe`
drop-in that severs `algif_aead`, `authenc`, and `authencesn` at the
kernel level. When your kernel exposes AF_ALG as a loadable module —
most stock mainline kernels do — this **stacks with the shim** and
deserves equal weight. The shim blocks every userspace caller at libc;
the blacklist removes the kernel attack surface entirely. Different
mechanisms, both one-line operator actions.

```sh
# Decide whether the blacklist will be effective on this kernel.
ls /sys/module/algif_aead 2>/dev/null && echo "modular - blacklist effective" \
    || echo "builtin or absent - shim is your primary defense"
grep -E 'ALG_USERMODE|CRYPTO_USER_API' /boot/config-$(uname -r) 2>/dev/null
# =m -> modular (blacklist is primary)   =y -> builtin (shim is primary)

# If it's modular, drop a blacklist into /etc/modprobe.d/ and unload
# anything already resident. The CVE-2026-31431 chain is the trio at
# the bottom; the algif_* family is added for general AF_ALG hygiene.
sudo tee /etc/modprobe.d/99-no-afalg.conf >/dev/null <<'EOF'
install af_alg          /bin/false
install algif_aead      /bin/false
install algif_skcipher  /bin/false
install algif_hash      /bin/false
install algif_rng       /bin/false
install authenc         /bin/false
install authencesn      /bin/false
EOF
sudo rmmod algif_aead authenc authencesn 2>/dev/null || true
```

(The package also ships this file under
`/usr/share/doc/afalg-defense/examples/no-afalg-modprobe.conf` — same
content, copy that into place if you prefer the audit trail.) Where
your kernel allows it, deploy **both** the shim and the blacklist —
belt-and-suspenders coverage for the price of two `sudo` commands.

## Verify

```sh
python3 -c 'import socket; socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)'
# expect: PermissionError [Errno 1] Operation not permitted
```

Blocked attempts log to `auth.priv`:

```
no-afalg[12345]: blocked AF_ALG (domain=38) via socket uid=0 euid=0 pid=12345
```

## Audit the host

```sh
sudo copyfail-local-check                # human-readable, only flags non-OK
sudo copyfail-local-check --json         # SIEM ingestion (posture.verdict)
sudo copyfail-local-check --emit-remediation   # bash script of suggested fixes
```

Read-only by design: writes only to `mkdtemp()` sentinels, never modifies
`/usr/bin` or `/etc`, runs unprivileged (some checks degrade gracefully
without root). Five categories: `ENV`, `KERNEL`, `MITIGATION`,
`HARDENING`, `DETECTION`.

Exit codes: `0` clean · `2` **VULN** (no userspace mitigation) ·
`3` VULN-but-mitigated · `4` hardening recommendations only.

## Remove

```sh
sudo /usr/sbin/copyfail-shim-disable
sudo dnf remove afalg-defense afalg-defense-shim afalg-defense-auditor
```

`%preun` also scrubs `/etc/ld.so.preload` on full erase as a safety
net, but disabling first keeps the operation transparent.

---

## What this protects against

> 🔬 **Full writeup:** [Copy Fail (CVE-2026-31431) — rfxn.com/research](https://www.rfxn.com/research/copyfail-cve-2026-31431)
> covers the kernel-level mechanics, exploit primitives, and why the
> userspace shim closes the practical attacker windows. Brief
> summary below.

`AF_ALG`'s `authencesn(hmac(sha256),cbc(aes))` AEAD path miscomputes
output length on decrypt, returning more bytes to userspace than were
actually authenticated. When the destination of that decrypt is a pipe
spliced from the page cache of a SUID binary or privileged config file,
the kernel writes attacker-controlled bytes into clean page-cache
pages — visible to every subsequent reader, including `execve()` of
`/usr/bin/su`. **No file on disk is changed**; the corruption lives in
RAM until pages are evicted.

The result is a local privilege-escalation primitive that does not
require a kernel module to be loaded by the attacker (the relevant
crypto modules are auto-loaded by `socket(AF_ALG, ...)` itself on most
distributions) and that **leaves no on-disk forensic artefacts**.

## Defense-in-depth: where this rung carries weight on its own

There are five layers of defense for AF_ALG-class bugs, and every one
has failure modes. The point of this package is that the conditions
that defeat the rungs above it are **not the same conditions that
defeat the shim** — which is what makes the shim a viable primary
defense, not just a backup.

| Rung | Where it fails | What the shim does there |
|---|---|---|
| 1. Kernel patch (vendor) | EL7 is EOL; EL8/EL9/EL10 patch rollout lags disclosure by days to weeks; production reboot may not be available in the window the bug is hot | **Closes the window without a reboot.** Live install, no kernel touch |
| 2. `modprobe` blacklist of `algif_aead` / `authenc` / `authencesn` | Only when these are loaded as **modules** (not builtin) — and not already resident from earlier in boot. **On modular kernels (most stock mainline), this is an equally low-barrier primary defense** that stacks with the shim. Becomes a no-op when `algif_aead` is builtin (the RHEL default) | **Picks up the slack on builtin-crypto kernels** — every userspace caller still goes through libc `socket(2)` regardless of how the kernel exposed AF_ALG |
| 3. systemd `RestrictAddressFamilies=~AF_ALG` | Reaches only services systemd starts post-restriction. Misses **cron jobs, sshd login shells, container payloads with their own pid 1**, anything pre-restriction | **Global.** `/etc/ld.so.preload` applies to every dynamic-linked process regardless of which init started it |
| 4. **`LD_PRELOAD` shim (this package)** | Static binaries; processes issuing the `syscall` instruction directly; SUID binaries (kernel strips `LD_PRELOAD` for secure-exec) | (see right column for coverage scope) |
| 5. seccomp filter (per-unit / container-runtime) | Per-service. Operationally heavy: each unit/runtime needs an explicit policy | **One .so + one ld.so.preload line** covers the whole host |

Where the shim itself fails — static binaries, direct `syscall`
instruction, SUID stripping — is **attacker engineering territory**.
The other rungs fail under **routine operator reality**: vendors
haven't shipped yet, the kernel was built with builtin crypto, the
threat surface includes a cron job. That asymmetry is the case for
deploying this rung first.

### When this is your primary defense

- The vendor kernel patch isn't out yet (zero-day window).
- It is out, but you can't reboot the host *right now*.
- The kernel has `algif_aead` builtin (so `modprobe` blacklist is a
  no-op).
- Your threat surface includes anything outside systemd — cron, login
  shells, container payloads, anything inheriting from a
  pre-restriction unit.
- You don't have the operational bandwidth to write per-service
  seccomp policy for every daemon.

The auditor scores all five rungs against the running host and tells
you which are present, stale, or bypassable — so you can layer
additional defenses as they become available without losing track of
what's actually load-bearing right now.

## What the shim deliberately does NOT do

It does not wrap `syscall(2)`. Reading six `long` varargs unconditionally
is undefined behaviour, and the bypasses it would catch
(`syscall(SYS_socket, AF_ALG, ...)` and inline-asm `syscall` instruction)
are unblockable from userspace anyway. Pair with seccomp or the kernel
patch for that surface.

---

## Subpackages

| Package | Arch | Contents |
|---|---|---|
| `afalg-defense` | x86_64 | meta — pulls shim + auditor |
| `afalg-defense-shim` | x86_64 | `/usr/lib64/no-afalg.so` + `copyfail-shim-{enable,disable}` |
| `afalg-defense-auditor` | noarch | `/usr/sbin/copyfail-local-check` (Python, stdlib-only, read-only) |

Per-EL binary RPMs are independently compiled against each
distribution's glibc (EL8: 2.28 with split `libdl`; EL9/EL10: 2.34+
with merged `libdl`). **Do not cross-install across ELs.** Direct
download links + sha256s:
[rfxn.github.io/copyfail](https://rfxn.github.io/copyfail/#direct-downloads).

## Verifying signatures

1.0.1 and later are signed by the **Copyfail Project Signing Key**.
The `.repo` file enforces both `gpgcheck=1` (per-RPM) and
`repo_gpgcheck=1` (detached `repomd.xml.asc` over the metadata) — so a
stock `dnf install` does end-to-end verification automatically.

```
fingerprint: 6001 1CDC EA2F F52D 975A  FDEE 6D30 F32C D5E8 0F80
uid:         Copyfail Project Signing Key <proj@rfxn.com>
key file:    https://rfxn.github.io/copyfail/RPM-GPG-KEY-copyfail
```

Out-of-band:

```sh
curl -sSL https://rfxn.github.io/copyfail/RPM-GPG-KEY-copyfail \
  | sudo rpm --import /dev/stdin
rpm -K afalg-defense-1.0.1-1.el9.x86_64.rpm
# expect: digests signatures OK
```

## Auditor JSON schema

`--json` emits a structured object SIEMs/dashboards can ingest
directly. The headline is `posture.verdict`; consume that, not the
human report.

```json
{
  "posture": {
    "verdict": "vulnerable_kernel_userspace_mitigated",
    "layers": {
      "kernel_patched":      "missing",
      "af_alg_unreachable":  "missing",
      "modprobe_blacklist":  "missing",
      "ld_preload_shim":     "ok",
      "systemd_restriction": "missing",
      "user_service_dropin": "missing",
      "seccomp_runtime":     "skipped",
      "auditd_running":      "ok",
      "audit_rule_af_alg":   "ok"
    }
  }
}
```

`verdict` is one of: `patched`, `kernel_likely_safe`, `inconclusive`,
`vulnerable_kernel_userspace_mitigated`, `vulnerable`. Designed so a
fleet console can render a per-host posture row without re-implementing
verdict logic over the raw checks.

`--emit-remediation` prints a bash script aggregating the per-check
remediation hints. Output is **fully commented** by default; review
every block before pasting (chmod on suid binaries, `modules_disabled`
sysctl, modprobe blacklist are policy-dependent or require a reboot to
undo).

## Why these checks?

The auditor is structured by attack-chain layer, not by checklist
convenience. Each category answers a specific question about the host:

- **`KERNEL`** — is the primitive actually reachable?
  AF_ALG socket open, cipher availability, `algif_aead` setsockopt,
  live trigger probe (only check that produces a definitive `VULN`).
- **`MITIGATION`** — if the kernel is vulnerable, is anything stopping
  the bug? `/etc/ld.so.preload` content, shim live-block test,
  `modprobe` blacklist, `/proc/modules` ground truth, systemd
  `RestrictAddressFamilies`, drop-in freshness vs running daemon,
  seccomp filter status.
- **`HARDENING`** — if mitigation fails, what is the blast radius?
  SUID inventory, page-cache vs `O_DIRECT` integrity sample (stable
  divergence is a potential IOC), `getcap -r` for non-SUID privilege.
- **`DETECTION`** — would we know if someone tried? `auditd` running
  with rules covering `socket(38)`, recent IOC signals in
  `auth.priv` and `audit.log`.
- **`ENV`** — context: kernel, distro, glibc, root status. Surfaces
  "skip" reasons up front so an unhelpful run doesn't look like a clean
  run.

---

## Build from source

`no-afalg.c` is single-file, no build system. Tested on EL7
(gcc 4.8 / glibc 2.17), EL8 (gcc 8.5 / glibc 2.28), EL9 (gcc 11.5 /
glibc 2.34), and EL10 (gcc 14 / glibc 2.39). x86_64 only.

```sh
gcc -shared -fPIC -O2 -Wall -Wextra \
    -o /usr/lib64/no-afalg.so no-afalg.c -ldl
echo /usr/lib64/no-afalg.so > /etc/ld.so.preload
```

To rebuild the RPMs from the published SRPM (under your own signing):

```sh
mock -r centos-stream+epel-9-x86_64 --rebuild \
  https://github.com/rfxn/copyfail/releases/download/v1.0.1/afalg-defense-1.0.1-1.el9.src.rpm
```

The spec lives at `packaging/afalg-defense.spec`.

## Limitations

- **x86_64 only.** The `AF_ALG` constant is universal but the
  `LD_PRELOAD` shim has architecture asserts and the trigger probe's
  struct layout is tested only on x86_64. Patches welcome for arm64.
- The userspace shim is irrelevant to static binaries and
  syscall-instruction issuers (see "What the shim deliberately does
  NOT do" above).
- `modprobe` blacklists do not unload already-resident modules. If
  `/proc/modules` shows them present after a blacklist edit, you need
  a reboot or `rmmod`.
- The auditor's trigger probe is destructive *only* against its own
  sentinel — it will not corrupt anything you would notice. It will,
  however, briefly load `algif_aead` and friends if they aren't already
  loaded (which is the point).

## License

GPL v2. See `LICENSE`.

---

[rfxn.com](https://www.rfxn.com/) | forged in prod | Ryan MacDonald
