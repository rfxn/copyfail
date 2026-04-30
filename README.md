# copyfail / afalg-defense

Userspace defense-in-depth primitives against **CVE-2026-31431
("Copy Fail")** — the AF_ALG / `authencesn` page-cache corruption
local privilege-escalation primitive. Ships an `LD_PRELOAD` shim that
blocks `AF_ALG` socket creation and a comprehensive read-only host
posture auditor, packaged as **signed RPMs for EL8 / EL9 / EL10**.

> **Project page (install instructions, downloads, signing key):
> [rfxn.github.io/copyfail](https://rfxn.github.io/copyfail/)**
> &nbsp;|&nbsp; [Latest release](https://github.com/rfxn/copyfail/releases/latest)
> &nbsp;|&nbsp; [File an issue](https://github.com/rfxn/copyfail/issues/new/choose)

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
| 2. `modprobe` blacklist of `algif_aead` / `authenc` / `authencesn` | No-op when `algif_aead` is built into the kernel (the **RHEL default**); already-resident modules from earlier in boot | **Still effective** — every userspace caller goes through libc `socket(2)` regardless of how the kernel exposed AF_ALG |
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
