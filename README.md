# Copy Fail - Defense-in-Depth Primitives for CVE-2026-31431

Kernel-side audit probe and a userspace mitigation shim for the
`AF_ALG` / `authencesn` page-cache corruption bug, a.k.a. **Copy
Fail** (CVE-2026-31431).

| Primitive | File | Layer |
|---|---|---|
| Comprehensive detection / posture auditor | `copyfail-local-check.py` | userspace, read-only |
| `LD_PRELOAD` shim that blocks `AF_ALG` socket creation | `no-afalg.c` | userspace, glibc-resident |

Both are designed to be safe to fleet-deploy: read-only by design
(the auditor) or fail-open on any non-`AF_ALG` traffic (the shim).

---

## The bug, briefly

`AF_ALG`'s `authencesn(hmac(sha256),cbc(aes))` AEAD path miscomputes
output length on decrypt, returning more bytes to userspace than were
actually authenticated. When the destination of that decrypt is a pipe
spliced from the page cache of a SUID binary or privileged config
file, the kernel writes attacker-controlled bytes into clean
page-cache pages - visible to every subsequent reader, including
`execve()` of `/usr/bin/su`. No file on disk is changed; the
corruption lives in RAM until pages are evicted.

The result is a local privilege-escalation primitive that does not
require a kernel module to be loaded by the attacker (the relevant
crypto modules are auto-loaded by `socket(AF_ALG, ...)` itself on most
distributions) and that leaves no on-disk forensic artefacts.

---

## Defense-in-depth framing

No single layer is enough. The reasons each layer can be defeated are
the reasons all of them ship together:

1. **Kernel patch (vendor).** The only complete fix. Not always
   available - EL7 is out of maintenance, and EL8/9/10 patch rollout
   lags disclosure by days to weeks. Until then:

2. **`modprobe` blacklist of `algif_aead`, `authenc`, `authencesn`.**
   Defeats the auto-load path. Bypassed if the modules are already
   resident (e.g. another consumer pulled them in earlier in boot) or
   if the kernel is built with these statically.

3. **systemd `RestrictAddressFamilies=` drop-in dropping `AF_ALG`
   (`38`) from the global default.** Defeats *new* services started
   by systemd. Bypassed by anything started outside systemd: cron
   jobs, sshd login shells, container payloads with their own pid 1,
   anything inheriting from a pre-restriction unit.

4. **`LD_PRELOAD` shim (this repo's `no-afalg.so`).** Defeats every
   dynamically-linked process that goes through libc's `socket(2)` /
   `socketpair(2)` - which is essentially every distro binary. **It
   does not stop:** static binaries, processes that issue the syscall
   instruction directly (`syscall(SYS_socket, AF_ALG, ...)` or inline
   asm), or processes that disable `LD_PRELOAD` (setuid binaries
   strip it; the kernel patch is the answer there, not a userspace
   shim).

5. **seccomp filter at the systemd-unit or container-runtime level.**
   The only userspace mechanism that catches the direct-syscall
   bypass. Operationally heavier than the others; recommended for
   high-value services that you can wrap individually (sshd,
   cpsrvd, tomcat, etc.).

The auditor scores all five layers and tells you which are present,
which are stale, and which are bypassable on the current host. It
does **not** assume that any single layer is sufficient.

---

## Building and installing the LD_PRELOAD shim

`no-afalg.c` is single-file, no build system. Tested on EL7 (gcc 4.8 /
glibc 2.17), EL8 (gcc 8.5 / glibc 2.28), EL9 (gcc 11.5 / glibc 2.34),
and EL10 (gcc 14 / glibc 2.39). x86_64 only.

```sh
gcc -shared -fPIC -O2 -Wall -Wextra \
    -o /usr/lib64/no-afalg.so no-afalg.c -ldl
```

Install system-wide (every dynamically-linked process inherits it):

```sh
echo /usr/lib64/no-afalg.so > /etc/ld.so.preload
```

Verify it took effect - quick one-liner:

```sh
python3 -c 'import socket; socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)'
# Expect: PermissionError: [Errno 1] Operation not permitted
# Without the shim: succeeds silently and returns a socket object.
```

Or with `strace` to see the syscall return directly:

```sh
strace -e trace=socket python3 -c \
  'import socket; socket.socket(38,5,0)' 2>&1 | grep AF_ALG
# Expect: socket(AF_ALG, SOCK_SEQPACKET, 0) = -1 EPERM
```

Blocked attempts log to `auth.priv`:

```
no-afalg[12345]: blocked AF_ALG (domain=38) via socket uid=0 euid=0 pid=12345
```

To remove:

```sh
rm /etc/ld.so.preload   # or: edit out the line if other shims share the file
```

### What the shim deliberately does NOT do

It does not wrap `syscall(2)`. Reading six `long` varargs
unconditionally is undefined behaviour, and the bypasses it would
catch (`syscall(SYS_socket, AF_ALG, ...)` and inline-asm `syscall`
instruction) are unblockable from userspace anyway. Pair with seccomp
or the kernel patch for that surface.

---

## Using the auditor

```sh
./copyfail-local-check.py                    # human-readable, only flags non-OK
./copyfail-local-check.py --verbose          # show passing checks too
./copyfail-local-check.py --json             # SIEM ingestion (stdout = JSON)
./copyfail-local-check.py --skip-trigger     # no live AF_ALG probe
./copyfail-local-check.py --skip-hardening   # skip suid/page-cache audit
./copyfail-local-check.py --category KERNEL,MITIGATION
./copyfail-local-check.py --no-progress      # suppress stderr progress line
./copyfail-local-check.py --emit-remediation # bash script of fixes (review first)
```

Categories: `ENV`, `KERNEL`, `MITIGATION`, `HARDENING`, `DETECTION`.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean - no vulnerability, mitigations adequate |
| 1 | Test framework error |
| 2 | **VULNERABLE** - trigger probe confirmed exploitable, no userspace mitigation |
| 3 | Vulnerable kernel but at least one userspace mitigation is active |
| 4 | Mitigation/hardening gaps (not actively exploitable as observed) |

Only `trigger_probe` produces a definitive `VULN` verdict. Page-cache
divergence is reported as `WARN` (potential IOC requiring human
investigation), not `VULN` - it can have benign causes too.

### JSON output

`--json` emits a structured object on stdout containing every check, a
counts summary, the exit code, and a top-level `posture` block that
SIEMs/dashboards can ingest directly:

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

### Remediation output

`--emit-remediation` prints a bash script aggregating the per-check
remediation hints and a canonical-commands appendix. Output is
**fully commented** by default; uncomment what you actually want to
apply. Several remediations (chmod on suid binaries, modules_disabled
sysctl, modprobe blacklist) are policy-dependent or require a reboot
to undo - review every block before pasting.

### Safety guarantees

- Writes only to `mkdtemp()` sentinel files; never touches `/usr/bin`,
  `/etc`, or anything you care about.
- All page-cache reads are passive - no file contents are modified.
- The trigger probe targets a freshly-created sentinel, never a real
  SUID binary.
- Runs unprivileged (some checks degrade gracefully without root).

---

## Why these checks?

The auditor is structured by attack-chain layer, not by checklist
convenience. Each category answers a specific question about the
current host.

### `KERNEL` - is the primitive actually reachable?

- **`AF_ALG` socket reachability.** Open `socket(AF_ALG, SOCK_SEQPACKET,
  0)`. If `EAFNOSUPPORT`, the family is gone - done. If it succeeds,
  the auto-load path works, which by itself is an exposure even
  without the rest of the cipher chain.
- **`authencesn(hmac(sha256),cbc(aes))` cipher availability.** Bind
  the algorithm name. Failure here means the specific composite
  cipher driving the bug is not present on this kernel build.
- **`algif_aead` setsockopt acceptance.** Confirm the AEAD operation
  state machine is reachable; needed because some downstream patches
  refuse the cipher at bind() time but still allow the family.
- **Live trigger probe.** Mirrors the public PoC against a sentinel
  file (never a SUID binary). This is the only check that produces a
  *VULN* verdict on its own - kernel-version heuristics lie too often
  on backported distros.

### `MITIGATION` - if the kernel is vulnerable, is anything stopping the bug?

Each check below corresponds to one rung of the defense-in-depth
ladder above and exists because the ladder above it is bypassable:

- **`/etc/ld.so.preload` contains `no-afalg.so`** - verifies the shim
  is wired at the global linker level.
- **Shim live-blocks `AF_ALG`** - actually calls `socket(AF_ALG)` from
  a child shell and confirms `EPERM`. Catches stale, deleted, or
  ABI-broken shim binaries.
- **`modprobe` blacklist for `algif_aead`, `authenc`, `authencesn`**
  - drops the auto-load path. Cross-checks `/etc/modprobe.d/*.conf`
  against `/proc/modules` because a blacklist set after the modules
  loaded is a no-op.
- **`/proc/modules` shows the modules absent** - independent of the
  blacklist config; this is the runtime ground truth.
- **systemd `RestrictAddressFamilies=` drops `AF_ALG`** - parsed from
  the *effective* unit configuration, with explicit handling for the
  `~AF_ALG` (deny-list) and positive-list dialects, because both are
  in use across distros.
- **Per-service drop-in freshness** - units that were loaded before
  the drop-in landed are still permissive. The check compares unit
  load time vs drop-in mtime and flags stale units that need
  `daemon-reload` + restart.
- **seccomp filter active for the running PID** (when run as a
  service wrapper) - catches the direct-syscall bypass at a
  per-process granularity.

### `HARDENING` - if mitigation fails, what does the blast radius look like?

- **SUID binary inventory** with `find / -perm -4000`, recorded so
  that a future delta against this output is meaningful even after
  a successful exploit (the bug doesn't change file contents, but it
  changes *which* SUID binaries an attacker would target).
- **Page-cache integrity sample.** For each `PRIV_CONFIG_FILES` /
  `SUID_BINARIES` entry: hash the file via the page cache (`read`)
  and via direct I/O (`O_DIRECT`) and compare. Divergence = the bug
  is not just present, it has already been triggered.
- **File capabilities** - `getcap -r` over `/usr/bin`, `/usr/sbin`,
  `/usr/local`, `/opt`. Files with `cap_setuid` etc. are
  hijack-equivalent to SUID and need the same audit.

### `DETECTION` - would we know if someone tried this?

- **`auditd` running, with rules covering `socket(AF_ALG)`** - the
  one syscall-level signature of the bug that survives userspace
  evasion. The check confirms both that auditd is up and that a
  rule actually targets `a0=38` (the `AF_ALG` constant).
- **Recent IOC signals** - short window scan of `auth.priv` for
  `no-afalg blocked` lines (forward-leaning IOC: a process *tried*
  to open `AF_ALG` and was stopped) and of audit log for matching
  `socket(38, ...)` records.

### `ENV` - does the script have what it needs to give a meaningful answer?

Architecture, kernel version, glibc version, Python version, root
status. Surfaces "skip" reasons up front so an unhelpful run doesn't
look like a clean run.

---

## Limitations

- x86_64 only. The `AF_ALG` constant is universal but the LD_PRELOAD
  shim has architecture asserts and the trigger probe's struct layout
  is tested only on x86_64. Patches welcome for arm64.
- The userspace shim is irrelevant to static binaries and
  syscall-instruction issuers. This is a known design boundary, not
  a bug - see "What the shim deliberately does NOT do" above.
- `modprobe` blacklists do not unload already-resident modules. If
  `/proc/modules` shows them present after a blacklist edit, you
  need a reboot or `rmmod`.
- The trigger probe is destructive *only* against its own sentinel.
  It will not corrupt anything you would notice. It will, however,
  briefly load `algif_aead` and friends if they aren't already loaded
  - which is the point.

---

## License

GPL v2. See `LICENSE`.
