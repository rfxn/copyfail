# CVE-2026-31431 "Copy Fail" — Handoff Brief

**Status as of 2026-04-30:** Public disclosure 2026-04-29. No vendor kpatch shipped yet. Mitigation posture is defense-in-depth with multiple userspace layers until kernel patch + reboot.

## What it is

Linux kernel `algif_aead` AEAD scratch-write bug. An unprivileged tenant can call `socket(AF_ALG, SOCK_SEQPACKET, 0)`, bind `authencesn(hmac(sha256),cbc(aes))`, and use `splice()` to drive a 4-byte write into the page cache of any readable file at attacker-chosen offset. Authentication fails (`EBADMSG`), the scratch write fires anyway. Patch is upstream commit `a664bf3d603d`, a revert of the 2017 in-place AEAD optimization.

## Why it's dangerous on hosting nodes

The primitive is "4-byte page-cache write to any readable file." Targets include:

- **Setuid binaries** — Theori PoC overwrites `/usr/bin/su` with a 160-byte ELF that does `setuid(0); execve("/bin/sh")`. Setuid bit is on the inode (kernel-grants euid=0 before parsing the planted ELF).
- **Privilege-relevant config files** — rootsecdev variant flips the UID field for the running user in `/etc/passwd` from `1234` to `0000`. PAM auths against untouched `/etc/shadow`, then `setuid(getpwnam(user).pw_uid)` lands at 0.
- **sshd path** — same `/etc/passwd` corruption hits sshd post-auth setuid; user logs in via SSH with their real password and gets a root shell. No suid binary in the chain.
- **systemd unit files, sudoers, PAM configs, file capabilities** — broader target class, all readable, all consulted by privileged code.

On-disk file is byte-for-byte unchanged. Corruption lives only in page cache. AIDE/Tripwire reading via standard POSIX I/O sees corruption *while it's cached*, but the corruption can be evicted by attacker (`POSIX_FADV_DONTNEED`) or by memory pressure. Forensic-traceless once evicted.

## RHEL/Alma/Rocky 7-10 specifics

`CONFIG_CRYPTO_USER_API_AEAD=y` — `algif_aead` and `af_alg` are **built into vmlinuz**, not loadable modules. Module-level mitigations (rmmod, modprobe blacklist) do nothing on the running kernel. Only userspace cuts and the kernel patch+reboot apply.

## Mitigation posture (defense in depth)

Apply in order. Each layer is independently useful — don't rely on any single one.

### 1. AF_ALG primitive cut (highest leverage)

Kills the entire bug class regardless of which target the attacker picks.

**LD_PRELOAD shim** — `/usr/lib64/no-afalg.so` referenced from `/etc/ld.so.preload`. Intercepts `socket(AF_ALG, ...)` via libc and returns `EPERM`. Defense-in-depth only — bypassed by static binaries, Go binaries with CGO_ENABLED=0, and inline-asm `syscall` instructions. Stops every published PoC and the script-kiddie tier (curl-pipe-to-python, gcc-and-run). Logs blocked attempts to `LOG_AUTHPRIV` (RHEL `/var/log/secure`, Debian `/var/log/auth.log`) — high-fidelity IOC.

**systemd `RestrictAddressFamilies=~AF_ALG` drop-ins** — kernel-enforced seccomp filter at the unit level. Cannot be bypassed by inline asm. Always pair with `SystemCallArchitectures=native` to prevent 32-bit compat-syscall bypass. High-leverage targets:

- `user@.service` — propagates to every login session and rootless podman container via conmon/crun
- `sshd.service` — covers all sshd-spawned login sessions
- Container runtimes (containerd, docker, podman, kubelet, cri-o)
- CI/job runners (gitlab-runner, jenkins, actions-runner, slurmd)
- Hosting daemons (httpd, nginx, php-fpm, exim, dovecot, named)

**Modprobe blacklist** — `/etc/modprobe.d/99-no-afalg.conf` with `install af_alg /bin/false` family. No effect on RHEL builtin kernels but recommended as defense in depth: costs nothing, protects against kernel rebuilds or swaps to a kernel where `algif_aead` is modular. Use the logger-prepended form for free IOC telemetry on attempted loads.

**`kernel.modules_disabled=1`** — irreversible until reboot. Consider for static-config production hosts as general hardening; breaks workflows that need on-demand module loading.

### 2. Suid surface lockdown

`chmod 4750 root:wheel` (or drop the suid bit entirely) on every setuid-root binary tenants don't legitimately need. Removes the *target* even if AF_ALG slips through. Audit with `find / -xdev -perm -4000 -type f -uid 0 \( -perm -001 -o -perm -010 \)`. Plus `getcap -r /` for non-suid file-cap-bearing binaries (CAP_SETUID, CAP_SYS_ADMIN, CAP_DAC_OVERRIDE, CAP_SYS_MODULE).

Hosting-stack-specific helpers in `/usr/local/cpanel/`, `/usr/local/interworx/`, `/scripts/` are the long tail — audit and lock down what tenants don't call.

`passwd` and the cPanel password helpers are typically the binaries you can't lock down without breaking product workflows. Those remain Tier 1 targets and must rely on the kernel-level cuts above.

### 3. Page-cache integrity detection

`O_DIRECT` read vs cached SHA-256 hash divergence on `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers`, `/etc/security/access.conf`, `/etc/pam.d/{su,sshd,login}`, `/etc/nsswitch.conf`, `/etc/ssh/sshd_config`. Any divergence is high-fidelity IOC — page cache lying to disk while attack is in flight. Five-minute scan interval. Page on divergence; forensic-image the host.

Caveat: attacker can `POSIX_FADV_DONTNEED` to evict corruption and erase the signature. Pair with audit rules for the underlying primitive.

### 4. Audit telemetry

Three high-signal rules:

```
-a always,exit -F arch=b64 -S socket -F a0=38 -k afalg_attempt
-a always,exit -F arch=b64 -S splice -F auid>=1000 -k splice_tenant
-a always,exit -F arch=b64 -S execve -F path=/usr/bin/su -F success=0 -k su_denied
```

AF_ALG socket creation by tenant uid on a hosting node is a near-perfect IOC for this exploit family. Normal hosting workloads never touch AF_ALG. Single hit warrants investigation; multiple hits = confirmed exploit attempt. Pair with the LD_PRELOAD shim's syslog entries — audit hits without corresponding shim block events mean someone bypassed the userspace shim deliberately. Page on-call.

### 5. Runtime verification

systemd drop-ins existing in the filesystem ≠ loaded into the running daemon. Check `/proc/PID/status` Seccomp field — value 2 means filter mode active. If drop-in mtime > daemon process start time, daemon is stale and needs restart. Audit fleet-wide.

### 6. Kernel patch + reboot (the actual fix)

Apply once vendor kpatch ships or kernel update lands in errata. Watch `errata.redhat.com` for `kpatch-patch-5_14_0-*` (RHEL 9) and `kpatch-patch-6_12_0-*` (RHEL 10). Note this is a revert-style fix touching `crypto/algif_aead.c`, `crypto/af_alg.c`, `crypto/algif_skcipher.c`, `include/crypto/if_alg.h` — header layout change makes kpatch builds non-trivial. Expect 1-3 week window from disclosure; don't assume kpatch ships at all.

## Tools

Two tools deliverable in this thread:

### `no-afalg.so` (LD_PRELOAD shim)

Single-file C, builds clean across EL7-EL10 (gcc 4.8 → gcc 14, glibc 2.17 → 2.39).

```bash
gcc -shared -fPIC -O2 -Wall -Wextra -o /usr/lib64/no-afalg.so no-afalg.c -ldl
echo /usr/lib64/no-afalg.so > /etc/ld.so.preload
```

After install, restart sshd so new login sessions inherit the preload (`systemctl restart sshd`). Existing sessions keep their original maps until exit.

Properties: x86_64-only (`#error` guard), POSIX-conforming dlsym idiom, fail-open if dlsym fails (falls through to direct `syscall(SYS_socket, ...)` so legitimate sockets keep working), syslog telemetry on every block to `LOG_AUTHPRIV`. Does NOT wrap `syscall(2)` — vararg UB risk and the bypass class isn't blockable from userspace anyway.

### `copyfail_checker.py` (audit tool)

Single-file Python 3.6+ stdlib-only (works on EL7's Python 3.6 through EL10's 3.12). 1173 lines, ~8s typical runtime.

Five categories: ENV, KERNEL, MITIGATION, HARDENING, DETECTION. Covers AF_ALG socket reachability, cipher loadability, sentinel-file trigger probe (with ctypes `splice` fallback for pre-3.10 Python), LD_PRELOAD presence + functional shim test, modprobe blacklist scan, kernel.modules_disabled, systemd `RestrictAddressFamilies` + `SystemCallArchitectures` across 22 daemon types, `user@.service` drop-in, drop-in freshness vs running daemon, suid binary audit, page-cache integrity check, file capabilities, auditd state + rules, runtime seccomp verification (`/proc/PID/status` Seccomp=2), recent IOC log sweep.

```bash
./copyfail_checker.py                    # human-readable, progress on stderr
./copyfail_checker.py --json             # SIEM ingestion
./copyfail_checker.py --skip-trigger     # skip live AF_ALG probe
./copyfail_checker.py --category KERNEL,DETECTION
```

Exit codes for automation: `0=clean`, `1=tool-error`, `2=VULNERABLE`, `3=vulnerable+mitigated`, `4=hardening-recs-only`. Wire JSON output into existing monitoring; exit 2 or 3 should page, exit 4 is informational.

Safe by design — only writes to mkdtemp sentinels, never touches `/usr/bin` or `/etc`, page-cache reads only.

## Rollout sequence for the fleet

1. Push `copyfail_checker.py` to all nodes; baseline audit. Triage by exit code.
2. Build and ship `no-afalg.so` RPM, deploy via Ansible, restart sshd. Re-run checker; verify shim blocks AF_ALG (exit code drops from 2 to 3 on vulnerable nodes).
3. Push `user@.service` drop-in fleet-wide via Ansible. Verify with checker's `dropin_freshness` and `seccomp_runtime` checks.
4. Audit setuid surface per node, push `chmod 4750 root:wheel` Ansible role for the agreed-safe set (su, chsh, chage, gpasswd, newgrp, mount/umount, cPanel helpers tenants don't call). Defer `passwd`, `sudo`.
5. Deploy auditd rules + page-cache integrity check (5-min cron) on all nodes.
6. Apply kernel patch + reboot on accelerated cycle when errata lands. Remove drop-ins / shim later if desired (optional — they're cheap).

## Operational risk if nothing done

Any tenant on a vulnerable node can root the box with the published PoC. Both Theori (`/usr/bin/su`) and rootsecdev (`/etc/passwd`) variants are weaponizable today. Expect derivative variants targeting `sudo`, sshd-via-passwd, and cPanel/InterWorx custom suid helpers within days. Multi-tenant shared hosting is the worst-case threat model for this CVE — tenants by definition have shell, and the primitive needs only an unprivileged process.

## Open items

- Watch for vendor kpatch (Red Hat, TuxCare KernelCare, Oracle Ksplice) — none shipped at time of writing.
- Validate page-cache integrity check doesn't false-positive on tmpfs-mounted `/etc/sudoers` setups (rare but possible in some hardened configs).
- Confirm CloudLinux CageFS posture — caged users may already have AF_ALG blocked at the CageFS layer; if so, the LD_PRELOAD is redundant for caged tenants but still needed for non-caged users and the control plane.
- Decide policy for `passwd` and `sudo` — these can't be locked down without breaking workflows, so they remain Tier 1 targets behind the kernel-level cuts.

## References

- Public disclosure: https://copy.fail/
- Theori writeup: https://github.com/theori-io/copy-fail-CVE-2026-31431
- Variant PoC (passwd UID flip): https://github.com/rootsecdev/cve_2026_31431
- Upstream fix: https://git.kernel.org/linus/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5
- Red Hat: https://access.redhat.com/security/cve/CVE-2026-31431
- Debian tracker: https://security-tracker.debian.org/tracker/CVE-2026-31431
- Reference Ansible playbook (m3nu): https://gist.github.com/m3nu/c19269ef4fd6fa53b03eb388f77464da
