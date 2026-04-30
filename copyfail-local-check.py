#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
##
# copyfail-local-check.py
#             (C) 2026, R-fx Networks <proj@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
#
"""
copyfail_checker.py - comprehensive CVE-2026-31431 ("Copy Fail") auditor.

Combines the kernel-level vulnerability probe (after rootsecdev/test_cve_2026_31431.py)
with mitigation, hardening, and detection-readiness checks suitable for fleet
auditing across RHEL/CentOS/Alma/Rocky 7-10.

SAFE BY DESIGN
  - Only writes to mkdtemp() sentinel files; never touches /usr/bin or /etc.
  - Page-cache reads only; never modifies any system file's contents.
  - Runs unprivileged (some checks degrade gracefully without root).
  - Trigger probe targets a freshly-created sentinel, not /usr/bin/su.

USAGE
  ./copyfail-local-check.py                       # human-readable
  ./copyfail-local-check.py --json                # SIEM ingestion (+ posture)
  ./copyfail-local-check.py --verbose             # show passing checks
  ./copyfail-local-check.py --skip-trigger        # skip AF_ALG probe
  ./copyfail-local-check.py --skip-hardening      # skip suid/page-cache audit
  ./copyfail-local-check.py --category KERNEL,MITIGATION
  ./copyfail-local-check.py --emit-remediation    # bash-script of fixes

EXIT CODES
  0 - clean (no vulnerability, mitigations adequate)
  1 - test framework error
  2 - VULNERABLE (trigger probe confirmed, no userspace mitigation)
  3 - vulnerable kernel but at least one userspace mitigation active
  4 - mitigation/hardening gaps (not actively exploitable as observed)
"""

import argparse
import ctypes
import ctypes.util
import errno
import glob
import hashlib
import json
import os
import re
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

# --- splice(2) wrapper ----------------------------------------------------
# os.splice was added in Python 3.10. EL7/8/9 default Pythons are 3.6/3.6/3.9
# so we need a ctypes fallback to actually run the trigger probe across the
# fleet. This calls splice(2) via libc directly.

_libc = None
def _get_libc():
    global _libc
    if _libc is None:
        path = ctypes.util.find_library("c") or "libc.so.6"
        _libc = ctypes.CDLL(path, use_errno=True)
        _libc.splice.argtypes = [
            ctypes.c_int, ctypes.POINTER(ctypes.c_longlong),
            ctypes.c_int, ctypes.POINTER(ctypes.c_longlong),
            ctypes.c_size_t, ctypes.c_uint,
        ]
        _libc.splice.restype = ctypes.c_ssize_t
    return _libc

def do_splice(fd_in, fd_out, length, offset_src=None):
    """Cross-Python splice() wrapper. Uses os.splice (3.10+) or libc fallback."""
    if hasattr(os, "splice"):
        if offset_src is not None:
            return os.splice(fd_in, fd_out, length, offset_src=offset_src)
        return os.splice(fd_in, fd_out, length)
    libc = _get_libc()
    off_ptr = (ctypes.byref(ctypes.c_longlong(offset_src))
               if offset_src is not None else None)
    n = libc.splice(fd_in, off_ptr, fd_out, None, length, 0)
    if n < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return n

# --- Constants -------------------------------------------------------------

AF_ALG                    = 38
SOL_ALG                   = 279
ALG_SET_KEY               = 1
ALG_SET_IV                = 2
ALG_SET_OP                = 3
ALG_SET_AEAD_ASSOCLEN     = 4
ALG_OP_DECRYPT            = 0
CRYPTO_AUTHENC_KEYA_PARAM = 1
ALG_NAME = "authencesn(hmac(sha256),cbc(aes))"
PAGE     = 4096
ASSOCLEN = 8
CRYPTLEN = 16
TAGLEN   = 16
MARKER   = b"PWND"

# Privilege-sensitive files where page-cache corruption = privesc
PRIV_CONFIG_FILES = [
    "/etc/passwd",
    "/etc/group",
    "/etc/sudoers",
    "/etc/security/access.conf",
    "/etc/pam.d/su",
    "/etc/pam.d/sshd",
    "/etc/pam.d/login",
    "/etc/nsswitch.conf",
    "/etc/ssh/sshd_config",
]
PRIV_CONFIG_ROOT_FILES = ["/etc/shadow", "/etc/gshadow"]

# --- Color/output ----------------------------------------------------------

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[31m"
    GREEN   = "\033[32m"
    YELLOW  = "\033[33m"
    BLUE    = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN    = "\033[36m"

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

def colorize(s: str, color: str) -> str:
    return color + s + C.RESET if USE_COLOR else s

# --- Progress emitter -----------------------------------------------------
# Some checks (trigger probe, getcap -r, page-cache hashing) can take several
# seconds. Without progress output the script looks hung. We emit progress to
# stderr so JSON output on stdout stays clean and machine-parseable.

class Progress:
    def __init__(self, enabled=True):
        self.enabled = enabled and sys.stderr.isatty() and \
                       os.environ.get("NO_COLOR") is None
        self.plain = enabled and not self.enabled  # non-tty: plain stderr lines
        self.start = time.monotonic()
        self.current = None

    def step(self, label):
        """Begin a labeled step. Updates the in-place progress line on TTY,
        emits a plain line on non-TTY, no-op when disabled."""
        self.current = label
        elapsed = time.monotonic() - self.start
        if self.enabled:
            # Carriage-return overwrite on TTY
            sys.stderr.write("\r\033[K[{:5.1f}s] {}".format(elapsed, label))
            sys.stderr.flush()
        elif self.plain:
            sys.stderr.write("[{:5.1f}s] {}\n".format(elapsed, label))
            sys.stderr.flush()

    def done(self):
        """Clear the progress line at the end."""
        if self.enabled:
            sys.stderr.write("\r\033[K")
            sys.stderr.flush()

PROGRESS = Progress(enabled=False)  # set up properly in main()

# --- Result type -----------------------------------------------------------

class Status:
    OK    = "ok"
    WARN  = "warn"
    FAIL  = "fail"
    VULN  = "vulnerable"
    SKIP  = "skip"
    ERROR = "error"
    INFO  = "info"

STATUS_GLYPH = {
    Status.OK:    ("[+]", C.GREEN),
    Status.WARN:  ("[!]", C.YELLOW),
    Status.FAIL:  ("[-]", C.RED),
    Status.VULN:  ("[X]", C.RED),
    Status.SKIP:  ("[~]", C.DIM),
    Status.ERROR: ("[?]", C.MAGENTA),
    Status.INFO:  ("[i]", C.BLUE),
}

class Check:
    def __init__(self, name, category, status, message,
                 details=None, remediation=None):
        self.name = name
        self.category = category
        self.status = status
        self.message = message
        self.details = details or {}
        self.remediation = remediation

    def to_dict(self):
        d = {"name": self.name, "category": self.category,
             "status": self.status, "message": self.message}
        if self.details:
            d["details"] = self.details
        if self.remediation:
            d["remediation"] = self.remediation
        return d

    def render(self, verbose=False):
        if not verbose and self.status == Status.OK:
            return None
        glyph, color = STATUS_GLYPH[self.status]
        line = "{} [{}] {}: {}".format(
            colorize(glyph, color), self.category, self.name, self.message)
        if verbose and self.remediation and \
                self.status not in (Status.OK, Status.INFO):
            line += "\n    " + colorize("→ " + self.remediation, C.CYAN)
        return line

# --- Helpers ---------------------------------------------------------------

def run_cmd(cmd, timeout=5):
    """Run command, return (rc, stdout, stderr) - never raises.
    Uses explicit PIPE rather than capture_output for Python 3.6 compat (EL7)."""
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return -1, b"", b"command not found"
    except subprocess.TimeoutExpired:
        return -1, b"", b"timeout"
    except Exception as e:
        return -1, b"", str(e).encode()

def read_file_safe(path, max_bytes=65536):
    try:
        with open(path, "rb") as f:
            return f.read(max_bytes)
    except (IOError, OSError):
        return None

def read_text_safe(path, max_bytes=65536):
    data = read_file_safe(path, max_bytes)
    if data is None:
        return None
    try:
        return data.decode("utf-8", errors="replace")
    except Exception:
        return None

def is_root():
    return os.geteuid() == 0

_SYSTEMD_RUNNING = None
def systemd_running():
    global _SYSTEMD_RUNNING
    if _SYSTEMD_RUNNING is None:
        _SYSTEMD_RUNNING = os.path.exists("/run/systemd/system")
    return _SYSTEMD_RUNNING

def _algif_aead_state():
    """Returns one of: 'builtin', 'loaded_module', 'absent'.
    'absent' means either not built at all, or built as a module that hasn't
    been loaded yet - both cases mean the kernel could load it on AF_ALG
    socket creation if it's a module."""
    if not os.path.exists("/sys/module/algif_aead"):
        return "absent"
    modules_text = read_text_safe("/proc/modules") or ""
    is_module = any(line.startswith("algif_aead ")
                    for line in modules_text.splitlines())
    return "loaded_module" if is_module else "builtin"

# --- Environment checks ----------------------------------------------------

def check_environment():
    out = []
    uname = os.uname()
    out.append(Check(
        "kernel_info", "ENV", Status.INFO,
        "{} {} {}".format(uname.sysname, uname.release, uname.machine),
        details={"sysname": uname.sysname, "release": uname.release,
                 "machine": uname.machine, "nodename": uname.nodename},
    ))

    distro, distro_ver = "unknown", "unknown"
    osr = read_text_safe("/etc/os-release")
    if osr:
        for line in osr.splitlines():
            if line.startswith("ID="):
                distro = line.split("=", 1)[1].strip().strip('"')
            elif line.startswith("VERSION_ID="):
                distro_ver = line.split("=", 1)[1].strip().strip('"')
    out.append(Check(
        "distro_info", "ENV", Status.INFO,
        "{} {}".format(distro, distro_ver),
        details={"id": distro, "version_id": distro_ver},
    ))
    out.append(Check(
        "privilege", "ENV", Status.INFO,
        "uid={} euid={}{}".format(
            os.getuid(), os.geteuid(),
            "" if is_root() else "  (some checks limited without root)"),
        details={"uid": os.getuid(), "euid": os.geteuid()},
    ))
    return out

# --- Kernel vulnerability probes -------------------------------------------

def check_af_alg_socket():
    """AF_ALG family reachable to caller?"""
    try:
        s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
        s.close()
        return Check(
            "af_alg_socket", "KERNEL", Status.WARN,
            "AF_ALG socket family is reachable",
            remediation="Block via LD_PRELOAD shim, seccomp filter, "
                        "modprobe blacklist (effective when algif_aead is a "
                        "loadable module - not when builtin), or "
                        "kernel.modules_disabled=1.",
        )
    except OSError as e:
        return Check(
            "af_alg_socket", "KERNEL", Status.OK,
            "AF_ALG unreachable: {}".format(e.strerror or str(e)),
            details={"errno": e.errno},
        )

def check_authencesn_cipher():
    """Vulnerable cipher loadable?"""
    try:
        s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
        try:
            s.bind(("aead", ALG_NAME))
            return Check(
                "authencesn_cipher", "KERNEL", Status.WARN,
                "Vulnerable cipher loadable: {}".format(ALG_NAME),
            )
        finally:
            s.close()
    except OSError as e:
        return Check(
            "authencesn_cipher", "KERNEL", Status.OK,
            "Cipher unavailable: {}".format(e.strerror or str(e)),
            details={"errno": e.errno},
        )

def check_algif_aead_state():
    """Module loaded, builtin, or absent?"""
    state = _algif_aead_state()
    if state == "absent":
        return Check(
            "algif_aead_state", "KERNEL", Status.OK,
            "algif_aead absent from kernel (not built or module not loaded)",
            details={"state": "absent"},
        )
    if state == "loaded_module":
        return Check(
            "algif_aead_state", "KERNEL", Status.WARN,
            "algif_aead loaded as kernel module (can be unloaded with rmmod)",
            details={"state": "loaded_module"},
            remediation="rmmod algif_aead && add 'install algif_aead /bin/false' "
                        "to /etc/modprobe.d/ to block reload.",
        )
    # builtin
    return Check(
        "algif_aead_state", "KERNEL", Status.WARN,
        "algif_aead built into kernel (cannot be unloaded - common on RHEL "
        "and other distros that compile crypto user-API in)",
        details={"state": "builtin"},
        remediation="No module-level mitigation possible on this kernel; use "
                    "LD_PRELOAD shim, seccomp, or kernel patch.",
    )

def _build_keyblob(authkey, enckey):
    rtattr = struct.pack("HH", 8, CRYPTO_AUTHENC_KEYA_PARAM)
    keyparam = struct.pack(">I", len(enckey))
    return rtattr + keyparam + authkey + enckey

def trigger_probe():
    """rootsecdev-style sentinel-file trigger; safe by design."""
    tmp = tempfile.mkdtemp(prefix="copyfail-")
    target = os.path.join(tmp, "sentinel.bin")
    try:
        sentinel = (b"COPYFAIL-SENTINEL-UNCORRUPTED!!\n" * (PAGE // 32))[:PAGE]
        with open(target, "wb") as f:
            f.write(sentinel)
        fd = os.open(target, os.O_RDONLY)
        try:
            os.read(fd, PAGE)
            os.lseek(fd, 0, os.SEEK_SET)

            try:
                master = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
            except OSError as e:
                return Check("trigger_probe", "KERNEL", Status.OK,
                             "AF_ALG unreachable, trigger inert: {}".format(
                                 e.strerror))
            try:
                try:
                    master.bind(("aead", ALG_NAME))
                except OSError as e:
                    return Check("trigger_probe", "KERNEL", Status.OK,
                                 "Cipher unavailable, trigger inert: {}".format(
                                     e.strerror))
                master.setsockopt(SOL_ALG, ALG_SET_KEY,
                                  _build_keyblob(b"\x00"*32, b"\x00"*16))
                op, _ = master.accept()
                try:
                    aad = b"\x00"*4 + MARKER
                    cmsg = [
                        (SOL_ALG, ALG_SET_OP,
                         struct.pack("I", ALG_OP_DECRYPT)),
                        (SOL_ALG, ALG_SET_IV,
                         struct.pack("I", 16) + b"\x00"*16),
                        (SOL_ALG, ALG_SET_AEAD_ASSOCLEN,
                         struct.pack("I", ASSOCLEN)),
                    ]
                    op.sendmsg([aad], cmsg, socket.MSG_MORE)

                    pr, pw = os.pipe()
                    try:
                        try:
                            n = do_splice(fd, pw, CRYPTLEN+TAGLEN, offset_src=0)
                            if n != CRYPTLEN+TAGLEN:
                                return Check("trigger_probe", "KERNEL",
                                             Status.ERROR,
                                             "splice file->pipe short: {}".format(n))
                            n = do_splice(pr, op.fileno(), n)
                            if n != CRYPTLEN+TAGLEN:
                                return Check("trigger_probe", "KERNEL",
                                             Status.ERROR,
                                             "splice pipe->op short: {}".format(n))
                        except OSError as e:
                            if e.errno in (errno.EOPNOTSUPP, errno.ENOTSUP):
                                return Check("trigger_probe", "KERNEL", Status.OK,
                                             "splice into AF_ALG unsupported on "
                                             "this kernel - vector unreachable",
                                             details={"errno": e.errno})
                            return Check("trigger_probe", "KERNEL", Status.ERROR,
                                         "splice failed: {}".format(e.strerror))
                    finally:
                        os.close(pr)
                        os.close(pw)

                    try:
                        op.recv(ASSOCLEN+CRYPTLEN+TAGLEN)
                    except OSError as e:
                        if e.errno not in (errno.EBADMSG, errno.EINVAL):
                            return Check("trigger_probe", "KERNEL", Status.ERROR,
                                         "AEAD recv failed: {}".format(e.strerror))
                finally:
                    op.close()
            finally:
                master.close()

            os.lseek(fd, 0, os.SEEK_SET)
            after = os.read(fd, PAGE)
        finally:
            os.close(fd)

        marker_off = after.find(MARKER)
        marker_orig = sentinel.find(MARKER)
        diffs = sum(1 for i in range(PAGE) if after[i] != sentinel[i])

        if marker_off >= 0 and marker_orig < 0:
            return Check("trigger_probe", "KERNEL", Status.VULN,
                         "VULNERABLE - marker landed at offset {} in sentinel "
                         "page cache; {} bytes corrupted".format(marker_off, diffs),
                         details={"marker_offset": marker_off,
                                  "bytes_changed": diffs},
                         remediation="Apply kernel patch (mainline a664bf3d603d) "
                                     "and reboot. Interim: LD_PRELOAD shim or seccomp.")
        if diffs > 0:
            return Check("trigger_probe", "KERNEL", Status.VULN,
                         "VULNERABLE - page cache corrupted ({} bytes) but "
                         "marker placement non-canonical".format(diffs),
                         details={"bytes_changed": diffs},
                         remediation="Apply kernel patch and reboot.")
        return Check("trigger_probe", "KERNEL", Status.OK,
                     "page cache intact after trigger; kernel appears patched")
    except Exception as e:
        return Check("trigger_probe", "KERNEL", Status.ERROR,
                     "{}: {}".format(type(e).__name__, e))
    finally:
        try: os.remove(target)
        except OSError: pass
        try: os.rmdir(tmp)
        except OSError: pass

# --- Mitigation checks -----------------------------------------------------

def check_ld_so_preload():
    content = read_text_safe("/etc/ld.so.preload")
    if content is None:
        return Check("ld_so_preload", "MITIGATION", Status.FAIL,
                     "/etc/ld.so.preload absent",
                     remediation="Build no-afalg.so and add to /etc/ld.so.preload.")
    if "no-afalg" not in content:
        return Check("ld_so_preload", "MITIGATION", Status.FAIL,
                     "/etc/ld.so.preload present but no AF_ALG shim referenced",
                     remediation="Add no-afalg.so path to /etc/ld.so.preload.")
    for line in content.splitlines():
        line = line.strip()
        if "no-afalg" in line and os.path.exists(line):
            return Check("ld_so_preload", "MITIGATION", Status.OK,
                         "AF_ALG shim referenced and file exists: {}".format(line),
                         details={"path": line})
    return Check("ld_so_preload", "MITIGATION", Status.FAIL,
                 "shim referenced in ld.so.preload but file missing on disk",
                 remediation="Reinstall the no-afalg shim package.")

def check_shim_blocks_af_alg():
    """Subprocess test: does AF_ALG socket creation actually fail?"""
    code = (
        "import socket, sys\n"
        "try:\n"
        "    s = socket.socket(38, socket.SOCK_SEQPACKET, 0); s.close()\n"
        "    print('UNBLOCKED')\n"
        "except PermissionError:\n"
        "    print('BLOCKED')\n"
        "except OSError as e:\n"
        "    print('ERR:{}'.format(e.errno))\n"
    )
    rc, out, err = run_cmd([sys.executable, "-c", code], timeout=5)
    out_s = out.decode("utf-8", errors="replace").strip()
    if out_s == "BLOCKED":
        return Check("shim_blocks_af_alg", "MITIGATION", Status.OK,
                     "AF_ALG socket creation blocked at userspace layer (EPERM)")
    if out_s == "UNBLOCKED":
        return Check("shim_blocks_af_alg", "MITIGATION", Status.FAIL,
                     "AF_ALG socket created successfully - no userspace block",
                     remediation="Verify shim loaded: ldd $(which python3) | grep no-afalg")
    return Check("shim_blocks_af_alg", "MITIGATION", Status.INFO,
                 "AF_ALG result: {}".format(out_s))

def check_modprobe_blacklist():
    pat = re.compile(
        r"^\s*(install|blacklist)\s+(af_alg|algif_aead|algif_skcipher|"
        r"algif_hash|algif_rng)\b", re.MULTILINE)
    matches = []
    paths = (glob.glob("/etc/modprobe.d/*.conf") +
             glob.glob("/usr/lib/modprobe.d/*.conf") +
             glob.glob("/lib/modprobe.d/*.conf"))
    for path in paths:
        text = read_text_safe(path) or ""
        for m in pat.finditer(text):
            matches.append("{} ({})".format(m.group(0).strip(), path))
    if matches:
        return Check("modprobe_blacklist", "MITIGATION", Status.OK,
                     "AF_ALG family blacklisted ({} entries)".format(len(matches)),
                     details={"entries": matches[:8]})

    # No blacklist found. Severity depends on whether the module is currently
    # loadable. Even on builtin kernels we still flag this as a defense-in-depth
    # gap - costs nothing and protects against kernel rebuilds, kernel swaps,
    # or scenarios where someone replaces the running kernel with one that
    # builds algif_aead as a module.
    state = _algif_aead_state()
    blacklist_lines = (
        "install af_alg /bin/false\n"
        "install algif_aead /bin/false\n"
        "install algif_skcipher /bin/false\n"
        "install algif_hash /bin/false\n"
        "install algif_rng /bin/false")

    if state == "loaded_module":
        return Check(
            "modprobe_blacklist", "MITIGATION", Status.WARN,
            "No AF_ALG modprobe blacklist; algif_aead is currently loaded "
            "as a module (real exposure - can be reloaded after rmmod)",
            details={"algif_aead_state": state},
            remediation="Write to /etc/modprobe.d/99-no-afalg.conf:\n" +
                        blacklist_lines + "\nthen rmmod algif_aead.")
    if state == "absent":
        return Check(
            "modprobe_blacklist", "MITIGATION", Status.WARN,
            "No AF_ALG modprobe blacklist; algif_aead can be auto-loaded on "
            "AF_ALG socket creation if built as a module",
            details={"algif_aead_state": state},
            remediation="Write to /etc/modprobe.d/99-no-afalg.conf:\n" +
                        blacklist_lines)
    # builtin
    return Check(
        "modprobe_blacklist", "MITIGATION", Status.INFO,
        "No AF_ALG modprobe blacklist; algif_aead is builtin (blacklist "
        "doesn't help current kernel but recommended as defense in depth)",
        details={"algif_aead_state": state},
        remediation="Add anyway as defense in depth - costs nothing and "
                    "protects against kernel rebuilds/swaps. "
                    "/etc/modprobe.d/99-no-afalg.conf:\n" + blacklist_lines)

def check_modules_disabled():
    val = read_text_safe("/proc/sys/kernel/modules_disabled")
    if val is None:
        return Check("modules_disabled", "MITIGATION", Status.SKIP,
                     "/proc/sys/kernel/modules_disabled unreadable")
    if val.strip() == "1":
        return Check("modules_disabled", "MITIGATION", Status.OK,
                     "kernel.modules_disabled=1 (no module loading possible)")
    return Check("modules_disabled", "MITIGATION", Status.INFO,
                 "kernel.modules_disabled=0",
                 remediation="Consider sysctl kernel.modules_disabled=1 after boot "
                             "as general hardening (irreversible until reboot).")

def _af_alg_blocked_by_restrict(raf_value):
    """Returns True if a RestrictAddressFamilies value blocks AF_ALG.

    systemd semantics:
      RestrictAddressFamilies=AF_X AF_Y     -> allowlist; only AF_X/AF_Y allowed
      RestrictAddressFamilies=~AF_X AF_Y    -> blocklist; AF_X/AF_Y denied
      RestrictAddressFamilies=              -> no restriction
    AF_ALG is blocked when listed in a ~-prefixed blocklist OR absent from
    a non-prefixed allowlist."""
    if not raf_value:
        return False
    raf = raf_value.strip()
    if raf.startswith("~"):
        return "AF_ALG" in raf
    return "AF_ALG" not in raf

def check_systemd_restrict_address_families():
    """Sample common daemons for AF_ALG seccomp via systemd.

    Hosting daemons (sshd, web, mail, scheduler) and container/orchestration
    runtimes are all candidates - any process that forks off code run by
    less-trusted principals benefits from the AF_ALG cut at the unit level."""
    if not systemd_running():
        return Check("systemd_restrict", "MITIGATION", Status.SKIP,
                     "systemd not running")
    daemons = [
        # Login / shell exposure
        "sshd",
        # Web stack (PHP-FPM, mod_php, CGI all run user-supplied code)
        "httpd", "nginx", "apache2", "php-fpm",
        # Mail (filter scripts, sieve, scanner integrations)
        "exim", "postfix", "dovecot",
        # DNS, DB
        "named", "mariadb", "mysqld", "postgresql",
        # Container / orchestration runtimes
        "containerd", "docker", "podman", "kubelet", "cri-o",
        # CI/CD agents that run untrusted PR/job code
        "gitlab-runner", "jenkins", "actions-runner",
        # Batch / HPC
        "slurmd", "slurmctld",
        # Cron-likes
        "crond", "atd",
    ]
    findings_ok = []
    findings_missing_arch = []
    daemons_loaded = 0
    for d in daemons:
        rc, out, err = run_cmd(["systemctl", "show",
                                "-p", "RestrictAddressFamilies",
                                "-p", "SystemCallArchitectures",
                                "{}.service".format(d)], timeout=3)
        if rc != 0:
            continue
        text = out.decode("utf-8", errors="replace")
        kv = {}
        for line in text.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                kv[k] = v
        raf = kv.get("RestrictAddressFamilies", "")
        sca = kv.get("SystemCallArchitectures", "")
        # Both empty = unit not loaded; skip silently.
        if not raf and not sca:
            continue
        daemons_loaded += 1
        if not _af_alg_blocked_by_restrict(raf):
            continue
        if "native" in sca:
            findings_ok.append(d)
        else:
            findings_missing_arch.append(d)

    if findings_ok and not findings_missing_arch:
        return Check("systemd_restrict", "MITIGATION", Status.OK,
                     "{} daemons block AF_ALG with SystemCallArchitectures=native".format(
                         len(findings_ok)),
                     details={"protected": findings_ok})
    if findings_ok or findings_missing_arch:
        msg_parts = []
        if findings_ok:
            msg_parts.append("{} fully protected".format(len(findings_ok)))
        if findings_missing_arch:
            msg_parts.append("{} block AF_ALG but missing SystemCallArchitectures=native".format(
                len(findings_missing_arch)))
        return Check("systemd_restrict", "MITIGATION", Status.WARN,
                     "; ".join(msg_parts) +
                     " - 32-bit compat syscalls may bypass filter",
                     details={"protected": findings_ok,
                              "needs_arch_directive": findings_missing_arch},
                     remediation="Add 'SystemCallArchitectures=native' alongside "
                                 "'RestrictAddressFamilies=~AF_ALG' in the drop-in.")
    return Check("systemd_restrict", "MITIGATION", Status.FAIL,
                 "no AF_ALG-restricting drop-ins on any of {} loaded daemons".format(
                     daemons_loaded),
                 remediation="Add drop-ins like /etc/systemd/system/<svc>.service.d/"
                             "no-afalg.conf with [Service] RestrictAddressFamilies="
                             "~AF_ALG and SystemCallArchitectures=native. "
                             "High-leverage candidates: sshd, user@.service, "
                             "container runtimes, CI runners.")

def check_user_service_dropin():
    """user@.service is the systemd template that spawns per-user systemd
    instances. A RestrictAddressFamilies drop-in here propagates the seccomp
    filter to every login session AND rootless podman/container - one of the
    highest-leverage mitigation points on a multi-user box."""
    if not systemd_running():
        return Check("user_service_dropin", "MITIGATION", Status.SKIP,
                     "systemd not running")
    paths = (glob.glob("/etc/systemd/system/user@.service.d/*.conf") +
             glob.glob("/usr/lib/systemd/system/user@.service.d/*.conf") +
             glob.glob("/lib/systemd/system/user@.service.d/*.conf"))
    for p in paths:
        text = read_text_safe(p) or ""
        if "RestrictAddressFamilies" in text and "AF_ALG" in text:
            return Check("user_service_dropin", "MITIGATION", Status.OK,
                         "user@.service has AF_ALG restriction: {}".format(p),
                         details={"path": p})
    return Check("user_service_dropin", "MITIGATION", Status.WARN,
                 "no user@.service drop-in restricting AF_ALG - high-leverage "
                 "mitigation point missing",
                 remediation="Create /etc/systemd/system/user@.service.d/no-afalg.conf:\n"
                             "[Service]\n"
                             "RestrictAddressFamilies=~AF_ALG\n"
                             "SystemCallArchitectures=native\n"
                             "Propagates to every login session and rootless "
                             "podman container. New sessions inherit; existing "
                             "lingering instances need restart.")

def _daemon_has_afalg_dropin(daemon):
    """Does <daemon>.service have a drop-in that blocks AF_ALG?"""
    raf_re = re.compile(
        r"^\s*RestrictAddressFamilies\s*=\s*(.+)$", re.MULTILINE)
    for unit_dir in ("/etc/systemd/system", "/usr/lib/systemd/system",
                     "/lib/systemd/system"):
        for f in glob.glob(unit_dir + "/" + daemon + ".service.d/*.conf"):
            text = read_text_safe(f) or ""
            m = raf_re.search(text)
            if m and _af_alg_blocked_by_restrict(m.group(1).strip()):
                return f
    return None

def check_seccomp_runtime():
    """Verify seccomp filter is actually loaded into running daemons by
    reading /proc/PID/status - Seccomp=2 means filter mode active. Catches
    the case where a drop-in exists but the daemon was never restarted to
    pick it up."""
    if not systemd_running():
        return Check("seccomp_runtime", "DETECTION", Status.SKIP,
                     "systemd not running")
    daemons = ["sshd", "httpd", "nginx", "containerd", "docker"]
    findings = []
    for d in daemons:
        rc, out, _ = run_cmd(["systemctl", "show", "{}.service".format(d),
                              "-p", "MainPID", "--value"], timeout=3)
        if rc != 0:
            continue
        pid = out.decode("utf-8", errors="replace").strip()
        if not pid or pid == "0":
            continue
        status = read_text_safe("/proc/{}/status".format(pid))
        if not status:
            continue
        m = re.search(r"^Seccomp:\s+(\d+)", status, re.MULTILINE)
        if not m:
            continue
        mode = int(m.group(1))
        # 0 = disabled, 1 = strict, 2 = filter
        dropin = _daemon_has_afalg_dropin(d)
        findings.append((d, pid, mode, dropin))
    if not findings:
        return Check("seccomp_runtime", "DETECTION", Status.SKIP,
                     "no relevant running daemons to inspect")
    filtered = [d for d, _, m, _ in findings if m == 2]
    unfiltered = [(d, dp) for d, _, m, dp in findings if m != 2]
    stale = [d for d, dp in unfiltered if dp is not None]
    no_dropin = [d for d, dp in unfiltered if dp is None]
    if filtered and not unfiltered:
        return Check("seccomp_runtime", "DETECTION", Status.OK,
                     "all {} inspected daemons have seccomp filter active".format(
                         len(filtered)),
                     details={"filtered": filtered})
    # Build remediation tailored to which sub-cause applies.
    rem_parts = []
    if stale:
        rem_parts.append("Stale daemons (drop-in exists but not loaded): "
                         "systemctl restart " + " ".join(stale))
    if no_dropin:
        rem_parts.append("No drop-in for: " + ", ".join(no_dropin) +
                         ". Add /etc/systemd/system/<svc>.service.d/"
                         "no-afalg.conf with [Service] "
                         "RestrictAddressFamilies=~AF_ALG and "
                         "SystemCallArchitectures=native, then daemon-reload "
                         "+ restart.")
    details = {"filtered": filtered,
               "unfiltered_stale_dropin": stale,
               "unfiltered_no_dropin": no_dropin}
    if filtered and unfiltered:
        return Check("seccomp_runtime", "DETECTION", Status.WARN,
                     "{} daemons have seccomp filter, {} do not".format(
                         len(filtered), len(unfiltered)),
                     details=details,
                     remediation=" ".join(rem_parts))
    return Check("seccomp_runtime", "DETECTION", Status.WARN,
                 "{} running daemons have NO seccomp filter loaded".format(
                     len(unfiltered)),
                 details=details,
                 remediation=" ".join(rem_parts))

def check_dropin_freshness():
    """Detect stale daemons: drop-in file is newer than the running daemon's
    process start time. Means the file changed but the daemon was never
    restarted to pick it up - filter isn't active despite the file existing."""
    if not systemd_running():
        return Check("dropin_freshness", "MITIGATION", Status.SKIP,
                     "systemd not running")
    daemons_to_dropins = {}
    raf_re = re.compile(
        r"^\s*RestrictAddressFamilies\s*=\s*(.+)$", re.MULTILINE)
    for unit_dir in ("/etc/systemd/system", "/usr/lib/systemd/system",
                     "/lib/systemd/system"):
        for d in glob.glob(unit_dir + "/*.service.d"):
            unit_name = os.path.basename(d).replace(".service.d", "")
            for f in glob.glob(d + "/*.conf"):
                text = read_text_safe(f) or ""
                # Only consider drop-ins whose actual RestrictAddressFamilies=
                # directive blocks AF_ALG. Substring matching here previously
                # mis-categorised drop-ins that merely mentioned AF_ALG in a
                # comment.
                m = raf_re.search(text)
                if not m:
                    continue
                if _af_alg_blocked_by_restrict(m.group(1).strip()):
                    daemons_to_dropins.setdefault(unit_name, []).append(f)
    if not daemons_to_dropins:
        return Check("dropin_freshness", "MITIGATION", Status.SKIP,
                     "no AF_ALG drop-ins to verify")
    stale = []
    fresh = []
    for daemon, dropins in daemons_to_dropins.items():
        rc, out, _ = run_cmd(["systemctl", "show", "{}.service".format(daemon),
                              "-p", "MainPID", "--value"], timeout=3)
        if rc != 0:
            continue
        pid = out.decode("utf-8", errors="replace").strip()
        if not pid or pid == "0":
            continue
        try:
            proc_start = os.stat("/proc/" + pid).st_mtime
        except OSError:
            continue
        for dp in dropins:
            try:
                dropin_mtime = os.stat(dp).st_mtime
            except OSError:
                continue
            if dropin_mtime > proc_start:
                stale.append("{} (drop-in {} newer than pid {})".format(
                    daemon, dp, pid))
            else:
                fresh.append(daemon)
    if stale:
        return Check("dropin_freshness", "MITIGATION", Status.WARN,
                     "{} stale daemons (drop-in newer than running process)".format(
                         len(stale)),
                     details={"stale": stale, "fresh": fresh},
                     remediation="Restart affected daemons so they pick up the "
                                 "AF_ALG restriction: systemctl restart <name>")
    return Check("dropin_freshness", "MITIGATION", Status.OK,
                 "all {} daemons with AF_ALG drop-ins are running with the "
                 "drop-in active".format(len(fresh)))

# --- Hardening checks ------------------------------------------------------

# Canonical SUID set across mainstream distros. Used as a "this is expected"
# allow-list when classifying setuid binaries, and as a fallback list when
# we can't run find as root. Membership here means "expected to exist as
# setuid on at least one mainstream distro" - missing or non-setuid on a
# given host is fine.
EXPECTED_SUID = set([
    "/usr/bin/su", "/bin/su", "/usr/bin/sudo",
    "/usr/bin/passwd", "/usr/bin/chsh", "/usr/bin/chage", "/usr/bin/chfn",
    "/usr/bin/gpasswd", "/usr/bin/newgrp", "/usr/bin/pkexec",
    "/usr/bin/mount", "/usr/bin/umount", "/bin/mount", "/bin/umount",
    "/usr/bin/at", "/usr/bin/crontab",
    "/usr/bin/fusermount", "/usr/bin/fusermount3",
    "/usr/bin/fusermount-glusterfs",
    "/usr/lib/polkit-1/polkit-agent-helper-1",
    "/usr/sbin/unix_chkpwd", "/usr/sbin/pam_timestamp_check",
    "/usr/sbin/mount.nfs", "/usr/sbin/usernetctl", "/usr/sbin/userhelper",
    "/usr/sbin/grub2-set-bootflag",
    "/usr/bin/ksu",
    "/usr/bin/keybase-redirector",
    # Debian/Ubuntu
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/eject/dmcrypt-get-device",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    # Fedora/RHEL
    "/usr/libexec/openssh/ssh-keysign",
    "/usr/libexec/dbus-1/dbus-daemon-launch-helper",
    "/usr/libexec/qemu-bridge-helper",
    "/usr/libexec/Xorg.wrap",
    "/usr/libexec/spice-gtk-x86_64/spice-client-glib-usb-acl-helper",
    # Vendor / third-party desktop
    "/usr/lib64/chromium-browser/chrome-sandbox",
    "/usr/share/antigravity/chrome-sandbox",
    "/opt/google/chrome/chrome-sandbox",
    "/opt/keybase/chrome-sandbox",
    "/usr/bin/vmware-user-suid-wrapper",
])

# System filesystem prefixes worth scanning for SUID outliers. We deliberately
# do NOT include /home, /var, /tmp, or container/snapshot mount roots:
# those produce noise from docker overlay layers, tarball extracts, snap
# images, and user-controlled content that isn't actually executable from
# the host's privilege boundary.
SUID_SCAN_ROOTS = ["/usr", "/opt", "/usr/local", "/sbin", "/bin"]

# Path substrings that, if present, mean a result is from an isolated
# container/snapshot layer rather than a host-reachable binary. Belt-and-
# suspenders for sites that have docker storage on the same FS as /usr.
SUID_PATH_EXCLUDES = (
    "/overlay2/", "/overlayfs/", "/snapshots/", "/containerd/",
    "/.snapshots/", "/.zfs/snapshot/", "/btrfs/subvol/",
    "/var/lib/containers/", "/var/lib/docker/",
)

def _scan_suid_inventory():
    """Return a list of paths whose setuid bit is set, under SUID_SCAN_ROOTS.

    Root: uses find for completeness. Container/snapshot paths are filtered
    out post-find, since some sites have docker storage on the same device
    as /usr and -xdev wouldn't catch them.

    Non-root or find failure: falls back to stat-checking EXPECTED_SUID. The
    fallback is best-effort - it cannot discover non-canonical setuid
    binaries planted by an attacker. That is documented as a limitation.
    """
    discovered = []
    if is_root():
        roots = [r for r in SUID_SCAN_ROOTS
                 if os.path.isdir(r) and not os.path.islink(r)]
        if roots:
            cmd = (["find"] + roots
                   + ["-xdev", "-type", "f", "-perm", "-4000",
                      "-printf", "%p\\n"])
            rc, out, _ = run_cmd(cmd, timeout=30)
            if rc == 0:
                for line in out.decode("utf-8", "replace").splitlines():
                    p = line.strip()
                    if not p:
                        continue
                    if any(ex in p for ex in SUID_PATH_EXCLUDES):
                        continue
                    discovered.append(p)
    if not discovered:
        for p in EXPECTED_SUID:
            try:
                st = os.stat(p)
            except OSError:
                continue
            if st.st_mode & stat.S_ISUID:
                discovered.append(p)
    return discovered

def check_suid_inventory():
    """Consolidated SUID audit (replaces N near-duplicate per-binary lines).

    Verdict:
      OK   - all setuid binaries are canonical and have nominal modes
      WARN - non-canonical paths or unusual modes (4777, 6755 with group
             write, etc.) found
    """
    paths = _scan_suid_inventory()
    confirmed = []
    for p in paths:
        try:
            st = os.stat(p)
        except OSError:
            continue
        # Defence against TOCTOU: only count files where the setuid bit is
        # actually set right now. Skip silently otherwise.
        if not (st.st_mode & stat.S_ISUID):
            continue
        confirmed.append((p, st.st_mode & 0o7777))
    if not confirmed:
        return Check("suid_inventory", "HARDENING", Status.OK,
                     "no setuid binaries found in {}".format(SUID_SCAN_ROOTS))
    unexpected = []
    odd_mode = []
    # Modes considered "nominal" for an expected setuid: setuid set, user
    # rwx, group/other r-x or x-only, optional setgid. We flag world/group
    # writable explicitly as anomalous.
    for p, mode in sorted(confirmed):
        if mode & 0o022:  # group-write or world-write set on a setuid binary
            odd_mode.append((p, oct(mode)))
            continue
        if p not in EXPECTED_SUID:
            unexpected.append((p, oct(mode)))
    msg = "{} setuid binaries inventoried".format(len(confirmed))
    details = {"total": len(confirmed), "scan_roots": SUID_SCAN_ROOTS,
               "canonical": len(confirmed) - len(unexpected) - len(odd_mode),
               "unexpected": [{"path": p, "mode": m} for p, m in unexpected],
               "odd_mode": [{"path": p, "mode": m} for p, m in odd_mode]}
    if unexpected or odd_mode:
        parts = []
        if unexpected:
            parts.append("{} non-canonical".format(len(unexpected)))
        if odd_mode:
            parts.append("{} group/world-writable".format(len(odd_mode)))
        return Check("suid_inventory", "HARDENING", Status.WARN,
                     msg + " (" + ", ".join(parts) + ")",
                     details=details,
                     remediation="Audit non-canonical entries; each is a "
                                 "page-cache substitution target equivalent "
                                 "to root if exploited via CVE-2026-31431.")
    return Check("suid_inventory", "HARDENING", Status.OK,
                 msg + " (all canonical, modes nominal)",
                 details=details)

def _hash_pagecache(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except (IOError, OSError):
        return None

def _hash_direct(path):
    """Read via dd iflag=direct to bypass page cache. Returns None if O_DIRECT
    isn't supported (e.g., tmpfs, some network filesystems). The caller treats
    None as 'cannot verify' rather than guessing."""
    rc, out, err = run_cmd(
        ["dd", "if=" + path, "iflag=direct", "bs=4096", "status=none"],
        timeout=10)
    if rc == 0:
        return hashlib.sha256(out).hexdigest()
    return None

def check_page_cache_integrity():
    out = []
    files = list(PRIV_CONFIG_FILES)
    if is_root():
        files += PRIV_CONFIG_ROOT_FILES
    for path in files:
        if not os.path.exists(path):
            continue
        cached = _hash_pagecache(path)
        if cached is None:
            continue
        direct = _hash_direct(path)
        if direct is None:
            out.append(Check("pagecache:" + path, "HARDENING", Status.SKIP,
                             "couldn't read {} via O_DIRECT".format(path)))
            continue
        if cached == direct:
            out.append(Check("pagecache:" + path, "HARDENING", Status.OK,
                             "{} page cache matches disk".format(path),
                             details={"path": path, "sha256": cached}))
            continue
        # Divergence is a *potential* IOC, not a confirmed CVE-2026-31431
        # exploitation: it can also arise from a concurrent writer between
        # the two reads, an active fsync window, or filesystem-level
        # caching quirks (overlay/btrfs snapshots). Trigger_probe is the
        # only check that produces a definitive VULN verdict.
        # Re-read after a short delay to filter out transient writer races;
        # only stable divergence is reported.
        time.sleep(0.2)
        cached2 = _hash_pagecache(path)
        direct2 = _hash_direct(path)
        if cached2 is None or direct2 is None or cached2 == direct2:
            out.append(Check("pagecache:" + path, "HARDENING", Status.OK,
                             "{} page cache transient divergence; "
                             "stable on re-read".format(path),
                             details={"path": path,
                                      "transient_first_sha256": cached,
                                      "stable_sha256": cached2 or direct2}))
            continue
        out.append(Check(
            "pagecache:" + path, "HARDENING", Status.WARN,
            "page cache differs from disk on {} (stable across re-read): "
            "cached={} disk={}".format(path, cached2[:16], direct2[:16]),
            details={"path": path, "cached_sha256": cached2,
                     "disk_sha256": direct2},
            remediation="Stable divergence is a potential page-cache "
                        "substitution IOC. Evict cache (vmtouch -e {}), "
                        "snapshot the host for forensics, and correlate "
                        "with audit logs for AF_ALG/splice activity.".format(path)))
    return out

def check_file_capabilities():
    """getcap -r / for non-suid privilege-bearing binaries."""
    if not any(os.path.exists(p) for p in
               ["/usr/sbin/getcap", "/sbin/getcap", "/usr/bin/getcap"]):
        return Check("file_capabilities", "HARDENING", Status.SKIP,
                     "getcap not installed")
    rc, out, err = run_cmd(["getcap", "-r", "/usr", "/bin", "/sbin"], timeout=20)
    if rc != 0:
        return Check("file_capabilities", "HARDENING", Status.SKIP,
                     "getcap failed: {}".format(err.decode("utf-8", "replace").strip()))
    text = out.decode("utf-8", errors="replace")
    risky = []
    for line in text.splitlines():
        if any(c in line for c in ("cap_setuid", "cap_sys_admin", "cap_dac_override",
                                    "cap_sys_module", "cap_sys_ptrace")):
            risky.append(line.strip())
    if risky:
        return Check("file_capabilities", "HARDENING", Status.WARN,
                     "{} binaries hold privilege-bearing file caps".format(len(risky)),
                     details={"entries": risky[:10]},
                     remediation="Audit each - these are page-cache substitution "
                                 "targets equivalent to suid root.")
    return Check("file_capabilities", "HARDENING", Status.OK,
                 "no privilege-bearing file capabilities found")

# --- Detection readiness ---------------------------------------------------

def check_auditd():
    out = []
    rc, sout, serr = run_cmd(["systemctl", "is-active", "auditd"], timeout=3)
    active = sout.decode("utf-8", "replace").strip() == "active"
    out.append(Check("auditd_running", "DETECTION",
                     Status.OK if active else Status.WARN,
                     "auditd is {}".format("active" if active else "NOT active"),
                     remediation=None if active
                     else "systemctl enable --now auditd"))
    if active and is_root():
        rc, sout, serr = run_cmd(["auditctl", "-l"], timeout=3)
        rules = sout.decode("utf-8", "replace")
        has_afalg = bool(re.search(r"-S\s+\S*socket\S*.*-F\s+a0=38", rules))
        has_splice = bool(re.search(r"-S\s+\S*splice\S*", rules))
        has_su_exec = "/usr/bin/su" in rules and "execve" in rules
        out.append(Check("audit_rule_af_alg", "DETECTION",
                         Status.OK if has_afalg else Status.FAIL,
                         "AF_ALG socket audit rule: {}".format(
                             "present" if has_afalg else "MISSING"),
                         remediation=None if has_afalg else
                         "auditctl -a always,exit -F arch=b64 -S socket "
                         "-F a0=38 -k afalg_attempt"))
        out.append(Check("audit_rule_splice", "DETECTION",
                         Status.OK if has_splice else Status.FAIL,
                         "splice audit rule: {}".format(
                             "present" if has_splice else "MISSING"),
                         remediation=None if has_splice else
                         "auditctl -a always,exit -F arch=b64 -S splice "
                         "-k splice_call"))
        out.append(Check("audit_rule_su_exec", "DETECTION",
                         Status.OK if has_su_exec else Status.WARN,
                         "/usr/bin/su execve audit rule: {}".format(
                             "present" if has_su_exec else "missing"),
                         remediation=None if has_su_exec else
                         "auditctl -a always,exit -F arch=b64 -S execve "
                         "-F path=/usr/bin/su -k su_exec"))
    return out

def _scan_text_for_ioc(text):
    """Returns (shim_blocks, afalg_audit, splice_audit) counts in text."""
    shim_blocks = 0
    if "no-afalg" in text and "blocked AF_ALG" in text:
        shim_blocks = text.count("blocked AF_ALG")
    return (shim_blocks,
            text.count("afalg_attempt"),
            text.count("splice_call"))

def check_recent_ioc_signals():
    """Look for shim/audit IOCs in recent logs (root-only, non-fatal).

    Sources, in order:
      - /var/log/secure (RHEL/Fedora rsyslog)
      - /var/log/auth.log (Debian/Ubuntu rsyslog)
      - journalctl (systemd-journald, fallback for journald-only hosts)
      - /var/log/audit/audit.log (auditd)
    """
    if not is_root():
        return Check("recent_iocs", "DETECTION", Status.SKIP,
                     "root needed to scan auth/audit logs")
    findings = []
    sources_seen = []
    shim_total = afalg_total = splice_total = 0

    for log_path in ("/var/log/secure", "/var/log/auth.log"):
        text = read_text_safe(log_path, max_bytes=512*1024)
        if text is None:
            continue
        sources_seen.append(log_path)
        sb, _, _ = _scan_text_for_ioc(text)
        if sb:
            shim_total += sb
            findings.append("{}: shim blocked {} AF_ALG attempts".format(
                log_path, sb))

    # Journald fallback: only consult journalctl if neither rsyslog file
    # surfaced shim activity (avoids double-counting on hosts that have
    # both rsyslog and persistent journal).
    if shim_total == 0 and os.path.exists("/run/systemd/journal/socket"):
        rc, out, _ = run_cmd(
            ["journalctl", "--no-pager", "-q", "--since", "-7d",
             "-t", "no-afalg"], timeout=10)
        if rc == 0:
            jtext = out.decode("utf-8", "replace")
            sources_seen.append("journalctl -t no-afalg")
            sb, _, _ = _scan_text_for_ioc(jtext)
            if sb:
                shim_total += sb
                findings.append("journalctl: shim blocked {} AF_ALG attempts "
                                "(last 7 days)".format(sb))

    audit_text = read_text_safe("/var/log/audit/audit.log",
                                max_bytes=1024*1024)
    if audit_text is not None:
        sources_seen.append("/var/log/audit/audit.log")
        _, af, sp = _scan_text_for_ioc(audit_text)
        if af:
            afalg_total += af
            findings.append("auditd logged {} afalg_attempt events".format(af))
        if sp:
            splice_total += sp
            findings.append("auditd logged {} splice events".format(sp))

    if not sources_seen:
        return Check("recent_iocs", "DETECTION", Status.SKIP,
                     "no readable auth/audit log sources found")
    if findings:
        return Check("recent_iocs", "DETECTION", Status.WARN,
                     "; ".join(findings),
                     details={"shim_blocks": shim_total,
                              "afalg_audit_events": afalg_total,
                              "splice_audit_events": splice_total,
                              "sources": sources_seen},
                     remediation="Investigate uids/pids and correlate with "
                                 "su/sshd authentication events.")
    return Check("recent_iocs", "DETECTION", Status.OK,
                 "no AF_ALG IOC signals in {} log source(s)".format(
                     len(sources_seen)),
                 details={"sources": sources_seen})

# --- Orchestration ---------------------------------------------------------

def run_all_checks(args):
    cats = (set(c.upper().strip() for c in args.category.split(","))
            if args.category else None)
    results = []

    def add_one(check, category):
        if cats and category not in cats:
            return
        if check is not None:
            results.append(check)

    def add_many(checks, category):
        if cats and category not in cats:
            return
        for c in checks or []:
            if c is not None:
                results.append(c)

    PROGRESS.step("collecting environment info")
    add_many(check_environment(), "ENV")

    PROGRESS.step("probing AF_ALG socket family")
    add_one(check_af_alg_socket(), "KERNEL")
    PROGRESS.step("probing authencesn cipher")
    add_one(check_authencesn_cipher(), "KERNEL")
    PROGRESS.step("checking algif_aead state")
    add_one(check_algif_aead_state(), "KERNEL")
    if not args.skip_trigger:
        PROGRESS.step("running trigger probe (sentinel file, AEAD/splice)")
        add_one(trigger_probe(), "KERNEL")

    PROGRESS.step("checking /etc/ld.so.preload")
    add_one(check_ld_so_preload(), "MITIGATION")
    PROGRESS.step("testing if shim blocks AF_ALG")
    add_one(check_shim_blocks_af_alg(), "MITIGATION")
    PROGRESS.step("scanning modprobe.d for AF_ALG blacklist")
    add_one(check_modprobe_blacklist(), "MITIGATION")
    PROGRESS.step("checking kernel.modules_disabled")
    add_one(check_modules_disabled(), "MITIGATION")
    PROGRESS.step("checking systemd RestrictAddressFamilies")
    add_one(check_systemd_restrict_address_families(), "MITIGATION")
    PROGRESS.step("checking user@.service drop-in")
    add_one(check_user_service_dropin(), "MITIGATION")
    PROGRESS.step("checking systemd drop-in freshness vs running daemons")
    add_one(check_dropin_freshness(), "MITIGATION")

    if not args.skip_hardening:
        PROGRESS.step("inventorying setuid binaries")
        add_one(check_suid_inventory(), "HARDENING")
        PROGRESS.step("checking page-cache integrity (privilege configs)")
        add_many(check_page_cache_integrity(), "HARDENING")
        PROGRESS.step("scanning file capabilities")
        add_one(check_file_capabilities(), "HARDENING")

    PROGRESS.step("checking auditd state and rules")
    add_many(check_auditd(), "DETECTION")
    PROGRESS.step("verifying seccomp filter active on running daemons")
    add_one(check_seccomp_runtime(), "DETECTION")
    PROGRESS.step("scanning recent log IOCs")
    add_one(check_recent_ioc_signals(), "DETECTION")

    PROGRESS.done()
    return results

def determine_exit_code(results):
    has_vuln = any(r.status == Status.VULN for r in results)
    has_fail = any(r.status == Status.FAIL for r in results)
    shim_blocks = any(r.name == "shim_blocks_af_alg" and r.status == Status.OK
                      for r in results)
    if has_vuln:
        return 3 if shim_blocks else 2
    if has_fail:
        return 4
    return 0

# Map check names to posture-layer slots. Each slot is "ok" if the named
# check is OK, "missing" otherwise. Lets a SIEM / dashboard consumer answer
# "what defenses does this host actually have?" without re-implementing
# our verdict logic on top of 50 raw check results.
POSTURE_LAYERS = [
    ("kernel_patched",       "trigger_probe"),
    ("af_alg_unreachable",   "af_alg_socket"),
    ("modprobe_blacklist",   "modprobe_blacklist"),
    ("ld_preload_shim",      "shim_blocks_af_alg"),
    ("systemd_restriction",  "systemd_restrict"),
    ("user_service_dropin",  "user_service_dropin"),
    ("seccomp_runtime",      "seccomp_runtime"),
    ("auditd_running",       "auditd_running"),
    ("audit_rule_af_alg",    "audit_rule_af_alg"),
]

def determine_posture(results):
    by_name = {r.name: r for r in results}
    layers = {}
    for slot, check_name in POSTURE_LAYERS:
        r = by_name.get(check_name)
        if r is None:
            layers[slot] = "not_evaluated"
        elif r.status == Status.OK:
            layers[slot] = "ok"
        elif r.status == Status.SKIP:
            layers[slot] = "skipped"
        else:
            layers[slot] = "missing"
    # Headline verdict, derived from layers + raw results.
    has_vuln = any(r.status == Status.VULN for r in results)
    if has_vuln and layers.get("ld_preload_shim") == "ok":
        verdict = "vulnerable_kernel_userspace_mitigated"
    elif has_vuln:
        verdict = "vulnerable"
    elif layers.get("kernel_patched") == "ok":
        verdict = "patched"
    elif layers.get("af_alg_unreachable") == "ok":
        verdict = "kernel_likely_safe"
    else:
        verdict = "inconclusive"
    return {"verdict": verdict, "layers": layers}

def emit_remediation_script(results):
    """Print a bash script of the remediations from non-OK checks.

    Aggregates Check.remediation strings as comments + commented-out
    commands. Fleet operators are expected to review before pasting:
    several remediations (chmod 4750 on suid binaries, modules_disabled
    sysctl) are operationally consequential and policy-dependent.
    """
    posture = determine_posture(results)
    lines = [
        "#!/bin/bash",
        "# Auto-generated remediation suggestions for CVE-2026-31431.",
        "# Hostname: {}    Kernel: {}".format(
            os.uname().nodename, os.uname().release),
        "# Verdict:  {}".format(posture["verdict"]),
        "#",
        "# REVIEW EVERY BLOCK BEFORE RUNNING. Some changes (chmod on suid",
        "# binaries, kernel.modules_disabled=1) are policy-dependent or",
        "# require a reboot to recover from. Lines are commented out by",
        "# default; uncomment the ones you actually want to apply.",
        "",
        "set -euo pipefail",
        "",
    ]
    actionable = [r for r in results
                  if r.status not in (Status.OK, Status.INFO, Status.SKIP)
                  and r.remediation]
    if not actionable:
        lines.append("# No actionable remediations - posture appears clean.")
        print("\n".join(lines))
        return
    for r in actionable:
        lines.append("# ----------------------------------------------------")
        lines.append("# [{}/{}] {}: {}".format(
            r.status.upper(), r.category, r.name, r.message))
        for ln in r.remediation.splitlines():
            lines.append("# " + ln)
        lines.append("")
    # Append a small block of canonical commands the auditor knows are
    # safe to run unattended; keep them commented so review remains
    # mandatory.
    lines += [
        "# === Canonical commands (review and uncomment to apply) =====",
        "#",
        "# # 1. Drop AF_ALG modules + blacklist:",
        "# rmmod algif_aead 2>/dev/null || true",
        "# cat >/etc/modprobe.d/99-no-afalg.conf <<'EOF'",
        "# install af_alg /bin/false",
        "# install algif_aead /bin/false",
        "# install algif_skcipher /bin/false",
        "# install algif_hash /bin/false",
        "# install algif_rng /bin/false",
        "# EOF",
        "#",
        "# # 2. systemd user@.service drop-in:",
        "# install -d /etc/systemd/system/user@.service.d",
        "# cat >/etc/systemd/system/user@.service.d/no-afalg.conf <<'EOF'",
        "# [Service]",
        "# RestrictAddressFamilies=~AF_ALG",
        "# SystemCallArchitectures=native",
        "# EOF",
        "# systemctl daemon-reload",
        "#",
        "# # 3. auditd rules:",
        "# auditctl -a always,exit -F arch=b64 -S socket -F a0=38 \\",
        "#   -k afalg_attempt",
        "# auditctl -a always,exit -F arch=b64 -S splice -k splice_call",
        "",
    ]
    print("\n".join(lines))

def main():
    parser = argparse.ArgumentParser(
        description="CVE-2026-31431 'Copy Fail' comprehensive checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit: 0=clean 1=err 2=VULN 3=vuln+mitigated 4=hardening_recs")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="show all checks including passing")
    parser.add_argument("--skip-trigger", action="store_true",
                        help="skip live AF_ALG probe")
    parser.add_argument("--skip-hardening", action="store_true",
                        help="skip suid/page-cache/getcap audit")
    parser.add_argument("--category", default="",
                        help="filter: ENV,KERNEL,MITIGATION,HARDENING,DETECTION")
    parser.add_argument("--no-progress", action="store_true",
                        help="suppress in-progress status output to stderr")
    parser.add_argument("--emit-remediation", action="store_true",
                        help="instead of the report, print a bash script "
                             "of the remediations for every non-OK check "
                             "(stdout); review before executing")
    args = parser.parse_args()

    # Enable progress output unless explicitly disabled or in JSON mode where
    # the user might be capturing stderr too.
    global PROGRESS
    PROGRESS = Progress(enabled=not args.no_progress and not args.json)

    if PROGRESS.enabled or PROGRESS.plain:
        sys.stderr.write("CVE-2026-31431 checker starting on {} ({})\n".format(
            os.uname().nodename, os.uname().release))
        sys.stderr.flush()

    try:
        results = run_all_checks(args)
    except Exception as e:
        print("internal error: {}: {}".format(type(e).__name__, e),
              file=sys.stderr)
        return 1

    if args.emit_remediation:
        emit_remediation_script(results)
        return determine_exit_code(results)

    if args.json:
        out = {
            "schema_version": "1.1",
            "tool": "copyfail_checker",
            "cve": "CVE-2026-31431",
            "timestamp": int(time.time()),
            "hostname": os.uname().nodename,
            "kernel": os.uname().release,
            "checks": [r.to_dict() for r in results],
            "posture": determine_posture(results),
            "summary": {
                "total": len(results),
                "ok":    sum(1 for r in results if r.status == Status.OK),
                "warn":  sum(1 for r in results if r.status == Status.WARN),
                "fail":  sum(1 for r in results if r.status == Status.FAIL),
                "vuln":  sum(1 for r in results if r.status == Status.VULN),
                "skip":  sum(1 for r in results if r.status == Status.SKIP),
                "error": sum(1 for r in results if r.status == Status.ERROR),
            },
            "exit_code": determine_exit_code(results),
        }
        print(json.dumps(out, indent=2, default=str))
    else:
        print(colorize("=" * 78, C.DIM))
        print(colorize("CVE-2026-31431 'Copy Fail' Checker  ", C.BOLD)
              + colorize("({})".format(os.uname().nodename), C.DIM))
        print(colorize("=" * 78, C.DIM))
        for r in results:
            line = r.render(verbose=args.verbose)
            if line:
                print(line)
        print(colorize("-" * 78, C.DIM))
        ok    = sum(1 for r in results if r.status == Status.OK)
        warn  = sum(1 for r in results if r.status == Status.WARN)
        fail  = sum(1 for r in results if r.status == Status.FAIL)
        vuln  = sum(1 for r in results if r.status == Status.VULN)
        skip  = sum(1 for r in results if r.status == Status.SKIP)
        print("Total: {} | {} | {} | {} | {} | {}".format(
            len(results),
            colorize("OK:" + str(ok), C.GREEN),
            colorize("WARN:" + str(warn), C.YELLOW),
            colorize("FAIL:" + str(fail), C.RED),
            colorize("VULN:" + str(vuln), C.RED + C.BOLD),
            colorize("SKIP:" + str(skip), C.DIM)))

    return determine_exit_code(results)

if __name__ == "__main__":
    sys.exit(main())
