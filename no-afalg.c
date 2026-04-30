/*
 * no-afalg.c
 *             (C) 2026, rfxn.com - forged in prod - <ryan@rfxn.com>
 * This program may be freely redistributed under the terms of the GNU GPL v2
 *
 * LD_PRELOAD shim blocking AF_ALG socket creation.
 *
 * CVE-2026-31431 ("Copy Fail") userspace defense-in-depth.
 * Intercepts AF_ALG socket creation via libc. Does NOT prevent direct
 * syscall instruction bypass - pair with seccomp, modprobe blacklist
 * (where applicable), and kernel patching for complete coverage.
 *
 * Build:
 *   gcc -shared -fPIC -O2 -Wall -Wextra \
 *       -o /usr/lib64/no-afalg.so no-afalg.c -ldl
 *
 * Install:
 *   echo /usr/lib64/no-afalg.so > /etc/ld.so.preload
 *
 * Tested across: EL7 (gcc 4.8 / glibc 2.17),
 *                EL8 (gcc 8.5 / glibc 2.28),
 *                EL9 (gcc 11.5 / glibc 2.34),
 *                EL10 (gcc 14 / glibc 2.39).
 * Architecture: x86_64 only.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>

#if !defined(__x86_64__)
#error "no-afalg.so currently only supports x86_64"
#endif

/* glibc < 2.24 (EL7) doesn't define AF_ALG in its headers. */
#ifndef AF_ALG
#define AF_ALG 38
#endif

static int (*real_socket)(int, int, int)             = NULL;
static int (*real_socketpair)(int, int, int, int[2]) = NULL;

static void __attribute__((constructor)) shim_init(void)
{
    /* POSIX dlsym(3) returns void*; ISO C forbids assigning that to
     * a function pointer. The dlsym(3) man page RATIONALE documents
     * this union-pun as the portable workaround. */
    *(void **)(&real_socket)     = dlsym(RTLD_NEXT, "socket");
    *(void **)(&real_socketpair) = dlsym(RTLD_NEXT, "socketpair");
    (void)dlerror();   /* clear any error state */
}

static void log_block(const char *via, int domain)
{
    static int opened = 0;
    if (!opened) {
        openlog("no-afalg", LOG_PID | LOG_NDELAY, LOG_AUTHPRIV);
        opened = 1;
    }
    syslog(LOG_WARNING,
           "blocked AF_ALG (domain=%d) via %s uid=%u euid=%u pid=%d",
           domain, via,
           (unsigned)getuid(), (unsigned)geteuid(), (int)getpid());
}

int socket(int domain, int type, int protocol)
{
    if (domain == AF_ALG) {
        log_block("socket", domain);
        errno = EPERM;
        return -1;
    }
    if (real_socket)
        return real_socket(domain, type, protocol);
    /* dlsym failed at constructor time - fall through to direct
     * syscall so legitimate sockets still work. */
    return (int)syscall(SYS_socket, (long)domain, (long)type, (long)protocol);
}

int socketpair(int domain, int type, int protocol, int sv[2])
{
    if (domain == AF_ALG) {
        log_block("socketpair", domain);
        errno = EPERM;
        return -1;
    }
    if (real_socketpair)
        return real_socketpair(domain, type, protocol, sv);
    return (int)syscall(SYS_socketpair, (long)domain, (long)type,
                                        (long)protocol, (long)sv);
}

/* NOTE: We deliberately do NOT wrap syscall(2).
 * Reading 6 long varargs unconditionally is undefined behavior, and
 * the bypasses it would catch (syscall(SYS_socket, AF_ALG, ...) and
 * inline-asm `syscall` instruction) are also unblockable from
 * userspace by any other means. Use seccomp or the kernel patch. */
