#!/bin/bash
#
# copyfail-defense-detect.sh
#   Detect IPsec / AFS / rootless-container workloads on the host
#   and decide which copyfail-defense conditional drop-ins to apply.
#
# Invoked from %posttrans of copyfail-defense-modprobe and
# copyfail-defense-systemd, and from /usr/sbin/copyfail-redetect.
#
# Modes:
#   apply  - decide, mutate /etc/, write auto-detect.json
set -euo pipefail

STATE_DIR="/var/lib/copyfail-defense"
STATE_FILE="${STATE_DIR}/auto-detect.json"
TEMPLATE_DIR="/usr/share/copyfail-defense/conditional"
ETC_MODPROBE="/etc/modprobe.d"
ETC_SYSTEMD="/etc/systemd/system"
ETC_SYSCTL="/etc/sysctl.d"
FORCE_FULL="/etc/copyfail/force-full"
TOOL_VERSION="2.0.2"

# Active tenant units (must match SPEC §4.2 and v2.0.0 CF_CLASS_TENANT_UNITS)
TENANT_UNITS=("user@" "sshd" "cron" "crond" "atd")

# Logging tag matches v2.0.0 spec line 369 convention
LOGGER_TAG="copyfail-defense-detect"

log() {
    logger -t "${LOGGER_TAG}" -p authpriv.info "$*" 2>/dev/null || true
}

IPSEC_PRESENT="false"
IPSEC_SIGNALS=()

detect_ipsec() {
    local unit
    # D-51: strongswan-starter is the legacy ipsec daemon entry on
    # Fedora/EPEL strongswan packaging (verified against
    # repoquery --list strongswan: ships both strongswan.service AND
    # strongswan-starter.service in /usr/lib/systemd/system/).
    # pluto.service covers some libreswan downstream rebuilds.
    # frr REMOVED: BGP-only deployments dominate; FP > FN.
    for unit in strongswan strongswan-starter strongswan-swanctl \
                ipsec libreswan openswan pluto; do
        if systemctl is-enabled "${unit}.service" 2>/dev/null \
           | grep -qx 'enabled'; then
            IPSEC_PRESENT="true"
            IPSEC_SIGNALS+=("systemctl: ${unit}.service enabled")
        fi
    done
    if [ -f /etc/ipsec.conf ] && \
       grep -qE '^[[:space:]]*conn[[:space:]]+[^[:space:]]' /etc/ipsec.conf 2>/dev/null; then
        IPSEC_PRESENT="true"
        IPSEC_SIGNALS+=("/etc/ipsec.conf: contains conn stanza")
    fi
    local d
    for d in /etc/swanctl/conf.d /etc/ipsec.d /etc/strongswan/conf.d /etc/strongswan.d; do
        [ -d "${d}" ] || continue
        if find "${d}" -maxdepth 1 -name '*.conf' -type f \
           -not -empty 2>/dev/null | grep -q .; then
            IPSEC_PRESENT="true"
            IPSEC_SIGNALS+=("${d}: non-empty *.conf present")
        fi
    done
}

AFS_PRESENT="false"
AFS_SIGNALS=()

detect_afs() {
    local unit
    for unit in openafs-client openafs-server kafs afsd; do
        if systemctl is-enabled "${unit}.service" 2>/dev/null \
           | grep -qx 'enabled'; then
            AFS_PRESENT="true"
            AFS_SIGNALS+=("systemctl: ${unit}.service enabled")
        fi
    done
    local f
    for f in /etc/openafs/CellServDB /etc/openafs/ThisCell; do
        if [ -f "${f}" ]; then
            AFS_PRESENT="true"
            AFS_SIGNALS+=("${f}: present")
        fi
    done
    if find /etc/krb5.conf.d -maxdepth 1 -name 'openafs*' -type f \
       2>/dev/null | grep -q .; then
        AFS_PRESENT="true"
        AFS_SIGNALS+=("/etc/krb5.conf.d/openafs*: present")
    fi
    if [ -d /proc/fs/afs ]; then
        AFS_PRESENT="true"
        AFS_SIGNALS+=("/proc/fs/afs: kernel kafs filesystem registered")
    fi
}

ROOTLESS_PRESENT="false"
ROOTLESS_SIGNALS=()

detect_rootless_containers() {
    # Signal 1: per-user rootless podman storage tree (canonical
    # marker). Per containers/storage upstream defaults the rootless
    # storage path is $HOME/.local/share/containers/storage; the
    # overlay-containers subdirectory is created by podman on first
    # successful rootless container run. Bound the find traversal
    # to maxdepth 6 with -mtime -180 to avoid pathological /home
    # walks (M-5 deferred).
    if find /home -maxdepth 6 -type d \
            -name overlay-containers \
            -path '*/.local/share/containers/storage/overlay-containers' \
            -mtime -180 2>/dev/null | grep -q .; then
        ROOTLESS_PRESENT="true"
        ROOTLESS_SIGNALS+=("/home/*/.local/share/containers/storage/overlay-containers: present")
    fi

    # Signal 2: rootful container storage tree with recent activity.
    # Rejects long-stale podman installs (operator may have purged
    # rootless workflows but left the directory). 90-day mtime gate.
    if [ -d /var/lib/containers/storage ] && \
       find /var/lib/containers/storage -mindepth 1 -maxdepth 1 \
            -mtime -90 2>/dev/null | grep -q .; then
        ROOTLESS_PRESENT="true"
        ROOTLESS_SIGNALS+=("/var/lib/containers/storage: non-empty + mtime<90d")
    fi

    # Signal 3: per-user runtime tmpfs (live or recent rootless
    # podman activity). /run/user/<UID>/containers is podman's
    # XDG_RUNTIME_DIR child for rootless state. Tmpfs clears on
    # logout, so this is a strong "live use" signal.
    local rud
    for rud in /run/user/*/containers; do
        [ -d "${rud}" ] || continue
        local uid
        uid=$(printf '%s\n' "${rud}" | cut -d/ -f4)
        if [ -n "${uid}" ] && [ "${uid}" -ge 1000 ] 2>/dev/null; then
            ROOTLESS_PRESENT="true"
            ROOTLESS_SIGNALS+=("/run/user/${uid}/containers: present")
            break
        fi
    done

    # Signal 4: podman.socket enabled (system or any per-user instance).
    # System-wide check first (works in mock chroots that lack a session bus).
    if systemctl is-enabled podman.socket 2>/dev/null | grep -qx 'enabled'; then
        ROOTLESS_PRESENT="true"
        ROOTLESS_SIGNALS+=("systemctl: podman.socket enabled")
    fi
    # Per-user enumeration via loginctl (best-effort; failures are silent
    # in mock or on hosts without active sessions). The `|| true` is
    # required: pipefail + a failing loginctl (no D-Bus / no PID 1
    # systemd) would otherwise propagate rc=1 through the cmd-sub
    # and trip set -e on the assignment.
    if command -v loginctl >/dev/null 2>&1; then
        local lusers user
        lusers=$(loginctl list-users --no-legend 2>/dev/null \
                     | awk '{print $2}' || true)
        for user in ${lusers}; do
            [ -n "${user}" ] || continue
            if systemctl --user --machine="${user}@.host" \
                         is-enabled podman.socket 2>/dev/null \
                | grep -qx 'enabled'; then
                ROOTLESS_PRESENT="true"
                ROOTLESS_SIGNALS+=("systemctl --user (${user}): podman.socket enabled")
                break
            fi
        done
    fi
    return 0
}

USERNS_CONSUMERS_PRESENT="false"
USERNS_CONSUMERS_SIGNALS=()

# v2.0.2: distinct signal set from rootless containers. Catches userns
# consumers that the cf-class host-wide sysctl drop-in would break but
# that don't show up in the rootless-podman detector: Flatpak runtime
# (uses bwrap which needs CLONE_NEWUSER), firejail (explicit userns
# sandboxer), and desktop browsers (Chromium/Chrome/Firefox use
# unprivileged userns for their renderer sandbox on Linux).
#
# Triggers suppression of /etc/sysctl.d/99-copyfail-defense-userns.conf
# only - the per-unit systemd RestrictNamespaces=~user drop-in is
# unaffected (it scopes to the five tenant units).
detect_userns_consumers() {
    # Signal 1: Flatpak installed apps or runtimes (system-wide install).
    # /var/lib/flatpak is the canonical system path; per-user installs
    # live under /home/*/.local/share/flatpak/ - both walked here.
    local d
    for d in /var/lib/flatpak/app /var/lib/flatpak/runtime; do
        if [ -d "${d}" ] && \
           find "${d}" -mindepth 1 -maxdepth 1 -type d 2>/dev/null \
               | grep -q .; then
            USERNS_CONSUMERS_PRESENT="true"
            USERNS_CONSUMERS_SIGNALS+=("${d}: non-empty (Flatpak install)")
        fi
    done
    if find /home -maxdepth 6 -type d \
            -path '*/.local/share/flatpak/app' \
            -mtime -180 2>/dev/null | grep -q .; then
        USERNS_CONSUMERS_PRESENT="true"
        USERNS_CONSUMERS_SIGNALS+=("/home/*/.local/share/flatpak/app: per-user Flatpak install")
    fi

    # Signal 2: firejail userns sandbox installed. Unlike bubblewrap
    # (which is a Flatpak dep on every workstation), firejail is only
    # installed when explicitly used - presence ~= active use.
    if [ -x /usr/bin/firejail ]; then
        USERNS_CONSUMERS_PRESENT="true"
        USERNS_CONSUMERS_SIGNALS+=("/usr/bin/firejail: installed")
    fi

    # Signal 3: desktop browser binaries. Chromium / Chrome / Firefox
    # default to unprivileged-userns renderer sandbox on Linux; with
    # user.max_user_namespaces=0 they fall back to setuid-sandbox where
    # available, but on hosts without that helper they hard-fail.
    # Presence on a server is unusual - if any of these exist, the host
    # is plausibly a workstation and we should not host-wide block userns.
    local b
    for b in /usr/bin/chromium /usr/bin/chromium-browser \
             /usr/bin/google-chrome /usr/bin/firefox \
             /usr/bin/firefox-esr; do
        if [ -x "${b}" ]; then
            USERNS_CONSUMERS_PRESENT="true"
            USERNS_CONSUMERS_SIGNALS+=("${b}: desktop browser present")
            break
        fi
    done
    return 0
}

# SUPPRESS_*: true if mitigation is suppressed; false if applied.
SUPPRESS_MODPROBE_CF2_XFRM="false"
SUPPRESS_MODPROBE_RXRPC="false"
SUPPRESS_SYSTEMD_RXRPC_AF="false"
SUPPRESS_SYSTEMD_USERNS_USER_AT="false"
SUPPRESS_SYSCTL_USERNS="false"

# force-full sentinel resolver: returns 0 (active) only for a regular
# file. Logs WARN if path exists as directory, broken symlink, etc -
# operator likely intended sentinel but staged the wrong shape.
check_force_full() {
    if [ -f "${FORCE_FULL}" ]; then
        return 0
    fi
    if [ -h "${FORCE_FULL}" ] && [ ! -e "${FORCE_FULL}" ]; then
        printf 'copyfail-defense: WARN: %s is a symlink to a missing target; force-full sentinel IGNORED\n' \
            "${FORCE_FULL}" \
          | tee /dev/stderr \
          | logger -t "${LOGGER_TAG}" -p authpriv.warning 2>/dev/null \
          || true
    elif [ -e "${FORCE_FULL}" ]; then
        printf 'copyfail-defense: WARN: %s exists but is not a regular file; force-full sentinel IGNORED\n' \
            "${FORCE_FULL}" \
          | tee /dev/stderr \
          | logger -t "${LOGGER_TAG}" -p authpriv.warning 2>/dev/null \
          || true
    fi
    return 1
}

decide_suppressions() {
    if check_force_full; then
        # Operator override - apply everything regardless of detection.
        return 0
    fi
    [ "${IPSEC_PRESENT}" = "true" ]    && SUPPRESS_MODPROBE_CF2_XFRM="true"
    [ "${AFS_PRESENT}" = "true" ]      && SUPPRESS_MODPROBE_RXRPC="true"
    [ "${AFS_PRESENT}" = "true" ]      && SUPPRESS_SYSTEMD_RXRPC_AF="true"
    [ "${ROOTLESS_PRESENT}" = "true" ] && SUPPRESS_SYSTEMD_USERNS_USER_AT="true"
    # v2.0.2 sysctl userns drop-in: host-wide userns sysctl is suppressed
    # by EITHER rootless containers (existing signal) OR Flatpak / firejail
    # / desktop browsers (new userns-consumers signal). Per-unit systemd
    # RestrictNamespaces is unaffected (still applies to the five tenant
    # units regardless of userns-consumer detection).
    if [ "${ROOTLESS_PRESENT}" = "true" ] || \
       [ "${USERNS_CONSUMERS_PRESENT}" = "true" ]; then
        SUPPRESS_SYSCTL_USERNS="true"
    fi
    # Explicit success: the chained `[ x ] && SUP=...` returns 1 when
    # the final test is false (clean host, nothing detected). Under
    # the script's `set -e` that would abort main() before
    # write_state_json runs, leaving no auto-detect.json on disk.
    return 0
}

# cmp-and-skip helper: install src to dst only if dst doesn't
# exist OR matches src exactly. If dst differs from src, log
# WARN and skip the install (preserves operator hand-edits per D-57).
# Returns 0 on success/skip, non-zero on filesystem error.
cmp_and_install() {
    local src="$1" dst="$2" tag="$3"
    if [ ! -f "${dst}" ]; then
        install -d -m 0755 "$(dirname "${dst}")"
        install -m 0644 -o root -g root "${src}" "${dst}"
        log "${tag}: applied (new install)"
        return 0
    fi
    if cmp -s "${src}" "${dst}"; then
        # Same content - nothing to do.
        return 0
    fi
    # Different content - operator hand-edit. Skip overwrite.
    # tee to stderr so dnf surfaces the warning (D-55).
    printf 'copyfail-defense: WARN: %s diverged from template; preserving operator edits (cmp-and-skip per D-57)\n' \
        "${dst}" | tee /dev/stderr | logger -t "${LOGGER_TAG}" -p authpriv.warning 2>/dev/null || true
    return 0
}

apply_modprobe() {
    local src dst
    # cf2-xfrm: cmp-and-install or remove
    src="${TEMPLATE_DIR}/modprobe/99-copyfail-defense-cf2-xfrm.conf"
    dst="${ETC_MODPROBE}/99-copyfail-defense-cf2-xfrm.conf"
    if [ "${SUPPRESS_MODPROBE_CF2_XFRM}" = "true" ]; then
        rm -f "${dst}"
        log "modprobe cf2-xfrm: suppressed (IPsec detected)"
    elif [ -f "${src}" ]; then
        cmp_and_install "${src}" "${dst}" "modprobe cf2-xfrm"
    fi
    # rxrpc: cmp-and-install or remove
    src="${TEMPLATE_DIR}/modprobe/99-copyfail-defense-rxrpc.conf"
    dst="${ETC_MODPROBE}/99-copyfail-defense-rxrpc.conf"
    if [ "${SUPPRESS_MODPROBE_RXRPC}" = "true" ]; then
        rm -f "${dst}"
        log "modprobe rxrpc: suppressed (AFS detected)"
    elif [ -f "${src}" ]; then
        cmp_and_install "${src}" "${dst}" "modprobe rxrpc"
    fi
}

apply_systemd() {
    local src dst unit suppress
    # 12-* AF_RXRPC drop-in (suppressed on AFS hosts; applies to all 5 units)
    src="${TEMPLATE_DIR}/systemd/12-copyfail-defense-rxrpc-af.conf"
    if [ -f "${src}" ]; then
        for unit in "${TENANT_UNITS[@]}"; do
            dst="${ETC_SYSTEMD}/${unit}.service.d/12-copyfail-defense-rxrpc-af.conf"
            if [ "${SUPPRESS_SYSTEMD_RXRPC_AF}" = "true" ]; then
                rm -f "${dst}"
                log "systemd rxrpc-af ${unit}: suppressed (AFS detected)"
            else
                cmp_and_install "${src}" "${dst}" "systemd rxrpc-af ${unit}"
            fi
        done
    fi
    # 15-* userns drop-in (suppressed on user@ only when rootless detected)
    src="${TEMPLATE_DIR}/systemd/15-copyfail-defense-userns.conf"
    if [ -f "${src}" ]; then
        for unit in "${TENANT_UNITS[@]}"; do
            dst="${ETC_SYSTEMD}/${unit}.service.d/15-copyfail-defense-userns.conf"
            suppress="false"
            if [ "${unit}" = "user@" ] && \
               [ "${SUPPRESS_SYSTEMD_USERNS_USER_AT}" = "true" ]; then
                suppress="true"
            fi
            if [ "${suppress}" = "true" ]; then
                rm -f "${dst}"
                log "systemd userns ${unit}: suppressed (rootless detected)"
            else
                cmp_and_install "${src}" "${dst}" "systemd userns ${unit}"
            fi
        done
    fi
}

apply_sysctl() {
    local src dst
    src="${TEMPLATE_DIR}/sysctl/99-copyfail-defense-userns.conf"
    dst="${ETC_SYSCTL}/99-copyfail-defense-userns.conf"
    if [ ! -f "${src}" ]; then
        # Subpackage -sysctl not installed; nothing to do.
        return 0
    fi
    if [ "${SUPPRESS_SYSCTL_USERNS}" = "true" ]; then
        rm -f "${dst}"
        log "sysctl userns: suppressed (rootless containers or userns-consumer detected)"
    else
        cmp_and_install "${src}" "${dst}" "sysctl userns"
    fi
}

teardown_modprobe() {
    rm -f "${ETC_MODPROBE}/99-copyfail-defense-cf2-xfrm.conf"
    rm -f "${ETC_MODPROBE}/99-copyfail-defense-rxrpc.conf"
    log "modprobe teardown: removed conditional /etc/modprobe.d/* files"
}

teardown_sysctl() {
    rm -f "${ETC_SYSCTL}/99-copyfail-defense-userns.conf"
    log "sysctl teardown: removed /etc/sysctl.d/99-copyfail-defense-userns.conf"
}

teardown_systemd() {
    local unit
    for unit in "${TENANT_UNITS[@]}"; do
        rm -f "${ETC_SYSTEMD}/${unit}.service.d/12-copyfail-defense-rxrpc-af.conf"
        rm -f "${ETC_SYSTEMD}/${unit}.service.d/15-copyfail-defense-userns.conf"
    done
    log "systemd teardown: removed conditional /etc/systemd/system/*.d/12-* and 15-*"
}

write_state_json() {
    local target="$1"   # final path
    local force_full="false"
    [ -f "${FORCE_FULL}" ] && force_full="true"

    install -d -m 0755 -o root -g root "$(dirname "${target}")"
    local tmp="${target}.tmp.$$"

    # Marshall signal arrays as NUL-delimited bytes via stdin.
    # Bash command substitution silently strips NUL bytes from a captured
    # string, so an env-var carrier collapses signal1\0signal2\0 into
    # signal1signal2 - a single concatenated string. Piping printf's
    # output straight into python avoids the bash variable round-trip
    # entirely. End-of-list markers separate the four arrays.
    {
        printf '%s\0' "${IPSEC_SIGNALS[@]+${IPSEC_SIGNALS[@]}}"
        printf 'CFD_END_IPSEC\0'
        printf '%s\0' "${AFS_SIGNALS[@]+${AFS_SIGNALS[@]}}"
        printf 'CFD_END_AFS\0'
        printf '%s\0' "${ROOTLESS_SIGNALS[@]+${ROOTLESS_SIGNALS[@]}}"
        printf 'CFD_END_ROOTLESS\0'
        printf '%s\0' "${USERNS_CONSUMERS_SIGNALS[@]+${USERNS_CONSUMERS_SIGNALS[@]}}"
        printf 'CFD_END_USERNS_CONSUMERS\0'
    } | env \
        CFD_TOOL_VERSION="${TOOL_VERSION}" \
        CFD_TIMESTAMP="$(date +%s)" \
        CFD_HOSTNAME="$(hostname 2>/dev/null || echo unknown)" \
        CFD_FORCE_FULL="${force_full}" \
        CFD_IPSEC_PRESENT="${IPSEC_PRESENT}" \
        CFD_AFS_PRESENT="${AFS_PRESENT}" \
        CFD_ROOTLESS_PRESENT="${ROOTLESS_PRESENT}" \
        CFD_USERNS_CONSUMERS_PRESENT="${USERNS_CONSUMERS_PRESENT}" \
        CFD_SUP_MODPROBE_CF2_XFRM="${SUPPRESS_MODPROBE_CF2_XFRM}" \
        CFD_SUP_MODPROBE_RXRPC="${SUPPRESS_MODPROBE_RXRPC}" \
        CFD_SUP_SYSTEMD_RXRPC_AF="${SUPPRESS_SYSTEMD_RXRPC_AF}" \
        CFD_SUP_SYSTEMD_USERNS_USER_AT="${SUPPRESS_SYSTEMD_USERNS_USER_AT}" \
        CFD_SUP_SYSCTL_USERNS="${SUPPRESS_SYSCTL_USERNS}" \
        python3 -c '
import json, os, sys

def b(name):
    return os.environ.get(name, "false") == "true"

raw = sys.stdin.buffer.read().decode("utf-8", errors="replace")
parts = raw.split("\0")

def take_until(marker):
    out = []
    while parts:
        item = parts.pop(0)
        if item == marker:
            return out
        if item:
            out.append(item)
    return out

ipsec_signals      = take_until("CFD_END_IPSEC")
afs_signals        = take_until("CFD_END_AFS")
rootless_signals   = take_until("CFD_END_ROOTLESS")
consumers_signals  = take_until("CFD_END_USERNS_CONSUMERS")

sup_xfrm     = b("CFD_SUP_MODPROBE_CF2_XFRM")
sup_rxrpc    = b("CFD_SUP_MODPROBE_RXRPC")
sup_rxaf     = b("CFD_SUP_SYSTEMD_RXRPC_AF")
sup_userns   = b("CFD_SUP_SYSTEMD_USERNS_USER_AT")
sup_sysctl   = b("CFD_SUP_SYSCTL_USERNS")

doc = {
    "schema_version": "2",
    "tool": "copyfail-defense-detect",
    "tool_version": os.environ["CFD_TOOL_VERSION"],
    "timestamp": int(os.environ["CFD_TIMESTAMP"]),
    "hostname": os.environ["CFD_HOSTNAME"],
    "force_full": b("CFD_FORCE_FULL"),
    "detected": {
        "ipsec":               {"present": b("CFD_IPSEC_PRESENT"),             "signals": ipsec_signals},
        "afs":                 {"present": b("CFD_AFS_PRESENT"),               "signals": afs_signals},
        "rootless_containers": {"present": b("CFD_ROOTLESS_PRESENT"),          "signals": rootless_signals},
        "userns_consumers":    {"present": b("CFD_USERNS_CONSUMERS_PRESENT"),  "signals": consumers_signals},
    },
    "suppressed": {
        "modprobe_cf2_xfrm":      sup_xfrm,
        "modprobe_rxrpc":         sup_rxrpc,
        "systemd_rxrpc_af":       sup_rxaf,
        "systemd_userns_user_at": sup_userns,
        "sysctl_userns":          sup_sysctl,
    },
    "applied": {
        "modprobe_cf1":              True,
        "modprobe_cf2_xfrm":         not sup_xfrm,
        "modprobe_rxrpc":            not sup_rxrpc,
        "systemd_always":            True,
        "systemd_rxrpc_af_user_at":  not sup_rxaf,
        "systemd_rxrpc_af_sshd":     not sup_rxaf,
        "systemd_rxrpc_af_cron":     not sup_rxaf,
        "systemd_rxrpc_af_crond":    not sup_rxaf,
        "systemd_rxrpc_af_atd":      not sup_rxaf,
        "systemd_userns_user_at":    not sup_userns,
        "systemd_userns_sshd":       True,
        "systemd_userns_cron":       True,
        "systemd_userns_crond":      True,
        "systemd_userns_atd":        True,
        "sysctl_userns":             not sup_sysctl,
    },
}
with open(sys.argv[1], "w") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")
' "${tmp}"

    mv -f "${tmp}" "${target}"
}

usage() {
    cat <<USAGE >&2
USAGE: $0 apply (modprobe|systemd|sysctl|both|all)
       $0 teardown (modprobe|systemd|sysctl|both|all)
       'both' = modprobe+systemd (back-compat with v2.0.1 callers).
       'all'  = modprobe+systemd+sysctl.
USAGE
    exit 1
}

main() {
    local action="${1:-}" scope="${2:-}"
    case "${action}" in
        apply)
            case "${scope}" in
                modprobe|systemd|sysctl|both|all) ;;
                *) usage ;;
            esac
            detect_ipsec
            detect_afs
            detect_rootless_containers
            detect_userns_consumers
            decide_suppressions
            if [ "${scope}" = "modprobe" ] || [ "${scope}" = "both" ] || [ "${scope}" = "all" ]; then
                apply_modprobe
            fi
            if [ "${scope}" = "systemd" ] || [ "${scope}" = "both" ] || [ "${scope}" = "all" ]; then
                apply_systemd
            fi
            if [ "${scope}" = "sysctl" ] || [ "${scope}" = "all" ]; then
                apply_sysctl
            fi
            write_state_json "${STATE_FILE}"
            log "apply ${scope} complete: ipsec=${IPSEC_PRESENT} afs=${AFS_PRESENT} rootless=${ROOTLESS_PRESENT} userns_consumers=${USERNS_CONSUMERS_PRESENT}"
            ;;
        teardown)
            case "${scope}" in
                modprobe|systemd|sysctl|both|all) ;;
                *) usage ;;
            esac
            if [ "${scope}" = "modprobe" ] || [ "${scope}" = "both" ] || [ "${scope}" = "all" ]; then
                teardown_modprobe
            fi
            if [ "${scope}" = "systemd" ] || [ "${scope}" = "both" ] || [ "${scope}" = "all" ]; then
                teardown_systemd
            fi
            if [ "${scope}" = "sysctl" ] || [ "${scope}" = "all" ]; then
                teardown_sysctl
            fi
            ;;
        *)
            usage
            ;;
    esac
}

main "$@"
