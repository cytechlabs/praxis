#!/bin/sh
# PRA-155 #2b-b: SSH-side facts collector.
#
# Runs on a managed host through SSHService.execute_command(). Emits
# one ``KEY=<base64-value>`` line per discovered fact on stdout. The
# backend (SshFactsCollectorService) decodes + normalizes into the
# canonical FactsService.ingest payload.
#
# POSIX shell only — no bashisms. The collector must run on every
# distro Praxis manages, including minimal containers / appliance
# images that ship dash or busybox sh.
#
# Locked rules (PRA-155 #2b-b):
#   * Read-only. The collector NEVER mutates host state. We only
#     invoke ``--version`` / read /proc / read /etc / call lsblk and
#     systemd-detect-virt. No package-manager mutations, no service
#     restarts, no file writes outside /tmp scratch.
#   * IMDSv1-only cloud probe with a 1s timeout. Skip on any error.
#     Never fetch role credentials, instance profile docs, user-data,
#     or SSH keys.
#   * Best-effort. Each probe runs in its own subshell with errors
#     swallowed; a probe that fails just doesn't emit its line, and
#     SshFactsCollectorService records that absence as a partial error.
#
# Wire format:
#
#   schema_version=1
#   collected_at=<rfc3339>
#   cpu_model=<base64>
#   cpu_cores=<base64>
#   ram_total_bytes=<base64>
#   kernel_version=<base64>
#   distro_id=<base64>
#   distro_release=<base64>
#   uptime_seconds=<base64>
#   reboot_required=<base64>           (literal "true" or "false")
#   package_manager=<base64>
#   package_manager_version=<base64>
#   virtualization=<base64>
#   ssh_permit_root_login=<base64>     (effective sshd PermitRootLogin)
#   ssh_password_authentication=<base64>
#   sysctl_kernel_randomize_va_space=<base64>
#   sysctl_net_ipv4_ip_forward=<base64>
#   sysctl_net_ipv4_conf_all_rp_filter=<base64>
#   disks_json=<base64>                (raw lsblk -J -b output)
#   cloud_provider=<base64>
#   cloud_instance_id=<base64>
#   cloud_region=<base64>
#   cloud_zone=<base64>
#
# A line is emitted only if its probe succeeded; missing lines tell
# the parser to fall back to NULL and record a partial error.

set -u

# ``b64`` is the only non-trivial dependency. busybox base64 +
# coreutils base64 + GNU base64 all accept stdin → stdout. If even
# this is missing, the host's environment is too constrained for
# inventory and we exit clean (parser sees zero lines).
if ! command -v base64 >/dev/null 2>&1; then
    exit 0
fi

emit() {
    # emit KEY VALUE — encodes VALUE with base64 (single line) and
    # writes ``KEY=<encoded>`` on stdout. Empty values short-circuit
    # so a probe that returned nothing doesn't poison the parser
    # with an unrelated value.
    if [ -z "${2-}" ]; then
        return
    fi
    printf '%s=%s\n' "$1" "$(printf '%s' "$2" | base64 | tr -d '\n')"
}

# schema_version + collected_at are unconditional — every line set
# carries them so the parser can detect a truncated transcript.
emit schema_version "1"
emit collected_at "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"

# ---- CPU ----
if [ -r /proc/cpuinfo ]; then
    # First "model name" line wins; strip leading whitespace + colon.
    cpu_model=$(awk -F: '/^model name/ { sub(/^ +/, "", $2); print $2; exit }' /proc/cpuinfo 2>/dev/null)
    cpu_cores=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)
    emit cpu_model "$cpu_model"
    emit cpu_cores "$cpu_cores"
fi

# ---- RAM ----
if [ -r /proc/meminfo ]; then
    # MemTotal:        16234156 kB
    mem_kb=$(awk '/^MemTotal:/ { print $2; exit }' /proc/meminfo 2>/dev/null)
    if [ -n "${mem_kb:-}" ]; then
        # Multiply by 1024 with shell arithmetic; keep busybox-safe.
        ram_bytes=$((mem_kb * 1024))
        emit ram_total_bytes "$ram_bytes"
    fi
fi

# ---- Kernel ----
kernel=$(uname -r 2>/dev/null)
emit kernel_version "$kernel"

# ---- Distro ----
if [ -r /etc/os-release ]; then
    # /etc/os-release is shell-syntax key=value; sourcing in a subshell
    # avoids polluting our env. Strip surrounding double-quotes.
    distro_id=$(. /etc/os-release 2>/dev/null; printf '%s' "${ID-}")
    distro_release=$(. /etc/os-release 2>/dev/null; printf '%s' "${VERSION_ID-}")
    emit distro_id "$distro_id"
    emit distro_release "$distro_release"
fi

# ---- Uptime ----
if [ -r /proc/uptime ]; then
    # First field is "<seconds>.<centiseconds>"; we want whole seconds.
    uptime_whole=$(awk '{ split($1, a, "."); print a[1]; exit }' /proc/uptime 2>/dev/null)
    emit uptime_seconds "$uptime_whole"
fi

# ---- Reboot required ----
# Marker-file presence semantics match the agent collector exactly so
# the SSH-vs-agent transports produce equivalent rows.
if [ -f /var/run/reboot-required ] || [ -f /run/reboot-required ]; then
    emit reboot_required "true"
else
    emit reboot_required "false"
fi

# ---- Package manager ----
# Order matches the agent collector. Stop at the first hit so a host
# that has both apt-get and dpkg-query reports as apt, not dpkg.
for pm_pair in \
    "apt:apt-get" \
    "dnf:dnf" \
    "yum:yum" \
    "zypper:zypper" \
    "pacman:pacman" \
    "apk:apk"; do
    pm_name=${pm_pair%%:*}
    pm_bin=${pm_pair#*:}
    if command -v "$pm_bin" >/dev/null 2>&1; then
        emit package_manager "$pm_name"
        # First line of `--version` output. apt's leading line is the
        # shape `apt 2.4.10 (amd64)` — keep verbatim, parser doesn't
        # need to split.
        pm_ver=$("$pm_bin" --version 2>/dev/null | head -n 1)
        emit package_manager_version "$pm_ver"
        break
    fi
done

# ---- Virtualization ----
if command -v systemd-detect-virt >/dev/null 2>&1; then
    # systemd-detect-virt exits 1 on bare-metal and prints "none"; we
    # want that to land as virtualization=none, not as a missing line.
    virt_out=$(systemd-detect-virt 2>/dev/null || true)
    if [ -n "$virt_out" ]; then
        emit virtualization "$virt_out"
    fi
fi

# ---- SSH server config (read-only, effective) ----
# `sshd -T` prints the effective merged config with lowercased keys, e.g.
# "permitrootlogin no". It's the honest effective value; if it fails (no
# privilege / no host key / binary not found), fall back to the last
# uncommented directive in sshd_config. If neither yields a value we emit
# nothing — the fact stays NULL rather than guessing a version-specific default.
#
# sshd usually lives in /usr/sbin or /sbin, which a non-login managed SSH
# command's PATH may not include — so resolve the binary explicitly, and run
# the sshd_config fallback even when NO sshd binary is found (a readable
# /etc/ssh/sshd_config still yields values). ``PRAXIS_SSHD_CONFIG`` overrides
# the config path for tests; production uses /etc/ssh/sshd_config.
sshd_config_path="${PRAXIS_SSHD_CONFIG:-/etc/ssh/sshd_config}"
sshd_bin=$(command -v sshd 2>/dev/null)
if [ -z "$sshd_bin" ]; then
    for _cand in /usr/sbin/sshd /sbin/sshd; do
        if [ -x "$_cand" ]; then
            sshd_bin=$_cand
            break
        fi
    done
fi
sshd_effective=""
if [ -n "$sshd_bin" ]; then
    sshd_effective=$("$sshd_bin" -T 2>/dev/null || true)
fi
_ssh_directive() {
    # _ssh_directive <effective-out> <lc-key> <sshd_config-Key>
    v=$(printf '%s\n' "$1" | awk -v k="$2" '$1 == k { print $2; exit }')
    if [ -z "$v" ] && [ -r "$sshd_config_path" ]; then
        # Last uncommented "Key value" wins (matches sshd merge order).
        v=$(awk -v k="$3" 'tolower($1) == tolower(k) && $1 !~ /^#/ { val=$2 } END { if (val != "") print val }' "$sshd_config_path" 2>/dev/null)
    fi
    printf '%s' "$v"
}
prl=$(_ssh_directive "$sshd_effective" "permitrootlogin" "PermitRootLogin")
pwauth=$(_ssh_directive "$sshd_effective" "passwordauthentication" "PasswordAuthentication")
[ -n "$prl" ] && emit ssh_permit_root_login "$prl"
[ -n "$pwauth" ] && emit ssh_password_authentication "$pwauth"

# ---- Kernel sysctls (read-only) ----
# Prefer `sysctl -n`; fall back to the /proc/sys file. Both are pure reads.
# Some sysctls print tab-separated multi-values (per-interface); take the
# first field. No value -> no emit -> NULL fact, never a fake pass/fail.
_emit_sysctl() {
    # _emit_sysctl <emit-key> <sysctl-key> <proc-path>
    sv=""
    if command -v sysctl >/dev/null 2>&1; then
        sv=$(sysctl -n "$2" 2>/dev/null || true)
    fi
    if [ -z "$sv" ] && [ -r "$3" ]; then
        sv=$(cat "$3" 2>/dev/null)
    fi
    sv=$(printf '%s' "$sv" | awk '{ print $1; exit }')
    [ -n "$sv" ] && emit "$1" "$sv"
}
_emit_sysctl sysctl_kernel_randomize_va_space kernel.randomize_va_space /proc/sys/kernel/randomize_va_space
_emit_sysctl sysctl_net_ipv4_ip_forward net.ipv4.ip_forward /proc/sys/net/ipv4/ip_forward
_emit_sysctl sysctl_net_ipv4_conf_all_rp_filter net.ipv4.conf.all.rp_filter /proc/sys/net/ipv4/conf/all/rp_filter

# ---- Disks ----
# lsblk -J emits JSON that the parser walks. -b for raw byte counts.
# -o limits columns so older lsblks (which still ship FSAVAIL) stay
# parseable. Errors → no disks_json line → parser records a partial.
if command -v lsblk >/dev/null 2>&1; then
    disks_json_out=$(lsblk -J -b -o MOUNTPOINT,FSTYPE,SIZE,FSUSED,FSAVAIL 2>/dev/null)
    emit disks_json "$disks_json_out"
fi

# ---- Cloud (IMDSv1-only) ----
# Single 1-second probe per cloud. We deliberately do NOT issue
# IMDSv2 tokens — that opens a credential-doc surface the v1 lock
# explicitly refuses. Hosts with v1 disabled simply don't get cloud
# fields populated; that's audited as a partial error backend-side.
if command -v curl >/dev/null 2>&1; then
    aws_iid=$(curl -fsS --max-time 1 \
        http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null)
    if [ -n "$aws_iid" ]; then
        emit cloud_provider "aws"
        emit cloud_instance_id "$aws_iid"
        aws_az=$(curl -fsS --max-time 1 \
            http://169.254.169.254/latest/meta-data/placement/availability-zone 2>/dev/null)
        if [ -n "$aws_az" ]; then
            # us-east-1a → us-east-1 (strip the trailing letter).
            aws_region=$(printf '%s' "$aws_az" | sed 's/[a-z]$//')
            emit cloud_region "$aws_region"
            emit cloud_zone "$aws_az"
        fi
    else
        gcp_iid=$(curl -fsS --max-time 1 \
            -H "Metadata-Flavor: Google" \
            http://169.254.169.254/computeMetadata/v1/instance/id 2>/dev/null)
        if [ -n "$gcp_iid" ]; then
            emit cloud_provider "gcp"
            emit cloud_instance_id "$gcp_iid"
            gcp_zone_full=$(curl -fsS --max-time 1 \
                -H "Metadata-Flavor: Google" \
                http://169.254.169.254/computeMetadata/v1/instance/zone 2>/dev/null)
            # GCP returns "projects/<id>/zones/<zone>"; keep the leaf.
            gcp_zone=$(printf '%s' "$gcp_zone_full" | awk -F/ '{print $NF}')
            emit cloud_zone "$gcp_zone"
        fi
    fi
fi
