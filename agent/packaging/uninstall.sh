#!/usr/bin/env bash
# Praxis fleet agent uninstaller.
#
# Idempotent: safe to re-run and safe to run on a host where the agent was
# never fully installed. Stops and disables the service, removes the unit
# and the binary, and reloads systemd only when the unit was actually
# removed.
#
# Identity material and configuration under /etc/praxis-agent are PRESERVED
# by default, so a host can be reinstalled without re-enrolling. Pass
# --purge to delete them; that is irreversible and forces a fresh
# enrollment on the next install.
#
# Revoking the agent certificate is a control-plane action and is not done
# here. Removing an agent from a host does not by itself invalidate its
# credentials.
set -euo pipefail

# ---- defaults ---------------------------------------------------------------

CONFIG_DIR="/etc/praxis-agent"
BIN_PATH="/usr/local/bin/praxis-agent"
SERVICE_NAME="praxis-agent"

PURGE="false"
NO_SYSTEMD="false"
DRY_RUN="false"

# ---- usage ------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: $0 [flags]

  --config-dir PATH     config directory               (default: /etc/praxis-agent)
  --bin-path PATH       installed binary location      (default: /usr/local/bin/praxis-agent)
  --service-name NAME   systemd unit name              (default: praxis-agent)
  --purge               also delete the config directory (identity material)
  --no-systemd          skip unit removal + daemon-reload
  --dry-run             print actions, change nothing
  -h, --help            show this help

Without --purge, /etc/praxis-agent (config.json, agent.key, agent.crt,
broker-ca.crt) is left in place so a later reinstall reuses the existing
enrollment.
EOF
}

# ---- arg parsing ------------------------------------------------------------

while [ $# -gt 0 ]; do
    case "$1" in
        --config-dir)    CONFIG_DIR="$2"; shift 2 ;;
        --bin-path)      BIN_PATH="$2"; shift 2 ;;
        --service-name)  SERVICE_NAME="$2"; shift 2 ;;
        --purge)         PURGE="true"; shift ;;
        --no-systemd)    NO_SYSTEMD="true"; shift ;;
        --dry-run)       DRY_RUN="true"; shift ;;
        -h|--help)       usage; exit 0 ;;
        *)               echo "unknown flag: $1" >&2; usage >&2; exit 2 ;;
    esac
done

# ---- helpers ----------------------------------------------------------------

log()  { printf 'uninstall: %s\n' "$*"; }
die()  { printf 'uninstall: error: %s\n' "$*" >&2; exit 1; }

# run - execute a command as ARGV. Each argument is passed literally to the
# command; nothing is ever handed to a shell for evaluation, so operator-supplied
# values cannot inject commands even when this script runs as root. In dry-run we
# print a safely shell-quoted representation for display only (printf %q); that
# string is NEVER fed back into a shell.
run() {
    if [ "$DRY_RUN" = "true" ]; then
        local shown="" arg
        for arg in "$@"; do
            shown="$shown $(printf '%q' "$arg")"
        done
        printf 'uninstall: DRY-RUN $%s\n' "$shown"
    else
        "$@"
    fi
}

# reject_control_chars - fail if a value contains newlines/CR or other control
# characters. Such characters in a path would corrupt output or systemctl
# arguments. Spaces are allowed so legitimate paths with spaces still work.
reject_control_chars() {
    local label="$1" val="$2"
    case "$val" in
        *$'\n'*|*$'\r'*) die "--$label must not contain newlines or carriage returns" ;;
    esac
    if printf '%s' "$val" | LC_ALL=C grep -q '[[:cntrl:]]'; then
        die "--$label must not contain control characters"
    fi
}

# validate_service_name - the name becomes both a filesystem path
# (/etc/systemd/system/<name>.service) and a systemctl argument. Restrict it to a
# safe unit basename: an alphanumeric first character followed by alphanumerics,
# dot, underscore, or hyphen. This rejects slashes (path traversal), a leading
# dash (systemctl option smuggling), whitespace, and every shell metacharacter.
# The script appends ".service" itself.
validate_service_name() {
    local name="$1"
    case "$name" in
        *$'\n'*|*$'\r'*) die "--service-name must not contain newlines" ;;
    esac
    if ! printf '%s' "$name" | LC_ALL=C grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]*$'; then
        die "--service-name '$name' is invalid: use letters, digits, dot, underscore, or hyphen (no slash, no leading dash, no spaces)"
    fi
}

# guard_purge_target - --purge deletes a directory tree as root. Refuse paths
# that are not absolute, that are the filesystem root, or that are well-known
# system directories whose removal would destroy the host. Only a nested
# absolute path may be purged.
guard_purge_target() {
    local dir="$1"
    case "$dir" in
        /*) : ;;
        *)  die "--config-dir must be an absolute path to use --purge (got '$dir')" ;;
    esac
    case "$dir" in
        *//*|*/./*|*/../*|*/..) die "--config-dir must be a normalized path to use --purge" ;;
    esac
    # Strip any trailing slash before comparing so "/etc/" is caught too.
    local normalized="${dir%/}"
    case "$normalized" in
        ""|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var)
            die "refusing to purge system directory '$dir'" ;;
    esac
    # Require at least two path segments (e.g. /etc/praxis-agent), never a
    # single top-level directory.
    case "${normalized#/}" in
        */*) : ;;
        *)   die "refusing to purge top-level directory '$dir'" ;;
    esac
}

# ---- validate attacker-controlled names/paths -------------------------------

validate_service_name "$SERVICE_NAME"
reject_control_chars config-dir "$CONFIG_DIR"
reject_control_chars bin-path "$BIN_PATH"
if [ "$PURGE" = "true" ]; then
    guard_purge_target "$CONFIG_DIR"
fi

# ---- preflight --------------------------------------------------------------

[ "$(uname -s)" = "Linux" ] || die "Linux only (got $(uname -s))"
# Real uninstalls mutate root-owned paths and must run as root. --dry-run
# changes nothing, so it is allowed unprivileged (useful for review + tests).
if [ "$DRY_RUN" != "true" ]; then
    [ "$(id -u)" -eq 0 ] || die "must run as root"
fi

# ---- stop + disable the service --------------------------------------------

UNIT_REMOVED="false"
if [ "$NO_SYSTEMD" != "true" ]; then
    if ! command -v systemctl >/dev/null 2>&1; then
        die "systemctl missing; pass --no-systemd if intentional"
    fi

    if systemctl is-active --quiet "$SERVICE_NAME.service" 2>/dev/null; then
        log "stopping $SERVICE_NAME"
        run systemctl stop "$SERVICE_NAME.service"
    else
        log "$SERVICE_NAME is not running"
    fi

    if systemctl is-enabled --quiet "$SERVICE_NAME.service" 2>/dev/null; then
        log "disabling $SERVICE_NAME"
        run systemctl disable "$SERVICE_NAME.service"
    else
        log "$SERVICE_NAME is not enabled"
    fi

    UNIT_DST="/etc/systemd/system/$SERVICE_NAME.service"
    if [ -f "$UNIT_DST" ]; then
        log "removing $UNIT_DST"
        run rm -f -- "$UNIT_DST"
        UNIT_REMOVED="true"
    else
        log "no unit at $UNIT_DST"
    fi

    if [ "$UNIT_REMOVED" = "true" ]; then
        log "systemctl daemon-reload"
        run systemctl daemon-reload
        run systemctl reset-failed "$SERVICE_NAME.service" || true
    fi
fi

# ---- remove the binary ------------------------------------------------------

if [ -e "$BIN_PATH" ]; then
    log "removing $BIN_PATH"
    run rm -f -- "$BIN_PATH"
else
    log "no binary at $BIN_PATH"
fi

# ---- config + identity ------------------------------------------------------

if [ "$PURGE" = "true" ]; then
    if [ -d "$CONFIG_DIR" ]; then
        log "purging $CONFIG_DIR (identity material is being deleted)"
        run rm -rf -- "$CONFIG_DIR"
    else
        log "no config dir at $CONFIG_DIR"
    fi
else
    if [ -d "$CONFIG_DIR" ]; then
        log "preserving $CONFIG_DIR (pass --purge to delete identity material)"
    fi
fi

log "done"
