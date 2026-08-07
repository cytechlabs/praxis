#!/usr/bin/env bash
# Praxis fleet agent installer.
#
# Idempotent: safe to re-run. Replaces the binary if changed,
# preserves /etc/praxis-agent (operator owns config + keys after
# first install), reloads systemd only when the unit file actually
# changes, and restarts the service only if it was already active
# (or if --start is passed).
#
# Identity bootstrap (gen-keypair / gen-csr / install-cert) is NOT
# part of this script — operators run those separately so install
# stays a pure file-placement step.
set -euo pipefail

# ---- defaults ---------------------------------------------------------------

BINARY_SRC="$(cd "$(dirname "$0")" && pwd)/praxis-agent"
UNIT_SRC="$(cd "$(dirname "$0")" && pwd)/praxis-agent.service"

CONFIG_DIR="/etc/praxis-agent"
BIN_PATH="/usr/local/bin/praxis-agent"
SERVICE_NAME="praxis-agent"

BROKER_URL=""
BACKEND_URL=""
SYSTEM_ID=""
START_NOW="false"
NO_SYSTEMD="false"
DRY_RUN="false"

# ---- usage ------------------------------------------------------------------

usage() {
    cat <<EOF
Usage: $0 [flags]

  --binary PATH         path to praxis-agent binary    (default: ./praxis-agent)
  --config-dir PATH     config directory               (default: /etc/praxis-agent)
  --bin-path PATH       binary install location        (default: /usr/local/bin/praxis-agent)
  --service-name NAME   systemd unit name              (default: praxis-agent)
  --broker-url URL      written to config.json on first install
  --backend-url URL     written to config.json on first install
  --system-id N         written to config.json on first install
  --start               systemctl start after install  (default: install only)
  --no-systemd          skip unit install + daemon-reload
  --dry-run             print actions, change nothing
  -h, --help            show this help

Existing /etc/praxis-agent/config.json, agent.crt, agent.key, and
broker-ca.crt are NEVER overwritten.
EOF
}

# ---- arg parsing ------------------------------------------------------------

while [ $# -gt 0 ]; do
    case "$1" in
        --binary)        BINARY_SRC="$2"; shift 2 ;;
        --config-dir)    CONFIG_DIR="$2"; shift 2 ;;
        --bin-path)      BIN_PATH="$2"; shift 2 ;;
        --service-name)  SERVICE_NAME="$2"; shift 2 ;;
        --broker-url)    BROKER_URL="$2"; shift 2 ;;
        --backend-url)   BACKEND_URL="$2"; shift 2 ;;
        --system-id)     SYSTEM_ID="$2"; shift 2 ;;
        --start)         START_NOW="true"; shift ;;
        --no-systemd)    NO_SYSTEMD="true"; shift ;;
        --dry-run)       DRY_RUN="true"; shift ;;
        -h|--help)       usage; exit 0 ;;
        *)               echo "unknown flag: $1" >&2; usage >&2; exit 2 ;;
    esac
done

# ---- helpers ----------------------------------------------------------------

log()  { printf 'install: %s\n' "$*"; }
warn() { printf 'install: warn: %s\n' "$*" >&2; }
die()  { printf 'install: error: %s\n' "$*" >&2; exit 1; }

# run — execute a command as ARGV. Each argument is passed literally to the
# command; nothing is ever handed to a shell for evaluation, so operator-supplied
# values (paths, names, URLs) cannot inject commands even when this script runs as
# root. In dry-run we print a safely shell-quoted representation for display only
# (printf %q) — that string is NEVER fed back into a shell.
run() {
    if [ "$DRY_RUN" = "true" ]; then
        local shown="" arg
        for arg in "$@"; do
            shown="$shown $(printf '%q' "$arg")"
        done
        printf 'install: DRY-RUN $%s\n' "$shown"
    else
        "$@"
    fi
}

# reject_control_chars — fail if a value contains newlines/CR or other control
# characters. Such characters in a path would let an attacker inject extra
# directives into the rendered systemd unit (each unit line is newline-delimited)
# or corrupt output. Spaces are allowed so legitimate paths with spaces still work.
reject_control_chars() {
    local label="$1" val="$2"
    case "$val" in
        *$'\n'*|*$'\r'*) die "--$label must not contain newlines or carriage returns" ;;
    esac
    if printf '%s' "$val" | LC_ALL=C grep -q '[[:cntrl:]]'; then
        die "--$label must not contain control characters"
    fi
}

# validate_service_name — the name becomes both a filesystem path
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

# sha256 of a file ($1) or empty string if file missing. The `--` stops a path
# that begins with a dash from being read as a sha256sum option.
sha_of() {
    if [ -f "$1" ]; then
        sha256sum -- "$1" | awk '{print $1}'
    else
        echo ""
    fi
}

# Atomic file install: write to .tmp, set mode + owner, rename. Argv execution —
# src/dst/mode are passed literally, never through a shell. `--` before the path
# operands stops a leading-dash path from being parsed as an install/mv option.
atomic_install() {
    local mode="$1" src="$2" dst="$3"
    local tmp="$dst.install.$$"
    run install -m "$mode" -o root -g root -- "$src" "$tmp"
    run mv -- "$tmp" "$dst"
}

# json_escape — escape a string value for safe inclusion inside a
# JSON string literal. Handles \, ", and control chars. Stdin -> stdout.
json_escape() {
    # python is on every modern Linux; falls back to a sed pipeline
    # that covers the common cases (\, ", newline, tab, CR).
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import json,sys; sys.stdout.write(json.dumps(sys.stdin.read())[1:-1])'
    else
        sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' \
            -e ':a;N;$!ba;s/\n/\\n/g' \
            -e 's/\r/\\r/g' -e 's/\t/\\t/g'
    fi
}

# Render the systemd unit from packaging/praxis-agent.service, substituting
# @BIN_PATH@ and @CONFIG_DIR@ with the operator's choices. Output goes to stdout.
#
# Uses Bash literal string replacement (not sed) so the substituted values are
# treated as plain text — no regex/delimiter/replacement metacharacters (&, |, \)
# are interpreted, and nothing is evaluated by a shell. reject_control_chars has
# already guaranteed the values carry no newline, so they cannot inject extra
# unit directives.
render_unit() {
    local content
    content=$(cat -- "$UNIT_SRC")
    content=${content//@BIN_PATH@/$BIN_PATH}
    content=${content//@CONFIG_DIR@/$CONFIG_DIR}
    printf '%s\n' "$content"
}

# ---- validate attacker-controlled names/paths -------------------------------
# Run before any value is used in a filesystem path, a systemd unit, or a
# systemctl argument. Command injection is already impossible (argv execution, no
# shell evaluation); these checks additionally stop path traversal and unit-file
# injection.

validate_service_name "$SERVICE_NAME"
reject_control_chars binary "$BINARY_SRC"
reject_control_chars config-dir "$CONFIG_DIR"
reject_control_chars bin-path "$BIN_PATH"

# ---- preflight --------------------------------------------------------------

[ "$(uname -s)" = "Linux" ] || die "Linux only (got $(uname -s))"
# Real installs mutate root-owned paths and must run as root. --dry-run changes
# nothing, so it is allowed unprivileged (useful for review + CI/regression tests).
if [ "$DRY_RUN" != "true" ]; then
    [ "$(id -u)" -eq 0 ] || die "must run as root"
fi
[ -f "$BINARY_SRC" ] || die "binary not found: $BINARY_SRC"
[ -x "$BINARY_SRC" ] || die "binary not executable: $BINARY_SRC"

# system_id, when supplied, must be a positive integer — it lands
# unquoted in JSON.
if [ -n "$SYSTEM_ID" ]; then
    case "$SYSTEM_ID" in
        ''|*[!0-9]*) die "--system-id must be a positive integer (got '$SYSTEM_ID')" ;;
    esac
fi
if [ "$NO_SYSTEMD" != "true" ]; then
    [ -d /etc/systemd/system ] || die "/etc/systemd/system missing — pass --no-systemd if intentional"
    [ -f "$UNIT_SRC" ] || die "unit file not found: $UNIT_SRC"
    command -v systemctl >/dev/null 2>&1 || die "systemctl missing — pass --no-systemd if intentional"
fi

# ---- ensure config dir ------------------------------------------------------

if [ ! -d "$CONFIG_DIR" ]; then
    log "creating config dir $CONFIG_DIR"
    run install -d -m 0755 -o root -g root -- "$CONFIG_DIR"
else
    log "config dir already exists at $CONFIG_DIR"
fi

# ---- write config.json on first install only --------------------------------

CONFIG_FILE="$CONFIG_DIR/config.json"
if [ -e "$CONFIG_FILE" ]; then
    log "config.json already exists; not overwriting"
elif [ -n "$BROKER_URL$BACKEND_URL$SYSTEM_ID" ]; then
    log "writing initial $CONFIG_FILE"
    # Build the JSON document — only include fields the operator
    # actually supplied so we don't lock in defaults.
    # String values pass through json_escape so embedded quotes /
    # backslashes / control chars don't produce invalid JSON.
    # system_id was validated as a positive integer above.
    body="{"
    sep=""
    if [ -n "$BACKEND_URL" ]; then
        esc=$(printf '%s' "$BACKEND_URL" | json_escape)
        body="$body${sep}\"backend_url\":\"$esc\""; sep=","
    fi
    if [ -n "$BROKER_URL" ]; then
        esc=$(printf '%s' "$BROKER_URL" | json_escape)
        body="$body${sep}\"broker_url\":\"$esc\""; sep=","
    fi
    if [ -n "$SYSTEM_ID" ]; then
        body="$body${sep}\"system_id\":$SYSTEM_ID"; sep=","
    fi
    body="$body}"
    if [ "$DRY_RUN" = "true" ]; then
        printf 'install: DRY-RUN > %s with: %s\n' "$CONFIG_FILE" "$body"
    else
        tmp="$CONFIG_FILE.install.$$"
        printf '%s\n' "$body" > "$tmp"
        chmod 0644 -- "$tmp"
        chown root:root -- "$tmp"
        mv -- "$tmp" "$CONFIG_FILE"
    fi
else
    log "no --broker-url/--backend-url/--system-id and no existing config.json; operator must populate $CONFIG_FILE before starting the service"
fi

# ---- install / replace binary ----------------------------------------------

NEW_HASH=$(sha_of "$BINARY_SRC")
OLD_HASH=$(sha_of "$BIN_PATH")
if [ "$NEW_HASH" = "$OLD_HASH" ] && [ -n "$OLD_HASH" ]; then
    log "binary unchanged at $BIN_PATH (sha=$NEW_HASH)"
    BINARY_REPLACED="false"
else
    # Shell-native dirname (no external command, so no option-parsing of a
    # leading-dash path). A bin path with no slash installs into the CWD (".");
    # a bin path directly under root (e.g. /foo) has parent "/".
    case "$BIN_PATH" in
        */*) bin_dir=${BIN_PATH%/*}; [ -z "$bin_dir" ] && bin_dir=/ ;;
        *)   bin_dir=. ;;
    esac
    if [ ! -d "$bin_dir" ]; then
        log "creating $bin_dir for binary install"
        run install -d -m 0755 -o root -g root -- "$bin_dir"
    fi
    log "installing binary -> $BIN_PATH"
    atomic_install 0755 "$BINARY_SRC" "$BIN_PATH"
    BINARY_REPLACED="true"
fi

# ---- install / replace systemd unit ----------------------------------------

UNIT_REPLACED="false"
if [ "$NO_SYSTEMD" != "true" ]; then
    UNIT_DST="/etc/systemd/system/$SERVICE_NAME.service"
    # Render to a tempfile so the rendered output (with --bin-path
    # and --config-dir substituted) is what we hash + install. A
    # verbatim copy of the template would silently ignore custom
    # paths and start the wrong binary against the wrong config.
    rendered_tmp=$(mktemp)
    render_unit > "$rendered_tmp"
    NEW_UNIT_HASH=$(sha_of "$rendered_tmp")
    OLD_UNIT_HASH=$(sha_of "$UNIT_DST")
    if [ "$NEW_UNIT_HASH" = "$OLD_UNIT_HASH" ] && [ -n "$OLD_UNIT_HASH" ]; then
        log "unit unchanged at $UNIT_DST"
        rm -f "$rendered_tmp"
    else
        log "installing unit -> $UNIT_DST (bin=$BIN_PATH config=$CONFIG_DIR)"
        atomic_install 0644 "$rendered_tmp" "$UNIT_DST"
        rm -f "$rendered_tmp"
        UNIT_REPLACED="true"
    fi
fi

# ---- post-install validation -----------------------------------------------

log "verifying binary"
if [ "$DRY_RUN" != "true" ]; then
    "$BIN_PATH" --version >/dev/null 2>&1 || die "$BIN_PATH --version failed"
    if [ -f "$CONFIG_FILE" ] && [ -f "$CONFIG_DIR/agent.crt" ] && [ -f "$CONFIG_DIR/agent.key" ]; then
        if "$BIN_PATH" show-config --config-dir "$CONFIG_DIR" >/dev/null 2>&1; then
            log "show-config OK"
        else
            warn "show-config failed — config or identity files are malformed"
        fi
    fi
fi

# ---- systemd: reload + (re)start as appropriate ----------------------------

if [ "$NO_SYSTEMD" != "true" ]; then
    if [ "$UNIT_REPLACED" = "true" ]; then
        log "systemctl daemon-reload"
        run systemctl daemon-reload
    fi

    WAS_ACTIVE="false"
    if systemctl is-active --quiet "$SERVICE_NAME.service" 2>/dev/null; then
        WAS_ACTIVE="true"
    fi

    if [ "$START_NOW" = "true" ]; then
        log "systemctl enable + restart $SERVICE_NAME"
        run systemctl enable "$SERVICE_NAME.service"
        run systemctl restart "$SERVICE_NAME.service"
    elif [ "$WAS_ACTIVE" = "true" ] && [ "$BINARY_REPLACED" = "true" ]; then
        log "service was active; restarting after binary swap"
        run systemctl restart "$SERVICE_NAME.service"
    elif [ "$WAS_ACTIVE" = "true" ] && [ "$UNIT_REPLACED" = "true" ]; then
        log "service was active; restarting after unit change"
        run systemctl restart "$SERVICE_NAME.service"
    else
        log "service not started (pass --start to start now)"
    fi
fi

log "done"
