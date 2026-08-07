#!/usr/bin/env bash
# Praxis agent bootstrap (PRA-154 #1d-b).
#
# Strict, boring, fail-closed. The control plane templates one
# sentinel — __PRAXIS_DEFAULT_URL__ — into this file at serve time;
# everything else is operator input via env.
#
# Required env:
#     PRAXIS_URL                 control plane base URL (no trailing /)
#     PRAXIS_ACTIVATION_TOKEN    "praxis_…" plaintext token
#     PRAXIS_SYSTEM_ID           target System id from the token
#
# Optional env:
#     PRAXIS_BROKER_URL          override the broker WSS URL. If unset
#                                we derive it from PRAXIS_URL by
#                                swapping the scheme; non-(http|https)
#                                URLs must set this explicitly.
#     PRAXIS_AGENT_CONFIG_DIR    where to install identity material
#                                (default: /etc/praxis-agent).
#
# Hard prereqs (the script does NOT install packages):
#     bash, curl, jq, tar, sha256sum, install, hostname, uname,
#     systemctl, cat, mktemp, install -m … as root.
#
# Inspect-mode: invoking with `--help` prints this comment block and
# exits 0 without touching the system.

set -euo pipefail
IFS=$'\n\t'

PRAXIS_DEFAULT_URL="__PRAXIS_DEFAULT_URL__"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
    exit 0
fi

log()  { printf '[praxis-bootstrap] %s\n' "$*"; }
fail() { printf '[praxis-bootstrap] ERROR: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- preflight

[[ "$(uname -s)" == "Linux" ]] || fail "Linux required (uname -s = $(uname -s))"
command -v systemctl >/dev/null 2>&1 || fail "systemctl required"
[[ "$(id -u)" -eq 0 ]] || fail "must run as root"

case "$(uname -m)" in
    x86_64)  ARCH=amd64 ;;
    aarch64) ARCH=arm64 ;;
    *)       fail "unsupported arch: $(uname -m)" ;;
esac

for tool in curl jq tar sha256sum install hostname mktemp; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing prereq: $tool"
done

PRAXIS_URL="${PRAXIS_URL:-${PRAXIS_DEFAULT_URL}}"
[[ -n "${PRAXIS_URL}" && "${PRAXIS_URL}" != "__PRAXIS_DEFAULT_URL__" ]] \
    || fail "PRAXIS_URL is required and the template was not substituted"
PRAXIS_URL="${PRAXIS_URL%/}"
[[ -n "${PRAXIS_ACTIVATION_TOKEN:-}" ]] || fail "PRAXIS_ACTIVATION_TOKEN is required"
[[ -n "${PRAXIS_SYSTEM_ID:-}" ]]        || fail "PRAXIS_SYSTEM_ID is required"
[[ "${PRAXIS_SYSTEM_ID}" =~ ^[0-9]+$ ]] || fail "PRAXIS_SYSTEM_ID must be an integer"

CONFIG_DIR="${PRAXIS_AGENT_CONFIG_DIR:-/etc/praxis-agent}"

# Derive broker URL if the operator didn't pin one. Handle both schemes;
# refuse anything else so we never produce an invalid wss URL by silent
# string surgery.
if [[ -z "${PRAXIS_BROKER_URL:-}" ]]; then
    case "${PRAXIS_URL}" in
        https://*) PRAXIS_BROKER_URL="wss://${PRAXIS_URL#https://}/agent/tunnel" ;;
        http://*)  PRAXIS_BROKER_URL="ws://${PRAXIS_URL#http://}/agent/tunnel" ;;
        *) fail "cannot derive broker URL from PRAXIS_URL=${PRAXIS_URL}; set PRAXIS_BROKER_URL explicitly" ;;
    esac
fi

# ---------------------------------------------------------------- temp scratch

WORK="$(mktemp -d -t praxis-bootstrap.XXXXXX)"
cleanup() { rm -rf "${WORK}"; }
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------- agent binary

TARBALL="agent.tar.gz"
log "downloading agent tarball"
(
    cd "${WORK}"
    # The control plane serves canonical filenames; the real per-arch
    # release asset name lives entirely server-side. The synthesized
    # checksum file already references "agent.tar.gz", so sha256sum -c
    # finds the local file directly without a rewrite step.
    curl -fsSL -o "${TARBALL}"          "${PRAXIS_URL}/agent/download/${ARCH}/${TARBALL}"
    curl -fsSL -o "${TARBALL}.sha256"   "${PRAXIS_URL}/agent/download/${ARCH}/${TARBALL}.sha256"
    sha256sum -c "${TARBALL}.sha256" >/dev/null \
        || fail "agent tarball checksum mismatch"
    tar -xzf "${TARBALL}"
)
# Release tarball layout (per agent/Makefile package target):
#     praxis-agent-<version>-linux-<arch>/
#         praxis-agent
#         install.sh
#         praxis-agent.service
#         README.md
#         LICENSE
# Locate the binary by name rather than baking the version into the
# script — bumping the agent version stays a control-plane-only
# change.
AGENT_BIN="$(find "${WORK}" -mindepth 2 -maxdepth 3 -type f -name praxis-agent | head -n1)"
[[ -n "${AGENT_BIN}" && -x "${AGENT_BIN}" ]] \
    || fail "tarball did not contain a praxis-agent binary"
install -m 0755 -o root -g root "${AGENT_BIN}" /usr/local/bin/praxis-agent
log "installed /usr/local/bin/praxis-agent"

# ---------------------------------------------------------------- identity

install -d -m 0750 -o root -g root "${CONFIG_DIR}"

if [[ -f "${CONFIG_DIR}/agent.key" ]]; then
    log "reusing existing keypair at ${CONFIG_DIR}/agent.key"
else
    log "generating new keypair"
    /usr/local/bin/praxis-agent gen-keypair --config-dir "${CONFIG_DIR}" >/dev/null
fi

CSR="$(/usr/local/bin/praxis-agent gen-csr --config-dir "${CONFIG_DIR}")"
[[ -n "${CSR}" ]] || fail "gen-csr produced empty output"

# ---------------------------------------------------------------- ca bundle

log "fetching CA bundle"
curl -fsSL -o "${WORK}/ca-bundle.json" "${PRAXIS_URL}/agent/ca-bundle"
jq -e '.agent_ca and .broker_ca' "${WORK}/ca-bundle.json" >/dev/null \
    || fail "ca-bundle response missing agent_ca/broker_ca"

# ---------------------------------------------------------------- enroll

log "enrolling system_id=${PRAXIS_SYSTEM_ID}"
ENROLL_BODY="$(jq -nc \
    --argjson sid "${PRAXIS_SYSTEM_ID}" \
    --arg fp  "$(cat /etc/machine-id)" \
    --arg csr "${CSR}" \
    --arg hn  "$(hostname -f 2>/dev/null || hostname)" \
    '{system_id:$sid, host_fingerprint:$fp, csr_pem:$csr, hostname:$hn}')"

ENROLL_RESPONSE="$(curl -fsS --fail-with-body -X POST \
    -H "Content-Type: application/json" \
    -H "X-Praxis-Activation-Token: ${PRAXIS_ACTIVATION_TOKEN}" \
    -d "${ENROLL_BODY}" \
    "${PRAXIS_URL}/agent/enroll")"

# Wipe the token from this script's environment so it cannot leak
# via a child process or a later debug dump.
unset PRAXIS_ACTIVATION_TOKEN

echo "${ENROLL_RESPONSE}" | jq -r '.certificate'  > "${WORK}/agent.crt"
RESPONSE_SYSTEM_ID="$(echo "${ENROLL_RESPONSE}" | jq -r '.system_id')"
[[ "${RESPONSE_SYSTEM_ID}" == "${PRAXIS_SYSTEM_ID}" ]] \
    || fail "server returned system_id=${RESPONSE_SYSTEM_ID}, expected ${PRAXIS_SYSTEM_ID}"

# ---------------------------------------------------------------- install cert

log "installing cert + config into ${CONFIG_DIR}"
/usr/local/bin/praxis-agent install-cert \
    --config-dir "${CONFIG_DIR}" \
    --cert       "${WORK}/agent.crt" \
    --bundle     "${WORK}/ca-bundle.json" \
    --backend-url "${PRAXIS_URL}" \
    --broker-url  "${PRAXIS_BROKER_URL}" \
    --system-id   "${PRAXIS_SYSTEM_ID}" >/dev/null

# ---------------------------------------------------------------- systemd

UNIT_PATH="/etc/systemd/system/praxis-agent.service"
log "writing ${UNIT_PATH}"
cat >"${UNIT_PATH}" <<UNIT
[Unit]
Description=Praxis Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/praxis-agent connect --config-dir ${CONFIG_DIR}
Restart=always
RestartSec=5
# No User=/Group= — v1 agent runs as root. Hardening (AppArmor /
# SELinux / cgroup squeeze) is intentionally deferred per PRA-154
# scope.

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 "${UNIT_PATH}"

systemctl daemon-reload
systemctl enable --now praxis-agent

# ---------------------------------------------------------------- verify

log "waiting for praxis-agent to become active"
for _ in $(seq 1 30); do
    if systemctl is-active --quiet praxis-agent; then
        log "enrolled system_id=${PRAXIS_SYSTEM_ID}"
        exit 0
    fi
    sleep 1
done

log "praxis-agent did not become active within 30s; recent journal:"
journalctl -u praxis-agent --no-pager -n 50 || true
fail "agent failed to start"
