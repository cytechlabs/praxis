#!/bin/sh
# Bundled secrets-runtime container entrypoint (PRA-246; OpenBao since PRA-311).
#
# The bundled runtime is OpenBao, driven via the `bao` CLI. The Docker service,
# volumes, and paths keep the `vault` / `/vault` names for 1.0 compatibility, and
# VAULT_ADDR is still honored by OpenBao. (OpenBao also ships a `vault`->`bao`
# shim, so a stray `vault` reference would still work, but we use `bao` directly.)
#
# Ties the container lifecycle to the OpenBao SERVER process. It runs as a
# supervised child and this script `wait`s on it as its final foreground
# operation, so PID 1 exits with Vault's exit code: if Vault crashes the
# container exits and Docker's `restart: unless-stopped` can recover the
# service. There is deliberately NO `tail -f /dev/null` keepalive that would
# otherwise keep the container "up" with a dead Vault inside it.
#
# Flow:
#   1. start Vault in the background and capture its PID
#   2. wait (bounded) until `bao status` is reachable
#   3. run the init/unseal/provision script
#   4. if init fails, terminate Vault and exit nonzero
#   5. otherwise `wait` on Vault and exit with its code
# SIGTERM/SIGINT are forwarded to Vault for a clean shutdown.

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
export VAULT_ADDR

# Overridable so the lifecycle can be tested with fake commands; defaults match
# the bundled container layout.
VAULT_CONFIG="${VAULT_CONFIG:-/vault/config/vault.hcl}"
VAULT_INIT_SCRIPT="${VAULT_INIT_SCRIPT:-/vault/scripts/init-vault.sh}"
# Bounded wait (seconds) for Vault to start answering `bao status`.
VAULT_READY_TIMEOUT="${VAULT_READY_TIMEOUT:-60}"

log() { echo "[vault-startup] $*"; }

# --- start Vault as a supervised child ------------------------------------
bao server -config="$VAULT_CONFIG" &
VAULT_PID=$!
log "started Vault server (pid $VAULT_PID)"

# --- forward termination to Vault -----------------------------------------
terminate() {
    trap '' TERM INT  # don't re-enter while shutting down
    log "termination signal received; forwarding to Vault (pid $VAULT_PID)"
    kill -TERM "$VAULT_PID" 2>/dev/null
    wait "$VAULT_PID"
    code=$?
    log "Vault exited with code $code after termination"
    exit "$code"
}
trap terminate TERM INT

# --- wait for Vault to become reachable (bounded) -------------------------
# `bao status` exit codes: 0 = unsealed, 2 = sealed (both mean the server is
# up and answering), 1 = not reachable yet. A fresh Vault is sealed until the
# init script unseals it, so 2 is the expected "ready to init" state.
ready=0
elapsed=0
while [ "$elapsed" -lt "$VAULT_READY_TIMEOUT" ]; do
    if ! kill -0 "$VAULT_PID" 2>/dev/null; then
        wait "$VAULT_PID"
        code=$?
        log "Vault process exited during startup (code $code)"
        exit "$code"
    fi
    status_rc=0
    bao status >/dev/null 2>&1 || status_rc=$?
    if [ "$status_rc" -eq 0 ] || [ "$status_rc" -eq 2 ]; then
        ready=1
        break
    fi
    elapsed=$((elapsed + 1))
    sleep 1
done

if [ "$ready" -ne 1 ]; then
    log "timed out after ${VAULT_READY_TIMEOUT}s waiting for Vault to become reachable"
    kill -TERM "$VAULT_PID" 2>/dev/null
    wait "$VAULT_PID" 2>/dev/null
    exit 1
fi
log "Vault is reachable; running initialization"

# --- initialize / unseal / provision --------------------------------------
if ! "$VAULT_INIT_SCRIPT"; then
    log "initialization ($VAULT_INIT_SCRIPT) failed; terminating Vault"
    kill -TERM "$VAULT_PID" 2>/dev/null
    wait "$VAULT_PID" 2>/dev/null
    exit 1
fi
log "initialization complete; supervising Vault (pid $VAULT_PID)"

# --- wait on Vault as the final foreground operation ----------------------
# When Vault exits (crash or clean stop) the container exits with its code.
wait "$VAULT_PID"
code=$?
log "Vault exited with code $code; container exiting"
exit "$code"
