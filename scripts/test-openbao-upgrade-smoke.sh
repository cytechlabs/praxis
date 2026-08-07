#!/usr/bin/env bash
# PRA-311 Slice 2: existing-volume upgrade smoke — old bundled HashiCorp Vault
# file-storage data must boot under the current bundled OpenBao runtime.
#
# Slice 1 swapped the bundled secrets runtime to openbao/openbao:2.6.1 and proved
# FRESH init/unseal/KV/SSH/PKI. This smoke closes the remaining migration risk: an
# operator upgrading an EXISTING install keeps the same `vault_data` / `vault_recovery`
# volumes, so OpenBao must read a barrier + tokens written by the old HashiCorp Vault
# 1.15.4 binary.
#
# Flow (two throwaway containers over two temp volumes; no host ports, no compose):
#
#   PHASE A — generate authentic OLD data:
#     Run hashicorp/vault:1.15.4 against the OLD scripts. The Slice-1 swap was a pure
#     `vault `->`bao ` rename, so we reproduce the pre-swap scripts by inverting it
#     (`bao `->`vault `) on the CURRENT scripts into a temp dir — self-contained, no git
#     history, always tracking the current script structure. The barrier, the
#     `hvs.`-prefixed tokens, and all engine data are written by the real Vault 1.15.4
#     binary, so the persisted volume is an authentic old-bundled-Vault volume. We then
#     write an extra representative KV secret and record the old backend token.
#
#   PHASE B — boot current OpenBao on the SAME volumes:
#     Stop the old container (keep the volumes), start openbao/openbao:2.6.1 against the
#     repo's current vault/config + vault/scripts (native `bao`, no shim). Assert:
#       - OpenBao unseals via the current scripts (keys from the old init-keys.json);
#       - the OLD `hvs.` backend token still authenticates with backend-service policy;
#       - the KV secret written by Vault 1.15.4 reads back through OpenBao;
#       - KV write, SSH sign (ssh-client-signer/praxis-user), and broker PKI issue work;
#       - every expected /vault/data/* runtime file and /vault/recovery/* operator file
#         is present.
#
# This is a heavy Docker smoke (pulls two images, ~60s); it is NOT part of the CI
# lanes. Run it locally before a release that touches the bundled secrets runtime. The
# lightweight, CI-runnable source/runtime contract lives in
# backend/tests/services/test_pra311_openbao_runtime_contract.py.
#
# Usage:  scripts/test-openbao-upgrade-smoke.sh
# Env:    OLD_VAULT_IMAGE (default hashicorp/vault:1.15.4)
#         OPENBAO_IMAGE   (default openbao/openbao:2.6.1)

set -euo pipefail

OLD_VAULT_IMAGE="${OLD_VAULT_IMAGE:-hashicorp/vault:1.15.4}"
OPENBAO_IMAGE="${OPENBAO_IMAGE:-openbao/openbao:2.6.1}"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PROJ="pra311upgrade$$"
OLDC="${PROJ}-old"
NEWC="${PROJ}-bao"
VOL_DATA="${PROJ}_data"
VOL_REC="${PROJ}_rec"
# Under $REPO (not /tmp): Docker here only bind-mounts paths under the repo tree.
OLD_SCRIPTS_DIR="$(mktemp -d "$REPO/.tmp-pra311-oldscripts-XXXXXX")"

log() { echo "[openbao-upgrade-smoke] $*"; }
fail() { echo "[openbao-upgrade-smoke] FAIL: $*" >&2; exit 1; }

cleanup() {
    docker rm -f "$OLDC" "$NEWC" >/dev/null 2>&1 || true
    docker volume rm "$VOL_DATA" "$VOL_REC" >/dev/null 2>&1 || true
    rm -rf "$OLD_SCRIPTS_DIR" 2>/dev/null || true
}
trap cleanup EXIT

# Shared run args for a bundled-secrets-style container: root user (OpenBao's image
# defaults to non-root; the startup command needs root to apk-add + chown), IPC_LOCK,
# the repo config, the persisted volumes, and a scripts dir ($3 selects which).
run_secrets_container() {
    _name="$1"; _image="$2"; _scripts_dir="$3"
    docker run -d --name "$_name" --user 0:0 --cap-add IPC_LOCK \
        -e VAULT_ADDR=http://127.0.0.1:8200 \
        -e PRAXIS_VAULT_RECOVERY_DIR=/vault/recovery \
        -v "$REPO/vault/config:/vault/config" \
        -v "$_scripts_dir:/vault/scripts" \
        -v "$VOL_DATA:/vault/data" \
        -v "$VOL_REC:/vault/recovery" \
        --entrypoint sh "$_image" \
        -c "apk add --no-cache jq openssl >/dev/null 2>&1; chmod +x /vault/scripts/*.sh; sh /vault/scripts/startup.sh" >/dev/null
}

# Wait until startup.sh reports init-vault.sh finished provisioning (the
# "initialization complete; supervising" line fires only after init returns 0, i.e.
# unsealed AND all engines/tokens/files provisioned). Fails fast if the container dies.
wait_provisioned() {
    _c="$1"; _t=0
    while [ "$_t" -lt 60 ]; do
        if [ "$(docker inspect -f '{{.State.Running}}' "$_c" 2>/dev/null)" != "true" ]; then
            docker logs "$_c" 2>&1 | tail -30 >&2
            fail "$_c exited during startup"
        fi
        if docker logs "$_c" 2>&1 | grep -q "initialization complete; supervising"; then
            return 0
        fi
        _t=$((_t + 1)); sleep 1
    done
    docker logs "$_c" 2>&1 | tail -30 >&2
    fail "$_c did not finish provisioning in time"
}

cleanup  # clear any stale containers/volumes from a previous run
docker volume create "$VOL_DATA" >/dev/null
docker volume create "$VOL_REC" >/dev/null

# Reproduce the PRE-SWAP scripts (which used the `vault` CLI) by inverting the Slice-1
# swap on the CURRENT scripts: the swap was a pure `vault `->`bao ` rename, so
# `bao `->`vault ` reproduces the old scripts exactly. This is self-contained (no git
# history, no CLI shim) and always tracks the current script structure. Phase A mounts
# these over /vault/scripts so the OLD image drives its native `vault` binary; Phase B
# uses the repo's current `bao`-based scripts unchanged. Populated AFTER the initial
# cleanup (which removes OLD_SCRIPTS_DIR) so the dir survives into Phase A.
mkdir -p "$OLD_SCRIPTS_DIR"
cp "$REPO"/vault/scripts/*.sh "$OLD_SCRIPTS_DIR"/
sed -i 's/\bbao /vault /g' "$OLD_SCRIPTS_DIR"/*.sh

# ---------------------------------------------------------------- PHASE A (old)
log "PHASE A: provisioning volumes with OLD $OLD_VAULT_IMAGE (current scripts, vault CLI)"
run_secrets_container "$OLDC" "$OLD_VAULT_IMAGE" "$OLD_SCRIPTS_DIR"
wait_provisioned "$OLDC"

docker exec "$OLDC" sh -c '
    set -e
    export VAULT_ADDR=http://127.0.0.1:8200
    export VAULT_TOKEN=$(cat /vault/data/backend-token)
    vault kv put praxis/upgradeprobe secret=preserve-me created_by=vault-1.15.4 >/dev/null
' || fail "phase A: writing representative KV data failed"

OLD_TOKEN_PREFIX=$(docker exec "$OLDC" sh -c 'cut -c1-4 /vault/data/backend-token')
OLD_VERSION=$(docker exec "$OLDC" sh -c 'vault version' | head -1)
log "old data written by: $OLD_VERSION (backend-token prefix: $OLD_TOKEN_PREFIX)"
[ "$OLD_TOKEN_PREFIX" = "hvs." ] || log "NOTE: expected an hvs. token from Vault 1.15; got '$OLD_TOKEN_PREFIX'"

log "stopping OLD container (keeping volumes)"
docker rm -f "$OLDC" >/dev/null

# ---------------------------------------------------------------- PHASE B (OpenBao)
log "PHASE B: booting CURRENT $OPENBAO_IMAGE (native bao) on the SAME volumes"
run_secrets_container "$NEWC" "$OPENBAO_IMAGE" "$REPO/vault/scripts"
wait_provisioned "$NEWC"

NEW_VERSION=$(docker exec "$NEWC" sh -c 'VAULT_ADDR=http://127.0.0.1:8200 bao version' | head -1)
log "runtime now: $NEW_VERSION"

log "asserting preserved behavior on the upgraded volume..."
docker exec "$NEWC" sh -c '
    set -e
    export VAULT_ADDR=http://127.0.0.1:8200
    export VAULT_TOKEN=$(cat /vault/data/backend-token)

    # 1) the OLD hvs. token still authenticates with the backend-service policy.
    pol=$(bao token lookup -format=json | jq -r ".data.policies | sort | join(\",\")")
    case "$pol" in *backend-service*) ;; *) echo "old token lost backend-service policy: $pol" >&2; exit 1;; esac

    # 2) the KV secret written by Vault 1.15.4 reads back through OpenBao.
    got=$(bao kv get -field=secret praxis/upgradeprobe)
    [ "$got" = "preserve-me" ] || { echo "persisted KV mismatch: $got" >&2; exit 1; }

    # 3) KV write of a NEW secret through OpenBao.
    bao kv put praxis/postupgrade v=written-by-openbao >/dev/null

    # 4) SSH signing at ssh-client-signer/praxis-user (backend path).
    apk add --no-cache openssh-keygen >/dev/null 2>&1
    ssh-keygen -t rsa -b 2048 -f /tmp/uk -N "" -q
    sk=$(bao write -field=signed_key ssh-client-signer/sign/praxis-user public_key=@/tmp/uk.pub valid_principals=testuser)
    case "$sk" in ssh-rsa-cert-v01@openssh.com*) ;; *) echo "ssh sign failed" >&2; exit 1;; esac

    # 5) broker PKI issue (policy allows issue/server).
    bao write -field=serial_number praxis-broker-ca/issue/server \
        common_name=backend alt_names=localhost,backend ip_sans=127.0.0.1 ttl=1h >/dev/null

    # 6) agent CA cert readable + agent role intact (agent uses sign/, exercised in the
    #    fresh proof; here we assert the persisted CA + role survived the upgrade).
    export VAULT_TOKEN=$(cat /vault/recovery/root-token)
    bao read -field=certificate praxis-agent-ca/cert/ca | head -1 >/dev/null
    bao read -field=key_type praxis-agent-ca/roles/agent >/dev/null
' || fail "phase B: preserved-behavior assertions failed"

log "asserting expected file outputs on the upgraded volume..."
docker exec "$NEWC" sh -c '
    for f in /vault/data/backend-token /vault/data/ssh-ca-public-key /vault/data/agent-ca-cert.pem \
             /vault/data/broker/server.crt /vault/data/broker/server.key /vault/data/broker/ca.crt \
             /vault/recovery/root-token /vault/recovery/init-keys.json; do
        [ -s "$f" ] || { echo "MISSING $f" >&2; exit 1; }
    done
' || fail "phase B: expected file outputs missing after upgrade"

log "PASS: $OLD_VAULT_IMAGE volume upgraded cleanly to $NEW_VERSION with all preserved behavior."
