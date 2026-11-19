#!/usr/bin/env bash
# Real-host qualification of unavailable compliance evidence.
#
# Starts a disposable Ubuntu sshd container on the stack's backend network, then
# proves against that real host:
#   1. a host with no stored facts yields a readable error reason
#      (no_host_facts_row);
#   2. a real probe passes while sshd is reachable;
#   3. stopping sshd yields a readable error (ssh_transport_failure), not a
#      silent pass or fail;
#   4. restarting sshd recovers to a real pass verdict.
# Each step requires exactly one persisted evidence row per expected check for
# that evaluation run, host and policy, then verifies verdict, reason and the
# runner_status of the evidence export contract.
#
# The Ubuntu 24.04 distro row that ships with the product is required, and is
# never created or deleted by this script.
#
# Every resource carries a per-run id. The script removes only what this
# invocation created, verifies they are gone (a Vault 404 and a "no such
# container" are the only accepted proofs of absence; an unavailable or denying
# service fails the run), and prints the success line only
# after that verification. Overlapping runs and pre-existing rows are untouched.
#
# Recovery of stored-facts evidence needs a facts collection from a managed
# host and is not exercised here.
#
# Usage (from the directory with the compose files; same variables as
# seed-demo.sh):
#   NETWORK=<project>_backend_net e2e/fixtures/qualify-unavailable-evidence.sh
#   e2e/fixtures/qualify-unavailable-evidence.sh --selftest   # no stack needed
#
# QUAL_TAMPER=empty|missing|duplicate damages the evidence of every evaluation
# on purpose, to show the verification rejects it (the run must then fail).

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

if [[ "${1:-}" == "--selftest" ]]; then
    exec python3 - "$HERE" <<'PY'
import sys, types
# The verification logic is plain Python; stub the app imports it declares.
for name in ("app", "app.db", "app.db.compliance_models", "app.db.models",
             "app.db.session", "app.db.ssh_security_models", "app.services",
             "app.services.compliance_evaluation_service",
             "app.services.vault_service"):
    sys.modules[name] = types.ModuleType(name)
stubs = {
    "app.db.compliance_models": ("CompliancePolicy", "CompliancePolicyEvidence"),
    "app.db.models": ("Credential", "Distro", "Group", "System", "SystemMetadata"),
    "app.db.session": ("SessionLocal",),
    "app.db.ssh_security_models": ("SSHHostKey", "SSHSecurityLog"),
    "app.services.compliance_evaluation_service": ("evaluate_policy_for_host", "evidence_export_row"),
    "app.services.vault_service": ("VaultService", "_split_path"),
}
for mod, names in stubs.items():
    for n in names:
        setattr(sys.modules[mod], n, object)
import os
os.environ["QUAL_RUN_ID"] = "0" * 12
import importlib.util
spec = importlib.util.spec_from_file_location("q", sys.argv[1] + "/qualify_unavailable_evidence.py")
q = importlib.util.module_from_spec(spec); spec.loader.exec_module(q)
q.selftest()
PY
fi

NETWORK="${NETWORK:?set NETWORK to the stack backend network, e.g. praxis-e2e_backend_net}"
# QUAL_FORCE_RUN_ID exists only so a test can provoke a name collision.
RUN_ID="${QUAL_FORCE_RUN_ID:-$(openssl rand -hex 6)}"
NAME="e2e-qual-sshd-$RUN_ID"
WORKDIR="$(mktemp -d)"
# Docker writes the container id here when it creates the container; that file
# is the evidence this invocation owns the container. A name collision or an
# unreachable daemon leaves it empty, and nothing is then removed.
CIDFILE="$WORKDIR/cid"
PASSWORD="$(openssl rand -hex 12)"
IP=""
SETUP_STARTED=0
PASSED=0

compose() {
    # shellcheck disable=SC2086
    docker compose ${COMPOSE_ENV_FILE:+--env-file "$COMPOSE_ENV_FILE"} \
        ${COMPOSE_FILES:--f docker-compose.yml -f docker-compose.prod.yml} \
        ${COMPOSE_PROFILES_ARGS:---profile bundled --profile proxy} "$@"
}
# The backend reads its Vault token from the bundled token file.
run_py() {
    compose exec -T -e QUAL_RUN_ID="$RUN_ID" -e QUAL_PASSWORD="$PASSWORD" \
        -e QUAL_IP="$IP" ${QUAL_TAMPER:+-e QUAL_TAMPER="$QUAL_TAMPER"} backend \
        sh -c 'VAULT_TOKEN="$(cat /vault/data/backend-token)" exec python - "$@"' sh "$@" \
        < "$HERE/qualify_unavailable_evidence.py"
}

# Remove the container this invocation created. Confirmed removal or confirmed
# absence ("No such container") succeeds; a daemon failure does not.
remove_container() {
    [[ -s "$CIDFILE" ]] || return 0
    local cid out
    cid="$(<"$CIDFILE")"
    if ! out="$(docker rm -f "$cid" 2>&1)"; then
        if [[ "$out" != *"No such container"* ]]; then
            echo "FAIL cannot remove container ${cid:0:12}: $out" >&2
            return 1
        fi
    fi
    if out="$(docker inspect "$cid" 2>&1)"; then
        echo "FAIL container ${cid:0:12} still present after removal" >&2
        return 1
    fi
    if [[ "$out" != *"No such object"* && "$out" != *"No such container"* ]]; then
        echo "FAIL cannot confirm container ${cid:0:12} is gone: $out" >&2
        return 1
    fi
    return 0
}

cleanup() {
    status=$?
    trap - EXIT INT TERM
    # Teardown only if setup was attempted: it is keyed on this run's id, so it
    # is safe after a partial setup and cannot touch another run's resources.
    if [[ "$SETUP_STARTED" == 1 ]]; then
        run_py teardown || status=1
    fi
    remove_container || status=1
    rm -rf "$WORKDIR"
    if [[ "$status" == 0 && "$PASSED" == 1 ]]; then
        echo "QUALIFICATION PASS (cleanup verified)"
    else
        echo "QUALIFICATION FAIL" >&2
        [[ "$status" == 0 ]] && status=1
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

docker run -d --cidfile "$CIDFILE" --name "$NAME" --network "$NETWORK" \
    ubuntu:24.04 sleep infinity >/dev/null
docker exec "$NAME" bash -c "
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server >/dev/null 2>&1 &&
    mkdir -p /run/sshd && echo root:$PASSWORD | chpasswd &&
    printf 'PermitRootLogin yes\nPasswordAuthentication yes\n' >> /etc/ssh/sshd_config &&
    /usr/sbin/sshd"
IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NETWORK\").IPAddress}}" "$NAME")"

SETUP_STARTED=1
run_py setup
run_py evaluate reachable
docker exec "$NAME" pkill -x sshd
sleep 1
run_py evaluate sshd_stopped
docker exec "$NAME" /usr/sbin/sshd
sleep 1
run_py evaluate recovered
PASSED=1
