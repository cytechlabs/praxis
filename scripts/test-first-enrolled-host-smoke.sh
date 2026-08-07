#!/usr/bin/env bash
# PRA-179 Slice 2a: hermetic local first-enrolled-host bootstrap smoke.
#
# Slice 2 verified the production-overlay fresh-install path through
# backend ``/health`` + authenticated API read + anonymous
# ``/agent/bootstrap.sh`` and ``/agent/ca-bundle`` reach. This smoke
# closes the remaining fresh-install end-to-end gap: a docker-side
# dummy host actually exercises the ``POST /agent/enroll`` redemption
# path that turns an activation token + CSR into an issued agent
# cert and flips ``System.agent_status`` to ``active``.
#
# What we do NOT exercise (intentional Slice 2a boundary, documented
# in docs/production-hardening.md):
#
#   - ``scripts/_assets/bootstrap.sh`` end-to-end. The script hard-
#     requires systemd (``systemctl required``) and a real
#     ``praxis-agent`` Go binary from the pinned GitHub Release tag
#     ``agent-v0.0.0-rc1``. Standing up a systemd-in-docker dummy
#     host adds a privileged-container surface area that we
#     deliberately don't bring into the smoke; pulling the agent
#     binary from GitHub Releases would make this smoke
#     network-dependent and slow. The Praxis-specific behaviour the
#     smoke needs to cover is the ``/agent/enroll`` handler (CSR
#     redemption + Vault PKI signing + System.agent_status
#     transition) — not the host-side curl/jq/systemctl wrapper.
#   - The agent's mTLS handshake against the broker
#     (``/agent/tunnel``). The bootstrap script wires the cert and
#     starts ``praxis-agent connect``; the actual broker handshake is
#     orthogonal to "first-enrolled-host" semantics and would
#     require the real agent binary.
#
# The dummy host IS a real disposable Ubuntu 22.04 docker container
# on the smoke project's ``backend_net``. It uses curl + openssl + jq
# — the same tools the committed bootstrap.sh relies on — to:
#
#   1. Fetch the anonymous ``/agent/ca-bundle`` over the docker
#      network (same code path bootstrap.sh hits).
#   2. Generate an EC P-256 keypair + CSR with openssl. The agent
#      role in Vault (``allow_subdomains=true``,
#      ``use_csr_common_name=false``, ``use_csr_sans=false``,
#      ``key_type=ec key_bits=256``) discards the CSR's CN/SANs and
#      issues a system-specific identity, so the CSR's own subject
#      doesn't matter — only the public key + signature do. This is
#      exactly how the real Go agent's CSR is treated.
#   3. POST ``/agent/enroll`` with the
#      ``X-Praxis-Activation-Token`` header and the CSR; assert the
#      response carries a certificate, the original system_id, and
#      ``agent_status=active``.
#
# After the dummy host enrolls, we re-read the System row from
# Postgres and assert ``agent_status=active`` plus a non-null
# ``agent_cert_serial`` to prove the redemption actually mutated
# the backend state (and not just an in-memory response).
#
# Flow:
#
#   1. Bring up the prod overlay in bundled mode in an isolated
#      compose project (``praxis-first-host-smoke``).
#   2. Wait for backend /health.
#   3. POST /auth/login as the auto-created admin.
#   4. Seed the synthetic state the activation-token POST requires
#      via direct psql against the smoke-owned db: one
#      ``credentials`` row, one ``systems`` row pinned to a known
#      Ubuntu 22.04 distro from seed_data.py.
#   5. POST /agent/activation-tokens for that system_id; capture
#      the plaintext token (returned exactly once).
#   6. ``docker run --rm`` an ubuntu:22.04 container on the smoke
#      project's backend_net. Inside it: apt-get install curl +
#      openssl + jq, generate an EC P-256 CSR, hit /agent/ca-bundle
#      to confirm the dummy host can reach the control plane, and
#      POST /agent/enroll.
#   7. Assert the response's certificate / system_id / agent_status.
#   8. Re-read the System row from postgres; assert agent_status=
#      active and agent_cert_serial is non-null.
#   9. Tear down strictly.
#
# Usage:
#     scripts/test-first-enrolled-host-smoke.sh
#
# Exit codes:
#     0 - smoke passed; project torn down (volumes removed).
#     1 - smoke failed; project LEFT UP for inspection.
#
# Safety:
#     - Dedicated compose project name (``praxis-first-host-smoke``);
#       never touches the default ``praxis`` project, any other
#       PRA-179 smoke project, or the user's dev stack.
#     - Writes its env file to a ``mktemp -d`` directory and unlinks
#       it only on a clean exit.
#     - Refuses to start if the smoke project already has containers.

set -euo pipefail

cd "$(dirname "$0")/.."

PROJECT_NAME="praxis-first-host-smoke"
OVERRIDE_FILE="scripts/fresh-install-smoke.override.yml"
COMPOSE_BASE=(
    -f docker-compose.yml
    -f docker-compose.prod.yml
    -f "${OVERRIDE_FILE}"
)
COMPOSE_PROFILE_ARGS=(--profile bundled)
DUMMY_HOST_NAME="${PROJECT_NAME}-dummy"
DUMMY_HOST_HOSTNAME="praxis-pra179-2a-dummy"

# ---------------------------------------------------------------- pre-flight

if ! command -v docker >/dev/null 2>&1; then
    echo "ERR: docker CLI not on PATH" >&2
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo "ERR: docker daemon is not reachable" >&2
    exit 1
fi

EXISTING=$(docker ps -a --quiet \
    --filter "label=com.docker.compose.project=${PROJECT_NAME}" 2>/dev/null || true)
if [[ -n "${EXISTING}" ]]; then
    echo "ERR: smoke project '${PROJECT_NAME}' already has containers." >&2
    docker ps -a \
        --filter "label=com.docker.compose.project=${PROJECT_NAME}" \
        --format '      {{.ID}}  {{.Names}}  {{.Status}}' >&2 || true
    echo "    Force-tear-down with project-label-only commands:" >&2
    echo "      docker rm -f \$(docker ps -aq --filter 'label=com.docker.compose.project=${PROJECT_NAME}')" >&2
    echo "      docker volume rm \$(docker volume ls -q --filter 'label=com.docker.compose.project=${PROJECT_NAME}')" >&2
    echo "      docker network rm \$(docker network ls -q --filter 'label=com.docker.compose.project=${PROJECT_NAME}')" >&2
    exit 1
fi
# Refuse if a previous run left the dummy host container behind.
if docker inspect "${DUMMY_HOST_NAME}" >/dev/null 2>&1; then
    echo "ERR: stale dummy host container '${DUMMY_HOST_NAME}' present." >&2
    echo "    Remove with: docker rm -f ${DUMMY_HOST_NAME}" >&2
    exit 1
fi

# ---------------------------------------------------------------- env + temp

SMOKE_TMP=$(mktemp -d -t praxis-2a-XXXXXX)
SMOKE_ENV_FILE="${SMOKE_TMP}/.env"

gen_secret() {
    python3 -c 'import secrets; print(secrets.token_urlsafe(32))' 2>/dev/null \
    || python -c 'import secrets; print(secrets.token_urlsafe(32))'
}

SMOKE_SECRET=$(gen_secret)
SMOKE_ADMIN_PASS=$(gen_secret | head -c 24)
SMOKE_PG_PASS=$(gen_secret   | head -c 24)

cat > "${SMOKE_ENV_FILE}" <<EOF
COMPOSE_PROFILES=bundled
ENVIRONMENT=production
SECRET_KEY=${SMOKE_SECRET}
ADMIN_PASSWORD=${SMOKE_ADMIN_PASS}
ADMIN_USERNAME=praxisadmin
ADMIN_EMAIL=admin@example.com
POSTGRES_USER=postgres
POSTGRES_PASSWORD=${SMOKE_PG_PASS}
POSTGRES_DB=praxis
PRAXIS_PUBLIC_URL=http://backend:8000
EOF

teardown_stack() {
    echo "==> tearing down smoke project"
    docker rm -f "${DUMMY_HOST_NAME}" >/dev/null 2>&1 || true
    docker compose --env-file "${SMOKE_ENV_FILE}" -p "${PROJECT_NAME}" \
        "${COMPOSE_BASE[@]}" "${COMPOSE_PROFILE_ARGS[@]}" \
        down -v
}

on_exit() {
    local rc=$?
    if [[ ${rc} -eq 0 ]]; then
        rm -rf "${SMOKE_TMP}" 2>/dev/null || true
        return
    fi
    echo "==> SMOKE FAILED (rc=${rc}). Project left up for inspection." >&2
    if [[ -f "${SMOKE_ENV_FILE}" ]]; then
        echo "    Smoke env file PRESERVED at:" >&2
        echo "      ${SMOKE_ENV_FILE}" >&2
        echo "    Logs:" >&2
        echo "      docker compose --env-file ${SMOKE_ENV_FILE} -p ${PROJECT_NAME} ${COMPOSE_BASE[*]} ${COMPOSE_PROFILE_ARGS[*]} logs --tail=200 backend vault db agent-broker" >&2
        echo "    Dummy host (if still up):" >&2
        echo "      docker logs ${DUMMY_HOST_NAME}" >&2
        echo "    Teardown when done:" >&2
        echo "      docker compose --env-file ${SMOKE_ENV_FILE} -p ${PROJECT_NAME} ${COMPOSE_BASE[*]} ${COMPOSE_PROFILE_ARGS[*]} down -v" >&2
        echo "      docker rm -f ${DUMMY_HOST_NAME}" >&2
        echo "    After teardown, remove the temp dir:" >&2
        echo "      rm -rf ${SMOKE_TMP}" >&2
    else
        echo "    Smoke env file was not written before exit; cleaning the empty temp dir." >&2
        rm -rf "${SMOKE_TMP}" 2>/dev/null || true
    fi
    echo "    Project-label-only fallback:" >&2
    echo "      docker rm -f \$(docker ps -aq --filter 'label=com.docker.compose.project=${PROJECT_NAME}')" >&2
    echo "      docker rm -f ${DUMMY_HOST_NAME}" >&2
    echo "      docker volume rm \$(docker volume ls -q --filter 'label=com.docker.compose.project=${PROJECT_NAME}')" >&2
    echo "      docker network rm \$(docker network ls -q --filter 'label=com.docker.compose.project=${PROJECT_NAME}')" >&2
}
trap on_exit EXIT

# ---------------------------------------------------------------- helpers

compose() {
    docker compose --env-file "${SMOKE_ENV_FILE}" -p "${PROJECT_NAME}" \
        "${COMPOSE_BASE[@]}" "${COMPOSE_PROFILE_ARGS[@]}" "$@"
}

wait_for_backend_health() {
    local healthy=0
    local n=${1:-90}
    for _ in $(seq 1 "${n}"); do
        if compose exec -T backend python -c "
import urllib.request, sys
try:
    r = urllib.request.urlopen('http://localhost:8000/health', timeout=3)
    sys.exit(0 if r.status == 200 else 1)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
            healthy=1
            break
        fi
        sleep 2
    done
    if [[ "${healthy}" -ne 1 ]]; then
        echo "==> backend never became healthy" >&2
        compose logs --tail=200 backend vault db agent-broker >&2 || true
        return 1
    fi
}

# ---------------------------------------------------------------- up

echo "==> bringing up smoke stack"
compose up -d --build

echo "==> waiting for backend /health"
wait_for_backend_health
echo "    backend healthy"

# ---------------------------------------------------------------- admin login

echo "==> POST /auth/login as praxisadmin"
ACCESS_TOKEN=$(compose exec -T \
    -e SMOKE_ADMIN_PASS="${SMOKE_ADMIN_PASS}" \
    backend python -c "
import os, sys, json, urllib.request, urllib.parse, urllib.error
form = urllib.parse.urlencode({'username': 'praxisadmin', 'password': os.environ['SMOKE_ADMIN_PASS']}).encode()
req = urllib.request.Request(
    'http://localhost:8000/auth/login',
    data=form,
    headers={'Content-Type': 'application/x-www-form-urlencoded'},
    method='POST',
)
try:
    resp = urllib.request.urlopen(req, timeout=10)
except urllib.error.HTTPError as exc:
    sys.stderr.write(f'login failed: HTTP {exc.code} {exc.read().decode()}\n')
    sys.exit(1)
body = json.loads(resp.read())
print(body['access_token'])
")
[[ -n "${ACCESS_TOKEN}" ]] || { echo "==> empty access_token" >&2; exit 1; }
echo "    got access_token (len=${#ACCESS_TOKEN})"

# ---------------------------------------------------------------- seed state via psql
#
# Slice 2 surfaced that seed_data.py does NOT create a default
# ``credentials`` row, so POST /systems can't be done end-to-end via
# the API without first POSTing /credentials (which has Vault-write
# side-effects, broadening the smoke). Direct INSERT into the
# smoke-owned db is the smaller path here, and only writes synthetic
# placeholder values: name='pra179-2a-smoke-cred',
# auth_method='password', vault_path='praxis/data/pra179-2a-smoke',
# username='smoke', NULL password (the value lives in Vault in the
# real path; for the smoke we never use the credential to SSH
# anywhere, so a NULL is fine).

echo "==> seeding synthetic credential + system via psql"
DISTRO_ID=$(compose exec -T db psql -v ON_ERROR_STOP=1 -U postgres -d praxis -tAc \
    "SELECT id FROM distros WHERE name='Ubuntu' AND version='22.04' LIMIT 1")
[[ -n "${DISTRO_ID}" ]] || { echo "==> Ubuntu 22.04 distro not found (seed_data.py)" >&2; exit 1; }
echo "    Ubuntu 22.04 distro_id=${DISTRO_ID}"

# INSERT ... RETURNING under ``psql -tAc`` prints the returned row
# AND a trailing ``INSERT 0 1`` command tag. ``head -n 1`` keeps just
# the returned id so the captured variable substitutes cleanly into
# the next INSERT statement. (Without it, the second INSERT receives
# a literal "1\nINSERT 0 1" and fails with a SQL syntax error.)
CREDENTIAL_ID=$(compose exec -T db psql -v ON_ERROR_STOP=1 -U postgres -d praxis -tAc \
    "INSERT INTO credentials (name, auth_method, vault_path, username)
     VALUES ('pra179-2a-smoke-cred', 'password', 'praxis/data/pra179-2a-smoke', 'smoke')
     RETURNING id" | tr -d '\r' | head -n 1)
echo "    credentials.id=${CREDENTIAL_ID}"

SYSTEM_ID=$(compose exec -T db psql -v ON_ERROR_STOP=1 -U postgres -d praxis -tAc \
    "INSERT INTO systems (hostname, ip_address, status, distro_id, os_version, group_id, credentials_id, registered_at, created_at, updated_at, agent_status)
     VALUES ('${DUMMY_HOST_HOSTNAME}', '10.99.99.99', 'Active', ${DISTRO_ID}, '22.04', 1, ${CREDENTIAL_ID}, NOW(), NOW(), NOW(), 'not_enrolled')
     RETURNING id" | tr -d '\r' | head -n 1)
echo "    systems.id=${SYSTEM_ID} (agent_status=not_enrolled)"

# ---------------------------------------------------------------- mint activation token

echo "==> POST /agent/activation-tokens"
TOKEN_PLAINTEXT=$(compose exec -T \
    -e SMOKE_ACCESS_TOKEN="${ACCESS_TOKEN}" \
    -e SMOKE_SYSTEM_ID="${SYSTEM_ID}" \
    backend python -c "
import os, sys, json, urllib.request, urllib.error
payload = json.dumps({
    'name': 'pra179-2a-smoke',
    'default_group_id': 1,
    'target_system_id': int(os.environ['SMOKE_SYSTEM_ID']),
    'default_tag_ids': [],
    'ttl_seconds': 3600,
    'max_uses': 1,
}).encode()
req = urllib.request.Request(
    'http://localhost:8000/agent/activation-tokens',
    data=payload,
    headers={'Authorization': f\"Bearer {os.environ['SMOKE_ACCESS_TOKEN']}\",
             'Content-Type': 'application/json'},
    method='POST',
)
try:
    resp = urllib.request.urlopen(req, timeout=10)
except urllib.error.HTTPError as exc:
    sys.stderr.write(f'mint failed: HTTP {exc.code} {exc.read().decode()}\n')
    sys.exit(1)
body = json.loads(resp.read())
print(body['plaintext'])
")
[[ -n "${TOKEN_PLAINTEXT}" ]] || { echo "==> empty TOKEN_PLAINTEXT" >&2; exit 1; }
echo "    minted activation token (len=${#TOKEN_PLAINTEXT})"

# ---------------------------------------------------------------- dummy host bootstrap
#
# Run an ubuntu:22.04 container on the smoke project's backend_net.
# We attach to the same network the backend listens on so the dummy
# host can resolve ``backend`` by service name (same hostname-based
# trust the operator-shaped DNS path would use).
#
# Inside the container we apt-get install curl + openssl + jq (allowed
# per Slice 2a locks: package-manager commands inside disposable
# Docker containers are in scope for the dummy-host smoke), then
# carry out exactly the steps the bootstrap.sh wrapper would have
# carried out for the /agent/enroll redemption: generate an EC P-256
# keypair + CSR, fetch /agent/ca-bundle, POST /agent/enroll.

BACKEND_NET="${PROJECT_NAME}_backend_net"

echo "==> starting docker-side dummy host on ${BACKEND_NET}"
docker run -d \
    --name "${DUMMY_HOST_NAME}" \
    --network "${BACKEND_NET}" \
    --hostname "${DUMMY_HOST_HOSTNAME}" \
    -e DUMMY_TOKEN="${TOKEN_PLAINTEXT}" \
    -e DUMMY_SYSTEM_ID="${SYSTEM_ID}" \
    ubuntu:22.04 \
    sleep infinity >/dev/null

# Install tools. We intentionally use the same shape bootstrap.sh
# documents as its host prereqs: curl, jq, openssl. No agent binary,
# no systemd.
echo "==> installing dummy-host tools (curl, openssl, jq)"
docker exec "${DUMMY_HOST_NAME}" bash -lc '
    set -e
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null
    apt-get install -y -qq --no-install-recommends curl openssl jq ca-certificates >/dev/null
' >/dev/null

echo "==> generating EC P-256 keypair + CSR on dummy host"
docker exec "${DUMMY_HOST_NAME}" bash -lc '
    set -e
    cd /tmp
    openssl ecparam -name prime256v1 -genkey -noout -out agent.key
    # CSR subject is throwaway; the Vault agent role uses
    # use_csr_common_name=false / use_csr_sans=false and supplies
    # CN + URI SAN itself based on the redeemed system_id.
    openssl req -new -key agent.key \
        -subj "/CN=pra179-2a-smoke" \
        -out agent.csr
    test -s agent.csr
'
echo "    csr ready at /tmp/agent.csr"

echo "==> dummy host fetches /agent/ca-bundle"
docker exec "${DUMMY_HOST_NAME}" bash -lc '
    set -e
    curl -fsSL -o /tmp/ca-bundle.json http://backend:8000/agent/ca-bundle
    jq -e ".agent_ca and .broker_ca" /tmp/ca-bundle.json >/dev/null
'
echo "    ca-bundle reachable"

echo "==> dummy host POSTs /agent/enroll"
docker exec "${DUMMY_HOST_NAME}" bash -lc "
    set -e
    cd /tmp
    HOSTNAME_FQDN=\"\$(hostname)\"
    # Fake machine-id; on a real host /etc/machine-id is populated by
    # systemd-machine-id-setup. On a plain ubuntu:22.04 container
    # without systemd, it can be empty; supply a synthetic value
    # since the enroll endpoint only requires host_fingerprint to be
    # a non-empty string.
    MACHINE_ID=\"pra179-2a-smoke-fingerprint\"
    CSR_PEM=\"\$(cat agent.csr)\"
    jq -nc \\
        --argjson sid '${SYSTEM_ID}' \\
        --arg fp \"\${MACHINE_ID}\" \\
        --arg csr \"\${CSR_PEM}\" \\
        --arg hn \"\${HOSTNAME_FQDN}\" \\
        '{system_id:\$sid, host_fingerprint:\$fp, csr_pem:\$csr, hostname:\$hn}' \\
        > enroll-body.json
    curl -fsS -X POST \\
        -H 'Content-Type: application/json' \\
        -H \"X-Praxis-Activation-Token: \${DUMMY_TOKEN}\" \\
        -d @enroll-body.json \\
        http://backend:8000/agent/enroll \\
        > enroll-response.json
    test -s enroll-response.json
"
echo "    enroll succeeded"

# ---------------------------------------------------------------- assertions

echo "==> verifying enroll response shape"
docker exec "${DUMMY_HOST_NAME}" bash -lc "
    set -e
    jq -e '.certificate and .system_id and .agent_status' /tmp/enroll-response.json >/dev/null
    RESPONSE_SID=\$(jq -r '.system_id' /tmp/enroll-response.json)
    [[ \"\${RESPONSE_SID}\" == \"${SYSTEM_ID}\" ]] \\
        || { echo \"system_id mismatch (got \${RESPONSE_SID})\" >&2; exit 1; }
    RESPONSE_STATUS=\$(jq -r '.agent_status' /tmp/enroll-response.json)
    [[ \"\${RESPONSE_STATUS}\" == 'active' ]] \\
        || { echo \"agent_status mismatch (got \${RESPONSE_STATUS})\" >&2; exit 1; }
    # The cert is a PEM-encoded x509; sanity check.
    jq -r '.certificate' /tmp/enroll-response.json | grep -q 'BEGIN CERTIFICATE'
"
echo "    response: certificate present, system_id=${SYSTEM_ID}, agent_status=active"

echo "==> verifying backend mutated System row"
POST_STATUS=$(compose exec -T db psql -v ON_ERROR_STOP=1 -U postgres -d praxis -tAc \
    "SELECT agent_status FROM systems WHERE id=${SYSTEM_ID}")
POST_SERIAL=$(compose exec -T db psql -v ON_ERROR_STOP=1 -U postgres -d praxis -tAc \
    "SELECT agent_cert_serial FROM systems WHERE id=${SYSTEM_ID}")
[[ "${POST_STATUS}" == "active" ]] \
    || { echo "==> systems.agent_status='${POST_STATUS}' (expected 'active')" >&2; exit 1; }
[[ -n "${POST_SERIAL}" ]] \
    || { echo "==> systems.agent_cert_serial is null after enroll" >&2; exit 1; }
echo "    systems.agent_status=active, agent_cert_serial=${POST_SERIAL}"

# Post-enrollment authenticated current-head API read (Slice 2a
# acceptance: backend ``/health`` is necessary but not sufficient —
# the slice also requires a representative authenticated read
# proving the enrolled row is reachable through the application
# stack, not just psql). ``GET /agent/status/{system_id}`` is admin-
# gated and returns the same agent_status / agent_cert_serial /
# agent_cert_fingerprint fields the System row carries, so it
# round-trips Vault → Postgres → SQLAlchemy → API response.
echo "==> GET /agent/status/${SYSTEM_ID} (admin, post-enroll authenticated read)"
STATUS_OUTPUT=$(compose exec -T \
    -e SMOKE_ACCESS_TOKEN="${ACCESS_TOKEN}" \
    -e SMOKE_SYSTEM_ID="${SYSTEM_ID}" \
    -e SMOKE_EXPECTED_SERIAL="${POST_SERIAL}" \
    backend python -c "
import os, sys, json, urllib.request, urllib.error
sid = os.environ['SMOKE_SYSTEM_ID']
req = urllib.request.Request(
    f'http://localhost:8000/agent/status/{sid}',
    headers={'Authorization': f\"Bearer {os.environ['SMOKE_ACCESS_TOKEN']}\"},
)
try:
    resp = urllib.request.urlopen(req, timeout=10)
except urllib.error.HTTPError as exc:
    sys.stderr.write(f'/agent/status failed: HTTP {exc.code} {exc.read().decode()}\n')
    sys.exit(1)
body = json.loads(resp.read())
if str(body.get('system_id')) != sid:
    sys.stderr.write(f'system_id mismatch: got {body.get(\"system_id\")} expected {sid}\n')
    sys.exit(1)
if body.get('agent_status') != 'active':
    sys.stderr.write(f'agent_status mismatch: got {body.get(\"agent_status\")} expected active\n')
    sys.exit(1)
if body.get('agent_cert_serial') != os.environ['SMOKE_EXPECTED_SERIAL']:
    sys.stderr.write(f'agent_cert_serial mismatch: api={body.get(\"agent_cert_serial\")} psql={os.environ[\"SMOKE_EXPECTED_SERIAL\"]}\n')
    sys.exit(1)
if not body.get('agent_cert_fingerprint'):
    sys.stderr.write('agent_cert_fingerprint is empty in /agent/status response\n')
    sys.exit(1)
print(f\"{body['agent_status']} | serial={body['agent_cert_serial']} | fp={body['agent_cert_fingerprint'][:24]}...\")
")
[[ -n "${STATUS_OUTPUT}" ]] || { echo "==> empty /agent/status response" >&2; exit 1; }
echo "    /agent/status/${SYSTEM_ID}: ${STATUS_OUTPUT}"

echo "==> verifying backend /health is still green after enroll"
wait_for_backend_health 5
echo "    backend healthy"

# ---------------------------------------------------------------- done

teardown_stack
echo "==> smoke passed"
