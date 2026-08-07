#!/usr/bin/env bash
# PRA-179 Slice 2: hermetic local fresh-install smoke for the production
# compose overlay.
#
# Brings up an isolated docker-compose project using
#   docker-compose.yml + docker-compose.prod.yml + scripts/fresh-install-smoke.override.yml
# in --profile bundled, generates ephemeral SECRET_KEY / ADMIN_PASSWORD /
# POSTGRES_PASSWORD, then drives a representative install-shaped path:
#
#   1. Backend /health responds 200.
#   2. POST /auth/login as the auto-created admin user; GET /auth/me
#      returns username=praxisadmin.
#   3. GET  /agent/activation-tokens as admin (admin-RBAC-gated read,
#      empty list on a fresh install).
#   4. GET  /agent/bootstrap.sh (anonymous; verifies that the
#      PRAXIS_PUBLIC_URL substitution path works and the committed
#      bootstrap.sh asset is served).
#   5. GET  /agent/ca-bundle (anonymous; verifies the bundled Vault
#      agent-PKI provisioning emitted the agent CA bundle the route
#      reads).
#
# Verification runs INSIDE the backend container via
# ``docker compose exec backend python -c "..."`` so the smoke does not
# bind any host ports — see scripts/fresh-install-smoke.override.yml.
#
# What this smoke does NOT cover (intentional Slice 2 scope, deferred
# to a Slice 2a candidate):
#
#   - Minting an activation token. The activation-token API requires a
#     valid ``target_system_id`` (a System row), and Systems require
#     ``credentials_id`` + ``distro_id`` that the fresh-install seed
#     path does not provision by default. The full token mint plus
#     end-to-end bootstrap against a docker-side dummy host is the
#     Slice 2a follow-up.
#   - Running bootstrap.sh end-to-end inside a dummy host container.
#     That path needs the agent binary tarball (downloaded either from
#     a local PRAXIS_AGENT_ARTIFACT_DIR or from GitHub Releases) plus
#     the broker mTLS handshake.
#   - The Caddy reverse-proxy + TLS layer.
#   - External Postgres / external Vault.
#
# Usage:
#     scripts/test-fresh-install-smoke.sh
#
# Exit codes:
#     0 - smoke passed; project torn down (volumes removed).
#     1 - smoke failed; project LEFT UP for inspection (run the printed
#         teardown command when done).
#
# Safety:
#     - Uses a dedicated compose project name; never touches the default
#       ``praxis`` project containers/volumes.
#     - Writes its env file to a ``mktemp -d`` directory and unlinks it on
#       exit; nothing is written to ./.env.
#     - Refuses to start if the smoke project is already up.

set -euo pipefail

cd "$(dirname "$0")/.."

PROJECT_NAME="praxis-fresh-install-smoke"
OVERRIDE_FILE="scripts/fresh-install-smoke.override.yml"
COMPOSE_BASE=(
    -f docker-compose.yml
    -f docker-compose.prod.yml
    -f "${OVERRIDE_FILE}"
)
COMPOSE_PROFILE_ARGS=(--profile bundled)

# ---------------------------------------------------------------- pre-flight

if ! command -v docker >/dev/null 2>&1; then
    echo "ERR: docker CLI not on PATH" >&2
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo "ERR: docker daemon is not reachable" >&2
    exit 1
fi

# Refuse to clobber an already-running smoke project. The detection
# uses ``docker ps`` with the compose project label rather than
# ``docker compose ... ps`` because ``docker compose`` would evaluate
# the base compose's ``${SECRET_KEY:?...}`` interpolations against the
# parent shell's environment — `SECRET_KEY` is not exported yet at
# this pre-flight point, so a normal run would fail interpolation,
# and the ``|| true`` would mask any actual leftover containers and
# let ``up -d --build`` clobber stale state. Label-only detection
# requires no compose evaluation, so it is safe to run before secret
# generation.
EXISTING=$(docker ps -a --quiet \
    --filter "label=com.docker.compose.project=${PROJECT_NAME}" 2>/dev/null || true)
if [[ -n "${EXISTING}" ]]; then
    echo "ERR: smoke project '${PROJECT_NAME}' already has containers." >&2
    echo "    Containers (label com.docker.compose.project=${PROJECT_NAME}):" >&2
    docker ps -a \
        --filter "label=com.docker.compose.project=${PROJECT_NAME}" \
        --format '      {{.ID}}  {{.Names}}  {{.Status}}' >&2 || true
    echo "    Force-tear-down with project-label-only commands (no env-file needed):" >&2
    echo "      docker rm -f \$(docker ps -aq --filter 'label=com.docker.compose.project=${PROJECT_NAME}')" >&2
    echo "      docker volume rm \$(docker volume ls -q --filter 'label=com.docker.compose.project=${PROJECT_NAME}')" >&2
    echo "      docker network rm \$(docker network ls -q --filter 'label=com.docker.compose.project=${PROJECT_NAME}')" >&2
    exit 1
fi

# ---------------------------------------------------------------- env + temp

SMOKE_TMP=$(mktemp -d -t praxis-smoke-XXXXXX)
SMOKE_ENV_FILE="${SMOKE_TMP}/.env"

# token_urlsafe(32) -> 43-char ASCII secret. Strong enough for the smoke
# without dragging in openssl.
gen_secret() {
    python3 -c 'import secrets; print(secrets.token_urlsafe(32))' 2>/dev/null \
    || python -c 'import secrets; print(secrets.token_urlsafe(32))'
}

SMOKE_SECRET=$(gen_secret)
SMOKE_ADMIN_PASS=$(gen_secret | head -c 24)
SMOKE_PG_PASS=$(gen_secret   | head -c 24)

# .env consumed by ``docker compose --env-file``. Variables here resolve
# the ${VAR:?} substitutions in the base compose. ENVIRONMENT=production
# exercises the production code paths (weak-secret rejection, hidden
# /docs). PRAXIS_PUBLIC_URL is consumed by the override file.
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
    # Strict: a failed ``down -v`` on the success path must NOT be
    # reported as a passing smoke. Slice 2 acceptance requires the
    # smoke to tear down only its own containers/volumes on success,
    # and the operator needs the temp env file to chase a stuck
    # teardown manually. ``set -e`` propagates the failure; the
    # EXIT trap then sees rc != 0, preserves ${SMOKE_TMP} /
    # ${SMOKE_ENV_FILE}, and prints the --env-file teardown commands.
    # No ``|| true`` and no stderr swallowing.
    echo "==> tearing down smoke project"
    docker compose --env-file "${SMOKE_ENV_FILE}" -p "${PROJECT_NAME}" \
        "${COMPOSE_BASE[@]}" "${COMPOSE_PROFILE_ARGS[@]}" \
        down -v
}

# Single exit handler. Captures ``$?`` at trap entry so it reflects the
# real exit status of the last command (or signal +128) regardless of
# how the script ended: ``set -e`` failure, explicit ``exit 1`` from
# one of the post-start checks (``healthy != 1``, empty access token,
# username mismatch), a user Ctrl-C/SIGINT, or a clean fall-through.
#
# Zero exit → remove the temp dir.
# Non-zero exit → preserve the temp env file (when it exists) and print
# the exact ``--env-file``-bearing logs/teardown commands plus a
# project-label-only fallback for the rare case where the temp file
# vanished.
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
        echo "    Logs (uses --env-file because the base compose has required interpolations):" >&2
        echo "      docker compose --env-file ${SMOKE_ENV_FILE} -p ${PROJECT_NAME} ${COMPOSE_BASE[*]} ${COMPOSE_PROFILE_ARGS[*]} logs --tail=200 backend vault db" >&2
        echo "    Teardown when done (same reason):" >&2
        echo "      docker compose --env-file ${SMOKE_ENV_FILE} -p ${PROJECT_NAME} ${COMPOSE_BASE[*]} ${COMPOSE_PROFILE_ARGS[*]} down -v" >&2
        echo "    After teardown, remove the temp dir:" >&2
        echo "      rm -rf ${SMOKE_TMP}" >&2
    else
        echo "    Smoke env file was not written before exit; cleaning the empty temp dir." >&2
        rm -rf "${SMOKE_TMP}" 2>/dev/null || true
    fi
    echo "    Project-label-only fallback (no env-file needed; use if the env file got lost):" >&2
    echo "      docker rm -f \$(docker ps -aq --filter 'label=com.docker.compose.project=${PROJECT_NAME}')" >&2
    echo "      docker volume rm \$(docker volume ls -q --filter 'label=com.docker.compose.project=${PROJECT_NAME}')" >&2
    echo "      docker network rm \$(docker network ls -q --filter 'label=com.docker.compose.project=${PROJECT_NAME}')" >&2
}
trap on_exit EXIT

# ---------------------------------------------------------------- up

echo "==> bringing up smoke stack (this may take a minute on first build)"
docker compose --env-file "${SMOKE_ENV_FILE}" -p "${PROJECT_NAME}" \
    "${COMPOSE_BASE[@]}" "${COMPOSE_PROFILE_ARGS[@]}" \
    up -d --build

# ---------------------------------------------------------------- helpers

exec_backend() {
    # Run a python heredoc inside the smoke project's backend container.
    docker compose --env-file "${SMOKE_ENV_FILE}" -p "${PROJECT_NAME}" \
        "${COMPOSE_BASE[@]}" "${COMPOSE_PROFILE_ARGS[@]}" exec -T "$@"
}

# ---------------------------------------------------------------- /health

echo "==> waiting for backend /health"
healthy=0
for _ in $(seq 1 90); do
    if exec_backend backend python -c "
import urllib.request, sys
try:
    r = urllib.request.urlopen('http://localhost:8000/health', timeout=3)
    sys.exit(0 if r.status == 200 else 1)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
        healthy=1
        echo "    backend healthy"
        break
    fi
    sleep 2
done

if [[ "${healthy}" -ne 1 ]]; then
    echo "==> backend never became healthy" >&2
    docker compose --env-file "${SMOKE_ENV_FILE}" -p "${PROJECT_NAME}" \
        "${COMPOSE_BASE[@]}" "${COMPOSE_PROFILE_ARGS[@]}" \
        logs --tail=200 backend vault db >&2 || true
    exit 1
fi

# ---------------------------------------------------------------- /auth/login

echo "==> POST /auth/login as praxisadmin"
ACCESS_TOKEN=$(exec_backend \
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
except Exception as exc:
    sys.stderr.write(f'login failed: {exc}\n')
    sys.exit(1)
body = json.loads(resp.read())
token = body.get('access_token') or body.get('accessToken')
if not token:
    sys.stderr.write(f'no access_token in response: {body}\n')
    sys.exit(1)
print(token)
")
if [[ -z "${ACCESS_TOKEN}" ]]; then
    echo "==> empty access_token" >&2
    exit 1
fi
echo "    got access_token (len=${#ACCESS_TOKEN})"

# ---------------------------------------------------------------- /auth/me

echo "==> GET /auth/me"
USERNAME=$(exec_backend \
    -e SMOKE_ACCESS_TOKEN="${ACCESS_TOKEN}" \
    backend python -c "
import os, sys, json, urllib.request, urllib.error
req = urllib.request.Request(
    'http://localhost:8000/auth/me',
    headers={'Authorization': f\"Bearer {os.environ['SMOKE_ACCESS_TOKEN']}\"},
)
try:
    resp = urllib.request.urlopen(req, timeout=10)
except urllib.error.HTTPError as exc:
    sys.stderr.write(f'/auth/me failed: HTTP {exc.code} {exc.read().decode()}\n')
    sys.exit(1)
except Exception as exc:
    sys.stderr.write(f'/auth/me failed: {exc}\n')
    sys.exit(1)
body = json.loads(resp.read())
print(body.get('username', ''))
")
if [[ "${USERNAME}" != "praxisadmin" ]]; then
    echo "==> /auth/me returned username='${USERNAME}', expected 'praxisadmin'" >&2
    exit 1
fi
echo "    /auth/me returned username=praxisadmin"

# ---------------------------------------------------------------- /agent/activation-tokens (admin)
#
# Lightweight admin-RBAC exercise: list activation tokens. Fresh
# install returns an empty array. This proves the admin role is
# wired through the auth stack into the route handler without
# requiring the full system + credential + distro seeding that
# minting a token needs.

echo "==> GET /agent/activation-tokens (admin)"
TOKEN_LIST_LEN=$(exec_backend \
    -e SMOKE_ACCESS_TOKEN="${ACCESS_TOKEN}" \
    backend python -c "
import os, sys, json, urllib.request, urllib.error
req = urllib.request.Request(
    'http://localhost:8000/agent/activation-tokens',
    headers={'Authorization': f\"Bearer {os.environ['SMOKE_ACCESS_TOKEN']}\"},
)
try:
    resp = urllib.request.urlopen(req, timeout=10)
except urllib.error.HTTPError as exc:
    sys.stderr.write(f'/agent/activation-tokens failed: HTTP {exc.code} {exc.read().decode()}\n')
    sys.exit(1)
body = json.loads(resp.read())
if not isinstance(body, list):
    sys.stderr.write(f'unexpected body shape: {type(body).__name__}\n')
    sys.exit(1)
print(len(body))
")
echo "    /agent/activation-tokens returned list (len=${TOKEN_LIST_LEN})"

# ---------------------------------------------------------------- /agent/bootstrap.sh

echo "==> GET /agent/bootstrap.sh (anonymous)"
exec_backend backend python -c "
import sys, urllib.request, urllib.error
try:
    resp = urllib.request.urlopen('http://localhost:8000/agent/bootstrap.sh', timeout=10)
except urllib.error.HTTPError as exc:
    sys.stderr.write(f'/agent/bootstrap.sh failed: HTTP {exc.code} {exc.read().decode()}\n')
    sys.exit(1)
body = resp.read().decode('utf-8', errors='replace')
if 'PRAXIS_URL' not in body or 'PRAXIS_ACTIVATION_TOKEN' not in body:
    sys.stderr.write('bootstrap.sh body missing expected markers\n')
    sys.stderr.write(body[:400] + '\n')
    sys.exit(1)
if '__PRAXIS_DEFAULT_URL__' in body:
    sys.stderr.write('bootstrap.sh still contains unresolved sentinel; PRAXIS_PUBLIC_URL substitution failed\n')
    sys.exit(1)
print(f'    bootstrap.sh ok ({len(body)} bytes)')
"

# ---------------------------------------------------------------- /agent/ca-bundle

echo "==> GET /agent/ca-bundle (anonymous)"
exec_backend backend python -c "
import sys, urllib.request, urllib.error
try:
    resp = urllib.request.urlopen('http://localhost:8000/agent/ca-bundle', timeout=10)
except urllib.error.HTTPError as exc:
    sys.stderr.write(f'/agent/ca-bundle failed: HTTP {exc.code} {exc.read().decode()}\n')
    sys.exit(1)
body = resp.read().decode('utf-8', errors='replace')
if 'BEGIN CERTIFICATE' not in body:
    sys.stderr.write('ca-bundle body missing PEM marker\n')
    sys.stderr.write(body[:200] + '\n')
    sys.exit(1)
print(f'    ca-bundle ok ({len(body)} bytes)')
"

# ---------------------------------------------------------------- done
#
# All checks passed. Tear the stack down and exit clean; on_exit will
# fire with $?=0 and remove the temp dir.

teardown_stack
echo "==> smoke passed"
