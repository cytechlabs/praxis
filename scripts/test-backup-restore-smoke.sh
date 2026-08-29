#!/usr/bin/env bash
# PRA-179 Slice 4: hermetic local backup/restore smoke.
#
# Proves the existing backup/restore contract end-to-end: invoke the
# committed ``scripts/backup.sh`` via the ``db_backup`` sidecar (same
# binary the daily 02:00 cron runs), then restore the produced dump
# with ``pg_restore --clean --if-exists`` (same path ``make
# backup-restore`` uses) and assert a known synthetic sentinel
# survived the round trip.
#
# Reuses the Slice 2 prod compose override
# (``scripts/fresh-install-smoke.override.yml``) so the smoke does not
# bind any host ports — different compose project name
# (``praxis-backup-restore-smoke``) keeps it isolated from the
# dev stack and from the other PRA-179 smokes.
#
# Flow per smoke run:
#
#   1. Bring up the full prod overlay in bundled mode.
#   2. Wait for backend ``/health``.
#   3. Insert a synthetic sentinel row into ``app_settings`` via
#      ``docker compose exec db psql``. Sentinel key is
#      ``pra179_sentinel`` and value is the current UTC timestamp
#      string — no PII, no secret.
#   4. Invoke ``/scripts/backup.sh`` inside ``db_backup`` (same
#      script the daily cron runs).
#   5. List ``/backups/`` and pick the newest dump. Assert it exists
#      and is non-empty. Custom-format dumps are not directly
#      grep-able for the sentinel row; the round trip below proves
#      content through ``pg_restore`` instead.
#   6. Delete the sentinel.
#   7. Restore the newest dump with
#      ``pg_restore --clean --if-exists -U postgres -d praxis`` —
#      the same invocation documented for operator restores in
#      README.md / docs/production-hardening.md.
#   8. Re-read ``app_settings`` and assert the sentinel returned
#      with the original timestamp value.
#   9. Wait briefly for backend ``/health`` again — ``pg_restore
#      --clean`` drops and recreates objects under the backend's
#      open connections; SQLAlchemy needs a moment to reconnect.
#  10. Tear down strictly (no ``|| true``).
#
# What this smoke does NOT cover (intentional Slice 4 scope; later
# slices or operator-owned work):
#
#   - Off-host backup shipping. The backup file lives on the
#     ``backup_data`` volume and never leaves the docker host. Copying
#     it off-host is the operator's job.
#   - Backup encryption at rest.
#   - Vault rotation / re-key / unseal-key rotation drills.
#   - Restore against an external Postgres deployment.
#
# Usage:
#     scripts/test-backup-restore-smoke.sh
#
# Exit codes:
#     0 - smoke passed; project torn down (volumes removed).
#     1 - smoke failed; project LEFT UP for inspection with the temp
#         env file preserved and the recovery commands printed.
#
# Safety:
#     - Dedicated compose project name (``praxis-backup-restore-smoke``);
#       never touches the default ``praxis`` project, the Slice 2
#       ``praxis-fresh-install-smoke`` project, or the Slice 3
#       ``praxis-upgrade-smoke`` project.
#     - Writes its env file to a ``mktemp -d`` directory and unlinks
#       it only on a clean exit.
#     - Refuses to start if the smoke project already has containers.

set -euo pipefail

cd "$(dirname "$0")/.."

PROJECT_NAME="praxis-backup-restore-smoke"
OVERRIDE_FILE="scripts/fresh-install-smoke.override.yml"
# PRA-179 Slice 4a: there is no separate backup-restore override
# any more. The bundled ``db_backup`` service now receives
# POSTGRES_USER / POSTGRES_PASSWORD / POSTGRES_DB via
# ``docker-compose.yml`` directly (the env block under the
# db_backup service), and ``scripts/backup.sh`` runs under
# ``set -euo pipefail`` so pg_dump failures propagate. The smoke
# therefore exercises the **shipped** backup path.
COMPOSE_BASE=(
    -f docker-compose.yml
    -f docker-compose.prod.yml
    -f "${OVERRIDE_FILE}"
)
COMPOSE_PROFILE_ARGS=(--profile bundled)
SENTINEL_SETTING="pra179_sentinel"

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

# ---------------------------------------------------------------- env + temp

SMOKE_TMP=$(mktemp -d -t praxis-backup-XXXXXX)
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
        echo "      docker compose --env-file ${SMOKE_ENV_FILE} -p ${PROJECT_NAME} ${COMPOSE_BASE[*]} ${COMPOSE_PROFILE_ARGS[*]} logs --tail=200 backend vault db db_backup" >&2
        echo "    Teardown when done:" >&2
        echo "      docker compose --env-file ${SMOKE_ENV_FILE} -p ${PROJECT_NAME} ${COMPOSE_BASE[*]} ${COMPOSE_PROFILE_ARGS[*]} down -v" >&2
        echo "    After teardown, remove the temp dir:" >&2
        echo "      rm -rf ${SMOKE_TMP}" >&2
    else
        echo "    Smoke env file was not written before exit; cleaning the empty temp dir." >&2
        rm -rf "${SMOKE_TMP}" 2>/dev/null || true
    fi
    echo "    Project-label-only fallback (no env-file needed):" >&2
    echo "      docker rm -f \$(docker ps -aq --filter 'label=com.docker.compose.project=${PROJECT_NAME}')" >&2
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
        compose logs --tail=200 backend vault db db_backup >&2 || true
        return 1
    fi
}

# ---------------------------------------------------------------- up

echo "==> bringing up smoke stack"
compose up -d --build

echo "==> waiting for backend /health"
wait_for_backend_health
echo "    backend healthy"

# ---------------------------------------------------------------- sentinel

# Use a high-precision UTC timestamp string as the synthetic value.
# Not a secret; not PII. Captured so we can assert exact-string return
# after restore.
SENTINEL_VALUE=$(date -u +"%Y-%m-%dT%H:%M:%S.%NZ")
echo "==> inserting sentinel app_settings(${SENTINEL_SETTING}) = '${SENTINEL_VALUE}'"
compose exec -T db psql -v ON_ERROR_STOP=1 -U postgres -d praxis -c \
    "INSERT INTO app_settings (setting_key, setting_value) VALUES ('${SENTINEL_SETTING}', '${SENTINEL_VALUE}')" >/dev/null
ACTUAL=$(compose exec -T db psql -v ON_ERROR_STOP=1 -U postgres -d praxis -tAc \
    "SELECT setting_value FROM app_settings WHERE setting_key='${SENTINEL_SETTING}'")
if [[ "${ACTUAL}" != "${SENTINEL_VALUE}" ]]; then
    echo "==> sentinel read-back mismatch: got '${ACTUAL}'" >&2
    exit 1
fi
echo "    sentinel present"

# ---------------------------------------------------------------- backup

echo "==> running scripts/backup.sh via db_backup sidecar"
# Every ``sh -c "..."`` payload below is prefixed with ``exec`` (or
# another non-``/`` command) so the argv token docker-cli receives
# does NOT start with ``/``. git-bash on Windows mangles top-level
# argv tokens that begin with ``/`` (translating ``/scripts/...``
# into ``C:/Program Files/Git/scripts/...``); a leading ``exec`` or
# command word makes the token start with a letter, so MSYS leaves
# it alone. Setting ``MSYS_NO_PATHCONV=1`` would also work, but it
# breaks the ``--env-file`` path that compose itself needs, so the
# per-call prefix is the targeted fix.
compose exec -T db_backup sh -c "exec /scripts/backup.sh"
# Pick the most recent .dump file from the shared backup_data volume.
LATEST_DUMP=$(compose exec -T db_backup sh -c "ls -t /backups/*.dump 2>/dev/null | head -n 1" | tr -d '\r')
if [[ -z "${LATEST_DUMP}" ]]; then
    echo "==> no .dump file produced under /backups" >&2
    compose exec -T db_backup sh -c "ls -la /backups || true" >&2
    exit 1
fi
DUMP_SIZE=$(compose exec -T db_backup sh -c "wc -c < '${LATEST_DUMP}'" | tr -d '\r ')
if [[ -z "${DUMP_SIZE}" || "${DUMP_SIZE}" -le 0 ]]; then
    echo "==> dump file ${LATEST_DUMP} is empty (size=${DUMP_SIZE:-<empty>})" >&2
    compose exec -T db_backup sh -c "ls -la /backups/" >&2 || true
    exit 1
fi
echo "    produced dump ${LATEST_DUMP} (${DUMP_SIZE} bytes)"

# Custom-format pg_dump output is not greppable as plain text. The
# round-trip restore assertion below proves the sentinel survived.

# ---------------------------------------------------------------- delete sentinel

echo "==> deleting sentinel (proves restore actually restores)"
compose exec -T db psql -v ON_ERROR_STOP=1 -U postgres -d praxis -c \
    "DELETE FROM app_settings WHERE setting_key='${SENTINEL_SETTING}'" >/dev/null
REMAINING=$(compose exec -T db psql -v ON_ERROR_STOP=1 -U postgres -d praxis -tAc \
    "SELECT COUNT(*) FROM app_settings WHERE setting_key='${SENTINEL_SETTING}'")
if [[ "${REMAINING}" != "0" ]]; then
    echo "==> sentinel still present after delete (count=${REMAINING})" >&2
    exit 1
fi
echo "    sentinel deleted"

# ---------------------------------------------------------------- restore

echo "==> restoring ${LATEST_DUMP} via pg_restore --clean --if-exists"
# Same invocation shape as the documented operator restore command. The
# ``/backups/...`` path stays inside the ``sh -c`` quoted string so
# git-bash on Windows does not translate it before docker-cli sees
# it. pg_restore prints to stderr by default; we accept that noise so
# operators see the same output as a manual restore.
compose exec -T db sh -c \
    "pg_restore --clean --if-exists -U postgres -d praxis '${LATEST_DUMP}'"

# ---------------------------------------------------------------- verify

echo "==> verifying sentinel returned"
POST=$(compose exec -T db psql -v ON_ERROR_STOP=1 -U postgres -d praxis -tAc \
    "SELECT setting_value FROM app_settings WHERE setting_key='${SENTINEL_SETTING}'")
if [[ "${POST}" != "${SENTINEL_VALUE}" ]]; then
    echo "==> sentinel did NOT return correctly after restore" >&2
    echo "    expected: ${SENTINEL_VALUE}" >&2
    echo "    got:      ${POST}" >&2
    exit 1
fi
echo "    sentinel restored: ${POST}"

echo "==> re-verifying backend /health after restore"
# pg_restore --clean dropped objects under the backend's open
# connections; SQLAlchemy needs a moment to reconnect. Give the
# /health probe up to ~30s of retries.
wait_for_backend_health 15
echo "    backend still healthy after restore"

# ---------------------------------------------------------------- done

teardown_stack
echo "==> smoke passed"
