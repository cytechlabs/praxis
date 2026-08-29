#!/usr/bin/env bash
# PRA-264: hermetic full-bundle backup/restore smoke.
#
# Proves the 1.0 encrypted full-app-state recovery path end-to-end in an isolated
# compose project (never touches the dev `praxis` project or the other smokes):
#
#   1. Bring up a fresh bundled stack; wait for backend /health.
#   2. Seed four sentinels across the four persistent stores:
#        - DB           : app_settings row
#        - vault_data   : sha256 of the PKI SSH-CA public key (public; no secret)
#        - recordings   : a small file on recordings_data
#        - mirror       : a small file on mirror_data
#   3. scripts/backup-bundle.sh --include-recovery -> encrypted bundle + sidecar.
#   4. Assert the bundle published atomically: final .bundle.enc + .sha256 exist,
#      no `.tmp.` partial remains, and the sidecar checksum matches the ciphertext.
#   5. Assert no secret leakage: the captured backup log contains neither the
#      passphrase nor an OpenBao token.
#   6. Fail-closed negatives (must be REJECTED, not applied):
#        - a byte-flipped bundle           -> checksum/decrypt failure
#        - a wrong passphrase              -> decrypt failure
#   7. Positive restore: scripts/restore-bundle.sh -y wipes (`down -v`) and
#      restores the SAME project from the good bundle, then waits for health.
#   8. Assert all four sentinels survived the wipe+restore and backend is healthy
#      (vault having unsealed from the restored recovery material is proven by the
#      backend reaching /health, since the backend needs its vault token).
#
# Usage:  scripts/test-bundle-backup-restore-smoke.sh
# Exit:   0 = passed (project torn down); 1 = failed (project left up for triage).

set -euo pipefail
cd "$(dirname "$0")/.."

PROJECT_NAME="praxis-bundle-dr-smoke"
OVERRIDE_FILE="scripts/fresh-install-smoke.override.yml"
COMPOSE_BASE=(-f docker-compose.yml -f docker-compose.prod.yml -f "${OVERRIDE_FILE}")
PROFILE=(--profile bundled)
SENTINEL_SETTING="pra264_sentinel"

# ---------------------------------------------------------------- pre-flight
command -v docker >/dev/null 2>&1 || { echo "ERR: docker CLI not on PATH" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "ERR: docker daemon not reachable" >&2; exit 1; }
EXISTING=$(docker ps -aq --filter "label=com.docker.compose.project=${PROJECT_NAME}" 2>/dev/null || true)
if [[ -n "${EXISTING}" ]]; then
    echo "ERR: smoke project '${PROJECT_NAME}' already has containers; tear it down first." >&2
    exit 1
fi

# ---------------------------------------------------------------- env + temp
SMOKE_TMP=$(mktemp -d -t praxis-bundle-smoke-XXXXXX)
SMOKE_ENV_FILE="${SMOKE_TMP}/.env"
OUT_DIR="${SMOKE_TMP}/out"
LOG="${SMOKE_TMP}/ops.log"
mkdir -p "${OUT_DIR}"

gen_secret() { python3 -c 'import secrets; print(secrets.token_urlsafe(32))' 2>/dev/null \
    || python -c 'import secrets; print(secrets.token_urlsafe(32))'; }
SMOKE_SECRET=$(gen_secret)
SMOKE_ADMIN_PASS=$(gen_secret | head -c 24)
SMOKE_PG_PASS=$(gen_secret | head -c 24)
PRAXIS_BACKUP_PASSPHRASE="$(gen_secret)"
export PRAXIS_BACKUP_PASSPHRASE
# Deliberately NON-DEFAULT DB role + database name so the smoke proves backup AND
# restore honor a custom POSTGRES_USER / POSTGRES_DB (regression cover for the
# restore-side host-shell expansion bug): with the defaults, a restore that
# targeted postgres/praxis would fail against this db.
SMOKE_PG_USER="pra264dbuser"
SMOKE_PG_DB="pra264appdb"

cat > "${SMOKE_ENV_FILE}" <<EOF
COMPOSE_PROFILES=bundled
ENVIRONMENT=production
SECRET_KEY=${SMOKE_SECRET}
ADMIN_PASSWORD=${SMOKE_ADMIN_PASS}
ADMIN_USERNAME=praxisadmin
ADMIN_EMAIL=admin@example.com
POSTGRES_USER=${SMOKE_PG_USER}
POSTGRES_PASSWORD=${SMOKE_PG_PASS}
POSTGRES_DB=${SMOKE_PG_DB}
PRAXIS_PUBLIC_URL=http://backend:8000
EOF

compose() {
    docker compose --env-file "${SMOKE_ENV_FILE}" -p "${PROJECT_NAME}" \
        "${COMPOSE_BASE[@]}" "${PROFILE[@]}" "$@"
}

on_exit() {
    local rc=$?
    if [[ ${rc} -eq 0 ]]; then
        compose down -v >/dev/null 2>&1 || true
        rm -rf "${SMOKE_TMP}" 2>/dev/null || true
        return
    fi
    echo "==> SMOKE FAILED (rc=${rc}). Project left up for inspection." >&2
    echo "    env-file: ${SMOKE_ENV_FILE}" >&2
    echo "    teardown: docker compose --env-file ${SMOKE_ENV_FILE} -p ${PROJECT_NAME} ${COMPOSE_BASE[*]} ${PROFILE[*]} down -v" >&2
    echo "    then: rm -rf ${SMOKE_TMP}" >&2
}
trap on_exit EXIT

wait_health() {
    local n=${1:-90}
    for _ in $(seq 1 "${n}"); do
        if compose exec -T backend python -c "
import urllib.request, sys
try:
    r = urllib.request.urlopen('http://localhost:8000/health', timeout=3); sys.exit(0 if r.status==200 else 1)
except Exception: sys.exit(1)" >/dev/null 2>&1; then return 0; fi
        sleep 2
    done
    echo "==> backend never became healthy" >&2
    compose logs --tail=150 backend vault db >&2 || true
    return 1
}

HELPER_IMAGE="alpine:3.19.9"
resolve_vol() {
    docker volume ls -q \
        --filter "label=com.docker.compose.project=${PROJECT_NAME}" \
        --filter "label=com.docker.compose.volume=$1" 2>/dev/null | head -n1
}
# Seed/read sentinels via throwaway root containers on the named volumes — the
# app services run as uid 1000 and the volume mountpoints are root-owned, so
# writing through `backend exec` hits EACCES. Reading a volume directly also
# matches how backup-bundle.sh snapshots them.
vol_write() { docker run --rm -v "$(resolve_vol "$1"):/d" "${HELPER_IMAGE}" sh -c "echo '$2' > /d/$3"; }
vol_read()  { docker run --rm -v "$(resolve_vol "$1"):/d:ro" "${HELPER_IMAGE}" sh -c "cat /d/$2 2>/dev/null" | tr -d '\r'; }
vault_ca_sha() {
    # sha256 of the PKI SSH-CA public key (public material). Stable; never a secret.
    docker run --rm -v "$(resolve_vol vault_data):/d:ro" "${HELPER_IMAGE}" \
        sh -c "sha256sum /d/ssh-ca-public-key 2>/dev/null | awk '{print \$1}'" | tr -d '\r'
}

# ---------------------------------------------------------------- up + seed
# Defensive pre-clean: a prior FAILED run leaves the project up (on_exit does not
# tear down on failure) and, once its containers are gone, orphan named volumes
# can linger. A stale postgres_data makes the fresh `up` "Skip initialization" and
# keep the OLD password, so the backend can't authenticate. `down -v` here removes
# any such orphan volumes (no-op on a truly clean host; preflight already ensured
# there are no leftover containers).
echo "==> pre-clean any orphan volumes from a prior run"
compose down -v >/dev/null 2>&1 || true

echo "==> bringing up smoke stack"
compose up -d --build
wait_health
echo "    backend healthy"

SENTINEL_VALUE=$(date -u +"%Y-%m-%dT%H:%M:%S.%NZ")
echo "==> seeding sentinels"
compose exec -T db psql -v ON_ERROR_STOP=1 -U "${SMOKE_PG_USER}" -d "${SMOKE_PG_DB}" -c \
    "INSERT INTO app_settings (setting_key, setting_value) VALUES ('${SENTINEL_SETTING}', '${SENTINEL_VALUE}')" >/dev/null
vol_write recordings_data "${SENTINEL_VALUE}" pra264-sentinel
vol_write mirror_data     "${SENTINEL_VALUE}" pra264-sentinel
VAULT_CA_BEFORE=$(vault_ca_sha)
[[ -n "${VAULT_CA_BEFORE}" ]] || { echo "ERR: could not read vault PKI SSH-CA public key" >&2; exit 1; }
echo "    sentinels seeded (vault CA sha=${VAULT_CA_BEFORE:0:12}...)"

# ---------------------------------------------------------------- backup
echo "==> scripts/backup-bundle.sh --include-recovery"
scripts/backup-bundle.sh -p "${PROJECT_NAME}" -o "${OUT_DIR}" --include-recovery \
    -f docker-compose.yml -f docker-compose.prod.yml -f "${OVERRIDE_FILE}" \
    > "${LOG}" 2>&1 || { echo "ERR: backup-bundle.sh failed" >&2; cat "${LOG}" >&2; exit 1; }

BUNDLE=$(ls -t "${OUT_DIR}"/praxis-backup-*.bundle.enc 2>/dev/null | head -n1)
[[ -n "${BUNDLE}" && -s "${BUNDLE}" ]] || { echo "ERR: no published bundle" >&2; exit 1; }
[[ -s "${BUNDLE}.sha256" ]] || { echo "ERR: no .sha256 sidecar" >&2; exit 1; }
# Atomic-publish invariant: no partial temp artifact left behind.
if ls "${OUT_DIR}"/.*.tmp.* >/dev/null 2>&1; then
    echo "ERR: partial .tmp artifact left in output dir (publish not atomic)" >&2; exit 1
fi
# Sidecar integrity.
if ! ( cd "${OUT_DIR}" && sha256sum -c "$(basename "${BUNDLE}").sha256" >/dev/null 2>&1 ); then
    echo "ERR: bundle does not match its .sha256 sidecar" >&2; exit 1
fi
echo "    published $(basename "${BUNDLE}") + sidecar; no partials"

# ---------------------------------------------------------------- no leakage
echo "==> checking logs for secret leakage"
if grep -qF "${PRAXIS_BACKUP_PASSPHRASE}" "${LOG}"; then
    echo "ERR: passphrase leaked into backup log" >&2; exit 1
fi
# OpenBao/Vault tokens are s.* / b.* / hvs.* — none should ever be logged.
if grep -qE '\b(hvs\.|s\.[A-Za-z0-9]{20}|b\.[A-Za-z0-9]{20})' "${LOG}"; then
    echo "ERR: a vault-token-shaped string appears in the backup log" >&2; exit 1
fi
echo "    no passphrase or token in logs"

# ---------------------------------------------------------------- fail-closed negatives
echo "==> fail-closed: corrupt bundle must be rejected"
CORRUPT="${SMOKE_TMP}/corrupt.bundle.enc"
cp "${BUNDLE}" "${CORRUPT}"; cp "${BUNDLE}.sha256" "${CORRUPT}.sha256"
# Flip the final byte of the ciphertext (sidecar now mismatches).
printf '\x00' | dd of="${CORRUPT}" bs=1 seek=$(( $(wc -c < "${CORRUPT}") - 1 )) count=1 conv=notrunc >/dev/null 2>&1
if scripts/restore-bundle.sh --bundle "${CORRUPT}" -p "${PROJECT_NAME}-neg" -y \
        -f docker-compose.yml -f docker-compose.prod.yml -f "${OVERRIDE_FILE}" \
        --env-file "${SMOKE_ENV_FILE}" >/dev/null 2>&1; then
    echo "ERR: restore ACCEPTED a corrupt bundle" >&2; exit 1
fi
echo "    corrupt bundle rejected"

echo "==> fail-closed: wrong passphrase must be rejected"
if PRAXIS_BACKUP_PASSPHRASE="definitely-the-wrong-passphrase" \
    scripts/restore-bundle.sh --bundle "${BUNDLE}" -p "${PROJECT_NAME}-neg" -y \
        -f docker-compose.yml -f docker-compose.prod.yml -f "${OVERRIDE_FILE}" \
        --env-file "${SMOKE_ENV_FILE}" >/dev/null 2>&1; then
    echo "ERR: restore ACCEPTED a wrong passphrase" >&2; exit 1
fi
echo "    wrong passphrase rejected"

# ---------------------------------------------------------------- positive restore
echo "==> restoring the good bundle into a wiped ${PROJECT_NAME} (down -v + restore)"
scripts/restore-bundle.sh --bundle "${BUNDLE}" -p "${PROJECT_NAME}" -y \
    -f docker-compose.yml -f docker-compose.prod.yml -f "${OVERRIDE_FILE}" \
    --env-file "${SMOKE_ENV_FILE}" >> "${LOG}" 2>&1 \
    || { echo "ERR: restore-bundle.sh failed" >&2; tail -60 "${LOG}" >&2; exit 1; }
# Re-check leakage on the appended restore output too.
if grep -qF "${PRAXIS_BACKUP_PASSPHRASE}" "${LOG}"; then
    echo "ERR: passphrase leaked into restore log" >&2; exit 1
fi

# ---------------------------------------------------------------- verify survivors
echo "==> verifying all four stores survived wipe+restore"
wait_health 30

DB_POST=$(compose exec -T db psql -v ON_ERROR_STOP=1 -U "${SMOKE_PG_USER}" -d "${SMOKE_PG_DB}" -tAc \
    "SELECT setting_value FROM app_settings WHERE setting_key='${SENTINEL_SETTING}'" | tr -d '\r')
[[ "${DB_POST}" == "${SENTINEL_VALUE}" ]] || { echo "ERR: DB sentinel did not survive (got '${DB_POST}')" >&2; exit 1; }

REC_POST=$(vol_read recordings_data pra264-sentinel)
[[ "${REC_POST}" == "${SENTINEL_VALUE}" ]] || { echo "ERR: recording sentinel did not survive" >&2; exit 1; }

MIR_POST=$(vol_read mirror_data pra264-sentinel)
[[ "${MIR_POST}" == "${SENTINEL_VALUE}" ]] || { echo "ERR: mirror sentinel did not survive" >&2; exit 1; }

VAULT_CA_AFTER=$(vault_ca_sha)
[[ "${VAULT_CA_AFTER}" == "${VAULT_CA_BEFORE}" ]] \
    || { echo "ERR: vault PKI SSH-CA changed across restore (before=${VAULT_CA_BEFORE} after=${VAULT_CA_AFTER})" >&2; exit 1; }

echo "    DB + recordings + mirror + vault(PKI) all survived; backend healthy"

echo "==> smoke passed"
