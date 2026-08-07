#!/usr/bin/env bash
# PRA-264: restore a full-app-state encrypted bundle (from scripts/backup-bundle.sh)
# into a FRESH bundled Praxis deployment.
#
# Restore is OFFLINE and destructive to the target project's volumes: it brings up
# a fresh bundled stack with empty volumes, populates vault_data / recordings_data /
# mirror_data (and vault_recovery when present in the bundle) from the bundle,
# restores PostgreSQL, then starts the full stack and waits for backend health.
#
# Fail-closed: the bundle's ciphertext is verified against its .sha256 sidecar
# (if present) BEFORE decryption; decryption uses the operator passphrase; every
# component is re-checksummed against the manifest and a single mismatch or a
# missing/corrupt manifest aborts the restore before anything is applied.
#
# A working vault restore needs the unseal keys. If the bundle was created
# WITHOUT --include-recovery, the restored vault comes up SEALED — the restore
# still populates everything else, warns loudly, and the operator must supply the
# unseal keys out of band. See docs/backup-restore.md.
#
# Usage:
#   PRAXIS_BACKUP_PASSPHRASE='<passphrase>' \
#     scripts/restore-bundle.sh --bundle <file.bundle.enc> [options]
#
# Options:
#   -b, --bundle FILE        encrypted bundle to restore (required)
#   -p, --project NAME       target compose project (default: praxis). Use a
#                            fresh/dedicated project for a clean restore.
#   -f, --compose-file FILE  compose file (repeatable; default: docker-compose.yml
#                            + docker-compose.prod.yml)
#       --env-file FILE      env file passed to docker compose (SECRET_KEY etc.)
#   -y, --yes                do not prompt before wiping the target project volumes
#   -h, --help               this help
#
# Exit codes: 0 = restored + backend healthy. Non-zero = restore aborted (fail
# closed); the target project is left as-is for inspection.

set -euo pipefail

cd "$(dirname "$0")/.."

# ------------------------------------------------------------------ args
BUNDLE=""
PROJECT="${COMPOSE_PROJECT_NAME:-praxis}"
ENV_FILE=""
ASSUME_YES=0
COMPOSE_FILES=()

usage() { sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        -b|--bundle)       BUNDLE="$2"; shift 2 ;;
        -p|--project)      PROJECT="$2"; shift 2 ;;
        -f|--compose-file) COMPOSE_FILES+=(-f "$2"); shift 2 ;;
        --env-file)        ENV_FILE="$2"; shift 2 ;;
        -y|--yes)          ASSUME_YES=1; shift ;;
        -h|--help)         usage 0 ;;
        *) echo "ERR: unknown argument: $1" >&2; usage 1 >&2 ;;
    esac
done

[[ -n "${BUNDLE}" ]] || { echo "ERR: --bundle is required" >&2; usage 1 >&2; }
[[ -f "${BUNDLE}" ]] || { echo "ERR: bundle not found: ${BUNDLE}" >&2; exit 1; }
if [[ ${#COMPOSE_FILES[@]} -eq 0 ]]; then
    COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.prod.yml)
fi

for tool in docker openssl tar sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || { echo "ERR: '$tool' not on PATH" >&2; exit 1; }
done
[[ -n "${PRAXIS_BACKUP_PASSPHRASE:-}" ]] || { echo "ERR: PRAXIS_BACKUP_PASSPHRASE must be set to decrypt the bundle." >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "ERR: docker daemon not reachable" >&2; exit 1; }

HELPER_IMAGE="alpine:3.19.9"
ENV_ARGS=()
[[ -n "${ENV_FILE}" ]] && ENV_ARGS=(--env-file "${ENV_FILE}")
compose() { docker compose "${ENV_ARGS[@]}" -p "${PROJECT}" "${COMPOSE_FILES[@]}" --profile bundled "$@"; }
resolve_volume() {
    docker volume ls -q \
        --filter "label=com.docker.compose.project=${PROJECT}" \
        --filter "label=com.docker.compose.volume=$1" 2>/dev/null | head -n1
}

STAGING="$(mktemp -d -t praxis-restore-XXXXXX)"
trap 'rm -rf "${STAGING}" 2>/dev/null || true' EXIT

# ------------------------------------------------------------------ 1. verify ciphertext
SIDECAR="${BUNDLE}.sha256"
if [[ -f "${SIDECAR}" ]]; then
    echo "==> verifying bundle checksum against sidecar"
    EXPECT=$(awk '{print $1}' "${SIDECAR}")
    ACTUAL=$(sha256sum "${BUNDLE}" | awk '{print $1}')
    if [[ "${EXPECT}" != "${ACTUAL}" ]]; then
        echo "ERR: bundle checksum MISMATCH — refusing to restore a corrupt/tampered bundle." >&2
        exit 1
    fi
else
    echo "WARN: no .sha256 sidecar next to the bundle; relying on decrypt + manifest checksums." >&2
fi

# ------------------------------------------------------------------ 2. decrypt + unpack
echo "==> decrypting bundle"
if ! openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 \
        -in "${BUNDLE}" -out "${STAGING}/bundle.tar" \
        -pass env:PRAXIS_BACKUP_PASSPHRASE 2>/dev/null; then
    echo "ERR: decryption failed (wrong passphrase or corrupt bundle). Fail closed." >&2
    exit 1
fi
tar xf "${STAGING}/bundle.tar" -C "${STAGING}"
MANIFEST="${STAGING}/manifest.json"
[[ -f "${MANIFEST}" ]] || { echo "ERR: bundle has no manifest.json — refusing to restore." >&2; exit 1; }

# ------------------------------------------------------------------ 3. verify components vs manifest
# Minimal, dependency-free JSON walk: pull "name","file","sha256" triples.
echo "==> verifying component checksums against manifest"
mapfile -t COMP_LINES < <(tr -d '\n' < "${MANIFEST}" \
    | grep -oE '\{"name":"[^"]*","file":"[^"]*","sha256":"[0-9a-f]*"[^}]*\}' \
    | sed -E 's/.*"name":"([^"]*)","file":"([^"]*)","sha256":"([0-9a-f]*)".*/\1|\2|\3/')
[[ ${#COMP_LINES[@]} -gt 0 ]] || { echo "ERR: manifest lists no components." >&2; exit 1; }

RECOVERY_PRESENT=0
for line in "${COMP_LINES[@]}"; do
    name="${line%%|*}"; rest="${line#*|}"; relfile="${rest%%|*}"; want="${rest##*|}"
    path="${STAGING}/${relfile}"
    [[ -f "${path}" ]] || { echo "ERR: manifest component missing from bundle: ${relfile}" >&2; exit 1; }
    got=$(sha256sum "${path}" | awk '{print $1}')
    if [[ "${got}" != "${want}" ]]; then
        echo "ERR: checksum mismatch for '${name}' (${relfile}) — fail closed." >&2
        exit 1
    fi
    [[ "${name}" == "vault_recovery" ]] && RECOVERY_PRESENT=1
done
echo "    all components verified (${#COMP_LINES[@]}); recovery material present: $([[ ${RECOVERY_PRESENT} -eq 1 ]] && echo yes || echo no)"

# ------------------------------------------------------------------ 4. confirm destructive restore
EXISTING=$(docker ps -aq --filter "label=com.docker.compose.project=${PROJECT}" 2>/dev/null || true)
if [[ ${ASSUME_YES} -ne 1 ]]; then
    echo "==> This will WIPE and restore the '${PROJECT}' compose project's volumes." >&2
    read -r -p "    Type 'restore' to proceed: " CONFIRM
    [[ "${CONFIRM}" == "restore" ]] || { echo "aborted." >&2; exit 1; }
fi

# Fresh target: tear down any existing project (removing volumes), then create the
# stack so the named volumes exist EMPTY before we populate them.
if [[ -n "${EXISTING}" ]]; then
    echo "==> tearing down existing '${PROJECT}' project (down -v)"
    compose down -v
fi
echo "==> creating fresh stack (volumes only, not started)"
compose create

# ------------------------------------------------------------------ 5. restore volumes (before services start)
restore_volume() {
    local logical="$1" relfile="$2" volname
    volname=$(resolve_volume "$logical")
    [[ -n "${volname}" ]] || { echo "ERR: volume '${logical}' not created for project '${PROJECT}'" >&2; exit 1; }
    echo "==> [vol] restoring ${logical}"
    # Wipe then extract, so the restored volume is exactly the snapshot.
    docker run --rm -v "${volname}:/dst" -v "${STAGING}/components:/comp:ro" "${HELPER_IMAGE}" \
        sh -c "rm -rf /dst/* /dst/..?* /dst/.[!.]* 2>/dev/null; tar xzf '/comp/${relfile}' -C /dst"
}
restore_volume vault_data      vault_data.tar.gz
restore_volume recordings_data recordings_data.tar.gz
restore_volume mirror_data     mirror_data.tar.gz
if [[ ${RECOVERY_PRESENT} -eq 1 ]]; then
    restore_volume vault_recovery vault_recovery.tar.gz
fi

# ------------------------------------------------------------------ 6. restore Postgres
echo "==> starting db and restoring PostgreSQL"
compose up -d db
# Use the db CONTAINER's POSTGRES_USER / POSTGRES_DB (set by compose from the
# --env-file), NOT whatever happens to be in the host shell. Single-quoting the
# `sh -c` payload defers ${POSTGRES_USER}/${POSTGRES_DB} expansion into the db
# container, so a customer whose custom role/name lives only in the env file
# restores against the right role/database instead of the postgres/praxis
# defaults.
# Wait for postgres to accept connections.
for _ in $(seq 1 60); do
    if compose exec -T db sh -c 'pg_isready -U "${POSTGRES_USER:-postgres}"' >/dev/null 2>&1; then break; fi
    sleep 2
done
compose exec -T db sh -c 'pg_isready -U "${POSTGRES_USER:-postgres}"' >/dev/null 2>&1 \
    || { echo "ERR: db never became ready" >&2; exit 1; }
# pg_restore --clean --if-exists into the (fresh, empty) app DB. Stream the dump
# in over stdin so no host path is translated / no dump lingers in a volume.
compose exec -T db sh -c \
    'pg_restore --clean --if-exists -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-praxis}"' \
    < "${STAGING}/components/postgres.dump"

# ------------------------------------------------------------------ 7. start the rest + health
echo "==> starting the full stack"
compose up -d
echo "==> waiting for backend /health"
HEALTHY=0
for _ in $(seq 1 90); do
    if compose exec -T backend python -c "
import urllib.request, sys
try:
    r = urllib.request.urlopen('http://localhost:8000/health', timeout=3)
    sys.exit(0 if r.status == 200 else 1)
except Exception:
    sys.exit(1)" >/dev/null 2>&1; then HEALTHY=1; break; fi
    sleep 2
done
if [[ ${HEALTHY} -ne 1 ]]; then
    echo "ERR: backend did not become healthy after restore." >&2
    if [[ ${RECOVERY_PRESENT} -ne 1 ]]; then
        echo "     The bundle had NO recovery material, so vault is likely still SEALED." >&2
        echo "     Supply the unseal keys into the ${PROJECT} vault_recovery volume and retry." >&2
    fi
    compose logs --tail=120 backend vault db >&2 || true
    exit 1
fi

echo "==> restore complete; backend healthy."
if [[ ${RECOVERY_PRESENT} -ne 1 ]]; then
    echo "    NOTE: bundle had no recovery material; vault was expected to need out-of-band unseal keys."
fi
