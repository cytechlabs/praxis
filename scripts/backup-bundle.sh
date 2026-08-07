#!/usr/bin/env bash
# PRA-264: full-app-state encrypted backup bundle for a BUNDLED Praxis deployment.
#
# This is the 1.0 "minimum honest recovery" path. `scripts/backup.sh` (the daily
# cron sidecar) backs up ONLY PostgreSQL; this operator command wraps that and
# additionally captures the other persistent app state, encrypts everything into
# a single bundle, and publishes it atomically. The operator then moves the
# encrypted bundle off-host (Praxis does NOT ship it anywhere in 1.0).
#
# What the bundle covers:
#   - PostgreSQL app DB     — via the existing validated scripts/backup.sh path
#                             (custom-format pg_dump, pg_restore --list validated)
#   - vault_data            — OpenBao file storage: KV secrets, PKI, broker cert,
#                             agent CA, backend token, SSH CA (read-only snapshot)
#   - recordings_data       — session recordings
#   - mirror_data           — mirrored repository content
#   - vault_recovery        — OpenBao unseal keys + init root token, ONLY when
#                             --include-recovery is passed (opt-in; see below)
#   - manifest.json         — components, sizes, sha256 checksums, timestamps,
#                             image/runtime versions, source compose files,
#                             restore instructions
#
# Recovery material (vault_recovery) and PRA-241:
#   The unseal keys live on the vault-only `vault_recovery` volume and are NEVER
#   mounted into backend/agent-broker (PRA-241). This script does NOT change that:
#   recovery material is captured only via the explicit, opt-in --include-recovery
#   flag, read read-only from the volume in a throwaway container, and NEVER
#   mounted into any long-lived app service. A restored vault CANNOT be unsealed
#   without the unseal keys, so a *working* full restore needs the recovery
#   material either in the bundle (--include-recovery) or supplied by the operator
#   out of band. See docs/backup-restore.md.
#
# Encryption:
#   The whole bundle is encrypted with AES-256-CBC (openssl, PBKDF2, 600k iters)
#   under an operator passphrase read from $PRAXIS_BACKUP_PASSPHRASE. The
#   passphrase is passed to openssl via `-pass env:` so it never appears in argv
#   / `ps`. No secret values, tokens, unseal keys, DB URLs, or passphrases are
#   ever printed (checksums and byte sizes are not secrets).
#
# Atomic publish:
#   The encrypted bundle + its .sha256 sidecar are written under temp names and
#   renamed to their final `praxis-backup-<UTC>.bundle.enc[.sha256]` names ONLY
#   after encryption + checksumming succeed. A failed/interrupted run cleans up
#   and never leaves a final-looking bundle.
#
# Usage:
#   PRAXIS_BACKUP_PASSPHRASE='<strong passphrase>' \
#     scripts/backup-bundle.sh [options]
#
# Options:
#   -p, --project NAME       compose project name (default: $COMPOSE_PROJECT_NAME
#                            or "praxis")
#   -o, --output-dir DIR     where to write the bundle (default: ./backups-bundle)
#   -f, --compose-file FILE  compose file (repeatable; default: docker-compose.yml
#                            + docker-compose.prod.yml)
#       --include-recovery   include vault_recovery (unseal keys + root token).
#                            Off by default — opt in deliberately.
#   -h, --help               this help
#
# Exit codes: 0 = published a complete, validated, encrypted bundle. Non-zero =
# nothing final was published.

set -euo pipefail

cd "$(dirname "$0")/.."

# ------------------------------------------------------------------ args
PROJECT="${COMPOSE_PROJECT_NAME:-praxis}"
OUTPUT_DIR="./backups-bundle"
INCLUDE_RECOVERY=0
COMPOSE_FILES=()

usage() { sed -n '2,66p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--project)      PROJECT="$2"; shift 2 ;;
        -o|--output-dir)   OUTPUT_DIR="$2"; shift 2 ;;
        -f|--compose-file) COMPOSE_FILES+=(-f "$2"); shift 2 ;;
        --include-recovery) INCLUDE_RECOVERY=1; shift ;;
        -h|--help)         usage 0 ;;
        *) echo "ERR: unknown argument: $1" >&2; usage 1 >&2 ;;
    esac
done

if [[ ${#COMPOSE_FILES[@]} -eq 0 ]]; then
    COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.prod.yml)
fi

# ------------------------------------------------------------------ preflight
for tool in docker openssl tar sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || { echo "ERR: '$tool' not on PATH" >&2; exit 1; }
done
if [[ -z "${PRAXIS_BACKUP_PASSPHRASE:-}" ]]; then
    echo "ERR: PRAXIS_BACKUP_PASSPHRASE must be set (the bundle is encrypted with it)." >&2
    echo "     e.g.  PRAXIS_BACKUP_PASSPHRASE=\"\$(openssl rand -base64 32)\" $0 ..." >&2
    exit 1
fi
docker info >/dev/null 2>&1 || { echo "ERR: docker daemon not reachable" >&2; exit 1; }

# The alpine tag matches db_backup so we don't pull an extra image.
HELPER_IMAGE="alpine:3.19.9"

# Resolve the REAL docker volume name for a compose logical volume via labels —
# robust against compose's project-name sanitization.
resolve_volume() {
    local logical="$1" name
    name=$(docker volume ls -q \
        --filter "label=com.docker.compose.project=${PROJECT}" \
        --filter "label=com.docker.compose.volume=${logical}" 2>/dev/null | head -n1)
    printf '%s' "$name"
}

compose() {
    docker compose -p "${PROJECT}" "${COMPOSE_FILES[@]}" --profile bundled "$@"
}

# ------------------------------------------------------------------ staging
STAGING="$(mktemp -d -t praxis-bundle-XXXXXX)"
COMPONENTS_DIR="${STAGING}/components"
mkdir -p "${COMPONENTS_DIR}"
# Temp artifacts that must never survive a failed run (they could look like a
# valid newest bundle). Cleared by the trap on ANY early exit.
TMP_ENC=""
TMP_SHA=""
cleanup() {
    rm -rf "${STAGING}" 2>/dev/null || true
    [[ -n "${TMP_ENC}" ]] && rm -f "${TMP_ENC}" 2>/dev/null || true
    [[ -n "${TMP_SHA}" ]] && rm -f "${TMP_SHA}" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

TS="$(date -u +%Y%m%d%H%M%S)"
CREATED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "==> Praxis backup bundle (project=${PROJECT}, recovery=$([[ ${INCLUDE_RECOVERY} -eq 1 ]] && echo yes || echo no))"

# ------------------------------------------------------------------ 1. Postgres
# Reuse the shipped, validated backup.sh (custom-format dump + pg_restore --list
# validation + atomic publish onto the backup_data volume), then copy the newest
# published dump into staging. This keeps ONE tested pg_dump path.
echo "==> [db] running scripts/backup.sh via db_backup sidecar"
# Invoke via `bash` (not `exec /scripts/backup.sh`) so a lost execute bit on the
# bind-mounted script — common on Windows/WSL checkouts — can't turn this into a
# "Permission denied". db_backup installs bash in its entrypoint.
compose exec -T db_backup sh -c "bash /scripts/backup.sh" >/dev/null
LATEST_DUMP=$(compose exec -T db_backup sh -c "ls -t /backups/*.dump 2>/dev/null | head -n1" | tr -d '\r')
[[ -n "${LATEST_DUMP}" ]] || { echo "ERR: db_backup produced no .dump" >&2; exit 1; }
compose exec -T db_backup sh -c "cat '${LATEST_DUMP}'" > "${COMPONENTS_DIR}/postgres.dump"
[[ -s "${COMPONENTS_DIR}/postgres.dump" ]] || { echo "ERR: copied dump is empty" >&2; exit 1; }

# ------------------------------------------------------------------ 2. volumes
# One-shot read-only tar of each named volume (independent of whether the owning
# service is running). tar streams to a host staging file.
snapshot_volume() {
    local logical="$1" outfile="$2" volname
    volname=$(resolve_volume "$logical")
    if [[ -z "${volname}" ]]; then
        echo "ERR: could not resolve volume '${logical}' for project '${PROJECT}'" >&2
        echo "     (is the stack created/running under this project name?)" >&2
        exit 1
    fi
    echo "==> [vol] snapshotting ${logical}"
    docker run --rm -v "${volname}:/src:ro" "${HELPER_IMAGE}" \
        tar czf - -C /src . > "${outfile}"
    [[ -s "${outfile}" ]] || { echo "ERR: empty snapshot for ${logical}" >&2; exit 1; }
}

snapshot_volume vault_data      "${COMPONENTS_DIR}/vault_data.tar.gz"
snapshot_volume recordings_data "${COMPONENTS_DIR}/recordings_data.tar.gz"
snapshot_volume mirror_data     "${COMPONENTS_DIR}/mirror_data.tar.gz"

RECOVERY_LINE="false"
if [[ ${INCLUDE_RECOVERY} -eq 1 ]]; then
    # Explicit, opt-in operator path. Read-only, throwaway container; the
    # recovery volume is never mounted into a long-lived app service (PRA-241).
    snapshot_volume vault_recovery "${COMPONENTS_DIR}/vault_recovery.tar.gz"
    RECOVERY_LINE="true"
fi

# ------------------------------------------------------------------ 3. manifest
# Record image/runtime versions for the restore target shape (no secrets).
image_ref() { compose images "$1" --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | head -n1; }

# Clean list of compose file paths (drop the -f flags) for the manifest.
COMPOSE_FILE_NAMES=()
_i=0
while [[ ${_i} -lt ${#COMPOSE_FILES[@]} ]]; do
    if [[ "${COMPOSE_FILES[$_i]}" == "-f" ]]; then
        COMPOSE_FILE_NAMES+=("${COMPOSE_FILES[$((_i+1))]}"); _i=$((_i+2))
    else _i=$((_i+1)); fi
done
CF_JSON="$(printf '"%s",' "${COMPOSE_FILE_NAMES[@]}")"; CF_JSON="[${CF_JSON%,}]"

sha_of() { sha256sum "$1" | awk '{print $1}'; }
size_of() { wc -c < "$1" | tr -d ' '; }

manifest_component() {
    # name file -> JSON object; only checksum/size/name (never contents).
    local name="$1" file="$2"
    printf '{"name":"%s","file":"components/%s","sha256":"%s","size_bytes":%s}' \
        "${name}" "$(basename "${file}")" "$(sha_of "${file}")" "$(size_of "${file}")"
}

COMPONENTS_JSON="$(manifest_component postgres      "${COMPONENTS_DIR}/postgres.dump")"
COMPONENTS_JSON="${COMPONENTS_JSON},$(manifest_component vault_data     "${COMPONENTS_DIR}/vault_data.tar.gz")"
COMPONENTS_JSON="${COMPONENTS_JSON},$(manifest_component recordings_data "${COMPONENTS_DIR}/recordings_data.tar.gz")"
COMPONENTS_JSON="${COMPONENTS_JSON},$(manifest_component mirror_data    "${COMPONENTS_DIR}/mirror_data.tar.gz")"
if [[ ${INCLUDE_RECOVERY} -eq 1 ]]; then
    COMPONENTS_JSON="${COMPONENTS_JSON},$(manifest_component vault_recovery "${COMPONENTS_DIR}/vault_recovery.tar.gz")"
fi

cat > "${STAGING}/manifest.json" <<EOF
{
  "format_version": 1,
  "kind": "praxis-bundled-backup",
  "created_at": "${CREATED_AT}",
  "project": "${PROJECT}",
  "recovery_included": ${RECOVERY_LINE},
  "compose_files": ${CF_JSON},
  "images": {
    "backend": "$(image_ref backend)",
    "vault": "$(image_ref vault)",
    "db": "$(image_ref db)",
    "agent-broker": "$(image_ref agent-broker)"
  },
  "components": [${COMPONENTS_JSON}],
  "restore": {
    "command": "PRAXIS_BACKUP_PASSPHRASE=... scripts/restore-bundle.sh --bundle <file> -p <fresh-project>",
    "downtime": "Restore is offline: bring up a FRESH bundled deployment (empty volumes). The restore recreates DB, vault_data, recordings, mirrors, then starts the stack. Expect the stack to be unavailable for the duration.",
    "note": "A working vault restore requires the unseal keys (recovery_included=true, or supplied out of band). Without them the restored vault stays SEALED."
  }
}
EOF

# ------------------------------------------------------------------ 4. pack + encrypt
# Deterministic inner tar (manifest + components), then encrypt the whole thing.
INNER_TAR="${STAGING}/bundle.tar"
tar cf "${INNER_TAR}" -C "${STAGING}" manifest.json components

mkdir -p "${OUTPUT_DIR}"
FINAL_ENC="${OUTPUT_DIR}/praxis-backup-${TS}.bundle.enc"
FINAL_SHA="${FINAL_ENC}.sha256"
# Temp names that can NEVER be mistaken for a final bundle (leading dot + suffix).
TMP_ENC="${OUTPUT_DIR}/.praxis-backup-${TS}.bundle.enc.tmp.$$"
TMP_SHA="${OUTPUT_DIR}/.praxis-backup-${TS}.bundle.enc.sha256.tmp.$$"

echo "==> encrypting bundle (AES-256-CBC, PBKDF2)"
( umask 077
  openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt \
      -in "${INNER_TAR}" -out "${TMP_ENC}" \
      -pass env:PRAXIS_BACKUP_PASSPHRASE )

# Integrity sidecar over the CIPHERTEXT so restore can detect truncation/
# corruption before it even attempts to decrypt.
( cd "${OUTPUT_DIR}" && sha256sum "$(basename "${TMP_ENC}")" | awk -v f="$(basename "${FINAL_ENC}")" '{print $1"  "f}' > "$(basename "${TMP_SHA}")" )

sync 2>/dev/null || true

# Atomic publish: rename both temp files into place only now that everything
# succeeded. Clear the trap so cleanup can't delete the published bundle.
mv -f "${TMP_ENC}" "${FINAL_ENC}"
mv -f "${TMP_SHA}" "${FINAL_SHA}"
TMP_ENC=""; TMP_SHA=""
trap - EXIT INT TERM
rm -rf "${STAGING}" 2>/dev/null || true
sync 2>/dev/null || true

BYTES="$(size_of "${FINAL_ENC}")"
echo "==> backup bundle published:"
echo "      ${FINAL_ENC} (${BYTES} bytes)"
echo "      ${FINAL_SHA}"
echo "    recovery material included: $([[ ${INCLUDE_RECOVERY} -eq 1 ]] && echo yes || echo 'NO — vault will stay sealed on restore unless supplied separately')"
echo "    Move this bundle OFF-HOST for durable custody (Praxis does not ship it)."
