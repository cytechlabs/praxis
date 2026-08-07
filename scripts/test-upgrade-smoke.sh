#!/usr/bin/env bash
# PRA-179 Slice 3: hermetic local upgrade/migration smoke.
#
# Proves that the normal Praxis upgrade path
# (``docker compose ... up -d``, backend's start.prod.sh runs
# ``alembic upgrade head``) lands cleanly on a database that was
# previously at a representative old revision, not just on a database
# that was never migrated at all.
#
# Reuses the Slice 2 prod compose override
# (``scripts/fresh-install-smoke.override.yml``) to drop host port
# bindings and inject ``PRAXIS_PUBLIC_URL`` — same isolation contract,
# different compose project name (``praxis-upgrade-smoke``), so this
# smoke does not collide with the Slice 2 fresh-install smoke or with
# a running dev stack.
#
# For each committed fixture under ``backend/tests/fixtures/upgrade/``
# the smoke:
#
#   1. Brings up the bundled ``db`` only in an isolated compose project.
#   2. Restores the fixture (a ``pg_dump`` of the schema at that
#      Alembic revision) into the bundled database.
#   3. Brings the rest of the stack up. ``start.prod.sh`` runs
#      ``alembic upgrade head`` from the fixture's revision; the chain
#      must converge cleanly on the current head.
#   4. Waits for backend ``/health``.
#   5. Asserts current-head invariants by exec-ing into the db:
#         - ``alembic_version`` advanced past the fixture's revision
#         - representative current-head tables are reachable
#           (``mirror_repos`` for PRA-157+, ``report_runs`` for
#           PRA-178+)
#   6. Tears down strictly (no ``|| true``); on any non-zero exit the
#      ``on_exit`` trap preserves the temp env file and prints
#      ``--env-file``-bearing logs/teardown commands.
#
# Modes:
#
#     scripts/test-upgrade-smoke.sh
#         Default. Run the smoke against every fixture in
#         ``backend/tests/fixtures/upgrade/*.sql``.
#
#     scripts/test-upgrade-smoke.sh --regenerate
#         Regenerate the committed fixtures from the current state of
#         the Alembic chain. Brings up a throwaway project, runs
#         ``alembic upgrade <target>`` for each target revision below,
#         dumps with ``pg_dump --no-owner --no-acl``, writes to
#         ``backend/tests/fixtures/upgrade/<name>.sql``, tears down.
#         Run this whenever the Alembic chain or the target revisions
#         change; the committed fixtures are otherwise static.
#
# Target revisions (chosen because they are the last revision before
# the M13 thin-agent / M15 mirror schema land):
#
#     pre_m13  = pra149_review                  (last pre-M13)
#     pre_m15  = pra156_lifecycle_notif_state   (last pre-M15)
#
# Exit codes:
#     0 - all fixtures upgraded to head cleanly; projects torn down.
#     1 - one or more fixtures failed; the offending project is LEFT UP
#         for inspection with the env file preserved.
#
# Safety:
#     - Dedicated compose project name (``praxis-upgrade-smoke``);
#       never touches the default ``praxis`` project or the Slice 2
#       ``praxis-fresh-install-smoke`` project.
#     - Writes its env file to a ``mktemp -d`` directory and unlinks it
#       only on a clean exit.
#     - Refuses to start if the smoke project already has containers.

set -euo pipefail

cd "$(dirname "$0")/.."

PROJECT_NAME="praxis-upgrade-smoke"
OVERRIDE_FILE="scripts/fresh-install-smoke.override.yml"
COMPOSE_BASE=(
    -f docker-compose.yml
    -f docker-compose.prod.yml
    -f "${OVERRIDE_FILE}"
)
COMPOSE_PROFILE_ARGS=(--profile bundled)
FIXTURE_DIR="backend/tests/fixtures/upgrade"

# Target revisions for --regenerate. Order matters only for the
# generated filenames; the smoke runs each fixture independently.
declare -A REGENERATE_TARGETS=(
    [pre_m13]="pra149_review"
    [pre_m15]="pra156_lifecycle_notif_state"
)

# ---------------------------------------------------------------- pre-flight

if ! command -v docker >/dev/null 2>&1; then
    echo "ERR: docker CLI not on PATH" >&2
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo "ERR: docker daemon is not reachable" >&2
    exit 1
fi

# Refuse to clobber an already-running smoke project. Label-only,
# same reason as the Slice 2 smoke: this runs before any env file is
# generated, so we can't depend on compose interpolation.
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

SMOKE_TMP=$(mktemp -d -t praxis-upgrade-XXXXXX)
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
    # Strict: failed teardown must propagate. The EXIT trap then
    # preserves the env file and prints the recovery commands.
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
    for _ in $(seq 1 90); do
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
        compose logs --tail=200 backend vault db >&2 || true
        return 1
    fi
}

# ---------------------------------------------------------------- regenerate

if [[ "${1:-}" == "--regenerate" ]]; then
    mkdir -p "${FIXTURE_DIR}"
    echo "==> regenerating upgrade fixtures into ${FIXTURE_DIR}"

    # One throwaway project hosts both regenerations. Use the same
    # ``--build`` posture as the smoke so the toolchain (alembic +
    # backend image) exactly matches what the smoke later exercises.
    echo "==> bringing up throwaway db + backend"
    compose up -d --build db
    # Wait for the db healthcheck so the backend's start.prod.sh has
    # a target to migrate against on first start.
    for _ in $(seq 1 60); do
        if compose ps --format json 2>/dev/null | grep -q '"Health":"healthy"'; then
            break
        fi
        sleep 1
    done

    # We don't actually start ``backend`` here — start.prod.sh would
    # immediately run ``alembic upgrade head`` and overshoot the
    # target revisions. Instead we ``run --rm backend`` with a custom
    # entrypoint that runs alembic to the target then dumps.
    for name in "${!REGENERATE_TARGETS[@]}"; do
        target="${REGENERATE_TARGETS[$name]}"
        out="${FIXTURE_DIR}/${name}.sql"
        echo "==> generating ${out} at alembic revision ${target}"
        # Reset db each time so the previous regeneration doesn't
        # leave state behind.
        compose exec -T db psql -v ON_ERROR_STOP=1 -U postgres -d praxis \
            -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;" >/dev/null
        # Run alembic from a one-shot container. Pass the alembic
        # command directly as the COMMAND (after the service name)
        # rather than wrapping it in ``bash -c "..."``: the prod
        # image's ENTRYPOINT is ``/usr/bin/tini --``, so tini will
        # forward the CMD it gets. CMD override replaces the default
        # ``start.prod.sh`` so we don't accidentally run
        # ``alembic upgrade head``. None of these argv tokens start
        # with ``/``, which avoids MSYS path-mangling on git-bash.
        compose run --rm backend alembic upgrade "${target}"
        # Dump to a host-visible file via stdout so we don't need a
        # shared volume contract.
        compose exec -T db pg_dump \
            -U postgres -d praxis \
            --no-owner --no-acl --no-comments \
            > "${out}"
        echo "    wrote $(wc -c < "${out}") bytes; alembic_version row:"
        grep -E "INSERT INTO public.alembic_version" "${out}" | head -1 || true
    done

    teardown_stack
    echo "==> fixture regeneration complete; committed dumps live under ${FIXTURE_DIR}/"
    exit 0
fi

# ---------------------------------------------------------------- smoke

if [[ ! -d "${FIXTURE_DIR}" ]] || \
   ! compgen -G "${FIXTURE_DIR}/*.sql" >/dev/null 2>&1; then
    echo "ERR: no fixtures found under ${FIXTURE_DIR}/." >&2
    echo "    Run: scripts/test-upgrade-smoke.sh --regenerate" >&2
    exit 1
fi

run_one_fixture() {
    local fixture="$1"
    local name
    name="$(basename "${fixture}" .sql)"

    echo
    echo "================================================================"
    echo "==> upgrade smoke: ${name}"
    echo "    fixture: ${fixture}"
    echo "================================================================"

    # Bring up db only first, so we can restore before the backend
    # races ahead with alembic upgrade head.
    echo "==> bringing up bundled db"
    compose up -d --build db

    # Wait for the db healthcheck.
    local ready=0
    for _ in $(seq 1 60); do
        if compose ps --format json 2>/dev/null | grep -q '"Health":"healthy"'; then
            ready=1
            break
        fi
        sleep 1
    done
    if [[ "${ready}" -ne 1 ]]; then
        echo "==> db never became healthy" >&2
        compose logs --tail=200 db >&2 || true
        return 1
    fi

    # Reset the db to empty before restoring. The bundled volume is
    # smoke-owned, so this is safe.
    echo "==> resetting db schema"
    compose exec -T db psql -v ON_ERROR_STOP=1 -U postgres -d praxis \
        -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;" >/dev/null

    echo "==> restoring fixture ${name}"
    # ON_ERROR_STOP=1 makes psql fail the script on any restore-time
    # SQL or meta-command error. Without it, plain psql swallows
    # errors and continues, which can let alembic upgrade head run
    # against a partially restored schema and produce a false-positive
    # smoke pass.
    compose exec -T db psql -v ON_ERROR_STOP=1 -U postgres -d praxis < "${fixture}" >/dev/null

    # Sanity-check the restored alembic_version row.
    local pre_version
    pre_version=$(compose exec -T db psql -v ON_ERROR_STOP=1 -U postgres -d praxis -tAc \
        "SELECT version_num FROM alembic_version")
    echo "    restored alembic_version=${pre_version}"

    # Bring the rest of the stack up. start.prod.sh runs alembic upgrade
    # head from whatever the db says (which is the fixture's revision).
    echo "==> bringing up backend stack (auto runs alembic upgrade head)"
    compose up -d --build

    # Wait for /health.
    echo "==> waiting for backend /health"
    if ! wait_for_backend_health; then
        return 1
    fi
    echo "    backend healthy"

    # Verify alembic advanced past the fixture revision.
    local post_version
    post_version=$(compose exec -T db psql -v ON_ERROR_STOP=1 -U postgres -d praxis -tAc \
        "SELECT version_num FROM alembic_version")
    echo "    post-upgrade alembic_version=${post_version}"
    if [[ "${post_version}" == "${pre_version}" ]]; then
        echo "==> alembic_version did not advance (${pre_version} == ${post_version})" >&2
        return 1
    fi

    # Verify representative current-head tables exist.
    local mirror_ok
    mirror_ok=$(compose exec -T db psql -v ON_ERROR_STOP=1 -U postgres -d praxis -tAc \
        "SELECT to_regclass('public.mirror_repos')")
    if [[ "${mirror_ok}" != "mirror_repos" ]]; then
        echo "==> mirror_repos table missing after upgrade" >&2
        return 1
    fi
    local reports_ok
    reports_ok=$(compose exec -T db psql -v ON_ERROR_STOP=1 -U postgres -d praxis -tAc \
        "SELECT to_regclass('public.report_runs')")
    if [[ "${reports_ok}" != "report_runs" ]]; then
        echo "==> report_runs table missing after upgrade" >&2
        return 1
    fi
    echo "    current-head tables present: mirror_repos, report_runs"

    # Representative post-upgrade read: the admin user should have
    # been created by start.prod.sh after migrations completed.
    # NOTE: the User table is named ``user`` (singular, SQL keyword
    # so it must be double-quoted).
    local admin_username
    admin_username=$(compose exec -T db psql -v ON_ERROR_STOP=1 -U postgres -d praxis -tAc \
        "SELECT username FROM public.\"user\" WHERE username='praxisadmin'")
    if [[ "${admin_username}" != "praxisadmin" ]]; then
        echo "==> admin user not present after upgrade + seed" >&2
        return 1
    fi
    echo "    admin user present in user table"

    # Tear this fixture's stack down so the next iteration starts
    # from a clean slate. Strict (no ``|| true``).
    teardown_stack
}

echo "==> upgrade smoke starting; fixtures:"
for fixture in "${FIXTURE_DIR}"/*.sql; do
    echo "      ${fixture}"
done

for fixture in "${FIXTURE_DIR}"/*.sql; do
    run_one_fixture "${fixture}"
done

echo
echo "==> upgrade smoke passed for all fixtures"
