#!/usr/bin/env bash
# Seed the synthetic demo fleet used by the demo-walkthrough and rollback specs.
#
# Idempotent and secret-free: hosts, plan and execution are fictional rows in
# the documentation address range and no credential material is written. Run it
# against the stack under test; teardown is `docker compose down -v` on that
# disposable stack.
#
# Usage:
#   COMPOSE_FILES="-f docker-compose.yml -f docker-compose.prod.yml" \
#   COMPOSE_PROFILES_ARGS="--profile bundled --profile proxy" \
#   e2e/fixtures/seed-demo.sh
#
# COMPOSE_ENV_FILE (optional) is passed as --env-file; COMPOSE_PROJECT_NAME
# selects the project. Run from the directory that holds the compose files.

set -euo pipefail

# shellcheck disable=SC2086
docker compose ${COMPOSE_ENV_FILE:+--env-file "$COMPOSE_ENV_FILE"} \
    ${COMPOSE_FILES:--f docker-compose.yml -f docker-compose.prod.yml} \
    ${COMPOSE_PROFILES_ARGS:---profile bundled --profile proxy} \
    exec -T backend python -m app.scripts.seed_demo_fixture
