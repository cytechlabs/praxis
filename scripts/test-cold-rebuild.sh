#!/usr/bin/env bash
# PRA-154 / PRA-299: cold from-scratch build + boot gate.
#
# Tears everything down, rebuilds the production images from scratch, and brings
# the bundled production-parity stack up, asserting the backend reaches /health.
# This satisfies the "every change must survive a from-scratch
# `down -v && up --build`" rule against the SAME production images a release runs.
#
# PRA-299 retired the dev runtime, so this gate no longer runs pytest inside a
# bind-mounted dev container. The full test suite runs in CI's backend-test lanes
# (and locally via the venv workflow in backend/tests/README.md); the app-level
# bring-up + auth round trip is covered by scripts/test-fresh-install-smoke.sh.
# This script's job is narrowly the cold build + boot + health of the canonical
# stack.
#
# Requires SECRET_KEY / ADMIN_PASSWORD / POSTGRES_PASSWORD in the environment or
# a repo-root .env (same as any production-parity bring-up).
#
# Usage:
#     scripts/test-cold-rebuild.sh
#
# Exit code: 0 on a healthy cold build; 1 if the rebuilt stack never becomes
# healthy. On success the stack is torn down; on failure it's left up for
# inspection.

set -euo pipefail

cd "$(dirname "$0")/.."

COMPOSE=(-f docker-compose.yml -f docker-compose.prod.yml --profile bundled)

echo "==> docker compose ${COMPOSE[*]} down -v"
docker compose "${COMPOSE[@]}" down -v

echo "==> docker compose ${COMPOSE[*]} up -d --build (from scratch)"
docker compose "${COMPOSE[@]}" build --no-cache
docker compose "${COMPOSE[@]}" up -d

echo "==> waiting for backend /health"
healthy=0
for _ in $(seq 1 60); do
    if docker compose "${COMPOSE[@]}" exec -T backend python -c \
        "import urllib.request, sys; \
         r = urllib.request.urlopen('http://localhost:8000/health', timeout=3); \
         sys.exit(0 if r.status == 200 else 1)" 2>/dev/null; then
        healthy=1
        echo "    backend healthy"
        break
    fi
    sleep 2
done

if [[ "${healthy}" -ne 1 ]]; then
    echo "==> backend never became healthy; tail of backend logs:" >&2
    docker compose "${COMPOSE[@]}" logs --tail=100 backend >&2 || true
    echo "==> stack left up for inspection. Tear down with:" >&2
    echo "    docker compose ${COMPOSE[*]} down -v" >&2
    exit 1
fi

echo "==> cold build + boot healthy; tearing down"
docker compose "${COMPOSE[@]}" down -v
echo "==> OK"
