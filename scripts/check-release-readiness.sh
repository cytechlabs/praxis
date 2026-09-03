#!/usr/bin/env bash
# PRA-185: read-only release-readiness check.
#
# Verifies the local tree is ready to cut a release WITHOUT changing anything:
#   1. product/package-version alignment (the displayed frontend product version,
#      root package.json, frontend-next/package.json, frontend-next/package-lock.json,
#      backend/setup.py, agent/VERSION, and the control plane's pinned agent
#      release) against a target version;
#   2. the reported product version being derived from the installed package
#      rather than restated as a literal in the backend;
#   3. presence of the required release docs, publication scripts, and agent
#      packaging scripts;
#   4. presence of the required release workflows;
#   5. clean whitespace (`git diff --check`).
#
# It NEVER tags, pushes, publishes, builds images, or mutates services/volumes.
# It is safe to run at any time.
#
# Usage:
#   scripts/check-release-readiness.sh            # target = root package.json version
#   scripts/check-release-readiness.sh 1.0.0      # assert an explicit target version
#
# Exit status is non-zero if any check fails.

set -euo pipefail

# Resolve repo root from this script's location so it works from any CWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT}"

PASS=0
FAIL=0

green() { printf '  \033[32mOK\033[0m   %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL + 1)); }

# Extract the first "version": "X.Y.Z" from a package.json.
pkg_version() {
    sed -nE 's/.*"version"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p; t done; b; :done q' "$1"
}

# Extract version="X.Y.Z" from setup.py.
setup_version() {
    sed -nE 's/.*version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p; t done; b; :done q' "$1"
}

# Extract PRODUCT_VERSION='X.Y.Z' from the frontend build-identity source.
product_version() {
    sed -nE "s/.*PRODUCT_VERSION[[:space:]]*=[[:space:]]*'([^']+)'.*/\1/p; t done; b; :done q" "$1"
}

ROOT_VERSION="$(pkg_version package.json)"
TARGET="${1:-${ROOT_VERSION}}"

printf 'Release readiness check — target version: %s\n\n' "${TARGET}"

# --- 1. Version alignment ---------------------------------------------------
printf 'Version alignment\n'
check_version() {
    local label="$1" actual="$2"
    if [ "${actual}" = "${TARGET}" ]; then
        green "${label} = ${actual}"
    else
        red "${label} = ${actual} (expected ${TARGET})"
    fi
}
check_version "root package.json      " "${ROOT_VERSION}"
check_version "displayed product      " "$(product_version frontend-next/src/config/version.ts)"
check_version "frontend-next/package  " "$(pkg_version frontend-next/package.json)"
check_version "frontend-next/lock     " "$(pkg_version frontend-next/package-lock.json)"
check_version "backend/setup.py       " "$(setup_version backend/setup.py)"

# The agent releases under its own agent-vX.Y.Z tag but shares X.Y.Z with the
# application. agent/VERSION is the source of truth for the agent; the backend
# carries a mirror because its image does not ship the agent source tree.
AGENT_VERSION="$(tr -d '[:space:]' < agent/VERSION 2>/dev/null || echo '')"
check_version "agent/VERSION          " "${AGENT_VERSION}"

BACKEND_PIN="$(sed -nE 's/^_DEFAULT_RELEASE_VERSION = "v([^"]+)".*/\1/p; t done; b; :done q' \
    backend/app/api/routes/agent_bootstrap.py)"
if [ -n "${AGENT_VERSION}" ] && [ "${BACKEND_PIN}" = "${AGENT_VERSION}" ]; then
    green "control-plane agent pin = v${BACKEND_PIN}"
else
    red "control-plane agent pin = v${BACKEND_PIN} (expected v${AGENT_VERSION} from agent/VERSION)"
fi

# --- 2. Reported version derivation -----------------------------------------
# The version served by /health, by the OpenAPI document, and by the support
# bundle must come from the installed package's metadata. A release version
# restated in the backend is a mirror nothing updates, so the release ships an
# artifact that reports the previous version over its own health endpoint.
printf '\nReported version derivation\n'

VERSION_SOURCE="backend/app/core/version.py"
if [ -f "${VERSION_SOURCE}" ]; then
    green "${VERSION_SOURCE}"
else
    red "${VERSION_SOURCE} (missing; the backend has no authoritative version source)"
fi

for src in \
    "${VERSION_SOURCE}" \
    backend/app/api/main.py \
    backend/app/services/diagnostics_service.py; do
    if [ ! -f "${src}" ]; then
        red "${src} (missing)"
        continue
    fi
    LITERAL="$(grep -nE '"[0-9]+\.[0-9]+\.[0-9]+"' "${src}" | head -n 1 || true)"
    if [ -n "${LITERAL}" ]; then
        red "${src} restates a release version: ${LITERAL}"
        red "  ^ delete the literal; derive the version from ${VERSION_SOURCE}"
    else
        green "${src} states no release version literal"
    fi
done

for consumer in \
    backend/app/api/main.py \
    backend/app/services/diagnostics_service.py; do
    if [ -f "${consumer}" ] && grep -q 'get_version()' "${consumer}"; then
        green "${consumer} derives its version from ${VERSION_SOURCE}"
    else
        red "${consumer} does not call get_version() from ${VERSION_SOURCE}"
    fi
done

# --- 3. Required release docs ----------------------------------------------
printf '\nRelease docs\n'
for doc in \
    CHANGELOG.md \
    docs/maintainers/release-notes-template.md \
    docs/upgrade-notes-1-0.md \
    docs/maintainers/release-checklist.md \
    docs/maintainers/agent-release.md \
    docs/maintainers/ghcr-release-operations.md \
    agent/packaging/README.md \
    agent/packaging/install.sh \
    agent/packaging/uninstall.sh \
    agent/GO_VERSION \
    agent/scripts/verify_sbom.py \
    scripts/build_release_index.py \
    scripts/check-release-absence.sh \
    scripts/check-tag-commit.sh \
    scripts/promote-release-images.sh; do
    if [ -f "${doc}" ]; then
        green "${doc}"
    else
        red "${doc} (missing)"
    fi
done

# --- 4. Required release workflows -----------------------------------------
printf '\nRelease workflows\n'
for wf in \
    .github/workflows/ci.yml \
    .github/workflows/publish.yml \
    .github/workflows/agent-release.yml; do
    if [ -f "${wf}" ]; then
        green "${wf}"
    else
        red "${wf} (missing)"
    fi
done

# --- 5. Whitespace ----------------------------------------------------------
printf '\nWorking tree\n'
if git diff --check >/dev/null 2>&1; then
    green "git diff --check clean"
else
    red "git diff --check reported whitespace/conflict errors"
fi

# --- Summary ----------------------------------------------------------------
printf '\n%d passed, %d failed.\n' "${PASS}" "${FAIL}"
if [ "${FAIL}" -ne 0 ]; then
    printf 'Not release-ready — resolve the failures above.\n'
    exit 1
fi
printf 'Release readiness checks passed. This does NOT cut or publish a release.\n'
