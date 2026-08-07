#!/usr/bin/env bash
# PRA-185: read-only release-readiness check.
#
# Verifies the local tree is ready to cut a release WITHOUT changing anything:
#   1. package-version alignment (root package.json, frontend-next/package.json,
#      frontend-next/package-lock.json, backend/setup.py) against a target
#      version;
#   2. presence of the required release docs;
#   3. presence of the required release workflows;
#   4. clean whitespace (`git diff --check`).
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
check_version "frontend-next/package  " "$(pkg_version frontend-next/package.json)"
check_version "frontend-next/lock     " "$(pkg_version frontend-next/package-lock.json)"
check_version "backend/setup.py       " "$(setup_version backend/setup.py)"

# --- 2. Required release docs ----------------------------------------------
printf '\nRelease docs\n'
for doc in \
    CHANGELOG.md \
    docs/release-notes-template.md \
    docs/upgrade-notes-1.0.md \
    docs/release-checklist.md \
    agent/packaging/README.md; do
    if [ -f "${doc}" ]; then
        green "${doc}"
    else
        red "${doc} (missing)"
    fi
done

# --- 3. Required release workflows -----------------------------------------
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

# --- 4. Whitespace ----------------------------------------------------------
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
