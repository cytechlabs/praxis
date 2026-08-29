#!/usr/bin/env bash
# Proves the repository gitleaks config actually detects secrets.
#
# A gitleaks config that declares no rules and does not extend the built-in
# set loads zero detection rules. gitleaks then exits 0 on everything, so the
# pre-commit hook reports a clean scan without having looked for anything.
# That failure is silent: nothing in the output distinguishes it from a tree
# with no secrets in it.
#
# This check removes the ambiguity with two controls, both created at runtime
# under a temporary directory so no credential-shaped fixture is ever
# committed:
#
#   negative control  a well-formed, randomly generated access key id, which
#                     the config must report (gitleaks exits 1)
#   positive control  ordinary prose, which the config must pass (exits 0)
#
# A third case runs the exact pre-commit hook entry
# (`gitleaks protect --verbose --redact --staged`) against a throwaway git
# repository carrying a copy of the repository config, so the gate developers
# actually hit is the one under test.
#
# Runs on every commit as the `gitleaks-config` hook, which reuses the pinned
# gitleaks hook environment and so already has the right binary on PATH. To run
# it by hand, put a gitleaks matching the .pre-commit-config.yaml pin on PATH
# first; this script downloads nothing.
#
# Usage: pre-commit run gitleaks-config --all-files
#        scripts/check-gitleaks-config.sh
# Exit:  0 all pass; 1 a failure (details printed); 2 gitleaks unavailable.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="${REPO_ROOT}/.gitleaks.toml"

if ! command -v gitleaks >/dev/null 2>&1; then
    echo "ERR: gitleaks is not on PATH; cannot verify the scanner config" >&2
    exit 2
fi

if [[ ! -f "${CONFIG}" ]]; then
    echo "ERR: ${CONFIG} is missing" >&2
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

FAILURES=0
pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILURES=$((FAILURES + 1)); }

# Writes a randomly generated access key id into "$1/leaky.txt". Random rather
# than a documentation sample, because the built-in rules allowlist the
# published example keys and the control would then be a false negative.
write_negative_control() {
    local dir="$1" body=""
    local alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    local i
    for ((i = 0; i < 16; i++)); do
        body+="${alphabet:$((RANDOM % ${#alphabet})):1}"
    done
    printf 'aws_access_key_id = %s%s\n' "AKIA" "${body}" >"${dir}/leaky.txt"
}

write_positive_control() {
    printf 'ordinary prose with no credential material in it\n' >"$1/clean.txt"
}

# --- case 1: the config reports a real secret ------------------------------
NEG="${WORK}/negative"
mkdir -p "${NEG}"
write_negative_control "${NEG}"

set +e
gitleaks detect --no-git --source "${NEG}" --config "${CONFIG}" \
    --redact --no-banner >"${WORK}/negative.log" 2>&1
NEG_STATUS=$?
set -e

if [[ ${NEG_STATUS} -eq 1 ]]; then
    pass "config detects a synthetic access key id"
else
    fail "config did not detect a synthetic access key id (exit ${NEG_STATUS})"
    echo "       the config loads no effective detection rules; every scan is vacuous"
    sed 's/^/       /' "${WORK}/negative.log" >&2
fi

# --- case 2: the config passes clean content -------------------------------
POS="${WORK}/positive"
mkdir -p "${POS}"
write_positive_control "${POS}"

set +e
gitleaks detect --no-git --source "${POS}" --config "${CONFIG}" \
    --redact --no-banner >"${WORK}/positive.log" 2>&1
POS_STATUS=$?
set -e

if [[ ${POS_STATUS} -eq 0 ]]; then
    pass "config passes content with no credential material"
else
    fail "config reported a finding in clean content (exit ${POS_STATUS})"
    sed 's/^/       /' "${WORK}/positive.log" >&2
fi

# --- case 3: the pre-commit hook entry, on a staged control ----------------
# Hermetic git: no user or system config, hooks, or signing settings leak in.
HOOK="${WORK}/hook"
mkdir -p "${HOOK}/home"
cp "${CONFIG}" "${HOOK}/.gitleaks.toml"
write_negative_control "${HOOK}"

set +e
(
    export HOME="${HOOK}/home"
    export GIT_CONFIG_NOSYSTEM=1
    cd "${HOOK}"
    git init -q
    git add leaky.txt
    gitleaks protect --verbose --redact --staged --no-banner
) >"${WORK}/hook.log" 2>&1
HOOK_STATUS=$?
set -e

if [[ ${HOOK_STATUS} -eq 1 ]]; then
    pass "pre-commit hook entry blocks a staged synthetic access key id"
else
    fail "pre-commit hook entry allowed a staged secret (exit ${HOOK_STATUS})"
    sed 's/^/       /' "${WORK}/hook.log" >&2
fi

printf '\n'
if [[ ${FAILURES} -ne 0 ]]; then
    echo "gitleaks config check FAILED (${FAILURES} failing case(s))" >&2
    exit 1
fi
echo "gitleaks config check passed"
