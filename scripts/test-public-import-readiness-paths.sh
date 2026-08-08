#!/usr/bin/env bash
# Focused regression for the tracked-path hygiene section of
# scripts/check-public-import-readiness.sh.
#
# The disallowed-path report must print one complete line per offending
# tracked path. Tracked paths may legitimately contain spaces or glob
# metacharacters, so the report must not word-split them into fragments and
# must not pathname-expand them against the working directory.
#
# Both cases run against a throwaway git repository built under a temporary
# directory, so nothing here reads or mutates the real tree.
#
# Usage: scripts/test-public-import-readiness-paths.sh
# Exit:  0 all pass; 1 a failure (details printed).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHECKER="${REPO_ROOT}/scripts/check-public-import-readiness.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# Hermetic git: no user/system config, hooks, or signing settings leaking in.
export HOME="${WORK}/home"
export GIT_CONFIG_NOSYSTEM=1
mkdir -p "${HOME}"

FAILURES=0
pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILURES=$((FAILURES + 1)); }

# Builds a fresh fake repo containing a copy of the checker and echoes its path.
make_repo() {
    local repo="$1"
    mkdir -p "${repo}/scripts"
    cp "${CHECKER}" "${repo}/scripts/check-public-import-readiness.sh"
    chmod +x "${repo}/scripts/check-public-import-readiness.sh"
    git -C "${repo}" init -q
}

# Echoes the indented body of the tracked-path failure block, one path per
# line with the report indentation stripped.
reported_paths() {
    awk '
        /disallowed private paths are tracked:/ { grab = 1; next }
        /^Namespace references$/                { grab = 0 }
        grab && /^        / { sub(/^        /, ""); print }
    ' "$1"
}

# --- case 1: offending paths with spaces and glob metacharacters ------------
REPO="${WORK}/dirty"
make_repo "${REPO}"

DOCS="${REPO}/project-docs"
mkdir -p "${DOCS}"
# "notes-[ab].md" is a bracket glob that matches the two decoy siblings, so an
# unquoted expansion silently rewrites it into the wrong paths. "spaced
# path.md" catches plain word splitting.
: > "${DOCS}/spaced path.md"
: > "${DOCS}/notes-[ab].md"
: > "${DOCS}/notes-a.md"
: > "${DOCS}/notes-b.md"
git -C "${REPO}" add -f -- project-docs

OUT="${WORK}/dirty.out"
(cd "${REPO}" && ./scripts/check-public-import-readiness.sh) > "${OUT}" 2>&1 || true

if grep -qF 'disallowed private paths are tracked:' "${OUT}"; then
    pass "offending tracked paths are reported as a failure"
else
    fail "offending tracked paths were not reported"
    cat "${OUT}"
fi

cat > "${WORK}/expected" <<'EOF'
project-docs/notes-[ab].md
project-docs/notes-a.md
project-docs/notes-b.md
project-docs/spaced path.md
EOF
reported_paths "${OUT}" | LC_ALL=C sort > "${WORK}/actual"
LC_ALL=C sort -o "${WORK}/expected" "${WORK}/expected"

if diff -u "${WORK}/expected" "${WORK}/actual" > "${WORK}/diff" 2>&1; then
    pass "every offending path is reported once, on its own complete line"
else
    fail "reported paths do not match the tracked paths"
    cat "${WORK}/diff"
fi

actual_count="$(wc -l < "${WORK}/actual" | tr -d ' ')"
if [ "${actual_count}" = "4" ]; then
    pass "report contains exactly one line per offending path"
else
    fail "report line count is ${actual_count}, want 4"
fi

# --- case 2: clean tree takes the no-offenders branch -----------------------
CLEAN_REPO="${WORK}/clean"
make_repo "${CLEAN_REPO}"
mkdir -p "${CLEAN_REPO}/docs"
: > "${CLEAN_REPO}/docs/overview.md"
git -C "${CLEAN_REPO}" add -f -- docs

CLEAN_OUT="${WORK}/clean.out"
(cd "${CLEAN_REPO}" && ./scripts/check-public-import-readiness.sh) > "${CLEAN_OUT}" 2>&1 || true

if grep -qF 'no disallowed private paths are tracked' "${CLEAN_OUT}"; then
    pass "clean tree reports no disallowed tracked paths"
else
    fail "clean tree did not take the no-offenders branch"
    cat "${CLEAN_OUT}"
fi

printf '\n'
if [ "${FAILURES}" -ne 0 ]; then
    printf '%d check(s) failed.\n' "${FAILURES}"
    exit 1
fi
printf 'All tracked-path report checks passed.\n'
