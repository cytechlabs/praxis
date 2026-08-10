#!/usr/bin/env bash
# Read-only public-import readiness check.
#
# Verifies the tracked tree is safe to import into the public
# cytechlabs/praxis repository WITHOUT changing anything. It NEVER creates a
# repo, rewrites history, deletes files, runs git init/filter, publishes, or
# touches the network. Safe to run at any time.
#
# What it checks:
#   1. No disallowed private paths are tracked (handoff notes, project-docs,
#      secrets, keys, logs, test-results, the local DO import file, .env).
#   2. No `cfreeman29` namespace references remain in tracked files.
#   3. Release-facing image / repo references point at `cytechlabs/praxis`
#      (no other org for a `praxis` image or module path).
#   4. No internal-process markers (Codex / Claude / ACTIVE_SLICE / handoff
#      protocol / claude-codex) leak into tracked files.
#   5. The curated public narrative docs are free of `PRA-NNN` / "slice"
#      implementation-history wording.
#   6. The public-import checklist doc exists.
#
# Scope note: code, migrations, tests, and workflow YAML may retain issue-tracker
# references (e.g. `PRA-`, `pra158` in filenames, "see design notes") as ordinary
# engineering history — see docs/maintainers/public-import-checklist.md for the
# classification. This checker gates the *narrative public docs* and the
# hard private-leak markers, not every code comment.
#
# Usage: scripts/check-public-import-readiness.sh
# Exit status is non-zero if any check fails.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT}"

SELF="scripts/check-public-import-readiness.sh"
CHECKLIST="docs/maintainers/public-import-checklist.md"

PASS=0
FAIL=0
green() { printf '  \033[32mOK\033[0m   %s\n' "$1"; PASS=$((PASS + 1)); }
red()   { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL + 1)); }

# --- 1. Disallowed private paths must not be tracked ------------------------
printf 'Tracked-path hygiene\n'
DISALLOWED_RE='(^|/)claude-codex/|(^|/)project-docs/|(^|/)\.secrets/|(^|/)id_rsa|(^|/)ssh_host_|\.pem$|\.key$|\.log$|(^|/)test-results/|praxis-do-import|(^|/)\.env$|(^|/)praxis[_-]ee/|(^|/)license_private'
# Read into an array so each offending path stays one whole line: tracked
# paths may contain spaces or glob metacharacters, and an unquoted expansion
# would word-split and pathname-expand them into misleading output.
mapfile -t bad_paths < <(git ls-files | grep -E "${DISALLOWED_RE}" || true)
if [ "${#bad_paths[@]}" -eq 0 ]; then
    green "no disallowed private paths are tracked"
else
    red "disallowed private paths are tracked:"
    printf '        %s\n' "${bad_paths[@]}"
fi

# --- 2. Namespace: no cfreeman29 -------------------------------------------
printf '\nNamespace references\n'
cfree="$(git grep -In 'cfreeman29' -- . ":!${SELF}" ":!${CHECKLIST}" || true)"
if [ -z "${cfree}" ]; then
    green "no 'cfreeman29' references in tracked files"
else
    red "'cfreeman29' still referenced:"
    printf '        %s\n' "${cfree}"
fi

# --- 3. Release-facing refs must be cytechlabs -----------------------------
# Any ghcr.io/<org>/praxis or github.com/<org>/praxis where <org> is not
# cytechlabs is a wrong-namespace leak.
wrong_org="$(git grep -InE 'ghcr\.io/[A-Za-z0-9_.-]+/praxis|github\.com/[A-Za-z0-9_.-]+/praxis' -- . ":!${SELF}" ":!${CHECKLIST}" \
    | grep -vE 'ghcr\.io/cytechlabs/praxis|github\.com/cytechlabs/praxis' || true)"
if [ -z "${wrong_org}" ]; then
    green "release-facing image/repo refs use cytechlabs/praxis"
else
    red "non-cytechlabs praxis image/repo refs found:"
    printf '        %s\n' "${wrong_org}"
fi

# --- 4. Internal-process markers must not leak -----------------------------
printf '\nInternal-process markers\n'
# .gitignore intentionally ignores claude-codex/; this script, the checklist,
# and the documentation content checker all have to name the markers to screen
# for them — allowlist those four and nothing else. docs/dev-notes/ is a tracked
# exclusion dropped from the exported snapshot, so its internal-history tone is
# exempt (same carve-out as the narrative-docs check below).
CONTENT_CHECKER="scripts/check-docs-public-content.mjs"
PROC_RE='claude-codex|ACTIVE_SLICE|READY_FOR_CODEX|READY_FOR_CLAUDE|CLAUDE_WORKING|\bCodex\b|\bClaude\b|slice handoff'
proc="$(git grep -InE "${PROC_RE}" -- . ':!.gitignore' ':!docs/dev-notes' ":!${SELF}" \
    ":!${CHECKLIST}" ":!${CONTENT_CHECKER}" || true)"
if [ -z "${proc}" ]; then
    green "no Codex/Claude/handoff-protocol markers in tracked files"
else
    red "internal-process markers leaked:"
    printf '        %s\n' "${proc}"
fi

# --- 5. Public narrative docs free of PRA-/slice wording -------------------
printf '\nPublic narrative docs\n'
# Curated set: README + docs/*.md (excluding dev-notes + this checklist) +
# agent narrative docs. Code/migrations/tests/workflows are out of scope here.
mapfile -t NARRATIVE < <(git ls-files 'README.md' 'docs/*.md' 'agent/README.md' 'agent/packaging/README.md' \
    | grep -vE '^docs/dev-notes/' | grep -vF "${CHECKLIST}")
doc_hits=""
scanned=0
for d in "${NARRATIVE[@]}"; do
    # The index still lists a path whose file has been moved but not yet
    # staged. There is no content there to judge, and grepping it would report
    # a missing file rather than a policy problem.
    [ -f "${d}" ] || continue
    scanned=$((scanned + 1))
    h="$(grep -InE 'PRA-[0-9]|[Ss]lice' "${d}" || true)"
    [ -n "${h}" ] && doc_hits="${doc_hits}${d}:\n${h}\n"
done
if [ -z "${doc_hits}" ]; then
    green "narrative docs clean of PRA-NNN / slice wording (${scanned} docs)"
else
    red "narrative docs still carry PRA-/slice wording:"
    printf '        %b' "${doc_hits}"
fi

# --- 6. Checklist deliverable exists ---------------------------------------
printf '\nDeliverables\n'
if [ -f "${CHECKLIST}" ]; then
    green "${CHECKLIST} present"
else
    red "${CHECKLIST} missing"
fi

# --- Summary ----------------------------------------------------------------
printf '\n%d passed, %d failed.\n' "${PASS}" "${FAIL}"
if [ "${FAIL}" -ne 0 ]; then
    printf 'Not import-ready — resolve the failures above.\n'
    exit 1
fi
printf 'Public-import readiness checks passed. This does NOT create or push the public repo.\n'
