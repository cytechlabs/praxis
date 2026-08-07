#!/usr/bin/env bash
# PRA-263: focused, hermetic tests for scripts/backup.sh atomic-publish
# behavior. No live database — pg_dump and pg_restore are replaced with
# stubs on PATH whose behavior is driven by env vars, and the backup
# directory is redirected with BACKUP_DIR. Proves:
#
#   1. a successful dump publishes exactly one final *.dump (0600) and
#      leaves no temp artifact;
#   2. pg_dump that writes bytes then fails publishes no final *.dump
#      and cleans up its temp;
#   3. pg_dump that fails without writing publishes no final *.dump;
#   4. a dump that fails `pg_restore --list` validation publishes no
#      final *.dump and cleans up its temp;
#   5. the in-progress path pg_dump writes to never matches *.dump;
#   6. retention deletes old final *.dump files but never treats a
#      temp/staging file as a restorable backup.
#
# Usage: scripts/test-pra263-backup-atomic.sh
# Exit:  0 all pass; 1 a failure (details printed).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BACKUP_SCRIPT="$REPO_ROOT/scripts/backup.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

BIN="$WORK/bin"
mkdir -p "$BIN"

FAILURES=0
pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILURES=$((FAILURES + 1)); }

# Assertion helpers (explicit if/else, not `A && pass || fail`, so a failing
# pass can never spuriously run fail).
check_eq() { # actual expected msg
    if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (got '$1' want '$2')"; fi
}
check_exists() { if [ -e "$1" ]; then pass "$2"; else fail "$2 (missing: $1)"; fi; }
check_absent() { if [ ! -e "$1" ]; then pass "$2"; else fail "$2 (unexpected: $1)"; fi; }

# --- stubs -----------------------------------------------------------------
# pg_dump stub: finds the "-f <path>" it is told to write and behaves per
# $STUB_PGDUMP. Records that path to $DUMP_TARGET_LOG so a test can assert the
# in-progress path never ends in .dump.
cat > "$BIN/pg_dump" <<'STUB'
#!/usr/bin/env bash
set -u
target=""
prev=""
for a in "$@"; do
    if [ "$prev" = "-f" ]; then target="$a"; fi
    prev="$a"
done
[ -n "${DUMP_TARGET_LOG:-}" ] && printf '%s\n' "$target" >> "$DUMP_TARGET_LOG"
case "${STUB_PGDUMP:-ok}" in
    ok)              printf 'PGDMP-fake-archive-bytes' > "$target"; exit 0 ;;
    write_then_fail) printf 'PGDMP-partial' > "$target"; exit 3 ;;
    fail_no_write)   exit 4 ;;
    *)               exit 99 ;;
esac
STUB
chmod +x "$BIN/pg_dump"

# pg_restore stub: only used with --list here; behavior per $STUB_PGRESTORE.
cat > "$BIN/pg_restore" <<'STUB'
#!/usr/bin/env bash
set -u
case "${STUB_PGRESTORE:-ok}" in
    ok)   exit 0 ;;
    fail) echo "pg_restore: corrupt archive" >&2; exit 5 ;;
    *)    exit 99 ;;
esac
STUB
chmod +x "$BIN/pg_restore"

# run_backup <backup_dir> — runs backup.sh with the stubs on PATH and the
# scenario env already exported by the caller. Prints nothing; returns the
# script's exit code.
run_backup() {
    local dir="$1"
    PATH="$BIN:$PATH" \
    BACKUP_DIR="$dir" \
    DB_HOST="stub" \
    POSTGRES_DB="testdb" \
    POSTGRES_USER="tester" \
    POSTGRES_PASSWORD="pw" \
        bash "$BACKUP_SCRIPT" > "$dir/.stdout" 2> "$dir/.stderr"
}

count_final() { find "$1" -maxdepth 1 -type f -name "*.dump" | wc -l | tr -d ' '; }
count_temp()  { find "$1" -maxdepth 1 -type f -name ".*tmp.*" | wc -l | tr -d ' '; }

# --- 1. success publishes exactly one 0600 final dump, no temp --------------
test_success() {
    local dir="$WORK/success"; mkdir -p "$dir"
    local log="$dir/targets.log"
    if DUMP_TARGET_LOG="$log" STUB_PGDUMP=ok STUB_PGRESTORE=ok run_backup "$dir"; then :; else
        fail "success: backup.sh exited non-zero"; return
    fi
    check_eq "$(count_final "$dir")" "1" "success: exactly one final *.dump"
    check_eq "$(count_temp "$dir")" "0" "success: no temp artifact left"
    local dump; dump="$(find "$dir" -maxdepth 1 -name '*.dump')"
    case "$dump" in
        */testdb-*.dump) pass "success: final name matches convention" ;;
        *) fail "success: unexpected final name '$dump'" ;;
    esac
    check_eq "$(stat -c '%a' "$dump")" "600" "success: final dump mode 0600"
    # The path pg_dump wrote to must NOT be a *.dump file.
    local target; target="$(cat "$log")"
    case "$target" in
        *.dump) fail "success: pg_dump wrote to a *.dump path ($target)" ;;
        *) pass "success: in-progress path is not *.dump" ;;
    esac
}

# --- 2. pg_dump writes then fails: no final dump, temp cleaned --------------
test_dump_write_then_fail() {
    local dir="$WORK/dump_partial"; mkdir -p "$dir"
    if STUB_PGDUMP=write_then_fail STUB_PGRESTORE=ok run_backup "$dir"; then
        fail "partial-dump: backup.sh should have failed"; return
    fi
    check_eq "$(count_final "$dir")" "0" "partial-dump: no final *.dump published"
    check_eq "$(count_temp "$dir")" "0" "partial-dump: temp cleaned up"
}

# --- 3. pg_dump fails without writing: no final dump ------------------------
test_dump_fail_no_write() {
    local dir="$WORK/dump_nowrite"; mkdir -p "$dir"
    if STUB_PGDUMP=fail_no_write STUB_PGRESTORE=ok run_backup "$dir"; then
        fail "nowrite-dump: backup.sh should have failed"; return
    fi
    check_eq "$(count_final "$dir")" "0" "nowrite-dump: no final *.dump published"
    check_eq "$(count_temp "$dir")" "0" "nowrite-dump: temp cleaned up"
}

# --- 4. validation failure: no final dump, temp cleaned --------------------
test_validation_fail() {
    local dir="$WORK/validate_fail"; mkdir -p "$dir"
    if STUB_PGDUMP=ok STUB_PGRESTORE=fail run_backup "$dir"; then
        fail "validation: backup.sh should have failed"; return
    fi
    check_eq "$(count_final "$dir")" "0" "validation: no final *.dump published"
    check_eq "$(count_temp "$dir")" "0" "validation: temp cleaned up"
}

# --- 5. retention deletes old final dumps but never temp/staging files ------
test_retention_scope() {
    local dir="$WORK/retention"; mkdir -p "$dir"
    # An old FINAL dump (41 days) must be pruned.
    local old="$dir/testdb-20200101000000.dump"
    : > "$old"; touch -d "41 days ago" "$old"
    # A stale temp-looking staging file (old mtime) must SURVIVE — it is not a
    # restorable backup and must never be selected or pruned as one.
    local stale_tmp="$dir/.testdb-20200101000000.dump.tmp.9999"
    : > "$stale_tmp"; touch -d "41 days ago" "$stale_tmp"

    if STUB_PGDUMP=ok STUB_PGRESTORE=ok run_backup "$dir"; then :; else
        fail "retention: backup.sh exited non-zero"; return
    fi
    check_absent "$old" "retention: old final *.dump pruned"
    check_exists "$stale_tmp" "retention: temp/staging file not treated as backup"
    # The fresh backup published this run must still be present.
    local fresh
    fresh="$(find "$dir" -maxdepth 1 -name 'testdb-*.dump' ! -name 'testdb-20200101000000.dump')"
    if [ -n "$fresh" ]; then pass "retention: new backup published alongside pruning"
    else fail "retention: new backup missing"; fi
}

echo "PRA-263 backup atomic-publish tests"
test_success
test_dump_write_then_fail
test_dump_fail_no_write
test_validation_fail
test_retention_scope

echo
if [ "$FAILURES" -eq 0 ]; then
    echo "ALL PASS"
else
    echo "$FAILURES CHECK(S) FAILED"
    exit 1
fi
