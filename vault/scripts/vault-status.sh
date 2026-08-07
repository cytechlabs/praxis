#!/bin/sh
# Bundled secrets-runtime status helper (PRA-248; OpenBao `bao` since PRA-311).
#
# Sourced by init-vault.sh. Defines a function only — NO side effects at source
# time — so it is unit-testable with a fake `bao` + `jq`.
#
# `bao status -format=json` is the documented, machine-readable status.
# Its exit code carries meaning: 0 = initialized AND unsealed, 2 = sealed, 1 =
# error / not-yet-reachable. An initialized-but-sealed Vault (rc 2) is a NORMAL
# restart state, but under `set -e` the old inline
# `INITIALIZED=$(bao status ... | jq ...)` risked short-circuiting the script
# before it reached the unseal branch (directly on some shells, or via a future
# `set -o pipefail`). This helper captures stdout + rc explicitly, accepts ONLY
# rc 0 and rc 2 as parseable status responses, and fails closed on anything else
# (unreachable Vault, non-JSON output, or a missing/invalid `.initialized` field).

# vault_initialized_state — print the Vault `.initialized` value ("true" or
# "false") on stdout and return 0, or print a clear (non-secret) error to stderr
# and return 1. Never prints the raw status body.
vault_initialized_state() {
    _rc=0
    _json=$(bao status -format=json 2>/dev/null) || _rc=$?
    case "$_rc" in
        0 | 2) ;; # 0 = unsealed, 2 = sealed — both are valid, parseable statuses
        *)
            echo "vault-status: 'bao status' failed (exit $_rc); Vault is unreachable or errored." >&2
            return 1
            ;;
    esac

    # -r prints the raw value; no -e, because a legitimate ".initialized": false
    # would make `jq -e` exit nonzero. A JSON parse error makes jq exit nonzero
    # (caught here); a missing key yields the literal "null" (caught below).
    _init=$(printf '%s\n' "$_json" | jq -r '.initialized' 2>/dev/null) || {
        echo "vault-status: could not parse 'bao status' JSON." >&2
        return 1
    }
    case "$_init" in
        true | false)
            printf '%s\n' "$_init"
            ;;
        *)
            echo "vault-status: 'bao status' JSON is missing a valid .initialized field." >&2
            return 1
            ;;
    esac
}
