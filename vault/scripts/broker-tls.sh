#!/bin/sh
# Bundled broker TLS certificate lifecycle (PRA-247).
#
# Sourced by init-vault.sh. Defines functions only — NO side effects at source
# time — so the logic is unit-testable with real OpenSSL fixtures and a fake
# `vault`.
#
# The bundled broker server cert at /vault/data/broker/{server.crt,server.key,
# ca.crt} is issued by the Vault praxis-broker-ca. The old behavior issued once
# and then skipped forever, so an EXPIRED cert could sit in place and break agent
# TLS. These helpers make the path expiry-aware and safe: they (re)issue when the
# material is missing, unparseable, cert/key-mismatched, untrusted (bad chain),
# expired, within the renewal threshold, or SAN-drifted; replacements are written
# to temp files, validated, then atomically renamed into place so a failed issue
# never partially overwrites working files.
#
# Renewal threshold: renew when fewer than PRAXIS_BROKER_RENEW_THRESHOLD_SECONDS
# of validity remain (default 30 days). The cert TTL is 1 year (issued below), so
# the default gives an ~11-month steady state with a month of runway.
#
# Operator overrides (PRAXIS_BROKER_TLS_{CERT,KEY,CA_CLIENT}, PRAXIS_BROKER_CA_CERT
# in app broker config) are unchanged — this only manages the bundled-Vault files.

# Normalized (sorted, unique) SAN list expected for the broker cert.
broker_expected_sans() {
    echo "${PRAXIS_BROKER_HOSTNAMES},127.0.0.1" | tr ',' '\n' | sort -u | paste -sd, -
}

# Normalized SAN list actually present in the cert at $1.
broker_cert_sans() {
    openssl x509 -in "$1" -noout -ext subjectAltName 2>/dev/null \
        | tr ',' '\n' | sed -E 's/^ *(DNS|IP Address):/\1:/' \
        | grep -E '^(DNS|IP Address):' | sed -E 's/^(DNS|IP Address)://' \
        | sort -u | paste -sd, -
}

# Return 0 only if (crt $1, key $2, ca $3) is a usable trio: all present and
# non-empty, cert + key parse, the key matches the cert, and the cert verifies
# against the CA. Any failure -> nonzero (fail closed).
broker_validate_material() {
    _crt="$1"; _key="$2"; _ca="$3"
    [ -s "$_crt" ] && [ -s "$_key" ] && [ -s "$_ca" ] || return 1
    openssl x509 -in "$_crt" -noout >/dev/null 2>&1 || return 1
    openssl pkey -in "$_key" -noout >/dev/null 2>&1 || return 1
    _cpub=$(openssl x509 -in "$_crt" -noout -pubkey 2>/dev/null | openssl dgst -sha256 2>/dev/null)
    _kpub=$(openssl pkey -in "$_key" -pubout 2>/dev/null | openssl dgst -sha256 2>/dev/null)
    [ -n "$_cpub" ] && [ "$_cpub" = "$_kpub" ] || return 1
    openssl verify -CAfile "$_ca" "$_crt" >/dev/null 2>&1 || return 1
    return 0
}

# Print a reason and return 0 when the material at (crt $1, key $2, ca $3) should
# be (re)issued; return 1 to keep it.
broker_needs_issue() {
    _crt="$1"; _key="$2"; _ca="$3"
    _thr="${PRAXIS_BROKER_RENEW_THRESHOLD_SECONDS:-2592000}"
    if ! broker_validate_material "$_crt" "$_key" "$_ca"; then
        echo "missing, unparseable, cert/key-mismatched, or untrusted material"
        return 0
    fi
    # -checkend N: exit 0 if the cert is valid for at least N more seconds; nonzero
    # if it is expired or will expire within N -> renew.
    if ! openssl x509 -in "$_crt" -noout -checkend "$_thr" >/dev/null 2>&1; then
        echo "expired or within ${_thr}s renewal threshold"
        return 0
    fi
    if [ "$(broker_cert_sans "$_crt")" != "$(broker_expected_sans)" ]; then
        echo "SAN drift vs PRAXIS_BROKER_HOSTNAMES"
        return 0
    fi
    return 1
}

# Issue a fresh server cert from Vault into temp files in $1, validate it, then
# atomically rename into place. On ANY failure, existing files are left intact and
# the return is nonzero. Requires the praxis-broker-ca mount + server role to
# already exist (init-vault.sh provisions those before calling this).
broker_issue_cert() {
    _dir="$1"
    _cn=$(echo "${PRAXIS_BROKER_HOSTNAMES}" | cut -d',' -f1)
    mkdir -p "$_dir"
    _tc="$_dir/server.crt.new"
    _tk="$_dir/server.key.new"
    _ta="$_dir/ca.crt.new"
    rm -f "$_tc" "$_tk" "$_ta"

    _resp=$(bao write -format=json praxis-broker-ca/issue/server \
        common_name="${_cn}" \
        alt_names="${PRAXIS_BROKER_HOSTNAMES}" \
        ip_sans="127.0.0.1" \
        ttl=8760h 2>/dev/null)
    if [ -z "$_resp" ]; then
        echo "broker: Vault issue call failed" >&2
        return 1
    fi

    # Restrictive perms on the freshly written temp files (private key material).
    # Use printf, not echo: the JSON carries backslash-escaped newlines in the PEM
    # values and some shells' `echo` would mangle them before jq.
    ( umask 077
      printf '%s\n' "$_resp" | jq -r '.data.certificate' > "$_tc"
      printf '%s\n' "$_resp" | jq -r '.data.private_key' > "$_tk"
      printf '%s\n' "$_resp" | jq -r '.data.issuing_ca'  > "$_ta" )

    if ! broker_validate_material "$_tc" "$_tk" "$_ta"; then
        rm -f "$_tc" "$_tk" "$_ta"
        echo "broker: newly issued material failed validation; keeping existing files" >&2
        return 1
    fi

    # Atomic in-place replacement (same-dir rename == rename(2)).
    mv -f "$_tc" "$_dir/server.crt" \
        && mv -f "$_tk" "$_dir/server.key" \
        && mv -f "$_ta" "$_dir/ca.crt"
    _rc=$?
    rm -f "$_tc" "$_tk" "$_ta" 2>/dev/null
    return "$_rc"
}

# Return 0 iff the on-disk material is usable RIGHT NOW: a valid trio (parses,
# key matches cert, chain verifies) AND the cert is not already expired. Note this
# is stricter than "kept by broker_needs_issue": a near-expiry or SAN-drifted cert
# still counts as usable-now (it will serve TLS today) even though we want to renew
# it. Used to decide whether a FAILED (re)issue is fatal.
broker_material_usable_now() {
    _crt="$1"; _key="$2"; _ca="$3"
    broker_validate_material "$_crt" "$_key" "$_ca" || return 1
    # -checkend 0: nonzero iff already expired.
    openssl x509 -in "$_crt" -noout -checkend 0 >/dev/null 2>&1 || return 1
    return 0
}

# Normalize ownership + modes so the broker process (UID 1000) can read the files.
# Runs every start, regardless of whether a (re)issue happened.
broker_normalize_perms() {
    _dir="$1"
    if [ -f "$_dir/server.key" ] && [ -f "$_dir/server.crt" ] && [ -f "$_dir/ca.crt" ]; then
        chown 1000:1000 "$_dir/server.key" "$_dir/server.crt" "$_dir/ca.crt" 2>/dev/null || true
        chmod 600 "$_dir/server.key"
        chmod 644 "$_dir/server.crt" "$_dir/ca.crt"
    fi
}

# Full bundled-broker TLS provisioning: (re)issue if needed, then normalize perms.
# No privileged cross-container restart is attempted from Vault; if the broker is
# already running it must be restarted to pick up renewed files (logged below).
#
# Fail-closed contract (init-vault.sh calls this under `set -e`, so a nonzero
# return terminates Vault startup and the container crash-loops via Docker's
# restart policy):
#   - reissue not needed        -> keep, return 0
#   - reissue succeeds          -> return 0
#   - reissue fails BUT the on-disk cert is still usable now (a proactive
#     near-expiry / SAN-drift renewal) -> warn, keep the working cert, return 0.
#     A transient Vault outage must not crash-loop the whole stack while the broker
#     still has weeks of valid TLS; the next start retries.
#   - reissue fails AND there is no usable TLS on disk (missing / unparseable /
#     mismatched / untrusted / expired) -> return NONZERO so startup fails closed
#     rather than reporting success with no broker TLS material.
provision_broker_tls() {
    _dir="$1"
    _crt="$_dir/server.crt"; _key="$_dir/server.key"; _ca="$_dir/ca.crt"
    if _reason=$(broker_needs_issue "$_crt" "$_key" "$_ca"); then
        echo "Broker server cert: (re)issuing (reason: ${_reason})..."
        if broker_issue_cert "$_dir"; then
            echo "Broker server cert issued and validated."
            echo "NOTE: if agent-broker is already running, restart it to load the renewed cert (docker compose restart agent-broker)." >&2
            broker_normalize_perms "$_dir"
            return 0
        fi
        # Issue failed; broker_issue_cert left any prior files intact. Normalize
        # perms on whatever is on disk, then decide fatality on whether we still
        # have usable TLS.
        broker_normalize_perms "$_dir"
        if broker_material_usable_now "$_crt" "$_key" "$_ca"; then
            echo "WARNING: broker server cert (re)issue failed; existing cert is still valid and will be kept. Retrying on next start." >&2
            return 0
        fi
        echo "ERROR: broker server cert (re)issue failed and no usable TLS material is present; failing closed." >&2
        return 1
    fi
    echo "Broker server cert valid, trusted, and not near expiry; keeping existing files."
    broker_normalize_perms "$_dir"
    return 0
}
