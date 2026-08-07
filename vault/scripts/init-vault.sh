#!/bin/sh
set -e

# ---------------------------------------------------------------------------
# PRA-241: keep Vault OPERATOR RECOVERY material (root token + unseal keys) OUT
# of the application-readable runtime volume.
#
# /vault/data is mounted read-only into backend + agent-broker, so anything
# written there is app-readable. Recovery material must NOT be: it goes to
# PRAXIS_VAULT_RECOVERY_DIR (default /vault/recovery), backed by a volume mounted
# ONLY into the Vault container. Only scoped service credentials (backend-token)
# and public cert/CA material (ssh-ca-public-key, agent-ca-cert.pem, broker/*)
# stay in /vault/data. Secrets are written with a restrictive umask and never
# echoed.
# ---------------------------------------------------------------------------
RECOVERY_DIR="${PRAXIS_VAULT_RECOVERY_DIR:-/vault/recovery}"
mkdir -p "$RECOVERY_DIR"
chmod 700 "$RECOVERY_DIR" 2>/dev/null || true
INIT_KEYS_FILE="$RECOVERY_DIR/init-keys.json"
ROOT_TOKEN_FILE="$RECOVERY_DIR/root-token"

# Migrate legacy recovery material off the app-readable /vault/data volume.
# Older stacks wrote root-token / init-keys.json into /vault/data (mounted into
# backend + broker); move them into the operator-only recovery dir and delete the
# app-readable copy. Same-container copy, restrictive umask, no secret echoed.
for _legacy in init-keys.json root-token; do
  if [ -f "/vault/data/$_legacy" ]; then
    if [ ! -f "$RECOVERY_DIR/$_legacy" ]; then
      ( umask 077; cat "/vault/data/$_legacy" > "$RECOVERY_DIR/$_legacy" )
    fi
    rm -f "/vault/data/$_legacy"
    echo "Migrated legacy /vault/data/$_legacy into the operator recovery dir."
  fi
done

# Check if Vault is already initialized.
#
# PRA-248: read `bao status` explicitly via the sourced helper so an
# initialized-but-sealed Vault (rc 2) — a normal restart state — cannot trip
# `set -e` and short-circuit the script before the unseal branch below. The
# helper accepts only rc 0 (unsealed) and rc 2 (sealed) as parseable status
# responses and fails closed on any other rc, non-JSON output, or a
# missing/invalid `.initialized` field. `|| exit 1` handles the fail-closed exit
# without disabling `set -e`.
STATUS_LIB="$(dirname "$0")/vault-status.sh"
[ -f "$STATUS_LIB" ] || STATUS_LIB=/vault/scripts/vault-status.sh
# shellcheck source=vault/scripts/vault-status.sh
. "$STATUS_LIB"
INITIALIZED=$(vault_initialized_state) || exit 1

if [ "$INITIALIZED" = "false" ]; then
  echo "Initializing Vault..."

  # Initialize Vault and capture the output
  INIT_OUTPUT=$(bao operator init -format=json)

  # Recovery material -> operator-only recovery dir (NOT /vault/data), restrictive
  # perms, never echoed. printf (not echo) so escaped JSON is written verbatim.
  ( umask 077; printf '%s\n' "$INIT_OUTPUT" > "$INIT_KEYS_FILE" )
  ( umask 077; printf '%s\n' "$INIT_OUTPUT" | jq -r '.root_token' > "$ROOT_TOKEN_FILE" )

  # Extract unseal keys
  UNSEAL_KEYS=$(printf '%s\n' "$INIT_OUTPUT" | jq -r '.unseal_keys_b64[]')

  # Unseal Vault using the keys
  echo "Unsealing Vault..."
  echo "$UNSEAL_KEYS" | while read -r key; do
    bao operator unseal "$key"
  done

  # Login with root token (read from the operator recovery dir)
  ROOT_TOKEN=$(cat "$ROOT_TOKEN_FILE")
  bao login "$ROOT_TOKEN"

  # Enable KV secrets engine version 2
  echo "Enabling KV secrets engine..."
  bao secrets enable -path=praxis kv-v2

  # PRA-44: Enable SSH secrets engine as a CA
  echo "Enabling SSH secrets engine..."
  bao secrets enable -path=ssh-client-signer ssh

  # Generate a signing CA keypair (Vault keeps the private key internal)
  echo "Generating SSH CA keypair..."
  bao write -field=public_key ssh-client-signer/config/ca generate_signing_key=true \
    > /vault/data/ssh-ca-public-key

  # Create a praxis-user role for signing short-lived user certs.
  # allow_user_certificates: sign user certs (not host certs).
  # allowed_users="*": signer decides principal per request (Praxis enforces via settings).
  # default_extensions enables permit-pty for interactive shell; others are omitted
  # for least-privilege. TTL values are upper bounds — per-call TTL from Vault request.
  echo "Creating praxis-user SSH signing role..."
  # algorithm_signer=rsa-sha2-256: Vault's default for an RSA CA key is
  # ssh-rsa (RSA/SHA-1). Modern OpenSSH (8.2+ CASignatureAlgorithms) and
  # RHEL/Alma system crypto-policies reject SHA-1 cert signatures, so the
  # signed user cert fails publickey auth on those hosts. Force SHA-2.
  bao write ssh-client-signer/roles/praxis-user - <<EOF
{
  "key_type": "ca",
  "algorithm_signer": "rsa-sha2-256",
  "allow_user_certificates": true,
  "allowed_users": "*",
  "allow_user_key_ids": true,
  "allowed_extensions": "permit-pty,permit-user-rc",
  "default_extensions": {"permit-pty": ""},
  "default_user": "",
  "ttl": "30m",
  "max_ttl": "1h"
}
EOF

  # Create a policy for the backend service (KV + SSH signing).
  # PRA-150 agent PKI paths are added by ensure_agent_pki below so existing
  # Vault volumes pick them up on the next start.
  echo "Creating backend service policy..."
  cat > /tmp/backend-policy.hcl << EOF
path "praxis/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# PRA-44: SSH CA operations
path "ssh-client-signer/config/ca" {
  capabilities = ["read"]
}
path "ssh-client-signer/sign/praxis-user" {
  capabilities = ["create", "update"]
}
path "ssh-client-signer/roles/praxis-user" {
  capabilities = ["read"]
}
EOF

  bao policy write backend-service /tmp/backend-policy.hcl

  # Create a token for the backend service
  echo "Creating backend service token..."
  BACKEND_TOKEN=$(bao token create -policy=backend-service -format=json | jq -r '.auth.client_token')
  echo "$BACKEND_TOKEN" > /vault/data/backend-token

  echo "Vault initialization complete!"
else
  echo "Vault is already initialized. Unsealing..."

  # Extract unseal keys from the operator recovery dir (not app-readable).
  if [ -f "$INIT_KEYS_FILE" ]; then
    UNSEAL_KEYS=$(jq -r '.unseal_keys_b64[]' "$INIT_KEYS_FILE")

    # Unseal Vault using the keys
    echo "$UNSEAL_KEYS" | while read -r key; do
      bao operator unseal "$key"
    done

    echo "Vault unsealed successfully!"
  else
    echo "Error: Unseal keys file not found in recovery dir ($INIT_KEYS_FILE)!"
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
# PRA-150: Ensure agent PKI mount + role + policy paths exist. Idempotent so
# existing Vault volumes get the agent CA on next start without losing any
# previously issued state.
# ---------------------------------------------------------------------------

# PRA-241: the root token used for idempotent restart provisioning lives in the
# operator recovery dir (never in the app-readable /vault/data mount). Bundled
# Vault deliberately RETAINS it there so each start can re-ensure the KV/SSH/
# agent/broker PKI wiring on upgrades; it is confined to the vault-only recovery
# volume with restrictive perms. Production should use external Vault + auto-unseal
# (see docs/security-model.md) so no long-lived root token is stored at all.
if [ ! -f "$ROOT_TOKEN_FILE" ]; then
  echo "Skipping agent PKI setup: root token not present in recovery dir."
  exit 0
fi

bao login "$(cat "$ROOT_TOKEN_FILE")" >/dev/null

# ---------------------------------------------------------------------------
# Ensure the praxis-user SSH signing role signs with rsa-sha2-256 rather than
# the Vault default ssh-rsa (RSA/SHA-1). Idempotent role overwrite so existing
# volumes get the SHA-2 signer on next start WITHOUT rotating the CA keypair —
# no previously deployed ca_trust is invalidated. Only touched if the SSH mount
# exists (skips gracefully on stacks that never enabled the CA).
# ---------------------------------------------------------------------------
if bao secrets list -format=json | jq -e '."ssh-client-signer/"' >/dev/null 2>&1; then
  echo "Ensuring praxis-user SSH role uses rsa-sha2-256..."
  bao write ssh-client-signer/roles/praxis-user - <<EOF
{
  "key_type": "ca",
  "algorithm_signer": "rsa-sha2-256",
  "allow_user_certificates": true,
  "allowed_users": "*",
  "allow_user_key_ids": true,
  "allowed_extensions": "permit-pty,permit-user-rc",
  "default_extensions": {"permit-pty": ""},
  "default_user": "",
  "ttl": "30m",
  "max_ttl": "1h"
}
EOF
else
  echo "SSH CA mount not present; skipping praxis-user role ensure."
fi

if bao secrets list -format=json | jq -e '."praxis-agent-ca/"' >/dev/null 2>&1; then
  echo "Agent PKI mount already present."
else
  echo "Enabling agent PKI mount..."
  bao secrets enable -path=praxis-agent-ca pki
fi

# Tune is idempotent.
bao secrets tune -max-lease-ttl=43800h praxis-agent-ca >/dev/null

if bao read praxis-agent-ca/cert/ca >/dev/null 2>&1; then
  echo "Agent CA root already generated."
else
  echo "Generating agent CA root..."
  bao write -field=certificate praxis-agent-ca/root/generate/internal \
    common_name="Praxis Agent CA" \
    issuer_name="praxis-agent-root" \
    ttl=43800h \
    > /vault/data/agent-ca-cert.pem
fi

# Role write is idempotent (overwrites).
echo "Ensuring agent role..."
bao write praxis-agent-ca/roles/agent \
  allowed_domains="agent.praxis.internal" \
  allow_subdomains=true \
  allow_any_name=false \
  allow_bare_domains=false \
  allow_glob_domains=false \
  allow_wildcard_certificates=false \
  allow_ip_sans=false \
  allow_localhost=false \
  use_csr_common_name=false \
  use_csr_sans=false \
  enforce_hostnames=true \
  allowed_uri_sans="praxis://system/*" \
  client_flag=true \
  server_flag=false \
  key_type=ec \
  key_bits=256 \
  ttl=1h \
  max_ttl=1h \
  no_store=false >/dev/null

# Refresh the backend-service policy to include agent PKI paths. Token
# already issued from this policy picks up the change on its next request,
# so existing dev stacks don't need a token rotation.
echo "Ensuring backend-service policy includes agent PKI..."
cat > /tmp/backend-policy.hcl << EOF
path "praxis/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# PRA-44: SSH CA operations
path "ssh-client-signer/config/ca" {
  capabilities = ["read"]
}
path "ssh-client-signer/sign/praxis-user" {
  capabilities = ["create", "update"]
}
path "ssh-client-signer/roles/praxis-user" {
  capabilities = ["read"]
}

# PRA-150: Agent CA operations
path "praxis-agent-ca/cert/ca" {
  capabilities = ["read"]
}
path "praxis-agent-ca/sign/agent" {
  capabilities = ["create", "update"]
}
path "praxis-agent-ca/roles/agent" {
  capabilities = ["read"]
}

# PRA-151 task #19: Broker CA operations
path "praxis-broker-ca/cert/ca" {
  capabilities = ["read"]
}
path "praxis-broker-ca/issue/server" {
  capabilities = ["create", "update"]
}
path "praxis-broker-ca/roles/server" {
  capabilities = ["read"]
}
EOF

bao policy write backend-service /tmp/backend-policy.hcl >/dev/null
echo "Agent PKI ensured."

# ---------------------------------------------------------------------------
# PRA-151 task #19: Broker server cert issuance.
#
# Provisions praxis-broker-ca + a 'server' role + a long-lived server
# cert at /vault/data/broker/{server.crt, server.key, ca.crt}. Idempotent
# so existing volumes pick up the wiring without losing prior state.
#
# Operator overrides via PRAXIS_BROKER_TLS_{CERT,KEY,CA_CLIENT} +
# PRAXIS_BROKER_CA_CERT take precedence in app.broker.main; this block
# only handles the bundled-Vault default.
# ---------------------------------------------------------------------------

PRAXIS_BROKER_HOSTNAMES="${PRAXIS_BROKER_HOSTNAMES:-localhost,backend,127.0.0.1,agent-broker}"

if bao secrets list -format=json | jq -e '."praxis-broker-ca/"' >/dev/null 2>&1; then
  echo "Broker PKI mount already present."
else
  echo "Enabling broker PKI mount..."
  bao secrets enable -path=praxis-broker-ca pki
fi

bao secrets tune -max-lease-ttl=43800h praxis-broker-ca >/dev/null

if bao read praxis-broker-ca/cert/ca >/dev/null 2>&1; then
  echo "Broker CA root already generated."
else
  echo "Generating broker CA root..."
  mkdir -p /vault/data/broker
  bao write -field=certificate praxis-broker-ca/root/generate/internal \
    common_name="Praxis Broker CA" \
    issuer_name="praxis-broker-root" \
    ttl=43800h \
    > /vault/data/broker/ca.crt
fi

# Server role: 1y TTL, locked to operator-supplied hostnames. Allows IP
# SANs so dev configs with 127.0.0.1 work; allow_localhost on for the
# same reason. Backend owns the cert identity (use_csr_*=false).
echo "Ensuring broker server role (allowed_domains=${PRAXIS_BROKER_HOSTNAMES})..."
bao write praxis-broker-ca/roles/server \
  allowed_domains="${PRAXIS_BROKER_HOSTNAMES}" \
  allow_subdomains=false \
  allow_any_name=false \
  allow_bare_domains=true \
  allow_glob_domains=false \
  allow_wildcard_certificates=false \
  allow_ip_sans=true \
  allow_localhost=true \
  use_csr_common_name=false \
  use_csr_sans=false \
  enforce_hostnames=false \
  client_flag=false \
  server_flag=true \
  key_type=ec \
  key_bits=256 \
  ttl=8760h \
  max_ttl=8760h \
  no_store=false >/dev/null

# PRA-247: (re)issue the broker server cert when it is missing, unparseable,
# cert/key-mismatched, untrusted, expired, within the renewal threshold, or
# SAN-drifted — replacing prior "issue once, then skip forever" which let an
# expired bundled cert linger and break agent TLS. The sourced helper does
# expiry-aware renewal, cert/key + chain validation, atomic temp-file+rename
# replacement (so a failed issue never partially overwrites working files), and
# ownership/mode normalization every run. No privileged cross-container restart is
# performed from Vault; agent-broker must be restarted to load renewed files if it
# is already running (the helper logs this).
#
# Fail-closed: provision_broker_tls returns nonzero when a (re)issue is required
# but fails AND no usable TLS material is left on disk (e.g. first-time provision).
# Because this script runs under `set -e`, that nonzero halts init-vault.sh, which
# startup.sh turns into a Vault container exit + crash-loop rather than a "healthy"
# Vault with no broker TLS. A failed proactive renewal that still has a valid cert
# on disk is non-fatal (kept + retried next start).
BROKER_TLS_LIB="$(dirname "$0")/broker-tls.sh"
[ -f "$BROKER_TLS_LIB" ] || BROKER_TLS_LIB=/vault/scripts/broker-tls.sh
# shellcheck source=vault/scripts/broker-tls.sh
. "$BROKER_TLS_LIB"
provision_broker_tls /vault/data/broker

echo "Broker PKI ensured."
