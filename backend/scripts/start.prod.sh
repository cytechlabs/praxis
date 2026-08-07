#!/bin/bash
# Production entrypoint. Differences vs start.sh:
# - No --reload (uvicorn --workers instead)
# - Workers count comes from UVICORN_WORKERS (default 1). The 1.0 supported
#   production model is a SINGLE backend worker while browser interactive SSH
#   sessions are enabled: the session runtime is process-local, so multiple
#   workers can route the WebSocket attach to a worker that did not open the
#   session. assert_session_worker_safety.sh below enforces this before boot
#   (override only via ALLOW_UNSAFE_MULTIWORKER_SESSIONS=1, which is unsupported
#   for interactive sessions).
# - No seed_data / populate_command_whitelist in the hot path — those
#   should be run as one-shot jobs at deploy time, but we keep them here
#   for first-boot convenience; they're idempotent.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# PRA-265: load /app/.env as DATA, never as shell. load_dotenv.py parses the file
# with python-dotenv and re-execs this script with the values merged into the
# environment, so a value like DATABASE_URL=$(touch /tmp/pwned) is exported
# literally instead of executed at boot. The guard prevents an exec loop.
if [ -f /app/.env ] && [ -z "${PRAXIS_DOTENV_LOADED:-}" ]; then
  export PRAXIS_DOTENV_LOADED=1
  exec python "${SCRIPT_DIR}/load_dotenv.py" /app/.env -- bash "$0" "$@"
fi

echo "Waiting for database to be ready..."
until python -c "
import psycopg2, os
try:
    conn = psycopg2.connect(os.environ['DATABASE_URL'])
    conn.close()
    print('Database ready')
except Exception as e:
    print(f'Waiting... {e}')
    exit(1)
" 2>&1; do
  sleep 1
done

echo "Running database migrations..."
alembic upgrade head

echo "Seeding initial data..."
python /app/scripts/seed_data.py

echo "Checking for admin user..."
python /app/scripts/create_admin_user.py

echo "Populating command whitelist baseline..."
python /app/scripts/populate_command_whitelist.py

INTERNAL_VAULT_URL="http://vault:8200"
USING_EXTERNAL_VAULT="false"
if [ -n "$VAULT_ADDR" ] && [ "$VAULT_ADDR" != "$INTERNAL_VAULT_URL" ]; then
  USING_EXTERNAL_VAULT="true"
fi

if [ -n "$VAULT_TOKEN" ]; then
  echo "Vault token provided via environment"
elif [ "$USING_EXTERNAL_VAULT" = "true" ]; then
  echo "WARNING: External VAULT_ADDR set ($VAULT_ADDR) but no VAULT_TOKEN. Credential operations will fail."
elif [ -f /vault/data/backend-token ]; then
  export VAULT_TOKEN=$(cat /vault/data/backend-token)
  echo "Vault token loaded from embedded Vault"
else
  echo "WARNING: No Vault token available. Credential operations will fail."
fi

echo "Configuring Vault connection..."
python /app/scripts/setup_vault.py

echo "Seeding default SSH security policy..."
python /app/scripts/seed_ssh_security_policy.py

WORKERS="${UVICORN_WORKERS:-1}"
# PRA-233: fail fast if configured for multiple workers while the interactive
# SSH session runtime is process-local (single-worker is the 1.0 invariant).
# Invoked via `bash` so it works even if the executable bit is dropped.
bash "${SCRIPT_DIR}/assert_session_worker_safety.sh"
# PRA-226 AUTH-05: only trust X-Forwarded-For / X-Forwarded-Proto from a known
# reverse proxy. Trusting every forwarded IP (the old wildcard default) let any
# direct peer spoof the client IP, poisoning rate-limit identity
# (app.core.rate_limit) and every audit actor_ip (which read the
# uvicorn-resolved request.client.host). Default to loopback — safe, because
# forwarded headers are then ignored for any real network peer. Operators
# terminating TLS at a separate proxy set FORWARDED_ALLOW_IPS to that proxy's
# address/subnet so real client IPs are trusted again.
FORWARDED_ALLOW_IPS="${FORWARDED_ALLOW_IPS:-127.0.0.1}"
echo "Starting FastAPI (production) with ${WORKERS} workers (trusted proxy IPs: ${FORWARDED_ALLOW_IPS})..."
exec uvicorn app.api.main:app \
  --host 0.0.0.0 --port 8000 \
  --workers "${WORKERS}" \
  --proxy-headers --forwarded-allow-ips="${FORWARDED_ALLOW_IPS}" \
  --no-access-log
