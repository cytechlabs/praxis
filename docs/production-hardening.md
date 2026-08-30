---
title: Production hardening and operations
description: Supported deployment shapes, environment validation, secrets posture, and database migration practice.
---

This guide covers operating the Praxis **control plane** (Praxis itself) in
production: supported deployment shapes, fresh install, upgrade and migration
posture, backup/restore, Vault unseal and token rotation, environment
validation, the bundled-vs-external data-tier boundary, and the deployment
shapes that are explicitly out of scope for 1.0.

> **Managed-host platforms.** This document covers the **control-plane**
> deployment (Praxis itself). For the supported Linux distributions,
> package-manager families, and architectures of the **managed fleet**, see
> the [Linux Support Matrix](support-matrix.md).

## Scope

In scope:

- Fresh install from `docker compose` to first enrolled host.
- Upgrade from representative earlier database states through the current
  Alembic head.
- Backup/restore, including documented RPO/RTO assumptions.
- Vault unseal and token rotation guidance.
- Database migration review and rollback posture.
- Production environment validation and startup checks.
- The bundled-vs-external Postgres/Vault support boundary.

Out of scope for 1.0:

- Remote-host deployment automation (no Ansible/Terraform/SSH-to-prod
  flows are part of Praxis 1.0; operators run `docker compose` on the
  control-plane host themselves).
- Reboot/rollback of the control plane host OS.
- OpenSCAP execution against the control plane.
- Package-manager driven install (no `.deb`/`.rpm` for Praxis itself, only
  container images on GHCR).

## Supported Deployment Shapes

The repository supports exactly three production deployment shapes,
all driven from `docker-compose.yml` plus the `docker-compose.prod.yml`
overlay.

### 1. Bundled (default)

`COMPOSE_PROFILES=bundled` (the default in `.env.example`) brings up
PostgreSQL 15, OpenBao 2.6.1 (the bundled secrets runtime; a drop-in for
HashiCorp Vault, driven via the `bao` CLI), the `db_backup` cron sidecar,
the backend, frontend, broker, and Prometheus inside a two-tier docker
network (`frontend_net`, `backend_net`).

Reference: `docker-compose.yml`, `docker-compose.prod.yml`.

### 2. External Postgres **and** External Secrets Service

Remove `COMPOSE_PROFILES=bundled` from `.env` and set `DATABASE_URL`,
`VAULT_ADDR`, and `VAULT_TOKEN` to point at the operator's own
infrastructure (an external OpenBao or HashiCorp Vault, whose API is
compatible). The `db`, `vault`, and `db_backup` services are all
gated behind the same `bundled` profile, so disabling the profile
turns off all three at once: the supported external path is
**fully external** (operator-owned Postgres **and** operator-owned
secrets service). External Postgres + bundled secrets, or bundled
Postgres + external secrets, are **not** supported deployment shapes
because those mixes require operator-authored compose changes that
this repo does not ship or verify.

Reference: `docker-compose.yml` (profile gating on `db`, `vault`,
`db_backup`).

### 3. Bundled (or external) + Caddy reverse proxy

Adding `--profile proxy` to compose brings up Caddy on ports 80/443
with three TLS modes (`internal`, `acme`, `byo`) selected by
`PRAXIS_TLS_MODE`.

Browser ingress is intentional and goes through Caddy only. Under the
prod overlay the backend and frontend publish **no** direct host ports
(`ports: !override []`); they are reachable only over the
Docker networks that Caddy proxies to. This fails secure in Compose
itself, so a direct client cannot bypass Caddy or TLS, and `--profile proxy`
is required for the public browser path. Running the prod overlay
*without* `--profile proxy` yields a healthy but deliberately
unreachable stack (useful for headless smokes / API-over-network use,
not for browser access).

Reference: `docker-compose.prod.yml`, `caddy/Caddyfile`.

Deliberately unsupported shapes are consolidated under the
**Unsupported Deployment Shapes** section below; see there for the
operator-facing single-line rationales.

## Fresh Install Path

The published path (from `README.md`) is (`--profile proxy` starts Caddy, the
browser ingress, because backend and frontend publish no direct host ports; omit it only
for a headless / external-reverse-proxy deployment):

```bash
git clone https://github.com/cytechlabs/praxis.git
cd praxis
cp .env.example .env
# Edit .env: set SECRET_KEY, ADMIN_PASSWORD, and POSTGRES_PASSWORD
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    --profile bundled --profile proxy pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    --profile bundled --profile proxy up -d
```

Generate the required secrets by hand into `.env`, for example
`SECRET_KEY=$(openssl rand -hex 32)`, `POSTGRES_PASSWORD=$(openssl rand -hex 24)`,
plus a strong `ADMIN_PASSWORD`. None of these have a default; no password ships
in the source tree.

Where each one is enforced differs, and the distinction matters when reading
failures:

- `SECRET_KEY` is required by Compose interpolation. Nothing is created at all;
  `docker compose config`, `up`, and `pull` all abort.
- `POSTGRES_PASSWORD` is enforced at **startup**, not at interpolation.
  Requiring it in Compose would also force external-database deployments to
  define a variable they never use, because Compose evaluates every
  interpolation eagerly regardless of the active profile. Instead the stack
  renders and containers are created, then fail immediately: the bundled `db`
  entrypoint exits before the server accepts connections, the backend and
  broker exit during startup validation before binding a listener, and the
  backup sidecar exits before running `pg_dump`. Nothing serves traffic and no
  data is written on a credential-less bundled deployment.

`POSTGRES_PASSWORD` applies to **bundled mode only**. External-database
deployments supply their credentials inside `DATABASE_URL` and must leave
`POSTGRES_PASSWORD` unset; there is nothing to duplicate.

Keep `POSTGRES_PASSWORD` in the unreserved URL character set (letters, digits,
`- . _ ~`): it is embedded in a connection string, so `@ : / ? # [ ] %` break
the URL, and a literal `$` must be written `$$` to survive Compose
interpolation. Local development uses this same production-parity stack
(there is no separate dev runtime); the only difference from a release is
building from source (`up -d --build`) instead of pulling a pinned image.

What is verified today:

- From-scratch cold build + boot is gated by
  `scripts/test-cold-rebuild.sh`, which runs the canonical bundled
  production-parity stack (`docker-compose.yml` +
  `docker-compose.prod.yml`) through `down -v` → `build --no-cache` →
  `up -d` and waits for the backend `/health`. There is no separate dev
  runtime, so this gate builds and boots the SAME production images a
  release runs; the full pytest suite is covered by CI's backend-test
  lanes (and the local venv workflow), and the app-level auth round
  trip by the fresh-install smoke below.
- The production compose overlay bring-up is gated by
  `scripts/test-fresh-install-smoke.sh`. The smoke
  brings up `docker-compose.yml` + `docker-compose.prod.yml` +
  `scripts/fresh-install-smoke.override.yml` in an isolated compose
  project (`praxis-fresh-install-smoke`) under `--profile bundled`,
  generates ephemeral `SECRET_KEY` / `ADMIN_PASSWORD` /
  `POSTGRES_PASSWORD` to a `mktemp -d` env file (never to `.env`),
  builds the prod images locally, waits for backend `/health`, then
  drives an authenticated `/auth/login` + `/auth/me` read, an
  admin-RBAC-gated `/agent/activation-tokens` list, and the
  anonymous `/agent/bootstrap.sh` + `/agent/ca-bundle` routes. On
  success it tears its own project down; on failure it leaves the
  project up with logs.
- The first-enrolled-host redemption path is gated by
  `scripts/test-first-enrolled-host-smoke.sh`.
  The smoke seeds a synthetic credential + system via direct SQL
  against the smoke-owned db, mints an activation token via
  `POST /agent/activation-tokens`, spins up a disposable
  `ubuntu:22.04` container on the smoke project's `backend_net`
  acting as the dummy host, installs curl + openssl + jq (the
  same tools the committed `bootstrap.sh` lists as host prereqs),
  generates an EC P-256 keypair + CSR with openssl, fetches
  `/agent/ca-bundle`, and `POST`s `/agent/enroll` with the
  `X-Praxis-Activation-Token` header. The smoke asserts the
  response carries an x509 certificate, the original
  `system_id`, and `agent_status=active`, then re-reads the
  System row from Postgres to confirm `agent_status` flipped and
  `agent_cert_serial` is populated. Successful round-trip
  produces a Vault-signed agent cert and persists serial +
  fingerprint + expiry on the backing System row.

What this smoke does NOT cover (intentional boundary):

- `backend/app/api/routes/_assets/bootstrap.sh` end-to-end. The
  script hard-requires systemd (`systemctl required`) and a
  real `praxis-agent` Go binary from the pinned GitHub Release
  tag (`agent-v0.0.0-rc1`). Running it would either need a
  systemd-in-docker dummy host (privileged container) or a
  GitHub-Releases dependency in the smoke; both make the local
  drill slower and more brittle than the `/agent/enroll`
  redemption proof, which exercises the actual Praxis-specific
  surface (token redemption, Vault CSR signing, `System.agent_status`
  transition).
- The agent's mTLS handshake against the broker
  (`/agent/tunnel`). That path is orthogonal to "first-enrolled-host"
  semantics and would require the real agent binary.

What is documented but not verified end-to-end:

- The GHCR-pull form of the prod overlay path
  (`docker-compose.prod.yml` with `--profile bundled pull`) is
  documented in `README.md`. The fresh-install smoke exercises
  `--profile bundled up --build` (local build) rather than `pull`,
  so the pull path itself is not regressed against by CI today.
- The Caddy `--profile proxy` path with `acme` and `byo` TLS modes
  is documented in `README.md` but is not exercised by any CI job.

Gaps to close in later releases:

- The `--profile bundled pull` path could be added to a future
  optional smoke variant when a published `PRAXIS_VERSION` GHCR
  tag is the actual ship target. The fresh-install smoke already
  exercises the harder local-build path.
- Caddy `internal` / `byo` TLS modes could be added to a future
  smoke variant; `acme` requires live DNS and stays out of scope.

## Upgrade And Migration Posture

The migration story today:

- A single linear Alembic chain lives under
  `backend/alembic/versions/`. The earliest revision is
  `20260402_2146_240b0ad2f12f_initial_schema.py`; the most recent
  revision at the time this baseline was written is
  `20260520_0001_pra175_compliance_dispatch_details.py`. The
  current head should be confirmed with `alembic heads` rather than
  read from this doc, because every release adds revisions.
- `docker compose exec backend alembic upgrade head` applies migrations;
  `docker compose exec backend alembic downgrade -1` rolls back one. There is
  no scripted multi-revision rollback path.
- The dev cold-rebuild gate runs `init.sql` against a fresh Postgres
  and then runs `alembic upgrade head` implicitly through the backend
  startup path. This proves the migration chain reaches head **from
  empty**.
- The upgrade smoke at `scripts/test-upgrade-smoke.sh`
  proves the chain also converges on head from two representative
  earlier production-shaped states (revisions `pra149_review` and
  `pra156_lifecycle_notif_state`).
  Committed fixtures live under
  `backend/tests/fixtures/upgrade/pre_m13.sql` and `pre_m15.sql`;
  the script can regenerate them in place via
  `scripts/test-upgrade-smoke.sh --regenerate`.
- There is one repeating live-data gotcha: `init.sql` seeds rows with
  explicit ids (e.g. `groups.id=1`, `distros.id=1..5`,
  `credentials.id=1`) but does not advance the sequences. The
  cold-rebuild script papers over this with explicit `setval()` calls
  (see `scripts/test-cold-rebuild.sh`); a fresh prod install hitting
  Alembic-only schema creation will not have this problem, but any
  operator who relies on `init.sql` for seed data outside the bundled
  compose will. This belongs in the install runbook.

What is verified today:

- Migration from two representative earlier database snapshots
  (revisions `pra149_review` and `pra156_lifecycle_notif_state`)
  through the current head, including the thin-agent identity
  columns, the facts and lifecycle tables, and the mirror and
  content schema. Verification runs via
  `scripts/test-upgrade-smoke.sh` against committed fixtures; it
  is **not** in CI, for the same reason as the cold-rebuild gate: it is
  slow and hostile to parallel pytest.

What is unverified today:

- The upgrade smoke covers two representative boundaries but does
  not yet capture every operator-shaped intermediate state. If
  later milestones introduce destructive schema changes (column
  drops, table renames, data backfills), a new fixture at the
  matching boundary should be added via `--regenerate` and
  committed.
- No down-revision is verified beyond `alembic downgrade -1` working
  in principle. Down-revisions are not part of CI.

Migration-rollback posture for Praxis 1.0:

- Forward migrations are the supported path. The supported recovery
  story is **restore the dump that was taken before the upgrade**
  (see Backup/Restore Drill below), not "downgrade through Alembic".
- This is the rollback contract that should be made explicit in the
  install runbook in a later release.

## Backup / Restore Drill

`scripts/backup.sh`:

- Runs inside the `db_backup` alpine sidecar container under cron at
  `0 2 * * *` (02:00 daily, container time).
- Connects to the bundled `db` service over the docker network using
  `${POSTGRES_USER:-postgres}` and the deployment's required
  `POSTGRES_PASSWORD` (the script has no password fallback and exits with a
  named error if the sidecar receives none).
- Writes a custom-format pg_dump to a restrictive (0600) same-directory
  temp file that does **not** match `*.dump`, validates the completed
  dump with `pg_restore --list`, then atomically renames it to
  `/backups/${POSTGRES_DB}-YYYYMMDDHHMMSS.dump` on the `backup_data`
  named volume. A failed, interrupted, or validation-failed
  dump is cleaned up and never leaves a final-looking `.dump` that
  restore selection could pick.
- Retains backups for 30 days (`find ... -mtime +30 -exec rm`), scoped
  to final `*.dump` files only, so in-progress temp files never match.
- Has **no off-host destination**. The dump never leaves the docker
  host unless the operator copies it.

Restore path:

- Restore the newest dump with:
  ```bash
  docker compose exec db sh -c "ls -t /backups/*.dump | head -n 1 \
      | xargs -I {} pg_restore --verbose --clean --if-exists \
            -U postgres -d praxis {}"
  ```
- This picks the most recent dump, runs `pg_restore --clean
  --if-exists` against the live `praxis` database. There is no
  scripted point-in-time selection and no scripted post-restore
  verification. Backups are integrity-checked at creation time, because
  `backup.sh` validates each dump with `pg_restore --list` before
  publishing it, but the restore itself is not
  independently verified.

### Full-app-state encrypted bundle

`scripts/backup.sh` above covers **only PostgreSQL**. For full bundled-deployment
recovery, after operator error, host loss, or volume corruption, use the encrypted
**full-bundle** path, which wraps `scripts/backup.sh` and additionally captures
`vault_data`, `recordings_data`, `mirror_data`, and (opt-in) the `vault_recovery`
unseal keys, all encrypted under an operator passphrase with a checksummed manifest and
atomic publish:

- Back up:  `PRAXIS_BACKUP_PASSPHRASE=... scripts/backup-bundle.sh --include-recovery -o <off-host-staging>`
- Restore:  `PRAXIS_BACKUP_PASSPHRASE=... scripts/restore-bundle.sh --bundle <file> --env-file <.env>`
- Smoke:    `scripts/test-bundle-backup-restore-smoke.sh`

The bundle is created on the host; **moving it off-host is the operator's
responsibility** in 1.0. A working Vault restore needs the unseal keys (in the bundle
via `--include-recovery`, or supplied out of band). See
[docs/backup-restore.md](backup-restore.md) for the full contract, recovery-material
handling (the secrets-volume separation is preserved), required downtime, supported target shape,
and what is not covered in 1.0.

What is **not** backed up by `scripts/backup.sh` (the DB-only cron path; all of these
ARE covered by `scripts/backup-bundle.sh` above, except Caddy/Prometheus):

- The Vault `vault_data` **and** `vault_recovery` named volumes.
  `vault_data` (runtime material, mounted read-only into backend +
  agent-broker) holds the backend service token, the SSH CA public key,
  the agent CA certificate, the broker server cert/key, all KV secrets,
  and PKI lease metadata; the SSH CA private key and PKI roots stay
  inside Vault's own file storage on this volume. `vault_recovery`
  (operator-only, mounted **only** into the Vault container)
  holds the unseal-key file (`/vault/recovery/init-keys.json`) and the
  init root token (`/vault/recovery/root-token`). Losing either volume is
  fatal. See the Vault section.
- Caddy `caddy_data` / `caddy_config` (ACME account keys and issued
  certificates if `acme` mode is used).
- `recordings_data` (session recordings).
- `mirror_data` (mirrored repository content).

What is verified today:

- `scripts/test-backup-restore-smoke.sh` exercises
  the round trip end-to-end in an isolated compose project: insert a
  synthetic sentinel into `app_settings`, invoke `scripts/backup.sh`
  via the `db_backup` sidecar, assert the produced dump is
  non-empty, delete the sentinel, run
  `pg_restore --clean --if-exists` (the restore invocation above),
  assert the sentinel returned with its
  original value, and re-verify backend `/health`. Custom-format
  dumps are not grep-able as plain text; the round trip is what
  proves the dump's contents are restorable.

### Praxis 1.0 RPO / RTO contract (bundled mode)

- **RPO ≈ 24 hours.** `scripts/backup.sh` runs once a day at 02:00
  container time. Any writes between two cron runs are lost if the
  host disk dies and no off-host backup was taken between them.
- **RTO**: minutes to single-digit hours for the bundled
  small-deployment shape, depending on dump size, image
  availability, and operator involvement (the operator runs
  `pg_restore --clean --if-exists` against a fresh stack). The
  The backup/restore smoke completes the full restore round-trip in well
  under five minutes on a developer laptop; production sizes
  dominated by the application database scale linearly with the
  dump.
- **Praxis 1.0 produces the dump only on the shared
  `backup_data` Docker volume.** Copying the dump (and the
  `vault_data` / `vault_recovery` / `recordings_data` / `mirror_data`
  volumes, because `vault_recovery` holds the unseal keys needed to bring Vault
  back up) off-host is the operator's responsibility. The repo
  ships no off-host shipping automation.

### Fatal failure modes (operator must know)

- **Losing the most recent dump together with `vault_data` /
  `vault_recovery` is fatal** for the bundled deployment. `vault_data`
  holds the SSH CA private key, the agent and broker PKI roots, and all
  KV secrets; `vault_recovery` holds the unseal keys, without which the
  Vault on `vault_data` cannot be unsealed on the next restart. There is
  no recovery path from a Postgres dump alone. The supported recovery
  story is "restore all three from off-host backup," not "regenerate from
  migrations." Operators running the bundled shape must capture the DB
  dump, `vault_data`, **and** `vault_recovery` on the same off-host
  cadence.

### Backup correctness notes

The bundled backup path is wired so the deployment's `POSTGRES_PASSWORD` cannot
silently produce empty dumps:

- `docker-compose.yml`'s `db_backup` service declares `POSTGRES_USER` /
  `POSTGRES_PASSWORD` / `POSTGRES_DB` in its `environment:` block, reading the
  same required `POSTGRES_PASSWORD` the `db` service is provisioned with, so the
  sidecar and the database can never drift apart.
- `scripts/backup.sh` runs under `set -euo pipefail`, so a failed `pg_dump`
  propagates immediately instead of printing a "Backup completed" success
  message over a zero-byte file.

### Rotating the bundled PostgreSQL password

`POSTGRES_PASSWORD` provisions the superuser **only on first initialization of
an empty `postgres_data` volume**. On an existing deployment, changing it in
`.env` alone leaves the database with the old password and every service unable
to authenticate. Rotate inside the database first, then in `.env`. The volume is
preserved throughout; do not `down -v`.

Use `psql`'s interactive `\password`. It prompts twice, hashes the new password
client-side, and sends only the hash, so the cleartext never appears in `argv`,
in shell history, or in the server's statement log. Do not use
`ALTER USER ... WITH PASSWORD '<literal>'` for this. `exec db psql` reaches the
database over the container's local socket, so it connects regardless of which
password the volume currently holds.

```bash
# 1. Open an interactive psql session on the bundled database. Note `-it` and
#    no `-T`: the prompt needs a TTY.
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    --profile bundled exec -it db \
    psql -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-praxis}"

# 2. At the psql prompt, rotate and quit:
#        \password
#        (enter the new password twice, e.g. from `openssl rand -hex 24`
#         generated in a separate shell)
#        \q

# 3. Put the same value in .env (replace the POSTGRES_PASSWORD line).
#    Everything that connects reads it from there.

# 4. Recreate the services that hold a connection string. This restarts
#    containers only; named volumes, including postgres_data, are untouched.
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    --profile bundled --profile proxy up -d \
    backend agent-broker db_backup

# 5. Confirm the stack still authenticates.
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    --profile bundled exec -T backend python -c \
    "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=5).status == 200 else 1)"
```

Recovery ordering matters. Step 1 and step 3 must agree:

- **Steps 1-2 done, step 3 skipped**: the database holds the new password while
  `.env` still holds the old one. Backend, broker, and the nightly backup fail
  to authenticate. Fix by completing step 3.
- **Step 3 done, steps 1-2 skipped**: `.env` holds a password the database was
  never given. Same failure. Fix by running steps 1-2 with the value now in
  `.env`, or by restoring the previous value in `.env`.
- In both cases the data is untouched. Nothing here drops or reinitializes
  `postgres_data`.

Upgrading a deployment whose `postgres_data` volume was initialized with the
old built-in `postgres` password: rotate before starting the app tier. The `db`
entrypoint refuses to start on that value, and the backend and broker refuse to
serve on it. Because `POSTGRES_PASSWORD` is only read when an empty volume is
initialized, the database still holds the old password internally while you
bring it up with the new one:

```bash
# 1. Put the new password in .env, then start ONLY the database.
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    --profile bundled up -d db
# 2. Run steps 1-2 above so the stored password matches .env.
# 3. Start the rest of the stack normally.
```

## Secrets Service (OpenBao) Unseal And Token Rotation

The bundled secrets service is **OpenBao** (a Vault-compatible service); the `vault`
Docker service name and `/vault` paths are kept for compatibility, and the bundled
runbook commands below use the `bao` CLI inside that container. What ships today
(`vault/config/vault.hcl`, `vault/scripts/`):

- File storage at `/vault/data` on the `vault_data` named volume.
- Single-listener, **TLS disabled** on the listener (network is
  docker-internal `backend_net`; backend reaches Vault as
  `http://vault:8200`).
- `disable_mlock = true` (acceptable in a container, and documented as
  such by both OpenBao and HashiCorp Vault).
- Init script (`vault/scripts/init-vault.sh`) runs once: initializes
  Vault, writes `init-keys.json` and `root-token` to the operator-only
  recovery dir (`/vault/recovery`, the `vault_recovery` volume),
  unseals using the keys it just wrote, enables `kv-v2` at
  `praxis/`, enables the SSH CA at `ssh-client-signer`, enables the
  agent PKI at `praxis-agent-ca`, and enables the broker PKI at
  `praxis-broker-ca`. A scoped, long-lived backend service token is
  written to `/vault/data/backend-token` (runtime material).
- On every subsequent start, `startup.sh` re-runs `init-vault.sh`,
  which detects the already-initialized state and re-uses the saved
  `/vault/recovery/init-keys.json` to unseal. This is
  auto-unseal-by-disk-file: it makes the bundled stack restart cleanly
  without operator prompting. The unseal keys and root token
  live on `vault_recovery`, mounted only into the Vault container, so
  read access to the app-mounted `vault_data` volume (backend +
  agent-broker) yields only scoped service credentials and public cert
  material, never root or unseal material.

Token rotation today:

- The backend service token is created once at init and is **not**
  rotated by any timer or script.
- The Vault root token is created once at init and is **not**
  rotated.
- The agent PKI role and the broker server cert role are reconciled
  every start (`init-vault.sh` rewrites the roles idempotently).
- Broker server cert hostname drift triggers a loud warning but the
  cert is **not** auto-rotated; the operator must rm the cert files
  and restart the Vault container (documented in-line in
  `init-vault.sh`).

What is **not** documented and **not** scripted:

- Manual rekey procedure for `init-keys.json`. There is no operator
  workflow for "rotate unseal keys" or "rotate the root token" in
  this repo. The Vault docs cover it (`vault operator rekey`,
  `vault token revoke`) but applying it cleanly to the bundled
  `init-keys.json` workflow has not been written down here.
- Backend token rotation. There is no scripted "issue a new
  backend-service token, swap it onto the volume, restart backend"
  flow.
- Recovery procedure if `init-keys.json` is lost. This case is fatal
  for the data in that Vault, because there is no key escrow.

Bundled-vs-external Vault support boundary:

- **Bundled Vault is supported only as part of the fully-bundled
  deployment shape** (bundled Postgres + bundled Vault together).
  Operators who need HA, KMS-backed auto-unseal, audit log
  shipping, or compliance-grade key management should switch the
  entire data tier to the fully-external shape and bring their own
  Vault (and their own Postgres). Bundled Vault paired with
  external Postgres is not a supported 1.0 shape.
- The repo guarantees the bundled init script provisions the
  required mounts/roles for any Vault it controls; it does not
  guarantee any feature parity for external Vault beyond
  KV-v2 + the documented SSH/PKI roles being reachable under the
  same paths. External-Vault operators are responsible for
  provisioning `praxis/`, `ssh-client-signer/`, `praxis-agent-ca/`,
  and `praxis-broker-ca/` with the same role definitions found in
  `vault/scripts/init-vault.sh`.

### Bundled Vault: manual unseal-key rotation

The bundled Vault stores its unseal keys in
`/vault/recovery/init-keys.json` on the operator-only `vault_recovery`
volume (mounted only into the Vault container). The Vault
container reads them on every start to auto-unseal. Rotation is
**manual**; the repo ships no scheduled rekey job.

Procedure (operator runs these from the host):

```bash
# 1. Make sure the bundled stack is up and Vault is unsealed.
docker compose ps vault       # State: Up (healthy)

# 2. Take a fresh dump + copy the vault_data AND vault_recovery volumes
#    off-host BEFORE rotation. If rekey fails partway, you restore from
#    these (vault_recovery holds the current unseal keys).
docker compose exec db_backup /scripts/backup.sh
docker run --rm -v praxis_vault_data:/data -v "$PWD":/out alpine \
    tar czf /out/vault_data-pre-rekey-$(date -u +%Y%m%dT%H%M%SZ).tgz -C /data .
docker run --rm -v praxis_vault_recovery:/data -v "$PWD":/out alpine \
    tar czf /out/vault_recovery-pre-rekey-$(date -u +%Y%m%dT%H%M%SZ).tgz -C /data .

# 3. Start a rekey ceremony. Defaults are 5 shares with threshold 3
#    (same as the original init); ``-init`` mode prints the new
#    unseal keys on completion.
docker compose exec vault sh -c 'export VAULT_ADDR=http://127.0.0.1:8200; \
    bao login "$(cat /vault/recovery/root-token)" >/dev/null; \
    bao operator rekey -init -key-shares=5 -key-threshold=3'

# Note the "Nonce" value printed. You will need to pass an OLD
# unseal key for each of the 3 threshold steps below.

# 4. Submit the threshold-many existing unseal keys.
docker compose exec vault sh -c 'export VAULT_ADDR=http://127.0.0.1:8200; \
    bao operator rekey -nonce <NONCE> "<old-unseal-key-1>"'
# Repeat with old-unseal-key-2, old-unseal-key-3. The third
# submission prints the NEW unseal keys (5 of them, plus a new
# threshold and a new root token IF you also ran rekey-recovery).

# 5. Rewrite /vault/recovery/init-keys.json with the new unseal keys
#    so the next startup.sh re-unseal succeeds. The shape that
#    init-vault.sh expects is the same JSON Vault prints on init:
#    {"unseal_keys_b64":[...], "unseal_threshold":N, ...}.
docker compose exec vault sh -c \
    'umask 077; cat > /vault/recovery/init-keys.json' < /path/to/new-init-keys.json

# 6. Verify by sealing + restarting.
docker compose exec vault bao operator seal
docker compose restart vault
# Wait for healthcheck to pass; startup.sh auto-unseals with the
# new keys.
docker compose ps vault       # State: Up (healthy)

# 7. Destroy the off-host pre-rotation backup taken in step 2
#    AFTER you have confirmed the new keys work.
```

If rekey fails partway: restore `vault_recovery` (and, if needed,
`vault_data`) from the off-host tarballs taken in step 2 and try again.
**Do not** lose the old keys until the new keys are confirmed working.

### Bundled Vault: manual root-token rotation

The init-time root token in `/vault/recovery/root-token` (operator-only
`vault_recovery` volume, not app-readable) is also manually
rotated.

```bash
# Issue a new root token, then revoke the old one.
docker compose exec vault sh -c 'export VAULT_ADDR=http://127.0.0.1:8200; \
    bao login "$(cat /vault/recovery/root-token)" >/dev/null; \
    NEW_ROOT=$(bao token create -policy=root -orphan -ttl=0 -field=token); \
    umask 077; echo "$NEW_ROOT" > /vault/recovery/root-token.new'

# Verify the new token works.
docker compose exec vault sh -c 'export VAULT_ADDR=http://127.0.0.1:8200; \
    bao login "$(cat /vault/recovery/root-token.new)" >/dev/null; \
    bao token lookup'

# Swap files atomically and revoke the old one.
docker compose exec vault sh -c \
    'OLD=$(cat /vault/recovery/root-token); \
     mv /vault/recovery/root-token.new /vault/recovery/root-token; \
     bao login "$(cat /vault/recovery/root-token)" >/dev/null; \
     bao token revoke "$OLD"'
```

`init-vault.sh` reads `/vault/recovery/root-token` on every start to
log in for the idempotent role/policy reconciliation, so the swap
is picked up automatically on the next container restart.

### Bundled Vault: backend service-token rotation

The backend reads `/vault/data/backend-token` (runtime material) at
startup (`backend/scripts/start.prod.sh`). Rotating it requires issuing a
new token under the `backend-service` policy, rewriting that file, and
restarting the backend so it re-reads it. Note the file the backend reads
stays in `vault_data`, but issuing the token requires logging in with the
root token from the recovery volume (`/vault/recovery/root-token`).

```bash
# 1. Issue a new backend-service token (login uses the recovery root token).
docker compose exec vault sh -c 'export VAULT_ADDR=http://127.0.0.1:8200; \
    bao login "$(cat /vault/recovery/root-token)" >/dev/null; \
    NEW_BE=$(bao token create -policy=backend-service -field=token); \
    echo "$NEW_BE" > /vault/data/backend-token.new'

# 2. Swap files.
docker compose exec vault sh -c \
    'OLD=$(cat /vault/data/backend-token); \
     mv /vault/data/backend-token.new /vault/data/backend-token; \
     echo "$OLD" > /tmp/old-backend-token'

# 3. Restart the backend so start.prod.sh re-reads the file.
docker compose restart backend agent-broker

# 4. After confirming the stack is healthy, revoke the old token.
docker compose exec vault sh -c 'export VAULT_ADDR=http://127.0.0.1:8200; \
    bao login "$(cat /vault/recovery/root-token)" >/dev/null; \
    bao token revoke "$(cat /tmp/old-backend-token)"; \
    rm /tmp/old-backend-token'
```

Backend and broker containers both read the same shared
`vault_data` volume, so restarting both is required when rotating
the backend service token.

### External OpenBao / Vault-compatible: provisioning checklist

To run Praxis with an operator-owned external OpenBao (or HashiCorp
Vault) service, that service must provide the same mounts, roles, and
policy paths the bundled `vault/scripts/init-vault.sh` provisions. The
checklist below mirrors `init-vault.sh` so an operator can replay it
against their service without reading the script. The commands are
identical whether you drive them with `bao` (OpenBao) or `vault`
(HashiCorp Vault): the CLI and API are compatible, and `vault` is shown here.

**Required secrets-engine mounts:**

```bash
vault secrets enable -path=praxis kv-v2
vault secrets enable -path=ssh-client-signer ssh
vault secrets enable -path=praxis-agent-ca pki
vault secrets enable -path=praxis-broker-ca pki

vault secrets tune -max-lease-ttl=43800h praxis-agent-ca   # 5 years
vault secrets tune -max-lease-ttl=43800h praxis-broker-ca  # 5 years
```

**SSH CA:**

```bash
vault write -field=public_key ssh-client-signer/config/ca \
    generate_signing_key=true > /path/to/ssh-ca-public-key
vault write ssh-client-signer/roles/praxis-user - <<'EOF'
{
  "key_type": "ca",
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
```

**Agent PKI:**

```bash
vault write -field=certificate praxis-agent-ca/root/generate/internal \
    common_name="Praxis Agent CA" issuer_name="praxis-agent-root" \
    ttl=43800h > /path/to/agent-ca-cert.pem
vault write praxis-agent-ca/roles/agent \
    allowed_domains="agent.praxis.internal" \
    allow_subdomains=true allow_any_name=false \
    allow_bare_domains=false allow_glob_domains=false \
    allow_wildcard_certificates=false allow_ip_sans=false \
    allow_localhost=false use_csr_common_name=false \
    use_csr_sans=false enforce_hostnames=true \
    allowed_uri_sans="praxis://system/*" \
    client_flag=true server_flag=false \
    key_type=ec key_bits=256 \
    ttl=1h max_ttl=1h no_store=false
```

**Broker PKI:**

```bash
vault write -field=certificate praxis-broker-ca/root/generate/internal \
    common_name="Praxis Broker CA" issuer_name="praxis-broker-root" \
    ttl=43800h > /path/to/broker-ca-cert.pem
vault write praxis-broker-ca/roles/server \
    allowed_domains="<comma-separated-broker-hostnames>" \
    allow_subdomains=false allow_any_name=false \
    allow_bare_domains=true allow_glob_domains=false \
    allow_wildcard_certificates=false allow_ip_sans=true \
    allow_localhost=true use_csr_common_name=false \
    use_csr_sans=false enforce_hostnames=false \
    client_flag=false server_flag=true \
    key_type=ec key_bits=256 \
    ttl=8760h max_ttl=8760h no_store=false
```

Then issue a broker server cert/key/CA bundle and mount them at
`/vault/data/broker/{server.crt, server.key, ca.crt}` for the
agent-broker process to pick up (or override via
`PRAXIS_BROKER_TLS_CERT` / `_KEY` / `_CA_CLIENT`).

**Backend service policy:**

```hcl
path "praxis/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# SSH CA operations
path "ssh-client-signer/config/ca"     { capabilities = ["read"] }
path "ssh-client-signer/sign/praxis-user" { capabilities = ["create", "update"] }
path "ssh-client-signer/roles/praxis-user" { capabilities = ["read"] }

# Agent CA operations
path "praxis-agent-ca/cert/ca"   { capabilities = ["read"] }
path "praxis-agent-ca/sign/agent" { capabilities = ["create", "update"] }
path "praxis-agent-ca/roles/agent" { capabilities = ["read"] }

# Broker CA operations
path "praxis-broker-ca/cert/ca"      { capabilities = ["read"] }
path "praxis-broker-ca/issue/server" { capabilities = ["create", "update"] }
path "praxis-broker-ca/roles/server" { capabilities = ["read"] }
```

Write the policy, then issue a long-lived token bound to it and
hand the token to the backend via `VAULT_TOKEN`:

```bash
vault policy write backend-service /path/to/backend-policy.hcl
BACKEND_TOKEN=$(vault token create -policy=backend-service -field=token)
# Set in the operator's .env:
#   VAULT_ADDR=https://vault.your-corp.com:8200
#   VAULT_TOKEN=<BACKEND_TOKEN>
```

External-Vault operators are responsible for token renewal /
rotation cadence; the repo's bundled rotation procedures above
do not apply, because there is no shared `vault_data` volume to
rewrite.

### Fatal Vault failure modes (operator must know)

- **Losing `init-keys.json`** (on the `vault_recovery` volume) means
  the bundled Vault cannot be unsealed on next restart. There is no key
  escrow; recovery requires restoring `vault_recovery` from an off-host
  backup that captured `/vault/recovery/init-keys.json`. Capture
  `vault_recovery` (alongside `vault_data` and the Postgres dump) on the
  same off-host cadence (see the Backup/Restore section).
- **Losing the root token** (`/vault/recovery/root-token`) is
  recoverable if you still have the unseal keys: run a Vault root-token
  regeneration ceremony (`vault operator generate-root`) using the
  threshold of unseal keys to mint a new root token.
- **Losing `vault_data` AND `vault_recovery` off-host backups** is
  terminal for the bundled deployment: the SSH CA private key,
  agent/broker PKI roots, and KV secrets (on `vault_data`) and the
  unseal keys (on `vault_recovery`) are gone. The supported recovery
  story is "restore both volumes from an off-host backup that captured
  them together."

## Production Env Validation And Startup Checks

What is enforced today on startup (`backend/app/api/main.py`,
`backend/app/core/auth.py`):

- `backend/app/api/main.py` raises `ValueError` if any of
  `SECRET_KEY`, `ALGORITHM`, `ACCESS_TOKEN_EXPIRE_MINUTES` is unset.
- `backend/app/core/auth.py` raises `RuntimeError` if `SECRET_KEY`
  is unset (redundant with above).
- `backend/app/core/auth.py` rejects a known-weak `SECRET_KEY` only
  when `ENVIRONMENT=production`. In any other environment the same
  weak secret is logged as a warning and accepted.
- `docker-compose.yml` uses the `${SECRET_KEY:?...}` compose-substitution
  form on the `backend` and `agent-broker` services, so a missing
  `SECRET_KEY` short-circuits `docker compose up` with a clear error.
- `backend/app/api/main.py` flips `docs_url` / `redoc_url` /
  `openapi_url` to `None` when `ENVIRONMENT=production`, hiding the
  OpenAPI surface from production deployments.
- `docker-compose.prod.yml` forces `ENVIRONMENT=production` on the
  backend as a literal value, so applying the prod overlay
  cannot silently inherit the base dev default
  (`ENVIRONMENT=${ENVIRONMENT:-development}`) and leave the
  production-only gates above disabled. This holds even if the
  operator's `.env` sets `ENVIRONMENT=development`.

### Production fail-clear validation

`backend/app/core/startup_validation.py` is called from
`backend/app/api/main.py` after the existing `required_env_vars`
check. Production-only rejections fire only when
`ENVIRONMENT=production`; the closed-set ENVIRONMENT check fires
in every mode (so the common `ENVIRONMENT=prod` typo can't
silently demote a production deployment to dev behavior).

Each rejection raises `StartupValidationError` with the variable
name and the corrective action:

- **`ENVIRONMENT` outside `{development, production, test}`**:
  fails before any other check so a typo like `ENVIRONMENT=prod`
  is caught immediately.
- **Missing, empty, or `postgres` bundled database password**:
  `validate_database_credentials` inspects the password carried
  in `DATABASE_URL` and runs in **every** mode, not only
  production, because that URL is the sole credential the backend
  and broker containers receive. It is the enforcement point for
  the bundled credential, since Compose deliberately does not
  require `POSTGRES_PASSWORD` at interpolation. Production
  additionally rejects a `POSTGRES_PASSWORD` that is empty or the
  retired default for deployments that assemble their own URL.
  External-Postgres operators set their own `DATABASE_URL` and
  are exempt everywhere.
- **Empty `VAULT_TOKEN` with non-bundled `VAULT_ADDR`**:
  external-Vault deployments must supply a token. Bundled-Vault
  deployments read the token from the shared
  `/vault/data/backend-token` at runtime, so empty is correct
  there.
- **Empty `ADMIN_PASSWORD` on a deployment that is still being
  initialized**: enforced on the boot path that provisions the
  first administrator; in production with no users yet and an
  empty `ADMIN_PASSWORD`, startup raises instead of silently
  skipping admin creation and leaving a production stack with no
  usable login. The gate stops applying once the deployment
  records that it has been initialized, because `ADMIN_PASSWORD`
  is a first-run input rather than desired state: a later restart
  neither reads it nor recreates an administrator that was
  removed. Clear it once the first administrator has signed in.

Test coverage:
`backend/tests/services/test_pra179_startup_validation.py` (13
tests) covers each rejection plus the bundled/external-mode
asymmetries.

Documented but not validated today (future
candidates or explicit no-validate):

- `CORS_ORIGINS` and `TRUSTED_HOSTS` have permissive defaults
  that are appropriate for dev but are not production-validated.
  Locking `TRUSTED_HOSTS` to a non-default value in production
  is an operator-side hardening step; see **Known limitations**
  below.
- `SECRET_KEY` weak-value rejection lives in
  `backend/app/core/auth.py` (unchanged); the new
  validator does not duplicate it. No-validate is intentional.

### Stored-email serialization (`UserResponse`)

`backend/app/api/schemas/auth.py` previously declared
`UserResponse.email` as `EmailStr`. `EmailStr` requires
`email-validator`, which rejects RFC 2606 reserved TLDs (`.invalid`,
`.test`, …). An operator who set
`ADMIN_EMAIL=admin@somecorp.invalid`, a defensible choice for
internal-only deployments, saw every endpoint that returned
`UserResponse` 500 with a Pydantic `ValidationError` at
response-model serialization time, including `/auth/me` and
`GET /users`.

The **response** schemas were loosened (`UserBase`,
`UserResponse`) to plain `str` for `email`. Input-side schemas
(`UserCreate`, `UserUpdate`) keep `EmailStr` so self-service
signup/edit still validates strictly; only already-stored values
get the relaxed serialization path.

Regression test:
`backend/tests/api/test_pra179_user_response_reserved_tld.py`
creates an admin with `admin-reserved@example.invalid`, hits
`/auth/me` and `/users`, asserts both return 200 with the email
round-tripped unchanged.

## Audit File Sink Confinement

A `file` audit sink appends newline-delimited JSON to local disk. The delivery
worker writes that path from inside the trust boundary, so every file sink is
confined to one operator-approved directory:

- `AUDIT_FILE_SINK_ROOT` sets the root. It defaults to
  `/data/praxis/audit-sinks`, backed by the dedicated `audit_sink_data` named
  volume that `docker-compose.yml` mounts into the **backend only**. Sink output
  therefore survives backend recreation, and no other service can read or write
  it. The production image pre-creates the mount point owned by the non-root
  runtime user (UID 1000), so the volume keeps that ownership on first mount.
- Sink targets are **relative paths beneath the root**, for example
  `exports/audit.jsonl`. Missing intermediate directories are created on first
  delivery.
- Absolute paths, empty or directory-only targets, `.` and `..` segments,
  repeated or trailing separators, and any symlinked path component are
  rejected. Rejection happens when the sink is created or updated (HTTP 400)
  and independently on every delivery. Saving a sink also refuses an
  already-existing symlink in the target's parents or at the target itself, a
  parent that is not a directory, and an existing target that is not a regular
  file.
- Both checks walk the root and the target one component at a time from a
  descriptor on the filesystem root, with pinned directory descriptors and
  no-follow opens. Paths are never resolved before the policy is applied and are
  never reopened by name, so a symlink planted after the sink was saved cannot
  redirect the write outside the root.
- The root must be an absolute path with no `.` or `..` segments, must not be
  the filesystem root, and must not be `/app`, `/boot`, `/dev`, `/etc`,
  `/proc`, `/root`, `/run`, `/sys`, `/vault`, or anything beneath them. A root
  that is itself a symlink, or that sits behind a symlinked ancestor, is
  refused rather than followed. Change the root only together with the compose
  mount.

Operator action for existing sinks: a `file` sink saved before this
confinement keeps its stored target and stays visible in **Settings > Audit
Export**, but its deliveries fail with an explanatory `last_error` and follow
the normal retry then dead-letter path. Nothing is rewritten or silently
redirected. Replace the target with a relative path under the root, then retry
the dead-lettered deliveries.

## Bundled-vs-External Data Tier Boundary

The bundled `db`, `vault`, and `db_backup` services share a single
compose profile. The supported deployment shapes for the data tier
are therefore exactly two:

1. **Fully bundled**: bundled Postgres + bundled Vault + bundled
   `db_backup` sidecar (`COMPOSE_PROFILES=bundled`).
2. **Fully external**: operator-owned Postgres + operator-owned
   Vault, no bundled data-tier services running, no `db_backup`
   sidecar.

Mixed bundled/external data-tier shapes are **not** supported in
Praxis 1.0. The repo neither ships a compose overlay nor exercises
any test that brings up bundled Vault against external Postgres or
the reverse; an operator who hand-rolls that mix is on their own.

Bundled Postgres:

- Single-node, single-volume, default credentials unless overridden,
  daily pg_dump at 02:00 with 30-day local retention.
- Suitable for small single-node deployments where the operator
  takes responsibility for off-host backup of the docker volumes.

External Postgres (only as part of the fully-external shape):

- Set `DATABASE_URL` (and `TEST_DATABASE_URL` if running the test
  suite against external Postgres). The bundled `db` service does
  not run (gated by `bundled` profile).
- The operator owns: HA, replication, backups, point-in-time
  recovery, monitoring, version pinning, and `pg_dump` schedule.
- The repo guarantees: schema is managed via Alembic, the connection
  string is the only contract, no Praxis component bypasses
  SQLAlchemy to issue server-specific DDL.
- Praxis 1.0 expects PostgreSQL 15.x (bundled image is
  `postgres:15.17-alpine`). External operators on newer majors are
  on their own for compatibility until that is explicitly verified.

## Unsupported Deployment Shapes

The operator-facing list of deployment shapes that are
**explicitly out of scope for Praxis 1.0**. None of these are
"we forgot to ship support"; each is an intentional boundary
with a one-line rationale below. Operators who need any of these
shapes today are running outside the supported deployment
contract.

### Orchestration / topology

- **Docker Swarm.** `docker-compose.prod.yml`'s preamble
  explicitly defers Swarm compatibility. No swarm-mode service
  definitions, no global / replicated mode stanzas, no
  swarm-routing mesh expectations.
- **Kubernetes.** No manifests, helm charts, or kustomize
  overlays ship in this repository, and nothing in the deployment
  model precludes an operator writing their own.
- **Multiple agent-broker instances / broker HA.** The agent
  broker holds the agent tunnel registry (`AgentRegistry`) and
  in-flight operation state (`OperationManager`) **in memory**,
  per process. 1.0 runs exactly **one** broker instance; scaling
  the broker to replicas would split agent connections and op
  state across processes with no shared registry, so an op
  dispatched to one broker could not reach an agent connected to
  another. The broker logs this invariant at startup. Horizontal
  broker scaling requires a future shared registry and is out of
  scope for 1.0. (This is independent of the single-backend-worker
  requirement for interactive SSH sessions, documented above.)
- **Mixed bundled/external data tier.** The bundled `db`,
  `vault`, and `db_backup` services share a single compose
  profile. The supported external shape is *fully* external
  Postgres **and** external Vault; bundled-Vault-with-external-
  Postgres (or the reverse) is not exercised by any test and is
  not a supported shape.

### Data tier scale-out

- **Multi-node Postgres replication or Patroni in bundled mode.**
  The bundled `db` is a single `postgres:15.17-alpine` container.
  External-Postgres operators can run whatever their managed
  Postgres supports.
- **Vault HA, integrated storage (Raft), KMS-backed auto-unseal.**
  Bundled Vault uses `storage "file"` with auto-unseal driven
  by an on-disk key file (see the Vault section above).
  Operators who need HA, KMS auto-unseal, audit log shipping,
  or compliance-grade key management must switch the entire
  data tier to the fully-external shape and bring their own
  Vault.

### Backup, restore, durability

- **Off-host backup shipping automation.** `scripts/backup.sh`
  produces dumps on the shared `backup_data` volume only.
  Copying dumps (and the other named volumes `vault_data`,
  `vault_recovery`, `recordings_data`, `mirror_data`) off-host is
  operator-owned.
  See the **Backup / Restore Drill** section for the
  RPO/RTO contract and the failure boundary.
- **Backup encryption at rest.** `scripts/backup.sh` writes
  custom-format pg_dump output unencrypted to the
  `backup_data` volume. Operators who need encryption at rest
  encrypt the volume (or the off-host destination) themselves.
- **Multi-revision Alembic downgrade.** Forward migrations are
  the supported path. The Praxis 1.0 rollback contract is
  **restore the pre-upgrade dump**, not `alembic downgrade`.

### Edge / TLS / external trust

- **Caddy `acme` live-DNS mode** as a smoke-tested path. The
  `acme` mode is supported as a configuration option (set
  `PRAXIS_TLS_MODE=acme` + `PRAXIS_DOMAIN` + `PRAXIS_ACME_EMAIL`)
  but exercising it requires live DNS + port 443 reachable,
  which is not feasible inside a local hermetic smoke. The
  `internal` and `byo` Caddy modes have the same operator
  contract; only `acme` has the live-DNS requirement.
- **Operator-owned external Vault automation.** The
  external-Vault provisioning checklist in this doc gives
  exact `vault` CLI commands, but the operator owns running
  them against their Vault. Praxis 1.0 ships no automation for
  external-Vault rotation, token renewal, or audit-log
  shipping.

### Agent-side surface

- **Activation-token agent bootstrap with the real Go binary
  + systemd unit.** The first-enrolled-host smoke
  verifies the `/agent/enroll` redemption end-to-end against a
  docker-side dummy host, but does **not** load the
  `praxis-agent` Go binary or run the agent's mTLS handshake
  against the broker. Operators who need those paths
  exercised do so against their own host. See the Fresh
  Install Path section's boundary note.
- **`bootstrap.sh` `curl --fail-with-body` on recent curl
  versions.** The committed `bootstrap.sh:147` uses
  `curl -fsS --fail-with-body -X POST ...`, which conflicts
  with the `-f` in `-fsS` on curl 7.76+ (including the curl
  shipped in ubuntu:22.04). An operator running the script
  on a recent Ubuntu host hits this; the first-enrolled-host smoke
  bypasses it by re-implementing the enroll POST. Documented
  queued for a future change; **not** in scope for 1.0.

### Compliance / scanning / OS surface

- **Embedded OpenSCAP runs.** Compliance probes are deferred
  to future compliance surfaces; Praxis 1.0 does not
  introduce or exercise OpenSCAP.
- **Host package-manager mutation.** Any change to the
  control-plane host's apt/yum/dnf state is operator-owned.
  Praxis 1.0 ships container images; container internals
  install via the Dockerfiles and are out of operator scope.

## Verification & Support Status

Legend: **Verified** = exercised by an automated test/script in this repo;
**Documented** = an operator procedure described here but run manually;
**Unsupported** = explicitly out of scope for Praxis 1.0.

Verified by repo tests/scripts:

- Dev cold rebuild (`down -v` -> `up --build` -> pytest) via
  `scripts/test-cold-rebuild.sh`.
- Prod-overlay fresh-install bring-up (bundled profile, locally built images;
  waits for `/health`, exercises authenticated and RBAC-gated routes) via
  `scripts/test-fresh-install-smoke.sh`.
- First-enrolled-host bootstrap (activation-token mint + redemption via
  `POST /agent/enroll` against a docker-side dummy host; asserts the System row
  reaches `agent_status=active` with a Vault-signed cert serial) via
  `scripts/test-first-enrolled-host-smoke.sh`.
- Alembic `upgrade head` from empty (cold-rebuild + CI) and from representative
  earlier snapshots (`pre_m13.sql`, `pre_m15.sql`) via
  `scripts/test-upgrade-smoke.sh`.
- Daily `pg_dump` via the `db_backup` sidecar + a `pg_restore` round-trip
  (sentinel insert -> backup -> delete -> restore -> re-verify `/health`) via
  `scripts/test-backup-restore-smoke.sh`.
- RPO/RTO targets: see the RPO/RTO contract above (RPO ~ 24 h, RTO minutes to
  single-digit hours).
- Startup validation: rejects missing/known-weak `SECRET_KEY`, empty
  `ADMIN_PASSWORD` in production, a missing/empty/default bundled database
  password, an empty `VAULT_TOKEN` in external mode, and unknown `ENVIRONMENT`
  values, in `backend/app/core/startup_validation.py` (plus unit tests).
- Bundled database credential contract: no password ships in the source; the
  bundled `db` entrypoint, the backend/broker startup preflight, and
  `scripts/backup.sh` each exit before doing useful work when it is missing,
  empty, or the retired default; and external `DATABASE_URL` mode renders and
  runs without `POSTGRES_PASSWORD`, in
  `backend/tests/services/test_pra387_postgres_credential_contract.py`.
  `UserResponse` serializes reserved-TLD emails as `str` (input schemas keep
  `EmailStr`).

Documented operator procedures (manual, not automated):

- GHCR-pull form of the prod overlay (`--profile bundled pull`); the smoke
  covers `--build`.
- Caddy `internal` and `byo` TLS modes (`caddy/Caddyfile`).
- Bundled Vault init / auto-unseal and the unseal-key / root-token /
  backend-service-token rotation procedures above.
- External Vault provisioning checklist above.
- Off-host shipping of the backup dump + named volumes.

Unsupported for 1.0 (see **Unsupported Deployment Shapes**):

- Docker Swarm, Kubernetes, multi-node bundled Postgres.
- Vault HA / integrated storage / KMS auto-unseal in bundled mode (external
  Vault only).
- Caddy `acme` TLS (needs live DNS + reachable :443).
- Backup encryption at rest; embedded OpenSCAP runs.
- Multi-revision Alembic downgrade; the supported rollback is "restore the
  pre-upgrade dump", not downgrade through Alembic.

## Known limitations

- `backend/app/api/routes/_assets/bootstrap.sh` uses a `curl --fail-with-body`
  flag pair that conflicts on curl 7.76+; the conflicting flag should be
  dropped.
- `TRUSTED_HOSTS` (and optionally `CORS_ORIGINS`) are not production-validated
  today; they carry permissive dev defaults. A startup-validation rule could
  require a non-default `TRUSTED_HOSTS` in production.
- Automated coverage does not include a GHCR-pull install smoke, Caddy
  `internal` and `byo` TLS smokes, or in-container Vault rotation dry-runs
  against a throwaway smoke-Vault.

## References

- `README.md`: public-facing install + deployment instructions.
- `docker-compose.yml`: production-parity base services (prod images/
  entrypoints), two-tier network, health checks.
- `docker-compose.prod.yml`: prod overlay (pinned images, logging,
  ENVIRONMENT=production, Caddy profile).
- `caddy/Caddyfile`: TLS modes and edge headers.
- `scripts/backup.sh`: daily pg_dump.
- `scripts/test-cold-rebuild.sh`: from-scratch build + boot gate.
- `scripts/test-fresh-install-smoke.sh`,
  `scripts/fresh-install-smoke.override.yml`: hermetic prod-overlay
  bring-up smoke.
- `scripts/test-upgrade-smoke.sh`,
  `backend/tests/fixtures/upgrade/pre_m13.sql`,
  `backend/tests/fixtures/upgrade/pre_m15.sql`: upgrade smoke +
  committed earlier-schema fixtures.
- `scripts/test-backup-restore-smoke.sh`: backup/restore round-trip
  smoke against the shipped backup path (no compose override).
- `backend/app/core/startup_validation.py`,
  `backend/tests/services/test_pra179_startup_validation.py`:
  production env / startup fail-clear validator and its unit suite.
- `backend/tests/api/test_pra179_user_response_reserved_tld.py`:
  regression test for the `UserResponse.email` / RFC 2606
  reserved-TLD serialization (input schemas keep `EmailStr`;
  response schemas loosened to `str`).
- `scripts/test-first-enrolled-host-smoke.sh`:
  first-enrolled-host redemption smoke. Spins up an ubuntu:22.04
  dummy host on the smoke project's `backend_net`, generates a
  CSR with openssl, redeems the activation token via
  `POST /agent/enroll`, and asserts the System row transitioned
  to `agent_status=active` with a Vault-signed cert serial.
- `vault/config/vault.hcl`, `vault/scripts/init-vault.sh`,
  `vault/scripts/startup.sh`: bundled Vault provisioning.
- `backend/app/api/main.py`, `backend/app/core/auth.py`: startup
  env validation today.
- `backend/alembic/versions/`: a single linear Alembic chain from the
  initial schema through the latest revision named in the Upgrade And
  Migration Posture section above.
- Operator commands are direct `docker compose ...` invocations
  (there is no root `Makefile`); see the README "Common
  operator commands" table.
