# Upgrade notes — 1.0.0

These notes cover moving to `1.0.0` from a prerelease or a local development
build. 1.0 is the first supported release; there is no supported upgrade from an
older tagged release because none exists.

If you are installing fresh, follow the
[Production Deployment](../README.md#production-deployment) section of the README
instead — you do not need this document.

## Before you upgrade

- **Back up the database.** Run `scripts/backup.sh` and confirm the dump
  completes. See
  [backend/docs/database-backup-restore.md](../backend/docs/database-backup-restore.md)
  for the backup and restore procedure.
- **Note your current versions.** Record the image tags (or the commit) you are
  upgrading from, so you can roll back by re-pinning `PRAXIS_VERSION`.
- **Read the known limitations** at the bottom of this document before
  committing to the upgrade.

## Upgrade steps

1. **Pin the target version.** In `.env`:

   ```sh
   PRAXIS_VERSION=1.0.0
   ```

2. **Pull (or build) the 1.0.0 images.**

   ```sh
   # Pull published images (--profile proxy starts Caddy, the browser ingress):
   docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile bundled --profile proxy pull

   # Or, to build locally / for air-gapped installs:
   docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile bundled --profile proxy up -d --build
   ```

3. **Apply database migrations.** The backend runs migrations on start, but you
   can apply them explicitly against the new image:

   ```sh
   docker compose exec -T backend alembic upgrade head
   ```

4. **Reconcile lifecycle / EOL reference data.** A fresh database loads this via
   migration; an existing database may have drifted from the shipped seed:

   ```sh
   docker compose exec -T backend python -m app.scripts.update_eol_data
   # Confirm nothing is left pending:
   docker compose exec -T backend python -m app.scripts.update_eol_data --dry-run
   #   -> summary should report "0 new, 0 pruned"
   ```

5. **Confirm the supported worker posture.** Keep `UVICORN_WORKERS=1` (the
   default) while browser interactive SSH sessions are enabled. The production
   entrypoint refuses to start with more than one worker unless you explicitly
   set the unsupported `ALLOW_UNSAFE_MULTIWORKER_SESSIONS=1` override.

6. **Verify health.** Confirm the services report healthy:

   ```sh
   docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile bundled --profile proxy ps
   #   -> backend and frontend should be "healthy"
   ```

7. **Run the smoke gates** (see [docs/release-checklist.md](release-checklist.md)
   for the full set): fresh-install / upgrade / backup-restore smokes and the
   demo walkthrough if you want a visual confirmation of the lifecycle story.

## Breaking change: privileged access baseline

Praxis 1.0 ships **no standing user-facing privileged escalation** — no
Praxis-issued root shell, no password-sudo path, no break-glass root profile, no
raw sudoers authoring, and no sudo inheritance. The upgrade migration corrects the
launch-incompatible defaults that earlier versions seeded:

- Every fleet role's raw `sudoers_snippet` is **cleared**, and privileged OS
  groups (`wheel`/`sudo`/`root`/`admin`) are **stripped** from every role —
  built-in **and** custom. The built-in `admin` and `maintainer` roles no longer
  carry `ALL=(ALL) NOPASSWD:ALL`. Raw sudoers text is **not** preserved as dormant
  config; if you genuinely need the prior policy text, recover it from your
  **pre-upgrade database backup**.
- The fleet-role API now rejects any request that sets a raw sudoers snippet or a
  privileged OS group.

**Clearing the database is not enough — you must reconcile hosts.** Any
`/etc/sudoers.d/praxis-<login>` drop-in already deployed by a pre-1.0 release
stays on the host until reconciliation removes it. The migration flags every live
managed account for privilege reconciliation; run a fleet reconcile after
upgrading to remove the on-host drop-ins:

```sh
docker compose exec -T backend python -c \
  "from app.db.session import SessionLocal; from app.services import fleet_reconciliation_service as f; \
   db=SessionLocal(); print(f.reconcile_pending_privilege(db)); db.close()"
#   -> {'provisioned': N, 'removed': .., 'errors': E, 'hosts': H, 'still_pending': P}
```

Any host that is unreachable stays flagged (and is surfaced as `error` /
unreconciled) and is retried on the next reconcile — the stale sudo privilege is
never silently left live. Check what is still outstanding with
`fleet_reconciliation_service.privilege_reconcile_status(db)`, which reports the
count of hosts/accounts still pending drop-in removal. Interactive root on managed
hosts is now **out-of-band** under your ops runbook, not a Praxis-issued grant.

## Rolling back

Re-pin `PRAXIS_VERSION` to the version you recorded before upgrading and
`pull` + `up -d` again. Note that database migrations are **not** automatically
reversed; if a migration ran, restore the pre-upgrade database backup before
starting the older image.

## Known limitations in 1.0

- **Single-instance backend only.** Horizontal scale-out is not supported, and
  Docker Swarm is explicitly out of scope for 1.0.
- **Single worker with interactive SSH.** Interactive session runtime is
  process-local, so multi-worker interactive SSH sessions are not supported;
  keep `UVICORN_WORKERS=1`.
- **Bring your own OIDC provider.** Praxis does not bundle an identity provider.
- **Manual release smokes.** The prod-overlay, end-to-end, upgrade, and
  backup/restore smokes are manual release gates, not blocking CI lanes.
- **Free edition host cap.** The open-core free edition is capped at 15 managed
  hosts; larger fleets require a license.
