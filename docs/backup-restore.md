---
title: Backup and restore
description: Take a consistent backup of a bundled deployment and restore it, including the secrets store.
---

This document covers the **1.0 encrypted full-app-state backup/restore** path for a
**bundled** Praxis deployment, the single-node shape where Praxis runs its own
PostgreSQL, OpenBao/Vault, recordings, and mirror content under Docker Compose.

> **Scope.** This is the minimum honest recovery layer for the bundled deployment,
> not an enterprise DR platform. There is no point-in-time recovery, no WAL
> archiving, no HA/replication, no managed cloud backup, and no always-on remote
> storage. Praxis produces an **encrypted bundle on the host**; **moving it off-host
> is the operator's responsibility.**

## What is backed up

`scripts/backup-bundle.sh` produces a single encrypted bundle covering all bundled
persistent state:

| Component | Source | How |
| --- | --- | --- |
| PostgreSQL app DB | `postgres_data` | the existing validated `scripts/backup.sh` (custom-format `pg_dump`, validated with `pg_restore --list`) |
| OpenBao/Vault data | `vault_data` | read-only snapshot: KV secrets, PKI, broker cert, agent CA, backend token, SSH CA |
| Session recordings | `recordings_data` | read-only snapshot |
| Mirror / repo content | `mirror_data` | read-only snapshot |
| **Recovery material** | `vault_recovery` | **opt-in** (`--include-recovery`): unseal keys and init root token |
| Manifest | none | components, sizes, SHA-256 checksums, timestamps, image versions, restore instructions |

Not included (out of scope for 1.0): Caddy ACME material (`caddy_data`/`caddy_config`),
Prometheus TSDB (`prometheus_data`, infra telemetry), and anything outside the bundled
volumes. If you did not include the mirror bytes, upstream repositories cannot be
reconstructed from the bundle.

## Recovery material and Vault (important)

The OpenBao unseal keys live on the **vault-only** `vault_recovery` volume and are
never mounted into backend/agent-broker. The backup script keeps that
separation: it reads recovery material **only** via the explicit, opt-in
`--include-recovery` flag, from a throwaway read-only container, and never mounts
`vault_recovery` into a long-lived app service.

A restored `vault_data` comes up **sealed**. A *working* restore therefore needs the
**unseal keys**, either:

- inside the bundle (`--include-recovery`), or
- supplied by the operator out of band (you kept `init-keys.json` somewhere safe).

Without the unseal keys the restore populates everything else, but Vault stays sealed
and the backend cannot reach its secrets, so it will not become healthy. The restore
script warns loudly in that case.

Because a bundle created with `--include-recovery` contains everything needed to
unseal Vault and read every secret, treat it as **maximally sensitive**: it is
encrypted (below), and off-host custody + the passphrase are yours to protect.

## Encryption

The whole bundle is encrypted with **AES-256-CBC** (OpenSSL, PBKDF2, 600k iterations)
under an operator passphrase read from `PRAXIS_BACKUP_PASSPHRASE`. The passphrase is
passed to OpenSSL via `-pass env:` so it never appears in `ps`/argv, and no secret
values, tokens, unseal keys, DB URLs, or passphrases are ever logged. A
`.sha256` sidecar next to the bundle lets restore detect corruption/tampering before
it even attempts to decrypt.

The bundle is published **atomically**: the encrypted file and its sidecar are written
under temp names and renamed into place only after encryption + checksumming succeed.
A failed or interrupted run leaves **no** final-looking bundle.

## Consistency (live snapshots)

The bundle mixes two kinds of capture, and you should understand the difference:

- **PostgreSQL** is a **transactionally consistent** dump: `scripts/backup.sh` uses
  `pg_dump` custom format (a single-transaction snapshot) and validates the completed
  archive with `pg_restore --list` before it is included. This is the store that holds
  your relational app state, and it is captured cleanly even while the stack is running.
- **`vault_data`, `recordings_data`, and `mirror_data`** are captured as **read-only
  live snapshots** of the Docker volumes while the services are still running (a `tar`
  of the volume at that instant). They are not point-in-time-consistent against
  in-flight writes: a secret being written, a recording mid-flush, or a mirror sync in
  progress at the exact moment of the snapshot could be captured partially.

In practice this is fine for the 1.0 recovery target (OpenBao's file storage and the
recordings/mirror trees tolerate a live tar), but for the **most conservative backup
window**, with no chance of a torn write, quiesce Praxis writes or take the stack offline
before running `backup-bundle.sh`:

```bash
# Most conservative: stop the app tier (keep volumes), back up, then restart.
docker compose stop backend agent-broker
PRAXIS_BACKUP_PASSPHRASE=... scripts/backup-bundle.sh --include-recovery -o <staging>
docker compose start backend agent-broker
```

## Taking a backup

```bash
# Choose a strong passphrase and STORE IT SAFELY. It is required to restore.
export PRAXIS_BACKUP_PASSPHRASE="$(openssl rand -base64 32)"

# Full bundle including the unseal keys (recommended for true single-bundle DR):
scripts/backup-bundle.sh --include-recovery -o /path/to/off-host-staging

# Or without recovery material (you keep the unseal keys separately):
scripts/backup-bundle.sh -o /path/to/off-host-staging
```

Then **move the resulting `praxis-backup-<timestamp>.bundle.enc` (and its `.sha256`)
off the host**: to encrypted object storage, a backup server, removable media, and so on.
Praxis does not ship it anywhere.

The daily `scripts/backup.sh` cron (PostgreSQL only) is unchanged and still runs; the
bundle command wraps it for the full-state path.

## Restoring

Restore is **offline** and **destructive to the target project's volumes**: it brings
up a fresh bundled stack with empty volumes, populates `vault_data`, recordings,
mirrors (and `vault_recovery` if present), restores PostgreSQL, then starts the stack
and waits for backend health.

```bash
export PRAXIS_BACKUP_PASSPHRASE="<the passphrase used at backup time>"

scripts/restore-bundle.sh \
  --bundle /path/to/praxis-backup-<timestamp>.bundle.enc \
  --env-file /path/to/.env        # SECRET_KEY, POSTGRES_PASSWORD, etc. for the target
```

Restore **fails closed**: a `.sha256` mismatch, a wrong passphrase, a missing
`manifest.json`, or any per-component checksum mismatch aborts the restore **before**
anything is applied to the target.

**Supported target shape.** The restore target is a fresh **bundled** deployment
(same compose files / image versions recorded in the manifest). Restoring into an
external-Postgres or external-secrets shape is not a supported 1.0 path.

**Downtime.** Plan for the stack to be unavailable for the whole restore, because bringing up
fresh volumes, extracting snapshots, `pg_restore`, and re-unsealing Vault. On a
developer laptop the full smoke round-trip completes in a few minutes; production time
is dominated by database and mirror size.

## What is verified

`scripts/test-bundle-backup-restore-smoke.sh` proves the whole path in an isolated
compose project: it seeds four sentinels (DB row, Vault PKI SSH-CA public key,
a recording file, a mirror file), takes an encrypted bundle with `--include-recovery`,
asserts the bundle published atomically (final files present, no partial temp,
sidecar verifies) with **no passphrase or token in the logs**, proves a corrupt bundle
and a wrong passphrase are **rejected**, then wipes the project (`down -v`) and
restores from the bundle and asserts **all four stores survived** and the backend is
healthy again (which also proves Vault unsealed from the restored recovery material).

## Not covered in 1.0

- Point-in-time recovery / WAL archiving.
- HA, replication, multi-region, or multi-node restore.
- Managed cloud backup integration or always-on remote storage.
- KMS/HSM auto-unseal.
- External Postgres / external secrets backup orchestration (operator-owned).
- Caddy ACME material and Prometheus TSDB.
