# Database Backup and Restore Process

## Backup Process

The backup process is automated using a script and a Docker service. The script is located at `scripts/backup.sh` and is executed within the `db_backup` service.

### Steps to Perform a Backup

1. **Manual Backup**: You can manually trigger a backup by running the following command:
   ```bash
   docker compose exec db_backup /scripts/backup.sh
   ```

2. **Automated Backup**: The backup is scheduled to run daily at 2 AM using a cron job within the `db_backup` service. This ensures regular backups without manual intervention.

3. **Retention Policy**: Backups older than 30 days are automatically deleted to manage storage space. This is handled by the `backup.sh` script.

## Restore Process

The restore process allows you to restore the latest backup to the database.

### Steps to Restore a Backup

1. **Restore Latest Backup**: You can restore the latest backup by running the following command:
   ```bash
   docker compose exec db sh -c "ls -t /backups/*.dump | head -n 1 | xargs -I {} pg_restore --verbose --clean --if-exists -U postgres -d praxis {}"
   ```
   This command locates the most recent backup file and restores it to the database.

## Testing Backup Integrity

Every backup is integrity-checked at creation time: `scripts/backup.sh` validates
the completed dump with `pg_restore --list` before publishing it (PRA-263), so a
corrupt or partial dump is never published as a restorable `*.dump`. The full
backup → restore round trip is exercised by `scripts/test-backup-restore-smoke.sh`.

## Important Notes

- Ensure that the `db_backup` service is running to perform backups and restores.
- The backup files are stored in the `/backups` directory within the `db_backup` container.
- The backup and restore processes are configured to work with the PostgreSQL database.
- The `backup.sh` script uses `pg_dump` to create backups in a custom format, which includes all database objects and data.
- Backups are published atomically (PRA-263): `pg_dump` writes to a same-directory temp file that does not match `*.dump`, the completed dump is validated with `pg_restore --list`, and only then is it atomically renamed to the final `${POSTGRES_DB}-YYYYMMDDHHMMSS.dump` name. A failed or interrupted backup is cleaned up and never leaves a partial `.dump` that the "newest dump" restore selection could pick.
