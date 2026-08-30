---
title: Upgrade
description: Move a Praxis deployment to a new release, and roll back if it does not go well.
---

Upgrades are a pull and a restart. The risk is not the containers; it is the
database migration, which is one-way. Everything below exists to make sure you
can go back.

For the step-by-step drill with the checks in order, see
[upgrade safely](guide-safe-upgrade.md). For what changes in a specific release,
see its release notes and [upgrade notes for 1.0](upgrade-notes-1-0.md).

## Before you start

1. **Take a backup and confirm it restores.** A backup you have not restored is
   an assumption. See [backup and restore](backup-restore.md).
2. **Record the digests you are running now.** This is the rollback target.
   ```sh
   docker compose -f docker-compose.yml -f docker-compose.prod.yml images
   ```
3. **Read the release notes** for the version you are moving to, and every
   version you are skipping over.
4. **Verify the new artifacts** before running them. See
   [verify release artifacts](verify-release-artifacts.md).

## Upgrade the control plane

Pin the new version in `.env`:

```text
PRAXIS_VERSION=1.0.1
```

Then pull and restart:

```sh
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    --profile bundled --profile proxy pull

docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    --profile bundled --profile proxy up -d
```

The backend applies outstanding database migrations on startup. Watch it come
up rather than assuming it did:

```sh
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    logs -f backend
```

## Confirm the upgrade

- Every service reports healthy.
- The login page loads and you can sign in.
- **Settings > License** still shows the expected edition and host count.
- A host detail page loads with current inventory.
- One low-risk command runs against one host.

## Rolling back

Rollback is a redeploy of the previous digests. It does not touch the registry
and does not require deleting anything that was published.

```sh
export PRAXIS_VERSION=<previous>
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    --profile bundled --profile proxy up -d
```

**The database is the constraint.** Migrations are not automatically reversed.
If the new release changed the schema, the previous application version may not
be able to read it, and the supported way back is to restore the backup you took
before the upgrade. That is why proving the restore is step one rather than
step four.

### Schema changes that refuse to reverse

Some migrations decline to undo themselves rather than destroy data. The 1.0.1
migration that adds host descriptions is one: its downgrade aborts with an
explanatory message if any host has a description stored, because dropping the
column would discard text an operator typed. Clear those descriptions
deliberately if you intend to lose them, then run the downgrade again. The
migration changes nothing when it refuses.

The same migration also adds a uniqueness constraint on host addresses, and it
refuses to apply while duplicate addresses exist, naming the addresses and the
hosts using them. Resolve those hosts and re-run it.

Never roll back by deleting the newer version from the registry. Deletion breaks
anyone who pinned that digest and destroys the record of what shipped. Deploy
forward instead.

## Upgrading the agent

The agent is versioned and released separately, and it never updates itself.
Upgrading the control plane does not change agents already running on hosts.

The control plane serves a pinned agent release to hosts, and that pin does not
move on its own. A deployment can serve a different published release without a
rebuild by setting `PRAXIS_AGENT_RELEASE_VERSION` to an exact `vX.Y.Z`. Moving
references such as `latest` are rejected, because hosts verify a checksum
against whatever the control plane serves and that artifact must not change
underneath them.

To update the agent on a host, verify and extract the new tarball and run
`sudo ./install.sh` over the existing deployment. Configuration and identity
material are preserved, so the host does not re-enroll and the change appears as
a brief liveness gap. Rolling back is the same operation against the older
tarball. See [enroll hosts](enroll-hosts.md).

For air-gapped sites, drop the release assets into the directory named by
`PRAXIS_AGENT_ARTIFACT_DIR`, default `/opt/praxis/agent-artifacts`, using their
published filenames. A local artifact is preferred over the network path.

## Order of operations

1. Back up, and prove the restore.
2. Upgrade the control plane and confirm it is healthy.
3. Update agents in waves, starting with a small cohort.

Agents tolerate a newer control plane, so there is no need to update every host
before the control plane is confirmed good. Updating agents first only means
rolling back more things if the control plane upgrade fails.
