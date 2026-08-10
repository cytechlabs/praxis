---
title: Upgrade safely
description: A drill for upgrading a production Praxis deployment with a rollback you have actually tested.
---

The mechanics of an upgrade are in [upgrade](upgrade.md). This is the drill: the
order to do things in so that a bad upgrade is recoverable rather than an
incident.

## The rule

**Do not start an upgrade you cannot reverse.** For Praxis that means: a backup
you have restored, and the digests of what you are running now written down
somewhere other than the host.

## Before the window

### 1. Read the release notes for every version you are crossing

Skipping releases is supported, but the notes for the versions you skip still
apply. Look for schema changes, configuration that has changed shape, and
anything that says it is one-way. For 1.0 specifically, see
[upgrade notes for 1.0](upgrade-notes-1-0.md).

### 2. Record the current state

```sh
docker compose -f docker-compose.yml -f docker-compose.prod.yml images
```

Save the image digests, the current `PRAXIS_VERSION`, and a copy of `.env`.
These are the rollback target.

### 3. Take a backup, and restore it somewhere

A backup that has never been restored is an assumption. Restore it onto a
scratch deployment and confirm you can sign in and see hosts. See
[backup and restore](backup-restore.md).

This is the step that gets skipped and the step that matters. Everything after
it assumes you can go back.

### 4. Verify the new artifacts

Confirm the images you are about to run were built by the project's pipeline,
by digest and attestation, before they run anywhere. See
[verify release artifacts](verify-release-artifacts.md).

### 5. Check the secrets service is healthy

An upgrade will not fix a sealed secrets service, and a restart during one turns
a sealed state into a fleet-wide outage. Confirm health under
**Secure > Vault Management** first.

### 6. Quiesce what you can

- Let any in-flight patch execution finish, or stop it deliberately at a wave
  boundary.
- Avoid upgrading inside a maintenance window that is about to fire.
- Tell anyone who might be mid-session.

## The upgrade

Pin the new version, pull, and bring the stack up. Watch the backend log
through the migration rather than checking back later; a migration failure is
much easier to act on while you still have the console.

## After it comes up

Work down this list before declaring it done:

1. Every service reports healthy.
2. Sign in. Single sign-on too, if you use it, because redirect configuration is
   a common casualty.
3. **Settings > License** shows the expected edition and host count.
4. A host detail page loads with current inventory.
5. Run one low-risk command against one host, end to end.
6. If you use agents, confirm at least one reports online.
7. Check that a scheduled job fires at its next opportunity.

Steps 5 and 6 are the ones that catch a broken transport path. A healthy
container is not a working control plane.

## If it goes wrong

- **The application is unhealthy but the schema is unchanged.** Redeploy the
  previous digests.
- **The schema migrated and the previous version cannot read it.** Restore the
  backup. This is the case the restore test existed for.
- **Something is degraded but working.** Do not roll back reflexively. A
  rollback that requires a restore loses everything since the backup. Decide
  whether the degradation is worse than the data loss.

Details in [upgrade](upgrade.md).

## Then the agents

Only after the control plane is confirmed good. Update a small cohort first,
confirm they reconnect and can run an operation, then widen. Agents tolerate a
newer control plane, so there is no rush.

## Write down what happened

Note the version you moved from and to, when, who did it, and anything that
surprised you. The next upgrade is done by someone with less context than you
have right now, quite possibly you.
