---
title: Uninstall
description: Remove the agent from a host, and remove the Praxis control plane, without leaving orphaned access behind.
---

Removing software is not the same as removing access. Work through this in
order so a decommissioned host does not keep a valid identity and a removed
control plane does not leave managed accounts behind on the fleet.

## Remove the agent from one host

```sh
cd praxis-agent-<version>-linux-<arch>

sudo ./uninstall.sh --dry-run   # preview, changes nothing
sudo ./uninstall.sh             # stop and remove the service and binary
```

By default this keeps `/etc/praxis-agent`, so the host can be reinstalled later
without re-enrolling. To remove the configuration, private key, and certificate
as well:

```sh
sudo ./uninstall.sh --purge
```

`--purge` is irreversible. The host must be re-enrolled to come back.

**Removing the agent does not revoke its certificate.** The identity remains
valid until you revoke the host in the control plane. Do that as a separate,
deliberate step whenever you are decommissioning rather than reinstalling.

## Decommission a host properly

1. Revoke access in the control plane. Setting the host to **Decommissioned**
   excludes it from every job and alert, keeps its history for audit, and stops
   it counting toward the licensed host cap.
2. Remove the agent with `--purge` if one is installed.
3. Remove certificate trust from the host if you deployed it and the host will
   keep running for another purpose.
4. Remove the automation account from the host, or remove its escalation
   entry, if Praxis was the only thing using it.

Timings for when each kind of access actually stops working are in
[access revocation](access-revocation.md). Read that before assuming a
revocation is immediate.

Prefer decommissioning to deleting. A deleted host takes its history with it;
a decommissioned one stays auditable.

## Remove the control plane

Stop the stack, keeping all data:

```sh
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    --profile bundled --profile proxy down
```

This removes the containers and network. Volumes survive, so bringing the stack
back up returns you to the same deployment.

To remove the data as well:

```sh
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    --profile bundled --profile proxy down -v
```

`-v` destroys the database volume, the secrets service volume, and any mirror
content. **This is irreversible and it destroys your audit history.** Take and
verify a backup first if there is any chance you will want the data. See
[backup and restore](backup-restore.md).

## Before you destroy a control plane

Removing Praxis does not undo what Praxis did to your hosts. Decide
deliberately what should outlive it:

- **Managed user accounts.** Fleet access provisions Linux accounts on hosts.
  Remove them through Praxis before it goes away, or you will be cleaning them
  up by hand across the fleet.
- **Certificate trust.** Hosts keep trusting the signing CA until the trust
  file is removed. A host that still trusts a CA whose private key you have
  destroyed is not exploitable, but it is untidy and confusing later.
- **Content profiles.** Applying a profile writes package source configuration
  on the host. Those hosts will keep pointing at mirrors that are about to stop
  existing.
- **Audit evidence.** Export anything a compliance regime expects you to retain
  before destroying the database. See
  [export evidence for an audit](guide-evidence-export.md).
- **Secrets.** Credentials live in the secrets service, not in the Praxis
  database. Destroying its volume destroys them. Make sure any password or key
  you still need exists somewhere else first.

## Air-gapped and mirror content

Mirror bytes can be large and live in their own volume. If you are reclaiming
space rather than removing Praxis, delete the mirrors through the interface so
the metadata stays consistent, rather than deleting files underneath the
application.
