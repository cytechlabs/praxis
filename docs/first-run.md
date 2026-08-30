---
title: First run
description: Secure the bootstrap administrator, set the deployment identity, and check the stack before enrolling hosts.
---

Work through this once, immediately after [install](install.md), before you
enroll any hosts. Everything here is a one-time task that is awkward to correct
later.

## Sign in as the bootstrap administrator

The first boot seeds a single administrator. The username is `praxisadmin`
unless you set `ADMIN_USERNAME`. It is not `admin`, because per-user fleet
access maps a Praxis username onto a managed Linux login and `admin` commonly
collides with an existing account or group on a host.

Sign in at your `PUBLIC_BASE_URL` with the `ADMIN_PASSWORD` you configured
before first boot. A fresh production deployment fails closed when that value
is empty; Praxis does not generate the password or write it to the backend log.

## Clear `ADMIN_PASSWORD` once you are in

`ADMIN_PASSWORD` and `ADMIN_USERNAME` are first-run inputs, not settings the
deployment keeps applying. A deployment records that it has been initialized,
and later restarts read that record rather than the environment: an
administrator you deactivate, rename, or delete stays that way, and changing
`ADMIN_USERNAME` does not create a second one.

Remove `ADMIN_PASSWORD` from `.env` once you have signed in. The value is spent
at that point, and leaving it in place only matters if you ever roll back to a
release that still treated it as desired state.

The one state this leaves without a way in is deleting every user. Recovering
from that is deliberate and local to the host running the stack:

```sh
docker compose exec backend python /app/scripts/reset_bootstrap_admin.py
```

It refuses while any user still exists, and it creates nothing itself: it clears
the record so the next restart provisions the administrator from `.env` the way
a first boot does. Set `ADMIN_PASSWORD` again before that restart.

## Rotate the bootstrap password immediately

Change it under **Settings > Account > Change Password**. Leaving the seeded
password in place is the single most common misconfiguration in deployments
that were promoted from an evaluation.

Better still, wire single sign-on, grant an administrator role to a real
identity, and deactivate the bootstrap account. Deactivating preserves its
audit history; deleting it does not. See [single sign-on setup](oidc-setup.md)
and [administration](admin.md).

## Check the secrets service

Open **Secure > Vault Management**. The health status must read healthy. A
sealed or tokenless secrets service means no credential can be read, so no host
will be reachable, and the failure will present as SSH errors rather than as a
secrets problem.

For the bundled service, record the unseal material somewhere you can reach
during an outage but that is not the same host. See
[production hardening](production-hardening.md).

## Apply a licence, or stay on the free edition

The free edition manages up to 15 hosts and needs no licence, no account, and
no network call. If you have bought a paid tier, apply the licence now so the
host cap is correct before you start enrolling.

Open **Settings > License**, copy the installation ID shown there, and follow
[licensing and activation](licensing.md).

## Set the deployment identity

Under **Settings > General**, set the site name and the default landing page.
Under **Settings > Timezone**, choose how timestamps render. Praxis stores every
timestamp in UTC; this only affects display, so administrators in different
zones each see their own local time without the stored data drifting.

## Review the connection defaults

**Settings > Connection Settings** holds the SSH tunables that apply to every
host unless a per-host policy overrides them: connection timeout, pool size,
idle eviction, the consecutive failure count that marks a host unreachable, and
the default port. The defaults suit a normal network. Adjust them before
enrolling if yours is not, for example a high-latency link that needs a longer
timeout and a smaller pool.

## Create the first real credential

Every host needs a credential to be reachable. Create one now under
**Secure > All Credentials > New Credential**, using a dedicated automation
account rather than a human login. Choose an escalation method deliberately:
patch, rollback, and reboot dispatch refuse to run against a credential with no
valid `sudo` method rather than silently running unprivileged.

[Credentials and secrets](credentials-and-vault.md) covers managed versus linked
credentials and rotation.

## Delete the demo data

An evaluation deployment seeds a demo credential. Delete it once a real
credential exists.

## Next

Continue to [enroll hosts](enroll-hosts.md).
