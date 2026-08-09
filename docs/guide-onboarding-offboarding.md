---
title: Onboard and offboard people
description: Give a new person the right access on day one, and take all of it away on their last day.
---

Two checklists. The second one matters more, and is the one that gets skipped.

## Onboarding

### 1. Create the identity

Prefer single sign-on. With an identity provider wired up, a new person signs in
and Praxis provisions an account keyed to their provider subject and issuer on
first login. Role assignment follows your group mappings; anyone who maps to
nothing lands as `auditor`. See [single sign-on setup](oidc-setup.md).

For a local account, **Settings > Admin > Users > New User**.

### 2. Give the smallest role that works

| Role | Envelope |
|---|---|
| `admin` | Everything, including users, CA rotation, approvals, and secrets configuration. |
| `maintainer` | Register hosts, build jobs, edit whitelist entries. Cannot edit users or rotate the CA. |
| `auditor` | Read-only, plus audit export. Cannot execute or mutate. |
| `viewer` | Read-only, without the wider auditor envelope. |

Roles union, so grant one. Most people are `maintainer`; reviewers and
compliance staff are `auditor`.

### 3. Scope the fleet

Roles say what someone can do. Fleet scope says which hosts they can do it to.
An out-of-scope host is a not-found rather than a permission error, so scoped
operators do not learn that hosts exist outside their scope. Set the scope to
the group or smart group the person actually looks after.

### 4. Host-level access, if they need a shell

Interactive access provisions a managed Linux account on the target hosts. Grant
it deliberately and only for the hosts in their remit. Fleet role accounts get
no standing `sudo`; privileged automation runs under a dedicated automation
credential, not under a person's login.

### 5. Confirm it works, and no more than it should

Have them sign in and open a host in their scope, then confirm a host outside
their scope is not visible. Verifying the negative is the part that catches a
mis-scoped grant.

## Offboarding

Work top down. Each step is independent; do not stop early because the first one
seemed to work.

### 1. Cut authentication

- **Single sign-on:** disable the person in your identity provider. This stops
  new logins.
- **Local account:** deactivate rather than delete. Deactivation blocks login
  and preserves their audit history. Deleting the user removes the trail of what
  they did.

### 2. Revoke live sessions

Disabling an account does not close a session that is already open.
**Settings > Admin > Sessions** lists active refresh tokens with user, issue
time, last use, and source IP. Revoke all of theirs. This is also the fast way
to lock someone out while you investigate, without deleting anything.

### 3. Remove host access

Remove their fleet access grants so the managed Linux accounts are
deprovisioned from hosts. This is the step that has a real convergence time
rather than being instant.

**Read [access revocation](access-revocation.md) before you assume this is
done.** It states how quickly each kind of access actually stops working. If the
departure is hostile, use those timings to decide what else you need to do now
rather than waiting for convergence.

### 4. Rotate anything they held

If the person had access to shared credentials, rotate them:

- Managed credentials, from **Secure > All Credentials**. Rotation pushes a
  new secret and every host picks it up on its next connection.
- The SSH signing CA, if they could have extracted signing material. Rotation
  invalidates every issued certificate immediately and requires redeploying
  trust across the fleet. See [SSH and security](ssh-and-security.md).

Rotate on the basis of what they could reach, not what you believe they used.

### 5. Reassign what they owned

Scheduled jobs, alert configurations, and patch policies keep running after
their author leaves. Find anything that names them and give it a new owner.

### 6. Record it

Deactivation, session revocation, grant removal, and credential rotation all
write audit rows. Export the window covering the offboarding if you need to show
it was done. See [export evidence for an audit](guide-evidence-export.md).

## Related

- [Administration](admin.md)
- [Grant temporary access](guide-temporary-access.md)
- [Run an access review](guide-access-review.md)
