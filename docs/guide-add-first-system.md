---
title: Add your first system
description: Walk through the guided setup that connects, verifies, and discovers a Linux host before adding it to the fleet.
---

Adding a host is a guided sequence rather than a form. Praxis connects to the
host, proves the credential works, and reads what the host actually is, all
before anything is written to your inventory. If any of that fails, nothing is
added and no licence capacity is used.

You need the **admin** or **maintainer** role, a host reachable over SSH from
the control plane, and an account on that host Praxis can log in as.

## Start the setup

Open **Operate > Add System**. The setup runs in seven steps, and you can go
back to any earlier one. Your progress is held server-side, so reloading the
page or coming back to the link resumes where you left off. A setup is private
to whoever started it, and expires after an hour of inactivity.

## 1. Connect

Give the address and SSH port. The address can be an IPv4 address, an IPv6
address, or a hostname the control plane can resolve. Port 22 is assumed.

Optionally give a display name. Leave it blank and Praxis uses whatever the host
calls itself, which it reads during discovery.

You are not asked for the distribution, group, or status here. Praxis works
those out by looking at the host, and asking you to declare them up front would
mean recording a guess.

Changing the address or port later discards the verification, the discovered
details, and any approved host key. A different endpoint is a different host
until proven otherwise.

## 2. Authenticate

Choose a stored credential. The list shows the account name, authentication
method, and elevation method, so you can tell a password credential from a key,
and passwordless sudo from one that needs a password. Where the secret lives is
deliberately not shown.

Password and SSH-key credentials both need a username. If the credential does
not carry one and none can be derived, verification reports
`username_missing` rather than failing as a wrong password.

Creating a credential from here requires tenant-wide admin access, matching the
rule the credentials API already enforces. If your access is scoped to specific
hosts, the setup says so before you fill anything in, and you select an existing
credential instead.

The SSH policy sets which algorithms are allowed and whether the host key must
be verified. The Default policy is preselected. A host with no policy at all
still requires host-key verification: an absent policy is missing configuration,
never permission to skip the check.

## 3. Verify

Praxis connects and reports each part separately, so a host that answers but
refuses the password reads as exactly that:

| Check | What it proves |
| --- | --- |
| Address | The address is a usable IP or resolvable name. |
| Network reachability | Something is listening on that port. |
| Host identity | The SSH handshake completed and the host key is known and approved. |
| Credential authentication | The stored credential logged in. |
| Command execution | The account can actually run a command. |
| Elevation (sudo) | The account can elevate, if the credential says it should. |

Each result carries a stable reason code:

| Code | Meaning |
| --- | --- |
| `verified` | The check passed. |
| `address_invalid` | Not a valid address or resolvable name. |
| `network_unreachable` | No route, or the port is closed. |
| `connection_timeout` | No answer in time; often a firewall dropping rather than refusing. |
| `host_key_unknown` | First contact. The fingerprint needs your approval. |
| `host_key_mismatch` | The host offered a different key than the one you approved. |
| `ssh_policy_rejected` | No algorithm in common, or the key type is not permitted. |
| `authentication_failed` | The host refused the credential. |
| `username_missing` | The credential names no account to log in as. |
| `key_type_unsupported` | The stored private key is not a usable format. |
| `command_failed` | Logged in, but a basic command did not run cleanly. |
| `sudo_password_required` | Elevation needs a password the credential does not carry. |
| `sudo_denied` | The account may not elevate on this host. |
| `sudo_unavailable` | No usable `sudo` was found. |

### Approving the host key

On first contact Praxis shows the key the host offered and stops. Compare the
SHA-256 fingerprint against the host itself before approving:

```sh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Approve it only if it matches. If it does not, something other than the host you
intend may be answering at that address, and the setup should be abandoned.

Once you approve a key, that key is pinned for the rest of the setup. If the
host later offers a different one, verification fails with `host_key_mismatch`
and will not continue. Nothing is written to the trusted host-key store until
the host is actually added.

### Skipping verification

You can proceed without verifying, but the result is honest about it: the host
is added as **Inactive**, its connection state is **Pending**, and Praxis does
not treat it as reachable. The finished page says so and points at the next
action. Praxis cannot inventory, patch, or connect to a host it has never
reached, so treat this as recording intent rather than adding a working host.

## 4. Discover

Praxis reads the host's own name, fully qualified name, distribution and
release, architecture, and package manager over the connection it just proved.

If the distribution maps to one Praxis supports, the setup continues. If it does
not, you are asked to confirm explicitly: pick the closest supported match, or
continue without one. Continuing without a match is allowed, but package and
patch features may not work until the distribution is supported.

Discovery needs a working session. If authentication has stopped working since
you verified, discovery reports the same reason code rather than a generic
failure, and you can retry it on its own.

## 5. Organize

Choose where the host belongs and how it is labelled: group, environment,
transport preference, tags, and a description. The group defaults to **All
Systems** and the SSH policy to the real **Default** policy.

You are not asked to choose a lifecycle status. Whether a host is Active is
decided by whether verification succeeded, not by asking you to assert it.

Everything on this step is stored with the host. Description, tags, SSH port,
and the selected SSH policy are all persisted.

## 6. Confirm

The summary is exactly what will be created, built server-side rather than
reassembled from what your browser remembers. It shows the verification result,
the discovered distribution, the credential, the host-key decision, every
organization value, and the status the host will be given.

It also lists what becomes available afterwards. Those are follow-ups, not
things that happen now.

## 7. Finish

Adding the host is a single step that rechecks everything that could have
changed since you confirmed: your access, the credential and group still
existing, whether the hostname or address is now taken, and whether you have
licence capacity. The capacity check runs immediately before the host is
created, so an abandoned setup never holds a seat.

If you submit the same confirmation twice, you get the same host back rather
than a duplicate. If you changed something after confirming, the setup asks you
to review and confirm again rather than creating something you did not see.

## Afterwards

The finished page links straight to the host. From there you can collect facts,
scan packages, change the credential, and retest the connection.

**Access Broker enrolment is a separate, explicit step.** It changes the host's
SSH configuration, so it never happens as part of adding a host. See
[onboard and offboard people](guide-onboarding-offboarding.md).

Installing the agent is also separate and optional. SSH remains the default
transport. See [enroll hosts](enroll-hosts.md).

## When it does not work

**The setup expired.** Setups expire after an hour of inactivity, and after
eight hours regardless. Nothing was added; start again.

**"This setup changed in another tab."** The same setup was edited somewhere
else. Reload it and continue from the current state.

**The host key changed.** If a host was genuinely rebuilt, remove its stored key
under **SSH Security > Host Keys** and add it again. Do not approve a changed
key without knowing why it changed.

**Sudo fails but everything else passes.** The host is fine; the credential's
elevation setting does not match reality. Fix the credential's sudo method, or
grant the account passwordless sudo, then verify again.

**A duplicate hostname or address.** Praxis rejects both. Addresses are unique
across the fleet. Check [all systems](fleet-and-hosts.md) for the existing
record.

For anything else, see [troubleshooting](troubleshooting.md).
