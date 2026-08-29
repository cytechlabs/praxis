---
title: SSH and security
description: SSH policy, host keys, certificate-based identity, command whitelisting, and approvals.
---

Praxis ships with a layered SSH security posture. Every layer is optional individually; together they give you zero-trust-ish SSH across the fleet without surrendering operator ergonomics.

## SSH Security policies

`Secure > SSH Security` defines per-system policy. Each policy bundles:

- **host_key_policy** - `strict`, `tofu`, or `ignore` (default `tofu`)
- **log_commands** - log every executed command to `ssh_security_logs` (default `true`)
- **require_encrypted_keys** - reject passphrase-less private keys
- **max_connections_per_system** - connection-pool cap per host
- **connection_timeout_seconds** - socket-level timeout

Every system is assigned a policy (the "Default" policy is seeded at first boot). Edit a system to assign a stricter policy for sensitive hosts.

## Negotiated algorithms

A policy's cipher, MAC, and key-exchange allow-lists **narrow** what Praxis will negotiate. They can never widen it: an algorithm Praxis does not support stays unsupported no matter what a policy lists. A list that names nothing supported is reported as such, naming what it allowed and what is available, rather than failing later as an unreachable host.

These are refused on every connection, including guided onboarding preflight and hosts with no policy assigned:

| Refused | Why |
|---|---|
| DSA (`ssh-dss`) keys and host keys | Obsolete; OpenSSH disables it by default |
| RSA signatures over SHA-1 (the `ssh-rsa` signature algorithm) | Forgeable hash; OpenSSH 8.8 dropped it from the defaults |
| SHA-1 key exchange (`diffie-hellman-group1-sha1`, `-group14-sha1`, `-group-exchange-sha1`) | Obsolete |
| GSSAPI/Kerberos key exchange (`gss-*`) | Not used by Praxis |

**RSA keys are unaffected.** An RSA key is stored, offered, and pinned under the name `ssh-rsa`, because that is what RSA key *material* is called on the wire. It is signed with `rsa-sha2-512` or `rsa-sha2-256`, never SHA-1, and the same holds for the user certificates Praxis mints. There is nothing to convert.

Two consequences are worth knowing before you enroll:

- A host that offers **only** a SHA-1 key exchange, or only a DSA or `ssh-rsa` host key, cannot be reached. Every supported release in [the support matrix](support-matrix.md) offers modern algorithms out of the box; re-enable SHA-1 on the host and you have not made Praxis accept it.
- A host key already pinned as `ssh-dss` is refused with a message naming the type. Delete it under `Secure > SSH Security > Host Keys` and re-trust the host, which pins its modern key instead. Ed25519, ECDSA and RSA host keys are all pinned normally, so this affects DSA alone.

## Host key TOFU

Trust-on-first-use means Praxis records a system's SSH host key on the first successful connection and verifies it on every subsequent one. If the key changes you get a `host_key_changed` event - this is usually fine (OS reinstall, key rotation) but sometimes it isn't (MitM, impersonation).

Review `Secure > SSH Security` to approve or reject a changed key. Approving pins the new key; rejecting drops the connection pool entry for that host and blocks further connects until you investigate.

## SSH Identity (Vault CA)

Praxis can sign a short-lived user certificate per SSH session via the secrets service's SSH engine (bundled **OpenBao**, or an external OpenBao/Vault-compatible service). With CA trust deployed to a system, Praxis no longer uses passwords for that connection - each connect signs a fresh user cert (default TTL 300 s).

> **Interactive sessions use SSH.** The browser terminal (**Connect** on a host's detail page) always connects over SSH, even on agent-enrolled hosts. A host's transport preference (Auto / SSH / Agent) only routes non-interactive ops - command execution, file transfer, and facts. Opening a shell therefore needs SSH reachability and deployed CA trust on the target.

### Deploying CA trust

From a system's detail page click **Deploy CA Trust**. Praxis:

1. Reads the CA public key from Vault
2. Installs it at `/etc/ssh/trusted_user_ca_keys` (mode 0644, root-owned)
3. Adds `TrustedUserCAKeys` to sshd_config with a Praxis marker comment
4. Reloads sshd

Once deployed, `system.ca_trust_deployed = true` and the system is ready for cert-based auth. Password fallback remains functional - if Vault is down, Praxis drops back to password.

### CA rotation

Under **Settings > SSH Identity > Danger zone** there are two destructive buttons for CA lifecycle management:

- **Rotate CA** - regenerates the Vault SSH CA keypair (`DELETE` + re-POST `ssh-client-signer/config/ca`). Every existing signed user cert becomes unusable immediately. Praxis bumps the `ca_identifier`, clears `ca_trust_deployed = false` on every system (so admins redeploy explicitly), drops the in-memory SSH connection pool, and records a row in `ca_rotations`.
- **Revoke all user certs** - same pool clear + identifier bump without regenerating the Vault CA. Existing short-lived certs complete their 5-minute TTL naturally; Praxis stops reusing them immediately. Use this for "pooled session might be compromised, rotate out the credentials in memory" incidents.

Both actions are audited in the rotation history table on the same page.

### After rotation

A CA rotation forces you to redeploy CA trust to every system - the old public key no longer matches the new private key. Because Praxis clears the `ca_trust_deployed` flag on rotation, every system shows up as un-deployed in the fleet listing; bulk-select and click **Deploy CA Trust** to re-push. Password auth keeps working while the redeploy runs.

## Command execution

`Operate > Run Command` is the interactive shell for ad-hoc commands against one or more targets. Every command:

1. Runs through the **command validation** pipeline (regex rules + whitelist matching)
2. If `requires_approval` fires, creates an approval request instead of executing
3. Otherwise executes via the system's credential and records the result in `command_execution_results`

Output streams back live. Use for triage and one-offs; use Jobs for anything scheduled or repeated.

## Command Whitelist

`Operate > Command Whitelist` defines which commands are allowed and at what risk level. Each entry has:

- **name**, **description** - what this entry covers
- **command_pattern** + **is_regex** - either literal prefix or regex
- **risk_level** - `low` / `medium` / `high` / `critical`
- **category** - organisational grouping (package_management, system_info, etc.)
- **requires_sudo** - the whitelisted form always runs with sudo
- **requires_approval** - matching commands go through the approval flow
- **required_approvals** - (only when `requires_approval=true`) number of distinct admin approvals required before execution ([see below](#multi-level-approvals))
- **timeout_seconds** - per-command execution timeout
- **distro_mappings** - per-distro overrides for the same logical command (e.g. `apt-get install -y` vs `dnf install -y`)

Whitelist entries cascade: a command tries to match the most-specific entry for the target's distro; if none matches, the global pattern applies; if nothing matches, the command is rejected.

## Validation rules

Validation rules are pre-matching filters that reject dangerous patterns before whitelist matching runs. Use them for hard bans: `rm -rf /`, `:(){:|:&};:`, `dd if=/dev/zero of=/dev/sda`, and so on. Every validation run writes to `command_validation_log` - useful for "why was my command rejected" triage.

## Command approval workflow

When a command matches a whitelist entry with `requires_approval=true`, the execution is paused and a **CommandApproval** row is created. The requester gets an in-app notification; admins see the request in `Operate > Approval Queue`.

### Expiration

Every approval row gets an `expires_at` timestamp computed from the whitelist entry's `timeout_seconds` (default 24 h). A scheduler sweeper runs every 5 minutes and marks pending requests past their expiry as `expired`, notifying the requester. Expired requests can't be approved - the requester re-submits.

The approval queue shows a countdown chip on every pending row. Chips turn red when less than 5 minutes remain so reviewers can prioritise.

### Multi-level approvals

Set `required_approvals > 1` on a whitelist entry when a command is high-enough risk that a single approver isn't sufficient. For `required_approvals = 3`, the execution waits until three distinct admin users have voted approve. A single reject from any admin rejects the whole request immediately (no threshold, short-circuit).

The approval queue shows an "Approvals: X / Y" indicator for multi-level rows so reviewers know how many more signatures are needed. A user can only vote once per request.

### Comment per decision

Every approve or reject vote accepts an optional comment. Comments land in the `command_approval_votes` table with the voter's user_id and timestamp, and are surfaced in the approval detail view.

## Command history + metrics

`Operate > Command History` is the audit trail of every executed command: who, what, where, when, exit code, duration. Filter by user, system, whitelist entry, status.

`Operate > Command Metrics` rolls the same data up - top commands, top-risk commands, rejection rate, approval-wait distribution. Use it to tune the whitelist (frequently-rejected commands may need an explicit entry) and to catch drift in operator behaviour.
