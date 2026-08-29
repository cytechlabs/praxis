---
title: Credentials and secrets
description: Manage SSH credentials backed by a Vault-compatible secrets service.
---

Praxis never stores secrets in its own database. Every SSH credential is a metadata row in the `credentials` table that points to a path in the secrets service - the bundled **OpenBao** (a Vault-compatible secrets service), or an external OpenBao/HashiCorp Vault cluster - where the actual password or private key lives. This section covers both halves.

## Credentials

`Secure > All Credentials` is the master list. Each row is one credential with:

- **Name** - human-readable label
- **Auth method** - `password` or `ssh_key`
- **Username** - Linux user Praxis connects as (typically a dedicated automation account, e.g. `ubuntu` or a `praxis-svc` user)
- **Sudo method** - `none`, `password`, or `nopasswd` - how a dedicated **automation** credential escalates for privileged Praxis workflows (not a user grant; see below)
- **Vault path** - where the secret is stored; auto-generated for managed credentials, user-supplied for linked credentials
- **Linked system count** - how many Systems reference this credential

### Managed vs linked

Praxis supports two credential modes:

- **Managed** - Praxis generates the Vault path on create and is authoritative for the secret. Rotation, renames, and updates happen through Praxis. Use this for 95 % of cases.
- **Linked** - Points at an existing Vault path that some other system writes. Praxis reads the secret at connect time but never writes. Use this when another tool owns credential lifecycle (Ansible vaults, rotated out-of-band by IAM tooling).

The credential form has a mode toggle. Once saved, mode can't change - create a new credential if you need to migrate between modes.

### Auth methods

- **password** - username + password. Password is written to Vault under `password`. Cheap and simple for lab / dev fleets.
- **ssh_key** - username + private key body. The key is written under `ssh_key`; a passphrase-protected key needs its passphrase stored in the same secret under `ssh_passphrase`. Preferred for production because keys can be rotated without locking out humans.

### Private key formats

Praxis reads Ed25519, ECDSA (nistp256, nistp384, nistp521), and RSA private keys, in both the `OPENSSH PRIVATE KEY` container that current `ssh-keygen` writes by default and the older `RSA PRIVATE KEY` / `EC PRIVATE KEY` PEM envelopes. Ed25519 is the recommended default for new credentials.

Strength is checked against the key's own algorithm. RSA keys must be at least 2048 bits, and an SSH security policy's minimum key size raises that floor for the systems it covers - see [ssh-and-security.md](ssh-and-security.md). Ed25519 and ECDSA carry their strength in the algorithm and curve, so the RSA size rule is not applied to them.

Three formats are rejected outright, with an error naming the format: DSA keys, PKCS#8 containers (`BEGIN PRIVATE KEY`), and PuTTY `.ppk` files. Convert a PuTTY key first with `puttygen mykey.ppk -O private-openssh-new -o mykey`. DSA is refused for the algorithm, not the envelope, and cannot be enabled - see [negotiated algorithms](ssh-and-security.md#negotiated-algorithms).

A stored RSA key is used exactly as it is. Its serialized name is `ssh-rsa`, which is what RSA key material is called on the wire, and Praxis signs with it using `rsa-sha2-512` or `rsa-sha2-256`. Nothing needs regenerating or converting.

An encrypted key is usable only when its passphrase is stored under `ssh_passphrase` in the same secret. Without it the connection fails and says so; Praxis never falls back to another authentication method to work around an unusable key.

### Sudo methods

This setting governs only how **Praxis automation** escalates when a named workflow (patching, package jobs, reboots) needs privileged host access using a dedicated automation credential. It is **not** a user-facing root grant: in Praxis 1.0 fleet-role user accounts receive no standing sudo, and interactive root is out-of-band under your ops runbook.

When automation runs a privileged command:

- **none** - no escalation; commands run as the connecting Linux user; fine for read-only inventory
- **password** - run `sudo -S` and pipe the automation account's Vault-stored password into stdin
- **nopasswd** - run `sudo -n`; requires a `NOPASSWD:` entry for the automation account, scoped to the Praxis workflow commands

Prefer `nopasswd` for a dedicated automation account, scoped to the commands Praxis actually runs. Keep that account distinct from human logins.

### Rotation

Click **Rotate** on a managed credential to generate a fresh password or key and push it to Vault atomically. The credential's `updated_at` advances and every System using that credential picks up the new secret on its next connection - no restart needed. Rotation records an audit entry visible in `Secure > Audit Log`.

For ssh_key credentials, rotation generates a new keypair and writes it to Vault. Remember to deploy the new public key to the target systems before/after rotation; Praxis can do this via a job or as part of CA trust deployment (see [SSH & Security](ssh-and-security.md)).

## Vault Management

`Secure > Vault Management` surfaces secrets-service connection state and lets admins switch between the embedded service (bundled **OpenBao**, for simple deployments) and an external OpenBao/HashiCorp Vault cluster.

### Internal vs external

- **Internal** - the bundled **OpenBao** container that ships with Praxis (dev default). Data lives in a Docker volume; fine for single-node deploys, not for HA
- **External** - point at a managed OpenBao/Vault-compatible URL and auth via a token Praxis reads from the `VAULT_TOKEN` environment variable

Switching mode restarts the Praxis backend's Vault client. Existing credentials keep pointing at their paths - if those paths don't exist in the new Vault, connection attempts fail and you'll see clear error messages in the SSH error surface.

### Vault paths

Praxis writes under the `praxis/` path prefix. Component names are validated (`[a-zA-Z0-9._\-/]+`, no traversal). Managed credentials get paths like `praxis/credentials/{name}`; the SSH CA config lives at `ssh-client-signer/config/ca`. During an outage an operator can recover a stored credential directly from Vault under the ops runbook - Praxis itself issues no in-product break-glass root path.

### Health status

Vault Management shows the last health check result (`healthy`, `sealed`, `no_token`, `connection_error`). A failed health check means no new connections will succeed, but existing pooled SSH sessions keep working until they time out. Unsealing or restoring the token clears the state on the next check.

### Seed credentials vs real credentials

In dev mode Praxis seeds a demo credential. Delete it once you've registered real credentials. The Vault path cleans up with the credential by default (managed mode); linked-mode deletion only removes the Praxis row, not the Vault secret.

## Secret hygiene

- Never commit a `VAULT_TOKEN` or a credential password to git - use a secrets store or environment-level config
- Rotate credentials on a schedule; a recurring job can run rotation against a smart group
- Audit access via `Secure > Audit Log` filtered to `credential_change`
- The `credential_change` event type fires for every rotation / create / delete - subscribe a Slack alert config to it for security visibility ([Alerts & Webhooks](monitoring-and-alerts.md#alerts-and-webhooks))
