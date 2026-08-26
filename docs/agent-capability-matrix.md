---
title: Agent and SSH capability matrix
description: Which operations each transport supports, so you can tell where the thin agent and SSH differ.
---

This page states, capability by capability, what the thin agent does and what
only SSH does. It tracks the behavior of the agent, the agent broker, and the
backend transport layer, so a claim made here is a claim the code keeps.

Two transports move host work in Praxis:

- **SSH**: the backend (or the SSH access broker) opens a paramiko session to
  the host. Always available for a reachable, credentialed host.
- **Agent**: the host runs the `praxis-agent` binary, which holds a long-lived
  mTLS WebSocket to the agent broker; the backend dispatches ops over that
  tunnel via the broker's internal API.

The transport for a capability is chosen by `TransportFactory.get_transport`
(`backend/app/services/transport/factory.py`) **only for capabilities that go
through the factory**. Many capabilities call `SSHService` directly and are
SSH-only regardless of whether a healthy agent tunnel exists; see the matrix.

---

## Transport-preference semantics

`System.transport_preference` ∈ `{auto, ssh, agent}` (default `auto`), consumed
by the factory:

| preference | agent tunnel healthy | agent tunnel down |
|---|---|---|
| `ssh`   | SSH | SSH |
| `auto`  | Agent | SSH (silent fallback) |
| `agent` | Agent | **`TransportUnavailable`, with no fallback** |

Force-agent (`agent`) fails loudly rather than silently dropping to SSH; the
factory raises and the op records an error. This preserves the operator's
intent ("I want agent or nothing").

> **Important truth for docs:** `transport_preference` only affects the
> **factory-routed** capabilities below. Capabilities marked *SSH-only
> (bypasses factory)* ignore the preference entirely, so setting a host to
> `agent` does **not** make package scans, repo management, health checks,
> user provisioning, drift, or the web terminal run over the agent.

---

## Capability matrix

Legend: **Either** = factory-routed (honors preference) · **SSH-only** =
hardcoded to `SSHService` · **Agent-push** = agent originates the data.
"Priv?" = requires root/sudo on the host.

| Capability | Transport | Priv? | Push/Pull | 1.0 claim | Code path |
|---|---|---|---|---|---|
| Command execution (`/execute`) | **Either** | No | Pull | ✅ agent or SSH | `command_execution_service.py` → `get_transport` → `run_command` |
| File download / upload | **Either** | No | Pull | ✅ agent or SSH | `file_transfer_service.py` (`_resolve_file_transport`) |
| Directory browse (ls/stat/mkdir/unlink) | **SSH-only** | No | Pull | ⚠️ SSH-only; force-agent → `transport_unsupported` | `file_transfer_service._open_sftp` (paramiko) |
| Facts refresh (on-demand) | **Either** | No | Pull | ✅ agent or SSH (agent gated on `facts` capability) | `routes/facts.py` (agent inline / SSH fallback) |
| Facts (autonomous push) | Agent-push | No | **Push** | 🚫 Not available: the backend can ingest `facts_report`, the agent does not emit it | `broker/handlers.py:_route_facts_report` (no agent sender) |
| Facts (enroll-time) | Agent-push | No | Push | ✅ optional at enroll | `routes/agent_enroll.py` → `facts_service.ingest` |
| Package scan / audit / update / hold | **SSH-only (bypasses factory)** | scan No; apply/hold **Yes** | Pull | ⚠️ SSH-only | `package_service.py` `execute_command` / `execute_privileged_command` |
| Health / connection test | **SSH-only** | No | Pull | ⚠️ SSH-only (distinct from broker tunnel health) | `health_service.py` → `ssh_service.test_connection` |
| Web terminal / interactive PTY | **SSH-only** | No | Pull (interactive) | 🚫 Not available over the agent (see below) | `session_service.py` `invoke_shell` (paramiko) |
| Session recording | **SSH-only** (tied to PTY) | No | n/a | 🚫 Not available over the agent | `recording_service` over the SSH PTY |
| Patch apply / reboot / rollback | **Either** | **Yes (sudo)** | Pull | ✅ agent or SSH; sudo via `wrap_argv_for_sudo` | `patch_execution_dispatch_service.py` `get_transport` |
| Baselines / drift checks | **SSH-only** | No | Pull | ⚠️ SSH-only | `drift_service.py` `execute_command` |
| Repo management (list/add/remove/sync) | **SSH-only (bypasses factory)** | add/remove/sync **Yes** | Pull | ⚠️ SSH-only | `repo_service.py` `execute_privileged_command` |
| Fleet access / user provisioning | **SSH-only** | **Yes (sudo)** | Pull | ⚠️ SSH-only | `host_user_provisioning_service.py` |
| Content profile apply | **Either** | depends | Pull | ✅ agent or SSH | `routes/content_profile_apply.py` `get_transport` |
| Mirror host trust | **Either** | Yes | Pull | ✅ agent or SSH | `routes/mirrors.py` `get_transport` |

### Agent op ceiling (what the tunnel can actually do)

The backend can dispatch exactly four ops over the tunnel:
`exec`, `file_get`, `file_put`, `facts`
(`broker/internal_api.py` + `broker_client.py`). The `AgentTransport`
implements `run_command`, `open_file_get`, `open_file_put`; `open_pty` raises
`TransportUnsupported` (`transport/agent.py`).

The Go agent advertises more than the backend uses (`exec`, `file_get`,
`file_put`, `pty`, `facts`). **PTY and autonomous facts are the two agent
capabilities the backend does not exercise**; see the limits below.

---

## Enrollment, identity, and security posture

- **Two enrollment paths**, both terminating in the same Vault-signed cert:
  - Activation token: `POST /agent/enroll` with `X-Praxis-Activation-Token`;
    single-use, scoped, TTL-bounded, bcrypt-at-rest, host-fingerprint
    idempotent (`activation_token_service.py`).
  - Admin SSH-once: `POST /agent/bootstrap/{system_id}`, admin-JWT-gated,
    proves the host via an SSH session (`routes/agent.py`).
- **Identity is backend-controlled.** The signing role discards the CSR's CN
  and SANs; the real identity is the URI SAN `praxis://system/<id>` minted by
  Vault (`agent_identity_service.py`). A host cannot influence its identity via
  the CSR.
- **No cross-system impersonation.** Tunnel admission requires the peer cert to
  chain to the agent CA **and** match the per-system `agent_cert_serial` +
  `agent_cert_fingerprint` with `agent_status == active`
  (`broker/handlers.py:make_db_validator`). Agent A's cert carries A's
  serial/fingerprint and cannot pass as system B.
- **Facts cannot be spoofed.** The facts writer keys on the mTLS-validated
  `system_id` and ignores any `system_id` in the message body
  (`broker/handlers.py`).
- **No secrets in logs.** Audited across the agent, broker, and support bundle:
  no private key, cert PEM, activation token, or Vault/OpenBao token is logged.
  The support bundle additionally redacts PEM keys, tokens, JWTs, and DSN creds
  (`core/redaction.py`).
- **OpenBao bootstrap.** The bundled secrets runtime is OpenBao,
  reachable at the compose service name `vault:8200` (name kept for compat).
  `vault/scripts/init-vault.sh` idempotently provisions the `praxis-agent-ca`
  PKI mount used to sign agent CSRs. mTLS uses TLS 1.2+; `VERIFY_X509_STRICT`
  is cleared in the broker context (documented; required for Python 3.13/3.14
  asyncio mTLS).
- **`(agent.key, agent.crt)` is a bearer credential.** Copying both files to
  another host makes that host the same system; the agent binds nothing to
  hardware/TPM. Treat `agent.key` (mode 0600) as a secret; this is a documented
  1.0 posture, not a bug.
- **Agent runs as root** with `file_put`/`exec`/`pty` primitives whose
  authorization is delegated to the broker. `praxis-agent.service` applies
  `NoNewPrivileges`/`PrivateTmp`/kernel protections but intentionally not
  `ProtectSystem=strict` (the agent must write anywhere by design).

---

## Agent connection states

Two **orthogonal** axes plus one unrelated SSH concept, which are easy to conflate:

| Axis | Field | Values | Source |
|---|---|---|---|
| Enrollment lifecycle | `agent_status` | `not_enrolled`, `active`, `disabled`, `revoked` | DB (`System.agent_status`) |
| Live tunnel liveness | `agent_liveness` | `online`, `stale`, `offline`, `unknown` | broker registry via `GET /agent/status/{id}` |
| SSH reachability | `connection_status` | `auth_failed`, and so on | `SystemMetadata`: **SSH only, not the agent** |

`agent_liveness` is derived live from the broker's in-memory registry, not from
the `agent_last_seen_at` timestamp:

- `online`: live tunnel and a heartbeat within `HEARTBEAT_DEAD_SECONDS` (90s)
- `stale`: tunnel registered but heartbeat past the dead window
- `offline`: broker has no tunnel for this system
- `unknown`: the broker itself was unreachable, which is deliberately distinct
  from `offline` so the agent is never reported gone when it could not be asked

`agent_last_seen_at` and `agent_version` are persisted on connect and by the
throttled heartbeat writer.

> **No thin-agent status screen.** These states are exposed by the API only.
> The "enrolled" indicator on the system page refers to the **SSH access
> broker** (CA trust and the principals hook), not the agent.

---

## Clean-host enrollment smoke (manual)

Automated smokes (`scripts/test-first-enrolled-host-smoke.sh`,
`scripts/test-fresh-install-smoke.sh`) exercise `/agent/ca-bundle` +
`/agent/enroll` redemption and the `/agent/bootstrap.sh` install script, but
they stop **before** the real agent binary dials the broker. The end-to-end
manual smoke below closes that gap.

Prereqs: a running Praxis stack, an admin login, and a clean Linux host
(systemd, amd64/arm64) with network reach to the backend + broker.

1. **Pre-register the host** in Praxis so it has a `system_id` (agent_status
   starts `not_enrolled`).
2. **Mint an activation token**: Settings > Activation Tokens > create, scoped
   to that system. Copy the one-time `praxis_…` token.
3. **Install the agent** on the host (from a release tarball):
   ```sh
   sudo ./install.sh --broker-url wss://<broker>:8443 \
                     --backend-url https://<backend> --system-id <id>
   ```
4. **Enroll** following `agent/packaging/README.md` → *Path A*: `gen-keypair`,
   `gen-csr`, fetch `/agent/ca-bundle`, `POST /agent/enroll` with the token,
   `install-cert`.
5. **Start the service:** `sudo systemctl enable --now praxis-agent`.
6. **Verify online:** `GET /agent/status/<id>` →
   `agent_status: active`, `agent_liveness: online`, and a populated
   `agent_version` + `agent_last_seen_at`.
7. **Verify reconnect:** stop/start the broker (or `systemctl restart
   praxis-agent`); the agent redials with jittered backoff and returns to
   `online`. Disabling the host NIC drives `agent_liveness` to `stale` then
   `offline` without stalling unrelated API requests.
8. **Verify identity rejection:** copying another system's cert/key does not
   grant this system's identity; the broker rejects on serial/fingerprint
   mismatch (`agent_status` stays as-is; tunnel is refused).

---

## Limits of the agent transport

Plan around these. Each is a property of the shipped behavior, not a gap you
can configure away.

1. **No interactive shell over the agent.** The Go agent implements `pty` and
   the broker negotiates it, but the backend never dispatches it and
   `AgentTransport.open_pty` raises `TransportUnsupported`. Web terminals and
   session recording are SSH-only, because SSH is what carries the operator's
   Unix principal.
2. **No autonomous facts push.** The backend can ingest an agent-pushed
   `facts_report`, but the agent emits only `hello`, `heartbeat`, and
   `op_complete`. Facts are collected on demand or at enrollment.
3. **Revoking an identity does not drop a live tunnel.** Identity is re-checked
   at handshake only, so a revoked agent keeps its tunnel until its mTLS cert
   expires (one hour or less) or the process restarts. The backend and the
   broker are separate processes with no disconnect channel between them, which
   bounds the exposure to the certificate lifetime.
4. **No thin-agent status screen.** `agent_status`, `agent_liveness`,
   `agent_version`, and `transport_preference` are API-only. No operator screen
   surfaces them, and the system page's "enrolled" label refers to the SSH
   access broker.
5. **The support bundle omits broker and agent logs.** It carries
   backend-process logs only: the broker is a separate container and the agent
   lives on the remote host.
6. **Distro and init scope.** Linux only, systemd only (or `--no-systemd` with
   operator-managed supervision), amd64 and arm64 only. See the
   [Linux support matrix](support-matrix.md).
