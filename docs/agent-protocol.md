---
title: Agent protocol
description: Thin-agent identity, tunnel, operation, and audit protocol contract.
---

## Overview

The Praxis thin agent is an outbound-only Linux daemon that gives the
control plane a multiplexed, mTLS-authenticated channel to a host without
requiring inbound SSH from the control plane. The SSH path remains the
default; the agent is opt-in per system.

Trust boundary is rooted in a dedicated Vault PKI mount,
``praxis-agent-ca``. Agents present a 1h mTLS cert; the backend verifies
the chain on every tunnel connect and on every renewal CSR.

## Versioning

Every protocol message carries a single-byte protocol version. The current
version is **`0x01`**. Backward compatibility within a major version is
mandatory; protocol-breaking changes bump the version byte and require a
coordinated agent rollout.

## Identity model

| Field | Value |
|---|---|
| CA mount | ``praxis-agent-ca`` (Vault PKI) |
| Role | ``agent`` |
| Cert TTL | 1h (role max) |
| Renewal cadence | 45 min over the live tunnel |
| Renewal grace | 24h past expiry, provided ``agent_status = active`` |
| Cert subject | CN = ``system-<id>.agent.praxis.internal`` (backend-controlled; CSR CN ignored) |
| Cert SAN | URI = ``praxis://system/<id>`` (real identity; backend-set, CSR SANs ignored) |
| Key type | EC P-256 |
| Revocation | ``agent_status -> revoked``; serial blocklisted; no CRL/OCSP |

State machine (single source of truth on ``System.agent_status``):

```
not_enrolled -> active <-> disabled
                   |
                   v
                revoked  (terminal; re-enrollment needs a new identity)
```

## Bootstrap (SSH-once)

1. Operator runs ``curl https://<praxis>/install.sh | sh`` on the target
   host with a one-time bootstrap token.
2. Installer drops the agent binary, generates a P-256 keypair, builds a
   CSR. The CSR's CN/SANs are placeholders, because the Vault role is configured
   with ``use_csr_common_name=use_csr_sans=false``, so the backend
   discards them and substitutes its own values.
3. Backend opens an SSH session to the host using the existing bootstrap
   credential, validates the requesting host matches ``system_id``.
4. Backend signs the CSR via ``praxis-agent-ca/sign/agent`` with
   backend-controlled ``CN=system-<id>.agent.praxis.internal`` and
   ``URI SAN=praxis://system/<id>``, then returns
   ``{certificate, ca_chain, serial_number, expires_at}``.
5. Agent installs the cert, starts the systemd service, opens the
   reverse tunnel.

## Reverse tunnel

**Mux strategy: Praxis-owned WebSocket protocol, not yamux.** A pure-Python
yamux port would be unmaintained code on a critical security path; HTTP/2
would force broader transport changes (Hypercorn, etc.) before the spine
is proven. We own the protocol on both sides instead.

### Process topology

The broker is a **dedicated Python process**, not a uvicorn-hosted
FastAPI app. An early spike confirmed Uvicorn 0.27 does
not surface the mTLS peer cert into ASGI scope, which makes per-route
identity extraction impossible. Pivoted to:

- **Network layer:** `websockets.serve()` + `asyncio.start_server` with
  an explicit `ssl.SSLContext` (`verify_mode=CERT_REQUIRED`, CA file
  pointed at the agent CA bundle).
- **Cert extraction:** in the WS handler,
  `ws.transport.get_extra_info("ssl_object").getpeercert(binary_form=True)`
  yields the DER bytes, parsed with `cryptography` to extract
  URI SAN, serial, SHA-256 fingerprint, and `NotAfter`.
- **Process:** `python -m app.broker.main` (or similar) running as its
  own Compose service on port `${PRAXIS_BROKER_PORT:-8443}`. Same image
  as the backend, different command. Independent healthcheck +
  restart policy.

The :8443 listener is **WebSocket-only and mTLS-only**. It exposes
`/agent/tunnel` and `/agent/op` and nothing else.

`/agent/ca-bundle` (anonymous, public certs) and any administrative
read-only endpoints live on the **main backend** at :8000 to avoid
the mTLS-only listener swallowing requests from clients without certs
(and to break the bootstrap trust loop where an agent would need to
trust the broker's server cert before it can fetch the broker CA).

`AgentRegistry` (and the `OperationManager` op state) is in-memory and
process-local. The main backend on :8000 reaches the broker out-of-process
over the internal HTTP API for host-targeted operations. Because this state
is not shared, **exactly one broker instance is supported**; running broker
replicas would split agent tunnels and in-flight ops across processes with no
shared registry. The broker logs this invariant at startup. Externalizing the
registry to a shared store (to allow horizontal broker scaling) is out of scope
for 1.0. See [Production Hardening](production-hardening.md) → Unsupported
Deployment Shapes.

### Two channels

| Channel | Purpose | Frame format |
|---|---|---|
| **Control WSS** (`/agent/tunnel`) | One per agent, persistent. Handshake, heartbeat, op orchestration, tunnel-level errors. | JSON over text frames, max 64 KiB. |
| **Per-op WSS** (`/agent/op`) | Short-lived, agent-initiated outbound, nonce-redeemed. Carries op data. | Common binary envelope (below), max 1 MiB payload. |

A third path, **in-band binary frames on the control WSS**, is
**reserved but not implemented in the current release**. With per-op WSS for streams
and `result_inline` (≤4 KiB) for trivial results, in-band fallback
buys little and adds a second data path. Defer until concrete need.

### Per-op WSS frame envelope

All per-op WSS data uses one common binary envelope so backend code paths
don't fork per op-type:

```
| u8 protocol_version |
| u8 frame_op         |
| u8 channel          |
| u8 flags            |
| u32 payload_length  | (network byte order, max 1 MiB)
| payload[payload_length] |
```

**`frame_op` values:**

| Value | Name | Meaning |
|---|---|---|
| 0x01 | DATA | Streaming chunk on this channel |
| 0x02 | CLOSE | Clean end of this channel (or whole op if channel = control) |
| 0x03 | ERROR | Abnormal end; payload is JSON `{code, detail}` |
| 0x04 | CANCEL_ACK | Acknowledges a control-WSS `op_cancel` |

**`channel` values:**

| Value | Name | Direction | Notes |
|---|---|---|---|
| 0x01 | stdin | backend → agent | Process input |
| 0x02 | stdout | agent → backend | Process output |
| 0x03 | stderr | agent → backend | Process error output |
| 0x04 | pty | bidirectional | Raw PTY bytes |
| 0x05 | file | direction depends on op | `file.read` is agent→backend; `file.write` is backend→agent |
| 0x06 | control | bidirectional | Op-specific control messages (JSON payload), e.g. PTY resize `{"type":"resize","cols":80,"rows":24}` |

**`flags`:** reserved (`0x00` for v1).

### Control WSS message types

Every message: `{"type": "...", ...}` over text frames.

#### Handshake (mandatory first exchange)

**Agent → Backend:**
```json
{
  "type": "hello",
  "protocol_version": 1,
  "agent_version": "0.1.0",
  "capabilities": ["exec","pty","file.read","file.write","file.list","file.checksum","facts","heartbeat"],
  "cert_fingerprint": "sha256:abc..."
}
```
`cert_fingerprint` must equal the SHA-256 of the cert presented at
TLS layer (defense-in-depth against any layer mismatch).

**Backend → Agent:**
```json
{
  "type": "welcome",
  "system_id": 42,
  "tunnel_session_id": "uuid",
  "cert_fingerprint": "sha256:abc...",
  "accepted_capabilities": ["exec","pty","file.read","file.write","file.list","file.checksum","facts","heartbeat"],
  "server_time": "2026-04-26T03:00:00Z",
  "heartbeat_interval_seconds": 30,
  "heartbeat_dead_seconds": 90,
  "cert_expires_at": "2026-04-26T04:00:00Z"
}
```
Backend echoes `cert_fingerprint` and includes `system_id` so the agent
can confirm both sides see the same identity. `cert_expires_at` lets the
agent schedule its own renewal before the broker enforces tunnel
termination (see "Cert expiry" below).

#### Heartbeat

Both sides send independently every 30s:
```json
{"type": "heartbeat", "ts": "2026-04-26T03:00:30Z"}
```
No ack. `ts` is **diagnostic only**; liveness uses each side's local
monotonic receive clock (`time.monotonic()`). Either side declares the
peer dead after 90s of silence and tears down.

#### Operation request (backend-initiated)

```json
{
  "type": "op_request",
  "operation_id": 12345,
  "op_type": "exec",
  "params": {"cmd": "uname -a", "timeout_s": 30},
  "transport": "per_op_wss",
  "nonce_expires_in_s": 30
}
```

`transport` for v1 is always `per_op_wss`. The nonce itself is delivered
in a separate message immediately after, allowing the broker to compute
and audit the nonce issuance:

```json
{"type": "op_nonce", "operation_id": 12345, "nonce": "<opaque-token>"}
```

(Nonces are split out of `op_request` so audit can capture issuance and
the agent can request a re-issue if the WSS round trip lost the nonce
without restating the whole op.)

#### Operation cancel

```json
{"type": "op_cancel", "operation_id": 12345, "reason": "user requested"}
```
Agent terminates the op and sends `op_complete` with
`outcome: "cancelled"`.

#### Operation complete (agent → backend)

```json
{
  "type": "op_complete",
  "operation_id": 12345,
  "outcome": "success",
  "exit_code": 0,
  "duration_ms": 142,
  "error": null,
  "result_inline": {"facts": {...}}
}
```

`result_inline` is **optional, bounded to 4 KiB serialized JSON**, used
for trivial ops where opening a per-op WSS round trip is overkill:
`facts`, `file.checksum`, small `file.list`, status checks. **Never used
for normal exec stdout/stderr**; those go through stdout/stderr channels
on the per-op WSS.

#### Tunnel-level error

```json
{"type": "error", "code": "protocol_violation", "detail": "..."}
```
Either side may send; sender then closes the connection.

#### Graceful close

```json
{"type": "bye", "reason": "agent shutdown"}
```
Other side acknowledges by closing.

### Per-op WSS open flow

1. Backend sends `op_request` then `op_nonce` on control WSS.
2. Agent dials WSS to `/agent/op`, presenting:
   - Same agent mTLS cert
   - Header `X-Praxis-Op-Nonce: <opaque-token>` (NEVER in URL, NEVER
     logged in plaintext; broker stores hashed)
3. Backend re-validates mTLS identity, hashes the nonce, looks up
   `(operation_id, system_id, op_type, expires_at)`. Rejects on miss,
   expiry, system_id mismatch, or already-redeemed.
4. Agent sends first message on the new WSS:
   ```json
   {"type": "op_attach", "operation_id": 12345}
   ```
   Backend confirms operation_id matches the redeemed nonce. Mismatch
   closes the WSS with a protocol_violation error.
5. After `op_attach`, all frames use the binary envelope above.
6. Either side closes the WSS to end the op. Agent sends
   `op_complete` on the control WSS afterward.

**Bounded concurrency (per agent):**

| Limit | Default |
|---|---|
| Concurrent per-op WSS | 16 |
| In-flight nonces (issued, not redeemed) | 32 |
| Nonce TTL | 30s |

Nonces stored server-side as **SHA-256 of the raw token**. The raw
token only exists in transit (control WSS → agent → header). Logs
record the hash, never the raw value.

### Duplicate tunnel handling

If a system already has an active tunnel and a new tunnel for the same
`system_id` connects with a valid cert:

1. **Newest valid tunnel wins.**
2. Old tunnel is sent `{"type": "bye", "reason": "replaced"}` and
   closed.
3. All in-flight ops on the old tunnel are cancelled
   (`op_complete: "cancelled"` reported up to the main backend if the
   op was backend-initiated).
4. Audit event: `agent.tunnel.replaced` with both `tunnel_session_id`
   values.

### Cert expiry enforcement

TLS validates the cert at connect time only, so a tunnel can outlive its
cert. The broker enforces freshness:

1. On connect, broker reads cert `NotAfter` and schedules a kill timer.
2. On every cert renewal (over the live tunnel via `/agent/renew`),
   broker updates `System.agent_cert_*` AND reschedules the kill timer
   to the new `NotAfter`.
3. When the timer fires:
   - Broker sends `{"type": "bye", "reason": "cert_expired"}` on the
     control WSS, closes.
   - All in-flight ops cancelled.
   - Audit: `agent.tunnel.cert_expired`.
4. Agent must reconnect with a freshly renewed cert.

### Connection-level constraints

| Limit | Value |
|---|---|
| Heartbeat interval | 30s |
| Heartbeat dead threshold | 90s |
| Reconnect backoff (agent side) | 1s → 2s → 4s → ... cap 60s |
| Max control WSS message size | 64 KiB |
| Max per-op WSS frame payload | 1 MiB |
| Max in-flight ops per agent | 16 |
| Max in-flight nonces per agent | 32 |
| Nonce TTL | 30s |

### What backend rejects on connect

- TLS chain doesn't validate against `praxis-agent-ca`
- No URI SAN matching `praxis://system/<id>`
- `AgentIdentityService.is_serial_active(serial)` returns False
  (status not active, expired, or unknown serial)
- `cert_fingerprint` in `hello` mismatches TLS-layer cert
- `protocol_version` not in supported set ({1} for v1)

Each rejection emits `agent.tunnel.rejected` with reason code.

### Reconnection without resume

A new tunnel is a new session. Backend does NOT resume in-flight ops
across tunnel restarts. If a backend-initiated op was outstanding when
the old tunnel died, it's reported as `cancelled` to the main backend,
which decides whether to re-issue.

## Capabilities

Agent exposes primitives only, with no policy. Initial capability set:

| Capability | Purpose |
|---|---|
| ``exec`` | Run a command (sync or streaming stdout/stderr/exit) |
| ``pty`` | Allocate a PTY for an interactive session (agent primitive exists; **not** wired to browser sessions; see "Interactive sessions" below) |
| ``file.read`` | Stream a file from host -> control plane |
| ``file.write`` | Stream a file from control plane -> host |
| ``file.list`` | List a directory |
| ``file.checksum`` | SHA-256 of a file |
| ``facts`` | Return host inventory dict |
| ``heartbeat`` | Liveness ping; both sides send independently every 30s, peer declared dead after 90s of silence |

All package, job, repo, and compliance logic stays backend-side and is
expressed in terms of the above primitives.

## Interactive sessions (1.0 transport split)

The agent exposes a ``pty`` primitive and advertises it in the handshake
``capabilities`` list, but **browser interactive terminal sessions in 1.0
always use SSH transport, never the agent tunnel.** This boundary is
deliberate and explicit:

- ``session_service.open_session`` opens a paramiko ``invoke_shell`` PTY
  over SSH using a short-lived Vault-signed user certificate. The cert
  principal is the fleet-role-resolved login, so the remote shell runs as
  the authorized Unix user.
- ``AgentTransport.open_pty`` raises ``TransportUnsupported`` with a
  message routing callers to SSH. ``BrokerClient`` has no ``pty`` method.
  No backend code path issues a ``pty`` op to the agent.
- A host's **transport preference** (``auto`` / ``ssh`` / ``agent``)
  governs only non-interactive ops (exec, file transfer, facts). Even with
  preference ``agent``, an interactive session uses SSH; the UI states
  this so the preference does not imply a browser shell over the agent.

**Why the agent does not serve interactive shells.** The agent runs as ``root`` and has no
per-user identity-switching design (``sudo -Hiu`` / ``runuser``). Routing a
fleet-role-authorized session to the agent would yield a root shell
regardless of the operator's resolved login, breaking session attribution
and least-privilege. SSH carries the Unix principal in the signed cert and
preserves the existing recording, multi-subscriber fanout, idle/max-duration
sweeps, and ``session.*`` audit attribution. Serving an interactive shell over the agent would
require that identity-switching design, a broker per-op WSS PTY bridge, and a
transport-neutral ``SessionRuntime``.

**Operator-facing rule:** interactive shells require SSH reachability and
deployed CA trust on the target host. Agent-only hosts with no inbound SSH
do not offer a browser terminal.

## Audit

Every agent-mediated operation is tagged ``transport: agent`` in the
audit log (vs ``transport: ssh`` for the legacy path). Cert lifecycle
events emit dedicated audit types:

- ``agent.cert.issued``
- ``agent.cert.renewed``
- ``agent.cert.revoked``
- ``agent.disabled``
- ``agent.enabled``

(Wired in later commits.)
