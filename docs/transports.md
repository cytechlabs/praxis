---
title: Transports
description: How SSH and the thin agent differ, which operations each one carries, and how to choose per host.
---

Praxis reaches a managed host over one of two transports. They are **not
equivalent**. Choose deliberately per host, because the choice removes
capabilities as well as adding them.

The authoritative, per-operation breakdown is the
[agent and SSH capability matrix](agent-capability-matrix.md). This page is the
decision, not the full table.

## The two transports

**SSH** is the default. The control plane opens a session to the host using a
stored credential. It requires the host to be reachable inbound from the
control plane.

**The thin agent** is a single static Go binary on the host that dials **out**
to the broker and holds a long-lived mutually authenticated WebSocket. The
control plane dispatches work down that tunnel. It requires no inbound
reachability, which is the entire reason it exists.

## What the agent tunnel can carry

The tunnel carries exactly four operations: run a command, get a file, put a
file, and collect facts.

Everything else runs over SSH regardless of what the host is set to. That
includes package scanning and package changes, repository management, health
checks, baseline and drift checks, directory browsing, fleet user provisioning,
and the browser terminal.

## What this means in practice

| You need | SSH | Agent |
|---|---|---|
| Command execution | Yes | Yes |
| File upload and download | Yes | Yes |
| Facts collection | Yes | Yes |
| Patch apply, reboot, and rollback | Yes | Yes |
| Content profile apply and mirror trust | Yes | Yes |
| Package inventory, updates, and holds | Yes | No, runs over SSH |
| Repository management | Yes | No, runs over SSH |
| Baselines and drift detection | Yes | No, runs over SSH |
| Health and connection tests | Yes | No, runs over SSH |
| Directory browsing | Yes | No, runs over SSH |
| Fleet user provisioning | Yes | No, runs over SSH |
| Browser terminal and session recording | Yes | Not available |

The last row is the one that surprises people. **Interactive sessions always
use SSH**, on every host, including agent-enrolled ones. Opening a shell on a
host therefore needs SSH reachability and deployed certificate trust on that
host, whatever its transport preference says.

## File downloads

A download is only reported as successful when the whole file arrived. Clients
and scripts that fetch `GET /transfer/{system_id}/download` should rely on this
contract on both transports:

- **Problems that exist before the first byte are error responses.** A missing
  file (404), a permission error (403), a path that is not a regular file (400),
  a file over the transfer limit (413), and an unreachable or unready host (502
  or 503) all return a JSON `detail` and no attachment. Nothing is sent that
  could be mistaken for the file.
- **A `200` declares its length.** When the host reports the file size the
  response carries `Content-Length`. Compare the bytes you received with it.
- **A failure after a `200` aborts the connection.** The status cannot change
  once it has been sent, so the transfer is cut off and the body ends short of
  the declared length (or, for a host that reports no size, the chunked body
  never terminates). HTTP clients report this as an incomplete or reset
  transfer, `curl` exits non-zero, and browsers show a failed download. Treat
  anything other than a complete body as a failure and discard it.
- **An empty file is a success.** A zero-byte file is a `200` with
  `Content-Length: 0` and an empty body.

The two transports differ in when a failure can appear. Over the agent the
backend receives the whole file into a bounded temporary spool before it sends
any header, so an agent transfer that fails part-way is an ordinary error
response and never a cut-off `200`. Over SSH the file is streamed as it is read
from the host, so a failure part-way is the aborted connection described above.
The agent path is limited to 1 GiB by default and the SSH path to 5 GiB.

Every download is recorded in the audit log whatever the outcome. A transfer
that fails, is cut short, or is abandoned by the client is recorded as a
failure with no checksum; a client that disconnects is recorded with the error
`client_disconnected`.

## Transport preference

Each host carries a preference:

| Preference | Agent tunnel healthy | Agent tunnel down |
|---|---|---|
| `ssh` | SSH | SSH |
| `auto` (default) | Agent | SSH |
| `agent` | Agent | Fails, with no fallback |

`auto` falls back to SSH silently, which is what you want for a host that has
both. `agent` fails loudly instead of falling back, which preserves the intent
"agent or nothing" for a host where an SSH path would be a policy violation.

The preference only affects the operations that can actually route. Setting a
host to `agent` does not move package scans, drift checks, provisioning, or the
terminal onto the agent; those remain on SSH.

## Choosing

**Use SSH** when the control plane can reach the host. It is the complete
transport and needs nothing installed on the host.

**Add the agent** when the host is behind NAT or a firewall and cannot accept
inbound connections. Understand that an agent-only host has no browser
terminal, no drift checks, no package inventory, and no fleet user
provisioning.

**Run both** for a host that can accept SSH but where you want the tunnel's
outbound path as well. Leave the preference on `auto`.

## Identity and trust

The agent's identity is minted by the backend, not asserted by the host:
nothing the host puts in its certificate request changes the identity it is
issued. Trust comes from how the request is authorised, either a single-use
activation token or an administrator-driven bootstrap over an existing SSH
path. See [enroll hosts](enroll-hosts.md) for both, and the
[security model](security-model.md) for where the trust boundaries sit.

The wire contract itself is documented in the [agent protocol](agent-protocol.md).
