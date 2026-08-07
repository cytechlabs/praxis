# Diagnostic Support Bundle

Praxis can generate a **safe, redacted diagnostic bundle** that an administrator
downloads and sends to Cytech Labs support. It is a customer-sendable support
artifact — not an observability platform — with strong redaction and hard bounds.

## Where to generate

**Settings → Support / Diagnostics** (admin-only tab). Choose a time range
(24h / 72h / 7d), click **Generate support bundle**, and the browser downloads a
compressed `.zip`. The panel shows the last-generated time and size.

The same operation is available via `POST /diagnostics/bundle?time_range=<24h|72h|7d>`.
It requires the `admin` role and is audited as `support.bundle.generated` (with the
time range, byte size, and file count — never the contents).

Nothing is stored server-side: the bundle is streamed to the caller and never
persisted at rest.

## What it contains

| File | Contents |
| --- | --- |
| `manifest.json` | Bundle version, Praxis version, generated-at, generating admin ID, time range, per-file sha256/size, deterministic file list |
| `version.json` | App version / build metadata |
| `schema.json` | Alembic migration head (schema version) |
| `config_summary.json` | **Allowlisted** non-secret config keys only |
| `health.json` | DB reachability + Vault health status summary |
| `audit_events.json` | Recent audit events — action / outcome / timestamp / actor / target only (no raw context) |
| `reconcile_status.json` | Access-revocation, privilege-reconcile, and shared-login conflict state |
| `failed_jobs.json` | Recent failed/errored/timed-out command executions — id / system / status / error type (no command text, stdout, or stderr) |
| `systems.json` | Limited host metadata — id / hostname / status / OS version / agent + CA-trust state (no IPs, no credentials) |
| `logs/backend.log` | Recent backend log lines from an in-memory ring buffer, bounded by time and count, **redacted** |
| `logs/broker.log` | Recent **agent-broker** log lines, **redacted** — present only when the broker was reachable (see [Broker logs](#broker-logs) below) |

The JSON file set is fixed and deterministic. `logs/broker.log` is the one
**conditional** member: it is included only when broker logs were collected;
otherwise the manifest's `broker_logs` block records why (see below). JSON is
emitted with sorted keys and the zip uses a fixed member order and mtime so
bundles are reproducible.

## Broker logs

The **agent broker** (mTLS tunnel, enrollment, liveness, reconnect) runs as a
separate process/container from the backend, so its logs aren't in the backend's
own ring buffer. For thin-agent troubleshooting the bundle pulls recent broker
logs over the broker's **authenticated, docker-network-only internal API** — the
same channel the backend already uses for tunnel health. **No Docker socket is
required or used.**

The manifest always contains a `broker_logs` block describing the outcome:

| `status` | Meaning | `logs/broker.log` present? |
| --- | --- | --- |
| `included` | Broker was reachable and returned log records | **yes** (redacted, same bounds as the backend log) |
| `unavailable` | Broker unreachable / errored / its log buffer isn't installed | no — `reason` explains |
| `unsupported` | No broker internal API for this deployment (no shared secret), or the broker build has no logs endpoint | no — `reason` explains |

Broker log records are passed through the **same redaction pass** as backend logs
and truncated to the same `MAX_LOG_BYTES` cap (the manifest reports `truncated` /
`omitted_bytes` under `broker_logs`). A broker problem never fails the bundle —
the backend log section and everything else are produced regardless.

## Remote agent logs (manual)

Logs from the **thin agent running on a managed host** are not collected
automatically in 1.0 — the bundle covers the control plane (backend + broker),
not remote hosts. To gather agent logs for a specific host, run on that host:

```bash
# Recent agent service logs (systemd hosts):
journalctl -u praxis-agent --since "24 hours ago"

# Follow live while reproducing an issue:
journalctl -u praxis-agent -f

# Agent version/build for the support ticket:
praxis-agent version
```

Attach the output alongside the support bundle. Automatic remote agent-log
collection is intentionally out of scope (no arbitrary remote reads).

## What it excludes (never collected)

The bundle **never** contains: passwords; Vault tokens, root tokens, or unseal keys;
refresh tokens; license JWTs or private signing material; session cookies or access
tokens; private keys; full environment dumps; or unbounded command output.

Redaction is defense-in-depth: sections are curated to safe fields, **and** every
JSON file plus the log stream is passed through a secret-scrubbing pass
(`app/core/redaction.py`) that strips PEM private-key blocks, Vault tokens, JWTs,
`Bearer` tokens, `key=value` secrets, and inline DSN credentials.

## Bounds

Bounds are enforced in order, and byte caps apply to the **uncompressed** content
*before* compression — so a highly compressible section can never expand into a
large uncompressed bundle behind a small zip:

1. **Time**: logs and events are limited to the selected window (24h / 72h / 7d).
2. **Count**: logs, audit events, failed jobs, and systems are each row/record capped.
3. **Per-log-section byte cap** (`MAX_LOG_BYTES`, 8 MB): the log section is
   **truncated** on a line boundary with an explicit marker
   (`«log truncated: N bytes omitted …»`). Logs truncate rather than fail because a
   bounded tail is still useful; the manifest records `log_truncated` and
   `log_omitted_bytes`.
4. **Per-JSON-section byte cap** (`MAX_JSON_SECTION_BYTES`, 8 MB): JSON sections are
   curated and row-bounded, so one exceeding its cap is anomalous — generation
   **fails closed** with `400` rather than shipping a surprising section.
5. **Total uncompressed byte cap** (`MAX_TOTAL_UNCOMPRESSED_BYTES`, 33 MB): checked
   across all sections **before** compression; over the ceiling **fails closed**
   with `400`. Sized to hold both the backend and broker log sections at their
   caps plus the JSON sections.
6. **Final compressed ceiling** (`MAX_BUNDLE_BYTES`, 25 MB): a last defense-in-depth
   guard on the produced zip.

`manifest.json` records the uncompressed size of every section (`files[].bytes`),
the `total_uncompressed_bytes`, and the active `bounds` (including whether logs were
truncated).

- **No arbitrary reads**: the only input is a closed `time_range` enum. There is no
  file-path parameter — the bundle reads a fixed set of DB queries plus the log
  buffer and nothing else.

## Operator review expectation

Even with redaction, **review the bundle against your own data-handling policy
before sending it to support.** Unzip it and confirm the contents are acceptable
for your environment. Redaction is thorough but the operator is the final gate.
