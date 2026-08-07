# Known Limitations

Praxis is deliberately scoped. This page states, plainly, what Praxis does *not*
do so operators can plan complementary controls. None of these are defects; they
are boundary decisions for the 1.0 product.

## Compliance is evidence, not attestation

Praxis produces compliance **evidence** and maps its audit vocabulary onto common
control frameworks (SOC 2, PCI DSS, HIPAA). It does **not** certify or attest that
your organization is compliant; running Praxis does not by itself make you SOC 2
/ PCI / HIPAA compliant. Use the [Compliance Evidence Map](compliance-map.md) as
the material you hand an auditor, alongside your own controls and review.

Control areas that are explicitly **outside** the product boundary include
physical security, endpoint data-loss prevention, and network segmentation beyond
the managed fleet.

## In-app audit events are retained indefinitely (no automatic pruning)

Praxis does **not** automatically prune the in-app `audit_events` table in 1.0:
events accumulate until you remove them, and there is no built-in retention
window or scheduled purge. For time-bound or immutable retention, configure an
external sink (syslog / HTTP / file) that meets your standard and manage that
store's retention there; if you also need to bound the in-app table, prune it
yourself against your own policy and storage budget. External delivery is
at-least-once, so receivers should deduplicate on `event_uuid`. See
[Audit Event Schema](audit-schema.md) and the
[Compliance Evidence Map](compliance-map.md).

## Certificate revocation is status- and short-TTL-based (no CRL/OCSP)

Praxis does not run a CRL or OCSP responder in 1.0. Revocation is enforced by
short certificate lifetimes plus authoritative status checks, not by a published
revocation list:

- **SSH user certificates** are Vault-signed and short-lived (TTL bounded by the
  fleet role's session limit). Revocation rotates the SSH CA identifier and drops
  pooled SSH connections so new operations must re-sign, while already-issued
  certs simply expire; rotating the CA keypair additionally redeploys CA trust to
  hosts.
- **Agent certificates** are enforced at the broker: a revoked agent has
  `agent_status = revoked` and its certificate serial is blocklisted, so the
  broker rejects it at verification even before expiry. There is no CRL/OCSP
  distribution point.

If your environment requires CRL/OCSP-based revocation, treat it as a
complementary control outside Praxis 1.0. See [Agent Protocol](agent-protocol.md).

## Not an endpoint DLP product

Praxis governs and audits fleet access and lifecycle actions. It is **not** an
endpoint data-loss-prevention tool: it does not inspect, classify, or block data
movement on the host beyond the operations it brokers and records. Pair Praxis
with a dedicated DLP control if you need one.

## Encryption at rest is an infrastructure responsibility

Praxis documents its deployment posture for PostgreSQL and Vault, but
disk/storage/database **encryption at rest** for the data tier is an operator and
infrastructure responsibility unless you configure it separately (encrypted
volumes, database-level encryption, a managed database with encryption enabled,
etc.). Secret material is custodied in Vault; application metadata and the audit
log live in PostgreSQL. See [Security Model](security-model.md) and
[Production Hardening](production-hardening.md).

## Interactive browser sessions use SSH, not the agent

The optional thin agent exposes a PTY primitive, but in 1.0 **browser interactive
terminal sessions always use SSH transport**, even when a host's transport
preference is set to `agent`. This is deliberate: the agent runs as root with no
per-user identity switching, while an SSH session carries the operator's Unix
principal in a short-lived signed certificate, keeping sessions attributable. A
host's `auto` / `ssh` / `agent` preference governs only non-interactive
operations (exec, file transfer, facts). See [Agent Protocol](agent-protocol.md).

## Remediation is governed and package-oriented

Compliance remediation is a tracked, approval-gated workflow, and its executable
path is package-oriented. **Not every compliance finding can be automatically
fixed.** Checks whose remediation depends on operator-defined steps or host
source content (for example file-content and command-output checks) resolve to
"review required" previews: documented operator intent, not an automated
control. Treat remediation as governed change management, not a guarantee that
every finding is auto-resolved. See [Remediation Workflow](remediation-workflow.md).

## Managed-host support has a defined boundary

Package servicing and the patch lifecycle are supported on a specific set of
distributions and package-manager families; other systems may appear in inventory
without being serviceable for changes. Rather than repeat every caveat here, see
the authoritative [Linux Support Matrix](support-matrix.md) for supported /
best-effort / unsupported distributions, package-manager families, architectures,
and known distro-specific limitations.
