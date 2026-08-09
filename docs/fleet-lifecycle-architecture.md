---
title: Fleet lifecycle architecture
description: The components of Praxis, how work flows between them, and why the control plane is the policy authority.
---

This document captures durable architecture and product boundaries:
implementation facts, trust boundaries, and system shape.

## Product Frame

Praxis is a Linux fleet lifecycle manager. It manages hosts across access,
inventory, package state, jobs, patching, compliance evidence, and remediation
workflow from one control plane.

The access broker is an important differentiator, but it is not the whole
product. SSH sessions, web terminals, approvals, file transfer, and session
recording sit beside the broader fleet lifecycle backbone.

Praxis should not be described as only access tooling. It should also not be
described as a clone of any single existing fleet product. The durable framing is
the control plane that owns the lifecycle from enrollment through evidence.

## Current Control Plane Shape

The core application is a FastAPI backend, PostgreSQL database, OpenBao (a
Vault-compatible secrets service) for secrets and PKI material, and a Next.js
frontend.

The backend owns:

- Authentication, authorization, and audit.
- System inventory and fleet grouping.
- Credential metadata and Vault-backed secret access.
- SSH execution and interactive access flows.
- Package, job, fleet operation, and reporting workflows.
- Agent identity, broker coordination, and transport selection as M13 lands.

Vault owns secret material and certificate authority state. PostgreSQL stores
application metadata, audit events, operation state, and lifecycle records.

## Transport Model

Praxis supports two host transports:

- **SSH transport:** the default and compatibility path. The control plane
  connects to managed hosts over SSH using Vault-backed credentials or
  certificate flows.
- **Agent transport:** optional per system. A thin Linux agent opens an
  outbound-only mTLS WebSocket tunnel to the broker. The agent provides local
  primitives only: exec, PTY, file operations, facts, and heartbeat.

The backend should express fleet lifecycle work in terms of transport-neutral
host operations wherever possible. Policy, orchestration, package semantics,
compliance logic, and audit ownership stay backend-side.

A host's transport preference (`auto` / `ssh` / `agent`) governs only
non-interactive ops (exec, file transfer, facts). **Interactive browser
terminal sessions always use SSH transport in 1.0**, independent of that
preference: the agent's `pty` primitive is not wired to browser sessions
because the agent runs as root with no per-user identity switching, while
SSH carries the operator's Unix principal in a short-lived signed cert. See
[agent-protocol.md](agent-protocol.md) ("Interactive sessions") for the full
rationale and the deferral boundary.

## Lifecycle Backbone

The long-term architecture should treat content, patching, facts, compliance,
and remediation as one connected backbone rather than isolated feature areas.

Durable boundaries:

- **Enrollment and facts:** establish identity, collect host facts, and attach
  lifecycle metadata such as distribution, kernel, uptime, reboot state, and
  end-of-life status.
- **Content:** mirror, trust, sign, retain, promote, and export package content
  in a way that supports connected and air-gapped environments.
- **Patch lifecycle:** model patch policy separately from execution. Rings
  describe rollout policy; update plans are execution instances.
- **Compliance:** collect evidence, record policy results, track severity, and
  drive remediation. External standards can map onto Praxis evidence, but the
  runtime model should stay Praxis-shaped.
- **Remediation:** turn drift, patch, and compliance findings into tracked work
  that can be approved, executed, audited, and reported.

## Content And Airgap Principles

Repository mirroring is infrastructure, not a decorative feature. It affects
trust, signing, retention, disk pressure, promotion, rollback, sync failure
handling, and air-gapped operation.

Public architecture docs should keep these principles visible:

- Repository signing and trust are part of the backbone.
- Channels and content profiles are control-plane primitives.
- Airgap support is an architectural constraint. Features that depend on
  mirrored content should define how export/import works.
- Native distribution metadata is preferred for advisory mapping before adding
  external intelligence sources.

## Trust And Audit Principles

Host access and lifecycle changes must remain auditable regardless of transport.

- SSH-mediated work is tagged as SSH transport.
- Agent-mediated work is tagged as agent transport.
- Access grants, sessions, command execution, file transfer, certificate
  lifecycle, content promotion, patch plans, and remediation actions should emit
  stable audit events.
- Short-lived credentials and certificates are preferred over long-lived host
  secrets.
- Agents expose primitives, not policy, so agent updates remain rare and the
  server remains the policy authority.

## Related Docs

- [Agent Protocol](agent-protocol.md)
- [Audit Event Schema](audit-schema.md)
- [Compliance Evidence Map](compliance-map.md)
