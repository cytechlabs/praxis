---
title: Compliance evidence map
description: Which Praxis evidence supports SOC 2, PCI DSS, and HIPAA control discussions, and where the boundary is.
---

Maps the Praxis audit event vocabulary to common compliance control frameworks. **This is not a compliance attestation.** It is the evidence map your auditor needs when they ask *"show me how access is controlled and audited."*

Frameworks covered:

- **SOC 2 Type II**: Trust Services Criteria (TSC) 2017, primarily CC6 (logical and physical access)
- **PCI DSS 4.0**: requirements 7 (access control) and 10 (audit logging)
- **HIPAA Security Rule**: 45 CFR §164.308 (administrative safeguards) and §164.312 (technical safeguards)

---

## SOC 2

### CC6.1: The entity implements logical access security software

| Control | Praxis evidence |
|---|---|
| Authentication before access | `session.open` events carry authenticated `actor` (OIDC or local). TOTP step-up for high-privilege fleet roles via `totp.step_up`. |
| Access granted per least privilege | Fleet-scoped RBAC (`binding.create` / `binding.delete`) with explicit `allowed_actions` per fleet role. `action_not_allowed` denials captured as `command.exec` outcome=`denied`. |
| Passwords protected | OIDC via BYO IdP (primary); local passwords bcrypt-hashed. TOTP secrets + recovery codes per `user.totp_secret` and bcrypt-hashed `user.totp_recovery_codes`. |

### CC6.2: New users authorized before access granted

| Control | Praxis evidence |
|---|---|
| Formal authorization | `access_request.create` → `access_request.approve` (admin-gated) → binding materialised with time-bound `expires_at`. |
| Revocation | `binding.delete` + automatic expiry. `access_request.revoke` early-close. Reconciler removes host accounts + archives home dirs on access revocation. |

### CC6.3: Role-based access control

| Control | Praxis evidence |
|---|---|
| Roles defined | `FleetRole` entities with `allowed_actions` + `os_groups`. Built-in: admin, maintainer, auditor. Fleet roles grant **no standing sudo/root**; privileged host work is done by named Praxis automation, and interactive root is out-of-band. |
| Role assignments | `AccessBinding` (user or app-role → fleet-role → group). `binding.create` / `binding.delete` audit events. |
| Separation of duties | JIT request + approve flow is two-person by design (requester ≠ approver). |

### CC6.6: Secure network access

| Control | Praxis evidence |
|---|---|
| Cryptographic session controls | Every SSH session uses a Vault-signed short-lived user cert. Cert TTL matches fleet-role `max_session_s`. `session.open` context carries `cert_serial`. |
| CA trust + revocation | SSH CA rotation bumps the CA identifier and drops pooled connections so new operations re-sign; short-lived user certs are the containment boundary (no CRL/OCSP). `ca.rotate` and `ca.revoke` operations logged. |
| Strong authentication for privileged access | TOTP step-up required by `fleet_role.totp_required=True`. `totp.step_up` events capture each successful step-up. |

---

## PCI DSS 4.0

### Requirement 7: Restrict access by business need to know

| Requirement | Praxis evidence |
|---|---|
| 7.2.1: Access control system | Fleet-scoped RBAC (access_bindings + access_grants), `allowed_actions` per role. |
| 7.2.2: Access based on job classification | Fleet roles (admin/maintainer/auditor) map to job classifications; custom roles extend. Bindings can target app-role (role inheritance) or specific users. |
| 7.2.4: Periodic review | Audit log supports queries like "show all active bindings" + `binding.*` event history per user. |
| 7.2.5: Application/system accounts | Per-user Linux accounts provisioned + tracked (`host_user_states`). Shared accounts only via explicit `role_account` login mode, and cert principals still identify the Praxis user in `session.open` context. |

### Requirement 10: Log and monitor all access

| Requirement | Praxis evidence |
|---|---|
| 10.2.1: All individual user accesses to system components | `session.open`, `session.close`, `command.exec`, `file.upload`, `file.download` events carry `actor.username` + `target.system_id`. |
| 10.2.2: Actions by individuals with admin privilege | `command.exec` with `bypass_validation=true`, all `binding.*` and `access_request.approve` events capture admin actor. |
| 10.2.4: Invalid logical access attempts | `outcome=denied` events: `command.exec` denials, authorization failures. |
| 10.2.5: Authentication credentials changes | `totp.step_up`, binding lifecycle events. |
| 10.3: Log record content | Schema includes user id/IP, date/time, event type, success/failure, affected resource, origination. |
| 10.5: Secure and preserve audit trails | Events persist to DB independently of any external sink. External sinks (syslog/HTTP/file) provide optional immutable storage with HMAC-signed delivery. |
| 10.7: Retain audit trail | Audit events retained indefinitely in-app (no automatic pruning). External sinks control their own retention. Session recordings retain per fleet-role `recording_retention_days`. |

---

## HIPAA Security Rule

### §164.308: Administrative safeguards

| Standard | Praxis evidence |
|---|---|
| (a)(3) Workforce security | Fleet-scoped bindings + JIT access requests with approval. Workforce members get access per role + scope, not flat admin. |
| (a)(4) Information access management | `access_request.*` flow = documented access authorization. `binding.*` events record the resulting authorization. |
| (a)(5) Security awareness and training | Out of scope for Praxis; operational. |

### §164.312: Technical safeguards

| Standard | Praxis evidence |
|---|---|
| (a)(1) Access control: unique user ID | Every user has a distinct Praxis account; SSH cert principal = Praxis username even under role-account Linux mode. |
| (a)(1) Access control: emergency access | Admin app-role retains implicit access grants on every system (documented, audited). |
| (a)(1) Access control: automatic logoff | `fleet_role.idle_timeout_s` + max session duration enforce automatic disconnect. Events: `session.idle_kill`, `session.max_duration`. |
| (b) Audit controls | In-app audit log + external sinks. Every session, command, and file transfer logged with stable schema. |
| (c) Integrity | HMAC-signed HTTP sinks prevent tampering in transit. DB-side audit records are append-only at the application layer. |
| (d) Person or entity authentication | OIDC (primary) + TOTP step-up for privileged fleet roles. |
| (e) Transmission security | TLS-wrapped syslog sinks, HTTPS HTTP sinks. SSH transport between Praxis and hosts. |

---

## Remediation workflow as compliance evidence

Praxis records a structured remediation workflow on top of compliance evidence: a failing evidence row can become a tracked remediation request, that request can be approved or rejected by a separate operator, an approved request can produce a structured plan preview, the plan can be explicitly acknowledged, and the read layer exposes a `ready_for_execution` gate. The whole workflow is **non-executing**: no host mutation, no command dispatch, no approval auto-execution. See [`remediation-workflow.md`](remediation-workflow.md) for the operator-facing walkthrough; see [`audit-schema.md`](audit-schema.md) for the wire format.

The workflow produces audit-trail evidence for the control families below. All events fire via the same `safe_emit` pipeline as the rest of the schema; consumers should not need a new sink configuration.

### SOC 2

| Trust Services Criterion | Praxis remediation evidence |
|---|---|
| CC6.3: Separation of duties | `compliance_remediation.approved` and `compliance_remediation.rejected` enforce approver ≠ requester at the service layer; audit context carries `separation_of_duties_enforced=true`. `compliance_remediation_plan.acknowledged` is admin-only. |
| CC7.1: Detection of vulnerabilities | A failing compliance check produces a `compliance_evidence.persisted` row; `compliance_remediation.requested` connects that finding to a tracked remediation intent so auditors can demonstrate that vulnerabilities are not just detected but also queued for follow-up. |
| CC8.1: Authorized change management | Each remediation moves through a documented state machine: `compliance_remediation.requested` → `.approved` / `.rejected` / `.cancelled`, then `compliance_remediation_plan.built` → `.acknowledged`. Every transition records actor + decided reason + snapshot identity, which is the change-management evidence trail. |
| CC8.1: Plan history / supersede | `compliance_remediation_plan.superseded` is emitted whenever an acknowledged plan is rebuilt; the old row is preserved with its acknowledgement metadata intact, satisfying the "we can prove what was approved when" prong. |

### PCI DSS 4.0

| Requirement | Praxis remediation evidence |
|---|---|
| 6.5: Vulnerability remediation tracking | `compliance_remediation.requested` opens the remediation ticket against a specific failing evidence row; subsequent `.approved` / `.rejected` / `.cancelled` events and the plan lifecycle events form the per-finding remediation history PCI auditors expect. |
| 10.2.2: Admin actions on critical functions | `compliance_remediation.approved`, `compliance_remediation_plan.acknowledged`, and `compliance_remediation_plan.superseded` are admin-actor events with full snapshot identity in `context`, satisfying the "individual admin actions are logged" requirement. |
| 10.3: Log record content | Every remediation event carries `policy_id` / `policy_slug` / `policy_version` / `check_id` / `check_slug` / `check_kind` / `system_id` / `evidence_id` / `evaluation_run_id` / `verdict_snapshot` / `severity_snapshot` in `context`, plus the actor block on the envelope. Sufficient detail to reconstruct each decision without consulting Praxis runtime state. |

### HIPAA Security Rule

| Standard | Praxis remediation evidence |
|---|---|
| §164.308(a)(1): Risk management activities | Compliance evidence catches risks; `compliance_remediation.requested` / `.approved` events record the documented risk-mitigation decisions per finding. |
| §164.308(a)(8): Periodic technical / non-technical evaluation | The fleet summary (`GET /compliance/remediation/fleet-summary`) and per-host inventory (`GET /compliance/systems/{system_id}/remediation`) provide the periodic-review surface: counts by request state, current-plan state, acknowledged / ready / stale buckets, per-severity rollup. |
| §164.312(b): Audit controls | All `compliance_remediation.*` and `compliance_remediation_plan.*` events persist to the standard `audit_events` table and fan out through the configured sinks. No remediation event is "fire-and-forget"; every transition is durable. |

### Limitations specific to the remediation workflow

- The remediation workflow is **non-executing**: the audit trail proves intent and approval, not execution outcome. Pair it with your own change records when a control asks for proof that the fix was applied.
- Plans for `file_*`, `command_*`, and `fact_*` check kinds resolve to `*_review_required` previews because Praxis does not currently store the source content or operator-defined remediation steps needed to automate them. Auditors should treat those plans as documented operator intent, not as automated controls.
- `ready_for_execution=true` indicates a plan has cleared every metadata gate (current + acknowledged + not stale + executable plan kind + approved request) but does not by itself prove remediation occurred, only that the operator authorized it.

---

## How to use this map in an audit

1. Point your auditor at this document for the mapping.
2. Show them the live audit log at `/audit`.
3. Demonstrate the filtering, for example all `command.exec` events with `outcome=denied` in the last 90 days for requirement 10.2.4.
4. Export relevant events via the configured sink (or download a range via the built-in UI).
5. For access-review evidence (PCI 7.2.4, SOC CC6.2), export `binding.*` and `access_request.*` events for the review period.
6. For remediation evidence (SOC 2 CC8.1, PCI 6.5, HIPAA §164.308(a)(1)), export `compliance_remediation.*` and `compliance_remediation_plan.*` events for the review period; also pull the fleet remediation summary at the start and end of the period for the periodic-review story.

## Evidence status, labels, and deferred coverage

Compliance evidence records a **stable internal enum** in `verdict`,
`verdict_reason`, `runner_owner`, and `runner_status`, pinned so auditor export
scripts can rely on the exact strings. Alongside them, every read/export surface
carries **humanized product fields** the operator UI renders:

- `status`: the single `error` verdict is split into distinguishable states:
  `pass`, `fail`, `error` (a real problem), `awaiting_scan` (host not scanned
  yet), `coverage_pending` (Praxis doesn't collect the required fact yet), and
  `unsupported`. Operators never see a not-yet-evaluated check as a red failure.
- `status_label`, `verdict_reason_label`, and `runner_label`: plain-language
  equivalents. CSV/JSONL exports carry both the stable enums and these labels.

**Fact coverage:** the CIS starter-pack SSH (`ssh.config.PermitRootLogin`,
`ssh.config.PasswordAuthentication`) and kernel (`sysctl.kernel.randomize_va_space`,
`sysctl.net.ipv4.ip_forward`, `sysctl.net.ipv4.conf.all.rp_filter`) checks are
now backed by real read-only host facts (collected via `sshd -T` /
`sysctl -n`) and produce genuine pass/fail once a host has been scanned. A host
with no facts row still reads as `awaiting_scan`, and a fact the host didn't
report reads as a null/missing value; neither is faked as pass/fail. Any
genuinely uncollected *future* fact key still surfaces as `coverage_pending`.

## Limitations

- Praxis does not attest to framework compliance. Running Praxis does not itself make you SOC 2 / PCI / HIPAA compliant.
- Control coverage gaps: physical security, endpoint DLP, network segmentation beyond the fleet, encryption at rest for the PostgreSQL data store, all out of scope for Praxis.
- Retention policies for the in-app `audit_events` table are not currently enforced. If your framework requires time-bound retention, configure a file or syslog sink that matches your retention standard and set up your own pruning.
