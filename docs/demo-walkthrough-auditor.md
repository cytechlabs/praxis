# Auditor demo walkthrough (1.0)

A one-page, **read-only** path for an auditor or reviewer to verify what Praxis
records — without mutating fleet state. It uses the same synthetic demo fixture
as the [operator walkthrough](demo-walkthrough-operator.md); seed it first:

```sh
docker compose exec -T backend python -m app.scripts.update_eol_data
docker compose exec -T backend python -m app.scripts.seed_demo_fixture
```

An auditor account should hold the **`auditor`** role (read-only). The demo can
be shown with an admin login, but the point of this path is that every screen
below is *evidence you inspect*, not an action you take.

## What an auditor can verify

| Question | Where | What's shown |
|---|---|---|
| What is in the fleet, and is it supported? | **Fleet → Dashboard** (`/fleet-dashboard`) and **All Systems** (`/system-management/all-systems`) | The three demo hosts and their lifecycle/EOL status — all **Supported** from the shipped lifecycle seed. The dashboard's Unknown breakdown explains any host that *isn't* classified, so "unknown" is never unexplained. |
| Which controls are defined and how do hosts score? | **Compliance → Dashboard** (`/compliance`) and **Policies** (`/compliance/policies`) | The **Demo baseline compliance** policy, its checks, and per-host pass/fail evidence — including a **failing** finding (`auditd` not installed) on `demo-web-01`. |
| Is there evidence behind a finding? | Compliance policy detail / evidence | Each evidence row carries the verdict, observed vs expected value, severity, the evaluation run id, and a timestamp — the material you hand a framework reviewer (see [Compliance Evidence Map](compliance-map.md)). |
| How are failures being remediated, and who approved? | **Compliance → Remediation** (`/compliance/remediation`) | The governed remediation lifecycle: a **requested** remediation for the failing finding, with requester and justification. Approvals and dispatch are recorded, not implicit. |
| What changed on the fleet, and who did it? | **Monitoring → Audit Logs** (`/monitoring-reporting/audit-logs`) | A stable audit trail: actor, action, target, outcome, and timestamp. Patch executions, approvals, rollbacks, signing-key and trust-pin changes, and remediation decisions all emit bounded audit events (see [Audit Event Schema](audit-schema.md)). |
| Can I take evidence away? | Reports / export surfaces | Report and audit export surfaces let an auditor take a point-in-time record off the system without changing anything. |

## What the auditor path deliberately does **not** do

- It does not start, approve, or roll back a patch.
- It does not approve or dispatch a remediation.
- It does not edit policies, credentials, or hosts.

Everything above is a read/inspect action. An `auditor`-role account cannot
mutate state even if they try — the read-only boundary is enforced server-side,
not just hidden in the UI.

See also: [Compliance Evidence Map](compliance-map.md) ·
[Audit Event Schema](audit-schema.md) ·
[Remediation Workflow](remediation-workflow.md).
