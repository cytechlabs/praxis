---
title: Compliance workflows
description: Compliance policies, evidence, exports, and the remediation lifecycle.
---

Compliance in Praxis is evidence-first: policies define checks, checks produce per-host evidence with a verdict, and failing evidence can be turned into an approved remediation. Everything lives under the **Verify** workspace.

## Dashboard

`Verify > Compliance Dashboard` rolls up the fleet's current verdicts from the latest evaluation of each enabled policy. Tiles link into the filtered evidence list. This is the "where do we stand right now" view for an operator or auditor.

## Policies and the starter pack

`Verify > Compliance Policies` lists the compliance policies and their checks. Each check has a **kind** (shown as a product label, and an **Evaluator** family - *Package & fact evaluation* or *Host probe (SSH)*) that determines what evidence it needs:

- **Fact-shaped checks** - evaluate host facts (installed packages, kernel version, etc.). A host that hasn't been scanned yet shows **Awaiting host scan**.
- **File / command checks** - evaluate file/command probe evidence over SSH.

`Verify > Compliance Starter Pack` seeds a set of CIS-aligned baseline policies (SSH, kernel, account hygiene, package hygiene). These are **spot checks**, not a full CIS profile or a certification - treat them as a starting baseline you extend. The SSH and kernel baselines are backed by real host facts (effective `sshd` config and kernel `sysctl` values, read-only), so they produce genuine pass/fail once a host has been scanned; a host with no facts yet shows **Awaiting host scan**.

### Reading an evidence status

Every evidence row shows a single **Status** that says exactly where the check stands:

- **Pass / Fail** - the check ran and the host met (or didn't meet) it.
- **Error** - the check ran but hit a real problem (e.g. a file couldn't be read, or the host was unreachable). The **Reason** column explains it in plain language.
- **Awaiting host scan** - the host hasn't reported the facts this check needs yet. Run a scan.
- **Coverage pending** - Praxis doesn't collect the host fact this check needs yet, so it can't be evaluated. Not a host problem and not an app failure.
- **Unsupported** - the check type isn't evaluable. These are distinct so a not-yet-evaluated check never reads as a red failure.

> **A green verdict is not an attestation.** Praxis reports what its checks observed against host facts and probe evidence. It does not claim certifiable compliance. See the [compliance evidence map](compliance-map.md).

## Evidence and exports

Evidence is viewable fleet-wide, per host (`Verify > Compliance Dashboard`), and per policy (the policy's Evidence tab). Each row carries the check, the host, the **Status**, the plain-language **Reason**, the **Evaluator** family, and when it was evaluated.

Admins and maintainers can **Export evidence** as JSONL or CSV. Evidence exports stream directly to your browser as a download, so large windows don't buffer in memory. Export rows carry BOTH the stable internal fields (`verdict`, `verdict_reason`, `runner_owner`, `runner_status` - pinned so auditor scripts stay stable) AND the humanized columns (`status`, `verdict_reason_label`, `runner_label`). Read-only auditors can review the evidence records in the app, but bulk export controls stay limited to admin/maintainer roles.

## Remediation lifecycle

`Verify > Compliance Remediation` is the fleet rollup of remediation work. The lifecycle, driven from the request and execution detail pages:

1. **Open a request** - from a failing evidence row. This records intent for an admin to approve; it does **not** run anything on a host.
2. **Approve / reject / cancel** - an approver decides on the request detail page.
3. **Build / acknowledge a plan** - build a structured preview of what dispatch would do (metadata only), then acknowledge it.
4. **Dispatch** - dispatch a ready, acknowledged execution attempt. **Dispatch is the only control that can reach a host**, and it stays behind the backend readiness gate; it runs through the approved patch execution transport and is audited per attempt.

Requests, plans, and executions each have their own labeled export (**Export requests / plans / executions**), admin/maintainer only.

> **Dispatch reaches hosts; build/acknowledge do not.** Building a plan is safe preview. Only dispatch changes a system, and only for a ready, acknowledged, approved attempt.

## For auditors

An auditor (read-only) can read every verdict and open every request/plan/execution, but cannot export bulk evidence, open requests, approve work, or dispatch remediation. Audit rows are written for import, evaluation, approval, and dispatch events.

## Related

- Remediation procedure detail: [remediation workflow](remediation-workflow.md).
- Control mapping: [compliance evidence map](compliance-map.md). Audit events: [audit event schema](audit-schema.md).
- **Patch Workflows** - remediation that changes packages rides the same governed patch execution path.
