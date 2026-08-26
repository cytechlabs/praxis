---
title: Operator walkthrough
description: A guided tour of the day-to-day operator path from fleet posture to a dispatched, verified patch.
---

A repeatable, one-page proof path for the complete Praxis lifecycle story,
suitable for evaluations, support reproductions, and release checks. It runs against
a **synthetic, secret-free** demo fixture, so it's safe to run on any local dev
stack and re-run as often as you like.

> The demo data is fictional. Hosts (`demo-web-01`, `demo-db-01`,
> `demo-edge-01`), IPs (RFC 5737 `198.51.100.0/24`), and the credential are
> display-only: no SSH is opened, no secret is stored, and the patch execution
> and compliance finding are seeded synthetic rows.

## 1. Bring up the stack and seed the demo

```sh
# Start the stack (build if needed; --profile proxy is the browser ingress).
# Do NOT pass -v/--volumes; keep your data.
docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile bundled --profile proxy up -d --build

# Load lifecycle/EOL reference data (idempotent). On an existing DB this
# reconciles the seed; on a fresh DB the migration already loaded it.
docker compose exec -T backend python -m app.scripts.update_eol_data

# Seed the synthetic demo fleet (idempotent, so re-run any time).
docker compose exec -T backend python -m app.scripts.seed_demo_fixture
```

The seeder prints the plan id and confirms the compliance finding + remediation
were created. It survives `docker compose down` and a fresh `up`; just re-run it.

## 2. Capture / verify the story (Playwright)

```sh
npx playwright test e2e/demo-walkthrough.spec.ts
```

This visits each screen in story order, asserts stable headings **and** the
seeded demo data (so it doubles as a release-QA gate), and writes screenshots to
`test-results/demo-walkthrough/` (ignored, not committed). Add `--headed` to
watch it drive the browser.

## 3. The story (what to show)

| Step | Screen | What the demo proves |
|---|---|---|
| Fleet health | **Fleet > Dashboard** (`/fleet-dashboard`) | The **Distro Lifecycle** card shows the three demo hosts as **Supported** (not an unexplained "unknown" tile). |
| Inventory & facts | **Fleet > All Systems** (`/system-management/all-systems`) | `demo-web-01` (Ubuntu 24.04), `demo-db-01` (AlmaLinux 9), `demo-edge-01` (Debian 13) with collected facts and lifecycle state. |
| Content | **Content > Profiles** (`/content-profiles/all`) | A content profile per host (e.g. `demo-ubuntu-web`) composed from a mirror + channel. |
| Patch policy | **Patch > Patch policies** (`/patch-policies/all`) | The **Demo baseline patch policy** (reboot-if-required, immediate cadence). |
| Update plan | **Patch > Patch Update Plans** (`/patch-update-plans/all`) > open **Demo baseline patch plan** | An **approved** plan with the demo hosts; the plan detail carries the approval, execution, reboot, and rollback surfaces. |
| Patch success | Plan detail > **Execution** | A **succeeded** execution upgraded `curl` on each host (before > after versions). |
| Reboot | Plan detail (reboot policy + per-host reboot state) | The reboot path is policy-driven (`if_required`); the execution surface shows per-host reboot handling. |
| Rollback | Plan detail > **Rollback** > click **Evaluate rollback** | Rollback feasibility resolves because each host's mirror is indexed with the old `curl` version. Then drive request-approval > vote > start > dispatch-next > verify-due to demo the full governed rollback. |
| Compliance | **Compliance > Dashboard** (`/compliance`) | The **Demo baseline compliance** policy and its per-host evidence, including a **failing** finding (`auditd` not installed) on `demo-web-01`. |
| Remediation | **Compliance > Remediation** (`/compliance/remediation`) | A **requested** remediation for the failing finding, through the governed request, approve, and plan flow. |

The rollback feasibility rows and the interactive rollback/remediation state
transitions are **produced by clicking through the UI** during the demo, so the
fixture deliberately leaves them for you to drive so the walkthrough shows the
real, governed flow rather than pre-baked terminal states.

## 4. Reset / re-run

The fixture is idempotent: re-running `seed_demo_fixture` reconciles the same
rows (same plan id, same hosts) without duplicating. To start clean you can
restart the stack with the canonical command above (drop `--build` if you don't
need a rebuild; this keeps named volumes) and re-seed. **Do not** pass `-v` /
`--volumes` unless you intend to wipe all data.

See also: [Auditor demo walkthrough](demo-walkthrough-auditor.md),
[Support Matrix](support-matrix.md), and [EOL data](eol-data.md).
