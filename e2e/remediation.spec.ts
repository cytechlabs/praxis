/**
 * PRA-177 Slice 1 — read-only remediation UI foundations smoke.
 *
 * Locked behaviors this spec guards:
 *
 *   - The Compliance group now exposes a Remediation entry; the
 *     /compliance/remediation route resolves and renders the fleet
 *     remediation dashboard header.
 *   - The Slice 1 disclaimer banner explains that mutation controls
 *     are not in this slice — no rogue "Approve" / "Build plan" /
 *     "Dispatch" buttons leak into the read-only surface.
 *   - An empty-fleet rollup renders explicit not-ready / no-data
 *     copy rather than blank tiles or a broken workflow.
 *   - The /compliance dashboard exposes a top-level link into the
 *     remediation surface.
 *   - The per-host inventory route at
 *     /compliance/systems/[id]/remediation resolves and renders all
 *     five bounded section headings (open / approved / current /
 *     ready / superseded).
 *
 * Auth state is pre-loaded from `auth.setup.ts` (admin user). The
 * spec does NOT seed remediation requests; the empty/explained
 * states are themselves part of the Slice 1 acceptance criteria.
 */
import { test, expect } from "@playwright/test";

test.describe("Compliance Remediation read-only surface", () => {
  test("Compliance nav exposes the Remediation entry", async ({ page }) => {
    await page.goto("/");
    await page
      .getByRole("button", { name: "Compliance", exact: true })
      .click();
    await expect(
      page.getByRole("link", { name: "Remediation", exact: true }),
    ).toBeVisible();
  });

  test("/compliance/remediation renders without 404 and shows the Slice 1 disclaimer", async ({
    page,
  }) => {
    await page.goto("/compliance/remediation");
    await page.waitForLoadState("networkidle");
    await expect(
      page.getByRole("heading", { name: "Fleet Remediation" }),
    ).toBeVisible({ timeout: 10_000 });
    // The disclaimer copy is part of the slice locks — it explains
    // why no mutation controls are visible.
    const body = await page.textContent("body");
    expect((body ?? "").toLowerCase()).toContain(
      "praxis does not execute remediation today",
    );
    expect((body ?? "").toLowerCase()).toContain("later pra-177 slice");
  });

  test("read-only remediation page exposes no mutation controls", async ({
    page,
  }) => {
    // Slice 1 hard boundary: no Approve / Reject / Build plan /
    // Acknowledge / Dispatch buttons should render on the read-only
    // surface, even if backend data exists.
    await page.goto("/compliance/remediation");
    await page.waitForLoadState("networkidle");
    for (const forbidden of [
      /^Approve$/i,
      /^Reject$/i,
      /^Build plan$/i,
      /^Acknowledge$/i,
      /^Dispatch$/i,
      /^Dispatch all$/i,
    ]) {
      await expect(
        page.getByRole("button", { name: forbidden }),
      ).toHaveCount(0);
    }
  });

  test("empty-fleet rollup renders not-ready/explained state", async ({
    page,
  }) => {
    // On a freshly-seeded environment there are no remediation
    // requests yet. The dashboard must still render and explain the
    // empty state rather than hide it or pretend execution exists.
    await page.goto("/compliance/remediation");
    await page.waitForLoadState("networkidle");
    const body = await page.textContent("body");
    const text = (body ?? "").toLowerCase();
    // At least one of the empty-state strings must be present (the
    // exact branch depends on whether prior tests seeded requests).
    const sawEmpty =
      text.includes("no remediation requests have been opened yet") ||
      text.includes("no remediation requests yet") ||
      text.includes("no remediation plan previews have been built yet");
    expect(sawEmpty).toBeTruthy();
  });

  test("/compliance dashboard links into Remediation", async ({ page }) => {
    await page.goto("/compliance");
    await page.waitForLoadState("networkidle");
    const link = page.getByRole("link", { name: /Remediation/i }).first();
    await expect(link).toBeVisible();
    await expect(link).toHaveAttribute("href", "/compliance/remediation");
  });

  test("per-host remediation inventory page renders all five sections", async ({
    page,
  }) => {
    // The per-host inventory should render its five bounded sections
    // even when the host has no remediation activity yet. The page
    // accepts any numeric id; missing-host 404s are a server-side
    // concern handled by the backend.
    await page.goto("/compliance/systems/1/remediation");
    await page.waitForLoadState("networkidle");
    await expect(
      page.getByRole("heading", { name: /System #1 Remediation/ }),
    ).toBeVisible({ timeout: 10_000 });
    for (const section of [
      "Open requests",
      "Approved requests",
      "Current plans",
      "Ready plans",
      "Superseded history",
    ]) {
      // Section heading appears at least once on the page.
      await expect(
        page.getByRole("heading", { name: section }).first(),
      ).toBeVisible();
    }
  });
});

// ---------------------------------------------------------------------------
// Slice 2 — request lifecycle mutation UI
//
// These tests use Playwright route mocking to keep them
// deterministic: the seeded admin user does not necessarily have a
// failing evidence row or a `requested` remediation request available
// in any given environment, and triggering a fresh evaluation would
// require backend infrastructure outside the slice scope.
// ---------------------------------------------------------------------------

const STUB_FAIL_ROW = {
  id: 901,
  policy_id: 1,
  check_id: 11,
  system_id: 1,
  policy_slug: "stub-policy",
  policy_version: 1,
  check_slug: "stub-check",
  check_kind: "package_installed",
  verdict: "fail",
  verdict_reason: "package not installed",
  observed_value: "not present",
  expected_value: "installed",
  severity: "high",
  runner_owner: "slice_2_evaluator",
  runner_status: "runner_executed",
  evaluation_run_id: "stub-run",
  evaluated_at: "2026-05-17T13:00:00Z",
  created_at: "2026-05-17T13:00:00Z",
  updated_at: "2026-05-17T13:00:00Z",
};

const STUB_PASS_ROW = {
  ...STUB_FAIL_ROW,
  id: 902,
  check_slug: "stub-check-pass",
  verdict: "pass",
  verdict_reason: null,
  observed_value: "installed",
  expected_value: "installed",
};

const STUB_ERROR_ROW = {
  ...STUB_FAIL_ROW,
  id: 903,
  check_slug: "stub-check-error",
  verdict: "error",
  verdict_reason: "runner timeout",
  observed_value: null,
  expected_value: "installed",
};

const FAIL_EVIDENCE_PAGE = {
  items: [STUB_FAIL_ROW],
  total: 1,
  offset: 0,
  limit: 50,
  next_offset: null,
};

const MIXED_EVIDENCE_PAGE = {
  items: [STUB_FAIL_ROW, STUB_PASS_ROW, STUB_ERROR_ROW],
  total: 3,
  offset: 0,
  limit: 50,
  next_offset: null,
};

const REQUESTED_REQUEST_BODY = {
  id: 9001,
  policy_id: 1,
  check_id: 11,
  system_id: 1,
  evidence_id: 901,
  policy_slug: "stub-policy",
  policy_version: 1,
  check_slug: "stub-check",
  check_kind: "package_installed",
  runner_owner: "slice_2_evaluator",
  evaluation_run_id: "stub-run",
  verdict_snapshot: "fail",
  verdict_reason_snapshot: "package not installed",
  severity_snapshot: "high",
  remediation_guidance_snapshot: null,
  state: "requested",
  justification: "stub justification",
  // 999_999 is far outside the seeded admin user id, so SoD lets the
  // admin approve/reject without colliding with the requester check.
  requested_by: 999_999,
  decided_by: null,
  decided_at: null,
  decided_reason: null,
  created_at: "2026-05-17T13:00:00Z",
  updated_at: "2026-05-17T13:00:00Z",
};

const EMPTY_EXECUTION_ROLLUP = {
  request_id: 9001,
  system_id: 1,
  generated_at: "2026-05-17T13:00:00Z",
  offset: 0,
  limit: 25,
  returned_count: 0,
  total_attempts: 0,
  next_offset: null,
  has_more: false,
  counts_by_state: {},
  counts_by_failure_reason: {},
  page_counts_by_state: {},
  page_counts_by_failure_reason: {},
  attempts: [],
};

test.describe("Slice 2 — request lifecycle mutation UI", () => {
  test("failing evidence row exposes Remediate CTA and opens modal", async ({
    page,
  }) => {
    // Intercept the per-system evidence list so we always have a
    // failing row to attach the CTA to.
    await page.route(
      "**/api/backend/compliance/systems/1/evidence**",
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(FAIL_EVIDENCE_PAGE),
        });
      },
    );

    await page.goto("/compliance/systems/1");
    await page.waitForLoadState("networkidle");

    // The injected fail row should render a Remediate CTA for the
    // admin user from auth.setup.ts.
    const remediate = page.getByRole("button", { name: /Remediate/i }).first();
    await expect(remediate).toBeVisible({ timeout: 10_000 });
    await remediate.click();

    // Modal opens with the justification textarea + Open / Cancel
    // controls. We close without submitting to avoid creating a real
    // request against the live backend.
    await expect(
      page.getByRole("dialog", { name: /Open remediation request/i }),
    ).toBeVisible();
    await expect(
      page.getByLabel(/Justification/i),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: /^Open request$/ }),
    ).toBeVisible();
    await page.getByRole("button", { name: /^Cancel$/ }).click();
  });

  test("non-failing evidence rows render an explanatory not-applicable label", async ({
    page,
  }) => {
    // Slice 2a fix: pass/error rows must explain why the open-request
    // action is unavailable instead of rendering an empty action cell.
    await page.route(
      "**/api/backend/compliance/systems/1/evidence**",
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(MIXED_EVIDENCE_PAGE),
        });
      },
    );

    await page.goto("/compliance/systems/1");
    await page.waitForLoadState("networkidle");

    // The fail row still shows the active CTA.
    await expect(
      page.getByRole("button", { name: /Remediate/i }).first(),
    ).toBeVisible({ timeout: 10_000 });
    // Pass and error rows render disabled explanatory labels.
    await expect(page.getByText(/Pass — no action/)).toBeVisible();
    await expect(page.getByText(/Error — re-evaluate first/)).toBeVisible();
    // And there is no active CTA inside the not-applicable label.
    await expect(
      page
        .getByTestId("remediation-not-applicable")
        .getByRole("button", { name: /Remediate/i }),
    ).toHaveCount(0);
  });

  test("requested-state request detail renders lifecycle controls", async ({
    page,
  }) => {
    await page.route(
      "**/api/backend/compliance/remediation-requests/9001",
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(REQUESTED_REQUEST_BODY),
        });
      },
    );
    await page.route(
      "**/api/backend/compliance/remediation-requests/9001/plan",
      async (route) => {
        await route.fulfill({
          status: 404,
          contentType: "application/json",
          body: JSON.stringify({ detail: "no plan preview yet" }),
        });
      },
    );
    await page.route(
      "**/api/backend/compliance/remediation-requests/9001/executions**",
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(EMPTY_EXECUTION_ROLLUP),
        });
      },
    );

    await page.goto("/compliance/remediation/requests/9001");
    await page.waitForLoadState("networkidle");

    await expect(
      page.getByRole("heading", { name: /Lifecycle decision/i }),
    ).toBeVisible({ timeout: 10_000 });
    // Admin can act on a request opened by a different user.
    await expect(
      page.getByRole("button", { name: /^Approve$/ }),
    ).toBeEnabled();
    await expect(
      page.getByRole("button", { name: /^Reject$/ }),
    ).toBeEnabled();
    await expect(
      page.getByRole("button", { name: /^Cancel$/ }),
    ).toBeEnabled();

    // Locked wording: approval flips state only, not host mutation.
    const body = await page.textContent("body");
    expect((body ?? "").toLowerCase()).toContain(
      "approval flips request state only",
    );
  });

  test("separation of duties disables Approve/Reject for the requester", async ({
    page,
  }) => {
    await _runSodTest(page);
  });
});

// ---------------------------------------------------------------------------
// Slice 3 — plan build / refresh / acknowledge UI
// ---------------------------------------------------------------------------

const APPROVED_REQUEST_BODY = {
  ...REQUESTED_REQUEST_BODY,
  id: 9100,
  state: "approved",
  decided_by: 999_998,
  decided_at: "2026-05-17T13:30:00Z",
  decided_reason: "approved for slice 3 stub",
};

const PLANNED_FRESH_PLAN = {
  id: 7100,
  request_id: 9100,
  policy_id: 1,
  check_id: 11,
  system_id: 1,
  policy_slug: "stub-policy",
  policy_version: 1,
  check_slug: "stub-check",
  check_kind: "package_installed",
  severity_snapshot: "high",
  state: "planned",
  plan_kind: "package_install_preview",
  plan_steps: [
    {
      action_intent: "install_package",
      target: { package: "openssh-server" },
      expected: "installed",
      safety_notes: "non-executing preview only; no host change",
    },
  ],
  unsupported_reason: null,
  error_message: null,
  check_definition_fingerprint: "sha256:stub",
  is_current: true,
  superseded_by_plan_id: null,
  acknowledged_at: null,
  acknowledged_by: null,
  is_stale: false,
  ready_for_execution: false,
  created_by: 999_998,
  created_at: "2026-05-17T13:35:00Z",
  updated_at: "2026-05-17T13:35:00Z",
};

const STALE_PLAN = {
  ...PLANNED_FRESH_PLAN,
  id: 7101,
  request_id: 9101,
  is_stale: true,
};

const STALE_REQUEST_BODY = { ...APPROVED_REQUEST_BODY, id: 9101 };

const SUPERSEDED_PLAN = {
  ...PLANNED_FRESH_PLAN,
  id: 7102,
  request_id: 9102,
  is_current: false,
  superseded_by_plan_id: 7103,
};

const SUPERSEDED_REQUEST_BODY = { ...APPROVED_REQUEST_BODY, id: 9102 };

const REVIEW_REQUIRED_PLAN = {
  ...PLANNED_FRESH_PLAN,
  id: 7103,
  request_id: 9103,
  check_kind: "file_exists",
  plan_kind: "file_review_required",
};

const REVIEW_REQUIRED_REQUEST_BODY = {
  ...APPROVED_REQUEST_BODY,
  id: 9103,
  check_kind: "file_exists",
};

test.describe("Slice 3 — plan build / refresh / acknowledge UI", () => {
  test("approved request with no plan exposes Build plan preview CTA", async ({
    page,
  }) => {
    await page.route(
      "**/api/backend/compliance/remediation-requests/9100",
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(APPROVED_REQUEST_BODY),
        });
      },
    );
    await page.route(
      "**/api/backend/compliance/remediation-requests/9100/plan",
      async (route) => {
        await route.fulfill({
          status: 404,
          contentType: "application/json",
          body: JSON.stringify({ detail: "no plan preview yet" }),
        });
      },
    );
    await page.route(
      "**/api/backend/compliance/remediation-requests/9100/executions**",
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ ...EMPTY_EXECUTION_ROLLUP, request_id: 9100 }),
        });
      },
    );

    await page.goto("/compliance/remediation/requests/9100");
    await page.waitForLoadState("networkidle");

    // Empty-state for plan preview shows the Build CTA for admin.
    await expect(
      page.getByRole("button", { name: /^Build plan preview$/ }),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("stale plan exposes Rebuild plan preview + Acknowledge disabled with stale explanation", async ({
    page,
  }) => {
    await page.route(
      "**/api/backend/compliance/remediation-requests/9101",
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(STALE_REQUEST_BODY),
        });
      },
    );
    await page.route(
      "**/api/backend/compliance/remediation-requests/9101/plan",
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(STALE_PLAN),
        });
      },
    );
    await page.route(
      "**/api/backend/compliance/remediation-requests/9101/executions**",
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ ...EMPTY_EXECUTION_ROLLUP, request_id: 9101 }),
        });
      },
    );

    await page.goto("/compliance/remediation/requests/9101");
    await page.waitForLoadState("networkidle");

    await expect(
      page.getByRole("button", { name: /^Rebuild plan preview$/ }),
    ).toBeVisible({ timeout: 10_000 });
    // Acknowledge button is rendered but disabled with stale explanation.
    const ack = page.getByRole("button", { name: /^Acknowledge plan$/ });
    await expect(ack).toBeVisible();
    await expect(ack).toBeDisabled();
    await expect(
      page.getByText(/plan is stale; rebuild it/i),
    ).toBeVisible();
  });

  test("planned fresh current plan exposes enabled Acknowledge CTA", async ({
    page,
  }) => {
    await page.route(
      "**/api/backend/compliance/remediation-requests/9100",
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(APPROVED_REQUEST_BODY),
        });
      },
    );
    await page.route(
      "**/api/backend/compliance/remediation-requests/9100/plan",
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(PLANNED_FRESH_PLAN),
        });
      },
    );
    await page.route(
      "**/api/backend/compliance/remediation-requests/9100/executions**",
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ ...EMPTY_EXECUTION_ROLLUP, request_id: 9100 }),
        });
      },
    );

    await page.goto("/compliance/remediation/requests/9100");
    await page.waitForLoadState("networkidle");

    const ack = page.getByRole("button", { name: /^Acknowledge plan$/ });
    await expect(ack).toBeVisible({ timeout: 10_000 });
    await expect(ack).toBeEnabled();
  });

  test("review-required current plan disables Acknowledge with explanation", async ({
    page,
  }) => {
    // Slice 3a fix: *_review_required plan kinds must render
    // disabled-with-explanation even when the plan is state=planned,
    // current, fresh, and not yet acknowledged, because the kind has
    // no automated shape for a future execution slice.
    await page.route(
      "**/api/backend/compliance/remediation-requests/9103",
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(REVIEW_REQUIRED_REQUEST_BODY),
        });
      },
    );
    await page.route(
      "**/api/backend/compliance/remediation-requests/9103/plan",
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(REVIEW_REQUIRED_PLAN),
        });
      },
    );
    await page.route(
      "**/api/backend/compliance/remediation-requests/9103/executions**",
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({ ...EMPTY_EXECUTION_ROLLUP, request_id: 9103 }),
        });
      },
    );

    await page.goto("/compliance/remediation/requests/9103");
    await page.waitForLoadState("networkidle");

    const ack = page.getByRole("button", { name: /^Acknowledge plan$/ });
    await expect(ack).toBeVisible({ timeout: 10_000 });
    await expect(ack).toBeDisabled();
    await expect(
      page.getByText(/plan kind requires manual operator review/i),
    ).toBeVisible();
  });

  test("superseded plan detail renders Acknowledge disabled with explanation", async ({
    page,
  }) => {
    await page.route(
      "**/api/backend/compliance/remediation-plans/7102",
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(SUPERSEDED_PLAN),
        });
      },
    );
    await page.route(
      "**/api/backend/compliance/remediation-requests/9102",
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(SUPERSEDED_REQUEST_BODY),
        });
      },
    );

    await page.goto("/compliance/remediation/plans/7102");
    await page.waitForLoadState("networkidle");

    const ack = page.getByRole("button", { name: /^Acknowledge plan$/ });
    await expect(ack).toBeVisible({ timeout: 10_000 });
    await expect(ack).toBeDisabled();
    await expect(
      page.getByText(/plan is superseded by a newer current plan/i),
    ).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Slice 4 — execution-attempt creation + single/batch dispatch UI
// ---------------------------------------------------------------------------

const READY_ACK_PLAN = {
  ...PLANNED_FRESH_PLAN,
  id: 7200,
  request_id: 9200,
  acknowledged_at: "2026-05-17T13:40:00Z",
  acknowledged_by: 999_998,
  ready_for_execution: true,
};

const READY_ACK_REQUEST_BODY = { ...APPROVED_REQUEST_BODY, id: 9200 };

const PENDING_ATTEMPT_BODY = {
  id: 5200,
  request_id: 9200,
  plan_id: 7200,
  policy_id: 1,
  check_id: 11,
  system_id: 1,
  policy_slug: "stub-policy",
  policy_version: 1,
  check_slug: "stub-check",
  check_kind: "package_installed",
  severity_snapshot: "high",
  plan_kind_snapshot: "package_install_preview",
  package_name: "openssh-server",
  package_version_target: null,
  approval_decided_by: 999_998,
  approval_decided_at: "2026-05-17T13:30:00Z",
  state: "pending",
  transport: null,
  failure_reason: null,
  error_message: null,
  exit_code: null,
  duration_ms: null,
  stdout_summary: null,
  stderr_summary: null,
  dispatched_at: null,
  completed_at: null,
  created_by: 999_998,
  created_at: "2026-05-17T13:50:00Z",
  updated_at: "2026-05-17T13:50:00Z",
};

const TERMINAL_ATTEMPT_BODY = {
  ...PENDING_ATTEMPT_BODY,
  id: 5201,
  state: "succeeded",
  transport: "patch_transport_stub",
  exit_code: 0,
  duration_ms: 1234,
  dispatched_at: "2026-05-17T13:51:00Z",
  completed_at: "2026-05-17T13:51:01Z",
};

const ROLLUP_WITH_PENDING = {
  ...EMPTY_EXECUTION_ROLLUP,
  request_id: 9200,
  returned_count: 1,
  total_attempts: 1,
  has_more: false,
  counts_by_state: { pending: 1 },
  counts_by_failure_reason: {},
  page_counts_by_state: { pending: 1 },
  page_counts_by_failure_reason: {},
  attempts: [PENDING_ATTEMPT_BODY],
};

const ROLLUP_WITHOUT_PENDING = {
  ...EMPTY_EXECUTION_ROLLUP,
  request_id: 9100,
  returned_count: 0,
  total_attempts: 0,
  has_more: false,
  counts_by_state: {},
};

test.describe("Slice 4 — execution-attempt creation + dispatch UI", () => {
  test("ready acknowledged plan exposes enabled Create execution attempt CTA", async ({
    page,
  }) => {
    await page.route(
      "**/api/backend/compliance/remediation-requests/9200",
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(READY_ACK_REQUEST_BODY),
        });
      },
    );
    await page.route(
      "**/api/backend/compliance/remediation-requests/9200/plan",
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(READY_ACK_PLAN),
        });
      },
    );
    await page.route(
      "**/api/backend/compliance/remediation-requests/9200/executions**",
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(ROLLUP_WITH_PENDING),
        });
      },
    );

    await page.goto("/compliance/remediation/requests/9200");
    await page.waitForLoadState("networkidle");

    const create = page.getByRole("button", {
      name: /^Create execution attempt$/,
    });
    await expect(create).toBeVisible({ timeout: 10_000 });
    await expect(create).toBeEnabled();
    // Batch dispatch CTA visible because rollup has 1 pending attempt.
    await expect(
      page.getByRole("button", { name: /Dispatch all pending \(1\)/ }),
    ).toBeEnabled();
  });

  test("not-ready plan disables Create execution attempt with explanation", async ({
    page,
  }) => {
    // Reuse the Slice 3 fresh planned non-acknowledged plan, which is
    // ready_for_execution=false because acknowledged_at is null.
    await page.route(
      "**/api/backend/compliance/remediation-requests/9100",
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(APPROVED_REQUEST_BODY),
        });
      },
    );
    await page.route(
      "**/api/backend/compliance/remediation-requests/9100/plan",
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(PLANNED_FRESH_PLAN),
        });
      },
    );
    await page.route(
      "**/api/backend/compliance/remediation-requests/9100/executions**",
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(ROLLUP_WITHOUT_PENDING),
        });
      },
    );

    await page.goto("/compliance/remediation/requests/9100");
    await page.waitForLoadState("networkidle");

    const create = page.getByRole("button", {
      name: /^Create execution attempt$/,
    });
    await expect(create).toBeVisible({ timeout: 10_000 });
    await expect(create).toBeDisabled();
    await expect(
      page.getByText(/Create attempt unavailable/i),
    ).toBeVisible();
    // Batch dispatch CTA is disabled because no pending attempts exist.
    const batch = page.getByRole("button", {
      name: /Dispatch all pending \(0\)/,
    });
    await expect(batch).toBeVisible();
    await expect(batch).toBeDisabled();
    // Slice 4a fix: the disabled-state copy must be visible (not
    // buried in the `title` tooltip).
    await expect(
      page.getByTestId("batch-dispatch-blocked"),
    ).toBeVisible();
    await expect(
      page.getByText(
        /No attempts are in state `pending` for this request\./,
      ),
    ).toBeVisible();
  });

  test("pending attempt detail exposes enabled Dispatch attempt CTA", async ({
    page,
  }) => {
    await page.route(
      "**/api/backend/compliance/remediation-executions/5200",
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(PENDING_ATTEMPT_BODY),
        });
      },
    );

    await page.goto("/compliance/remediation/executions/5200");
    await page.waitForLoadState("networkidle");

    const dispatch = page.getByRole("button", {
      name: /^Dispatch attempt$/,
    });
    await expect(dispatch).toBeVisible({ timeout: 10_000 });
    await expect(dispatch).toBeEnabled();
  });

  test("terminal attempt detail disables Dispatch with explanation", async ({
    page,
  }) => {
    await page.route(
      "**/api/backend/compliance/remediation-executions/5201",
      async (route) => {
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(TERMINAL_ATTEMPT_BODY),
        });
      },
    );

    await page.goto("/compliance/remediation/executions/5201");
    await page.waitForLoadState("networkidle");

    const dispatch = page.getByRole("button", {
      name: /^Dispatch attempt$/,
    });
    await expect(dispatch).toBeVisible({ timeout: 10_000 });
    await expect(dispatch).toBeDisabled();
    await expect(
      page.getByText(/only `pending` attempts can be dispatched/i),
    ).toBeVisible();
  });
});

// Helper extracted so the Slice 2 SoD test can keep its full
// implementation while the Slice 3 describe block is appended below.
async function _runSodTest(page: import('@playwright/test').Page) {
  // Resolve the admin user id from the live /auth/me, then mock the
  // request envelope so its requested_by equals that id. The
  // frontend should disable Approve/Reject and show the SoD banner.
  const me = await page.request.get("/api/auth/me");
  expect(me.ok()).toBeTruthy();
  const meBody = await me.json();
  const myId = Number(meBody.id);
  expect(Number.isFinite(myId)).toBeTruthy();

  const selfRequest = {
    ...REQUESTED_REQUEST_BODY,
    id: 9002,
    requested_by: myId,
  };
  await page.route(
    "**/api/backend/compliance/remediation-requests/9002",
    async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(selfRequest),
      });
    },
  );
  await page.route(
    "**/api/backend/compliance/remediation-requests/9002/plan",
    async (route) => {
      await route.fulfill({
        status: 404,
        contentType: "application/json",
        body: JSON.stringify({ detail: "no plan preview yet" }),
      });
    },
  );
  await page.route(
    "**/api/backend/compliance/remediation-requests/9002/executions**",
    async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ ...EMPTY_EXECUTION_ROLLUP, request_id: 9002 }),
      });
    },
  );

  await page.goto("/compliance/remediation/requests/9002");
  await page.waitForLoadState("networkidle");

  await expect(
    page.getByRole("heading", { name: /Lifecycle decision/i }),
  ).toBeVisible({ timeout: 10_000 });
  await expect(
    page.getByRole("button", { name: /^Approve$/ }),
  ).toBeDisabled();
  await expect(
    page.getByRole("button", { name: /^Reject$/ }),
  ).toBeDisabled();
  // Self-cancel is still allowed for the requester.
  await expect(
    page.getByRole("button", { name: /^Cancel$/ }),
  ).toBeEnabled();
  // The SoD explanation banner is visible.
  const body = await page.textContent("body");
  expect((body ?? "").toLowerCase()).toContain("separation of duties");
}
