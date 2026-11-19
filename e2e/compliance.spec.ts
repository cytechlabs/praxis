/**
 * PRA-165 Slice 4 / 4a — compliance UX smoke.
 *
 * Locked behaviors this spec guards:
 *
 *   - The Compliance group exists in the top nav and routes resolve.
 *   - The compliance dashboard renders (route exists; no 404 even
 *     when the fleet is empty).
 *   - Stale wording on policy badges is "Evaluation overdue" or
 *     "Not yet evaluated" — never "compliance failure".
 *   - Export download CTAs on the dashboard are direct `<a href>`
 *     elements (so the browser handles streaming, not JS memory).
 *   - The typed check-kind form on the policy detail surface shows
 *     a PRA-166 deferred warning when a file/command kind is picked.
 *
 * Auth state is pre-loaded from `auth.setup.ts` exactly like
 * `smoke.spec.ts`; the spec runs as the seeded admin user.
 */

import { test, expect } from "@playwright/test";

import { API_BASE, EXPECTED_EDITION } from "./support/env";
import { openWorkspace } from "./support/navigation";

test.describe("Compliance navigation + dashboard", () => {
  test("Verify workspace exposes the compliance destinations", async ({
    page,
  }) => {
    await page.goto("/");
    await openWorkspace(page, "Verify");
    const group = page.getByRole("group", { name: "Verify navigation" });
    for (const label of [
      "Compliance Dashboard",
      "Compliance Policies",
      "Compliance Remediation",
      "Compliance Starter Pack",
    ]) {
      await expect(group.getByRole("link", { name: label, exact: true })).toBeVisible();
    }
  });

  test("compliance dashboard renders without 404", async ({ page }) => {
    await page.goto("/compliance");
    await page.waitForLoadState("networkidle");
    await expect(
      page.getByRole("heading", { name: "Compliance Dashboard" }),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("dashboard never uses the phrase 'compliance failure'", async ({ page }) => {
    // The slice review locks pin the wording: stale policies are
    // "Evaluation overdue" or "Not yet evaluated", never the harsher
    // "compliance failure". Assert that the dashboard body never
    // contains the forbidden phrasing regardless of fleet state.
    await page.goto("/compliance");
    await page.waitForLoadState("networkidle");
    const body = await page.textContent("body");
    expect((body ?? "").toLowerCase()).not.toContain("compliance failure");
  });

  test("free edition shows the evidence export as locked", async ({ page }) => {
    test.skip(
      EXPECTED_EDITION !== "free",
      "E2E_EDITION=paid: the locked state is not rendered on a licensed stack",
    );
    await page.goto("/compliance");
    await page.waitForLoadState("networkidle");
    const locked = page.getByRole("button", { name: /Export evidence \(Pro\)/ });
    await expect(locked).toBeVisible();
    await expect(locked).toBeDisabled();
    await expect(page.getByRole("link", { name: /^(JSONL|CSV)$/ })).toHaveCount(0);
  });

  test("licensed edition exports evidence through direct GET <a> tags", async ({
    page,
  }) => {
    test.skip(
      EXPECTED_EDITION !== "paid",
      "requires a licensed stack with compliance.bulk_exports (set E2E_EDITION=paid)",
    );
    await page.goto("/compliance");
    await page.waitForLoadState("networkidle");
    await page.getByRole("button", { name: /^Export evidence$/ }).click();
    const jsonlLink = page.getByRole("link", { name: "JSONL", exact: true });
    const csvLink = page.getByRole("link", { name: "CSV", exact: true });
    // Direct GET hrefs against the streaming export endpoints: the browser
    // handles the download, not a fetch into page memory.
    await expect(jsonlLink).toHaveAttribute(
      "href",
      /\/api\/backend\/compliance\/exports\/evidence\.jsonl/,
    );
    await expect(csvLink).toHaveAttribute(
      "href",
      /\/api\/backend\/compliance\/exports\/evidence\.csv/,
    );
  });

  test("the edition under test matches E2E_EDITION", async ({ request }) => {
    const res = await request.get(`${API_BASE}/edition`);
    expect(res.ok()).toBeTruthy();
    const edition = (await res.json()) as {
      entitlements: Record<string, boolean>;
    };
    expect(edition.entitlements["compliance.bulk_exports"] === true).toBe(
      EXPECTED_EDITION === "paid",
    );
  });
});

test.describe("Compliance policies list + detail", () => {
  test("policies route resolves and shows the table header", async ({ page }) => {
    // P1 fix: /compliance/policies must resolve (no 404), since
    // detail pages back-link there and NavBar points there.
    await page.goto("/compliance/policies");
    await page.waitForLoadState("networkidle");
    await expect(
      page.getByRole("heading", { name: "Compliance Policies", exact: true }),
    ).toBeVisible({ timeout: 10_000 });
    // Origin filter (built-in / custom / all) is the P2 fix surface.
    await expect(page.getByText("Origin", { exact: false })).toBeVisible();
  });

  test("starter pack page renders the admin Seed CTA", async ({ page }) => {
    await page.goto("/compliance/starter-pack");
    await page.waitForLoadState("networkidle");
    await expect(
      page.getByRole("heading", { name: "Compliance Starter Pack" }),
    ).toBeVisible({ timeout: 10_000 });
    // Admin user from auth.setup.ts → Seed CTA visible.
    await expect(
      page.getByRole("button", { name: /Seed starter pack|All seeded/i }),
    ).toBeVisible();
    // Locked wording: not a compliance attestation.
    const body = await page.textContent("body");
    expect((body ?? "").toLowerCase()).toContain("not a compliance attestation");
  });
});

// ── Slice 4b coverage: policy-detail form behavior + evidence filter wiring.
//
// These tests need an actual policy to navigate into. We seed the
// CIS-aligned starter pack first (idempotent, admin-only — admin is
// what auth.setup.ts provides) and then pick the first policy from
// the list. The seed POST is a no-op if a prior test run already
// seeded, so the spec stays re-runnable.

test.describe("Compliance policy detail typed-check form + filters", () => {
  test.beforeAll(async ({ request }) => {
    const res = await request.post(
      "/api/backend/compliance/starter-pack/seed",
    );
    // Idempotent: 200 on first-seed and on re-seed.
    expect(res.ok()).toBeTruthy();
  });

  test("typed check form warns that file kinds need probe evidence", async ({ page }) => {
    await page.goto("/compliance/policies");
    await page.waitForLoadState("networkidle");

    // Open the first policy in the list. Starter-pack rows render
    // with a monospace slug link; click whichever lands first.
    const firstLink = page.locator("a[href^='/compliance/policies/']").first();
    await firstLink.click();
    await page.waitForLoadState("networkidle");

    // Switch to the Checks tab. Tab label includes the count, so
    // match on a "Checks" prefix.
    await page.getByRole("tab", { name: /^Checks/ }).click();

    // Open the create-check form. Admin user has canWrite, so the
    // CTA is visible.
    await page.getByRole("button", { name: /New check/i }).click();

    // Pick a file kind from the typed-kind dropdown. The form must
    // then surface the PRA-166 deferred warning so operators know
    // it will never produce an executed verdict in this slice.
    //
    // The Kind <select> is the third Field labelled "Kind". Use
    // getByLabel for resilience against future re-orderings.
    await page.getByLabel("Kind").selectOption("file_exists");
    await expect(
      page.getByText(/File and command checks require probe evidence/i),
    ).toBeVisible();
  });

  async function openFirstPolicyEvidence(page: import("@playwright/test").Page) {
    await page.goto("/compliance/policies");
    await page.waitForLoadState("networkidle");
    await page.locator("a[href^='/compliance/policies/']").first().click();
    await page.waitForLoadState("networkidle");
    await page.getByRole("tab", { name: "Evidence" }).click();
    // Pick "fail" verdict + a specific System ID.
    await page.getByLabel("Verdict").selectOption("fail");
    await page.getByLabel("System ID").fill("42");
  }

  test("free edition keeps the evidence export locked while filtering", async ({
    page,
  }) => {
    test.skip(
      EXPECTED_EDITION !== "free",
      "E2E_EDITION=paid: the locked state is not rendered on a licensed stack",
    );
    await openFirstPolicyEvidence(page);
    await expect(
      page.getByRole("button", { name: /Export evidence \(Pro\)/ }),
    ).toBeDisabled();
  });

  test("licensed edition carries evidence filters into the export hrefs", async ({
    page,
  }) => {
    test.skip(
      EXPECTED_EDITION !== "paid",
      "requires a licensed stack with compliance.bulk_exports (set E2E_EDITION=paid)",
    );
    await openFirstPolicyEvidence(page);
    await page.getByRole("button", { name: /^Export evidence$/ }).click();

    // Both filters must travel into the export hrefs, otherwise the download
    // would not honor what the operator is looking at.
    const jsonl = page.getByRole("link", { name: "JSONL", exact: true });
    const csv = page.getByRole("link", { name: "CSV", exact: true });
    await expect(jsonl).toHaveAttribute("href", /verdict=fail/);
    await expect(jsonl).toHaveAttribute("href", /system_id=42/);
    await expect(csv).toHaveAttribute("href", /verdict=fail/);
    await expect(csv).toHaveAttribute("href", /system_id=42/);
  });
});

// ── Deferred coverage: auditor / read-only CTA hiding.
//
// A remaining P2 item also asked for an auditor RBAC assertion.
// The existing `e2e/auth.setup.ts` only mints an admin storageState,
// and the slice scope explicitly prohibits "expanding test
// infrastructure". Adding a second-user storage state (seeded
// auditor account + parallel login flow) crosses that boundary, so
// the auditor-CTA-hiding case is recorded here as an accepted
// deferral.
//
// The frontend code is already gated on `canWrite` and `isAdmin`
// from `AuthContext`, and the backend enforces the same RBAC at the
// route layer (verified by the PRA-165 backend test suite). The
// gap is purely browser-level "did we render the right buttons for
// a non-admin user"; promoting that to a Playwright assertion is a
// P3/follow-up once the e2e harness grows a non-admin fixture.
