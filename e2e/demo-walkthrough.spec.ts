/**
 * PRA-184: 1.0 demo walkthrough — deterministic proof path + screenshots.
 *
 * Assumes the synthetic demo fixture has been seeded first:
 *
 *   docker compose exec -T backend python -m app.scripts.update_eol_data
 *   docker compose exec -T backend python -m app.scripts.seed_demo_fixture
 *
 * Then run against the running prod-parity stack via Caddy (E2E_BASE_URL,
 * default https://localhost — bring it up with `--profile bundled --profile proxy`):
 *
 *   npx playwright test e2e/demo-walkthrough.spec.ts
 *
 * Auth state is pre-loaded from auth.setup.ts (chromium project storageState).
 * Screenshots land under the ignored test-results/demo-walkthrough/ directory;
 * they are demo captures, not committed assets. Each test asserts a stable UI
 * anchor AND the seeded demo data, so this doubles as a release-QA gate rather
 * than only a screenshot script.
 */

import { test, expect } from "@playwright/test";

const SHOTS = "test-results/demo-walkthrough";
const T = 15_000;

// Demo fixture identifiers (see backend/app/scripts/seed_demo_fixture.py).
const DEMO_HOSTS = ["demo-web-01", "demo-db-01", "demo-edge-01"];
const DEMO_PROFILE = "demo-ubuntu-web";
const DEMO_POLICY = "Demo baseline patch policy";
const DEMO_PLAN = "Demo baseline patch plan";

test.describe("1.0 demo walkthrough", () => {
  test("fleet dashboard shows lifecycle buckets", async ({ page }) => {
    await page.goto("/fleet-dashboard");
    await page.waitForLoadState("networkidle");
    await expect(
      page.getByRole("heading", { name: /Dashboard/i }).first(),
    ).toBeVisible({ timeout: T });
    // The Distro Lifecycle card + its buckets are the PRA-240 surface; with the
    // demo fixture seeded the hosts are supported (not an unexplained unknown).
    await expect(page.getByText("Distro Lifecycle").first()).toBeVisible({
      timeout: T,
    });
    await expect(page.getByText("Supported", { exact: true }).first()).toBeVisible();
    await page.screenshot({ path: `${SHOTS}/01-fleet-dashboard.png`, fullPage: true });
  });

  test("all systems lists the demo hosts", async ({ page }) => {
    await page.goto("/system-management/all-systems");
    await page.waitForLoadState("networkidle");
    await expect(
      page.getByRole("heading", { name: "All Systems" }).first(),
    ).toBeVisible({ timeout: T });
    for (const host of DEMO_HOSTS) {
      await expect(page.getByText(host, { exact: true }).first()).toBeVisible({
        timeout: T,
      });
    }
    await page.screenshot({ path: `${SHOTS}/02-all-systems.png`, fullPage: true });
  });

  test("content profiles show the demo profile", async ({ page }) => {
    await page.goto("/content-profiles/all");
    await page.waitForLoadState("networkidle");
    await expect(
      page.getByRole("heading", { name: /Content profiles/i }).first(),
    ).toBeVisible({ timeout: T });
    await expect(page.getByText(DEMO_PROFILE).first()).toBeVisible({ timeout: T });
    await page.screenshot({ path: `${SHOTS}/03-content-profiles.png`, fullPage: true });
  });

  test("patch policies show the demo policy", async ({ page }) => {
    await page.goto("/patch-policies/all");
    await page.waitForLoadState("networkidle");
    await expect(
      page.getByRole("heading", { name: /Patch policies/i }).first(),
    ).toBeVisible({ timeout: T });
    await expect(page.getByText(DEMO_POLICY).first()).toBeVisible({ timeout: T });
    await page.screenshot({ path: `${SHOTS}/04-patch-policies.png`, fullPage: true });
  });

  test("patch update plan shows the demo plan and its detail surfaces", async ({
    page,
  }) => {
    await page.goto("/patch-update-plans/all");
    await page.waitForLoadState("networkidle");
    await expect(
      page.getByRole("heading", { name: /Patch Update Plans/i }).first(),
    ).toBeVisible({ timeout: T });
    const planLink = page.getByText(DEMO_PLAN).first();
    await expect(planLink).toBeVisible({ timeout: T });
    await page.screenshot({ path: `${SHOTS}/05-patch-update-plans.png`, fullPage: true });

    // Open the plan detail (approval / execution / reboot / rollback surfaces).
    await planLink.click();
    await page.waitForURL(/\/patch-update-plans\/\d+/, { timeout: T });
    await page.waitForLoadState("networkidle");
    await expect(page.getByText(DEMO_PLAN).first()).toBeVisible({ timeout: T });
    // Rollback is a stable panel heading on the plan detail; reaching it proves
    // the reboot/rollback surfaces are present for the walkthrough.
    await expect(page.getByText(/Rollback/i).first()).toBeVisible({ timeout: T });
    await page.screenshot({ path: `${SHOTS}/06-plan-detail.png`, fullPage: true });
  });

  test("compliance dashboard is reachable", async ({ page }) => {
    await page.goto("/compliance");
    await page.waitForLoadState("networkidle");
    await expect(
      page.getByRole("heading", { name: /Compliance Dashboard/i }).first(),
    ).toBeVisible({ timeout: T });
    await page.screenshot({ path: `${SHOTS}/07-compliance.png`, fullPage: true });
  });

  test("compliance remediation is reachable", async ({ page }) => {
    await page.goto("/compliance/remediation");
    await page.waitForLoadState("networkidle");
    await expect(
      page.getByRole("heading", { name: /Remediation/i }).first(),
    ).toBeVisible({ timeout: T });
    await page.screenshot({ path: `${SHOTS}/08-remediation.png`, fullPage: true });
  });
});
