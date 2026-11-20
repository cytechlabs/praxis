/**
 * Load every main page, prove it is the intended authenticated destination,
 * and capture a PNG of it.
 *
 * Output goes to the ignored test-results/help-screenshots/ directory, never
 * to the tracked bundled help tree. Promoting a capture into the published
 * documentation is a deliberate, reviewed copy.
 *
 * A capture is only taken after the navigation succeeded, the browser ended on
 * the expected path (not the login page or an error page) and a page-specific
 * heading is visible. The negative controls at the end prove those checks
 * reject a wrong destination.
 */

import { test, expect, type Page } from "@playwright/test";
import path from "path";

import { EXPECTED_EDITION } from "./support/env";

const OUT_DIR = path.join(__dirname, "..", "test-results", "help-screenshots");

interface Shot {
  name: string;
  path: string;
  /** Path the browser must end on; defaults to `path` (canonical redirects). */
  finalPath?: string;
  /** Heading that identifies the page. */
  heading: string;
  /** Heading level of that marker; defaults to 1. */
  level?: number;
  /** Full page or just viewport. */
  fullPage?: boolean;
}

// The command approval queue is a paid-edition surface: the free edition
// intentionally renders its upsell page at the same route.
const APPROVAL_QUEUE_HEADING =
  EXPECTED_EDITION === "paid" ? "Approval Queue" : "Command approval queue";

const SHOTS: Shot[] = [
  { name: "dashboard", path: "/fleet-dashboard", heading: "Fleet Operations Dashboard", fullPage: true },
  { name: "all-systems", path: "/system-management/all-systems", heading: "All Systems" },
  { name: "smart-groups", path: "/system-management/smart-groups", heading: "Smart Groups" },
  { name: "system-groups", path: "/system-management/system-groups", heading: "System Groups" },
  { name: "credentials", path: "/credentials/all", heading: "Credential Management" },
  { name: "vault-management", path: "/system-management/vault-management", heading: "Vault Management" },
  { name: "ssh-security", path: "/ssh-security", heading: "SSH Security Management" },
  { name: "command-whitelist", path: "/ssh/command-whitelist", heading: "Command Whitelist" },
  {
    name: "approval-queue",
    path: "/ssh/approval-queue",
    heading: APPROVAL_QUEUE_HEADING,
    level: EXPECTED_EDITION === "paid" ? 1 : 3,
  },
  { name: "command-history", path: "/ssh/command-history", heading: "Command History" },
  { name: "package-inventory", path: "/package-management/inventory", heading: "Package Inventory" },
  { name: "available-updates", path: "/package-management/available-updates", heading: "Available Updates" },
  { name: "scheduled-jobs", path: "/job-scheduling/scheduled-jobs", heading: "Scheduled Jobs" },
  { name: "job-history", path: "/job-scheduling/job-history", heading: "Job History" },
  { name: "package-reports", path: "/monitoring-reporting/package-reports", heading: "Package Reports" },
  { name: "baselines", path: "/monitoring-reporting/baselines", heading: "Baselines" },
  { name: "drift", path: "/monitoring-reporting/drift", heading: "Configuration Drift" },
  { name: "activity-feed", path: "/monitoring-reporting/activity-feed", heading: "Activity Feed" },
  { name: "audit-logs", path: "/monitoring-reporting/audit-logs", heading: "Audit Logs" },
  { name: "settings", path: "/settings", heading: "Settings" },
];

/** Navigate and prove the page is the intended authenticated destination. */
async function openExpectedPage(page: Page, shot: Shot): Promise<void> {
  const response = await page.goto(shot.path);
  if (response === null) {
    throw new Error(`no response for ${shot.path}`);
  }
  expect(response.status(), `${shot.path} did not load`).toBeLessThan(400);
  await page.waitForLoadState("networkidle", { timeout: 15_000 });
  expect(new URL(page.url()).pathname, `${shot.path} ended elsewhere`).toBe(
    shot.finalPath ?? shot.path,
  );
  await expect(
    page.getByRole("heading", {
      level: shot.level ?? 1,
      name: shot.heading,
      exact: true,
    }),
  ).toBeVisible({ timeout: 10_000 });
}

for (const shot of SHOTS) {
  test(`screenshot ${shot.name}`, async ({ page }) => {
    await openExpectedPage(page, shot);
    // Small settle so charts and animations land.
    await page.waitForTimeout(800);
    await page.screenshot({
      path: path.join(OUT_DIR, `${shot.name}.png`),
      fullPage: shot.fullPage ?? false,
    });
  });
}

test.describe("capture guards reject a wrong destination", () => {
  test("a signed-out session lands on login and is rejected", async ({
    browser,
    baseURL,
  }) => {
    const context = await browser.newContext({
      baseURL,
      ignoreHTTPSErrors: true,
      storageState: { cookies: [], origins: [] },
    });
    const page = await context.newPage();
    await expect(openExpectedPage(page, SHOTS[0])).rejects.toThrow();
    expect(new URL(page.url()).pathname).toContain("/login");
    await context.close();
  });

  test("a page with the wrong heading is rejected", async ({ page }) => {
    // The path is right but the marker belongs to a different page.
    await expect(
      openExpectedPage(page, { ...SHOTS[0], heading: "Settings" }),
    ).rejects.toThrow();
  });

  test("an unexpected final path is rejected", async ({ page }) => {
    await expect(
      openExpectedPage(page, { ...SHOTS[0], finalPath: "/settings" }),
    ).rejects.toThrow();
  });

  test("an error page is rejected", async ({ page }) => {
    await expect(
      openExpectedPage(page, {
        name: "missing",
        path: "/definitely-not-a-page",
        heading: "Settings",
      }),
    ).rejects.toThrow();
  });
});
