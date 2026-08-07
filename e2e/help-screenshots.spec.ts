/**
 * Capture PNG screenshots of the main pages for embedding in /help/*.mdx
 * guides (PRA-130).
 *
 * Run with:
 *   docker compose exec frontend npx playwright test help-screenshots
 *
 * Output: frontend-next/public/help/*.png
 */

import { test } from "@playwright/test";
import path from "path";

const OUT_DIR = path.join(
  __dirname,
  "..",
  "frontend-next",
  "public",
  "help",
);

interface Shot {
  name: string;
  path: string;
  /** Optional selector to wait on before capturing. */
  waitFor?: string;
  /** Full page or just viewport. */
  fullPage?: boolean;
}

const SHOTS: Shot[] = [
  { name: "dashboard", path: "/fleet-dashboard", fullPage: true },
  { name: "all-systems", path: "/system-management/all-systems" },
  { name: "smart-groups", path: "/system-management/smart-groups" },
  { name: "system-groups", path: "/system-management/system-groups" },
  { name: "credentials", path: "/credentials/all" },
  { name: "vault-management", path: "/system-management/vault-management" },
  { name: "ssh-security", path: "/ssh-security" },
  { name: "command-whitelist", path: "/ssh/command-whitelist" },
  { name: "approval-queue", path: "/ssh/approval-queue" },
  { name: "command-history", path: "/ssh/command-history" },
  { name: "package-inventory", path: "/package-management/inventory" },
  { name: "available-updates", path: "/package-management/available-updates" },
  { name: "scheduled-jobs", path: "/job-scheduling/scheduled-jobs" },
  { name: "job-history", path: "/job-scheduling/job-history" },
  { name: "package-reports", path: "/monitoring-reporting/package-reports" },
  { name: "baselines", path: "/monitoring-reporting/baselines" },
  { name: "drift", path: "/monitoring-reporting/drift" },
  { name: "activity-feed", path: "/monitoring-reporting/activity-feed" },
  { name: "audit-logs", path: "/monitoring-reporting/audit-logs" },
  { name: "settings", path: "/settings" },
];

for (const shot of SHOTS) {
  test(`screenshot ${shot.name}`, async ({ page }) => {
    await page.goto(shot.path);
    await page.waitForLoadState("networkidle", { timeout: 15_000 });
    if (shot.waitFor) {
      await page.waitForSelector(shot.waitFor, { timeout: 10_000 });
    }
    // Small settle so charts and animations land.
    await page.waitForTimeout(800);
    await page.screenshot({
      path: path.join(OUT_DIR, `${shot.name}.png`),
      fullPage: shot.fullPage ?? false,
    });
  });
}
