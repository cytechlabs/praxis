/**
 * Global auth setup — runs once before the test suite.
 * Logs in as admin and saves the browser state (cookies) to a file
 * that all test projects import via `storageState`.
 */

import { test as setup, expect } from "@playwright/test";
import path from "path";

const ADMIN_USER = process.env.E2E_USERNAME ?? "admin";
const ADMIN_PASS = process.env.E2E_PASSWORD ?? "admin";

export const STORAGE_STATE = path.join(
  __dirname,
  "..",
  "test-results",
  ".auth",
  "user.json",
);

setup("authenticate", async ({ page }) => {
  await page.goto("/login");
  await page.fill("#username", ADMIN_USER);
  await page.fill("#password", ADMIN_PASS);
  await page.click('button[type="submit"]');
  await expect(
    page.getByRole("heading", {
      name: "Fleet Operations Dashboard",
      exact: true,
    }),
  ).toBeVisible({
    timeout: 10_000,
  });
  await page.context().storageState({ path: STORAGE_STATE });
});
