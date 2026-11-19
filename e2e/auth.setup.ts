/**
 * Global auth setup: runs once before the suite.
 *
 * Signs in as the bootstrap administrator and saves the browser state to a
 * file that every browser project imports through `storageState`. The login
 * endpoint is rate limited (five attempts a minute) and the limiter is left
 * untouched, so a still-valid saved session is reused instead of spending a
 * login on every run. Specs that need a session must use this state rather
 * than signing in again.
 */

import { test as setup, expect } from "@playwright/test";
import fs from "fs";
import path from "path";

import { API_BASE, ADMIN_USER, STORAGE_STATE, adminPassword } from "./support/env";

setup("authenticate", async ({ page, playwright }) => {
  if (fs.existsSync(STORAGE_STATE)) {
    const api = await playwright.request.newContext({
      storageState: STORAGE_STATE,
      ignoreHTTPSErrors: true,
    });
    const me = await api.get(`${API_BASE}/auth/me`);
    const user = me.ok() ? ((await me.json()) as { username?: string }) : null;
    await api.dispose();
    if (user?.username === ADMIN_USER) return;
  }

  await page.goto("/login");
  await page.fill("#username", ADMIN_USER);
  await page.fill("#password", adminPassword());
  await page.click('button[type="submit"]');
  await expect(
    page.getByRole("heading", {
      name: "Fleet Operations Dashboard",
      exact: true,
    }),
  ).toBeVisible({
    timeout: 10_000,
  });
  fs.mkdirSync(path.dirname(STORAGE_STATE), { recursive: true });
  await page.context().storageState({ path: STORAGE_STATE });
});
