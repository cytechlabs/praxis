/**
 * Praxis E2E — PRA-157 #5 mirror UI smoke.
 *
 * Bootstraps a mirror via the API (no UI for create in #5), then drives
 * the read-only operator surface: list → detail → sync-now button →
 * runs poll. Cleans up the mirror at the end.
 *
 * Auth state is pre-loaded from auth.setup.ts.
 */

import { test, expect } from "@playwright/test";

// PRA-299: the backend publishes no direct host port on the prod-proxy stack; the
// API is reached through Caddy + the Next proxy (/api/backend/*) at
// https://localhost/api/backend. Override with PRAXIS_API_BASE for other topologies.
const API_BASE = process.env.PRAXIS_API_BASE ?? "https://localhost/api/backend";

async function apiAuth(page: import("@playwright/test").Page): Promise<string> {
  // Browser already has the auth cookies from auth.setup.ts; the
  // backend exposes /auth/login that returns an access_token. We
  // re-use that path to get a Bearer token for the API calls.
  const username = process.env.E2E_USERNAME ?? "admin";
  const password = process.env.E2E_PASSWORD ?? "admin";
  const res = await page.request.post(`${API_BASE}/auth/login`, {
    form: { username, password },
  });
  expect(res.ok(), await res.text()).toBeTruthy();
  const body = (await res.json()) as { access_token: string };
  return body.access_token;
}

test.describe("Mirrors UI smoke (PRA-157 #5)", () => {
  const slug = `e2e-mirror-${Date.now()}`;
  let mirrorId: number | null = null;
  let token: string;

  test.beforeAll(async ({ browser }) => {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    token = await apiAuth(page);

    // Create the test mirror via API.
    const res = await page.request.post(`${API_BASE}/mirrors`, {
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      data: {
        slug,
        display_name: "E2E Smoke Mirror",
        package_family: "deb",
        upstream_url: "http://archive.ubuntu.com/ubuntu",
        distribution: "jammy",
        components: ["main"],
        architectures: ["amd64"],
        sync_schedule_cron: "0 2 * * *",
      },
    });
    expect(res.ok(), await res.text()).toBeTruthy();
    const body = (await res.json()) as { id: number };
    mirrorId = body.id;
    await ctx.close();
  });

  test.afterAll(async ({ browser }) => {
    if (mirrorId == null) return;
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    const t = await apiAuth(page);
    await page.request.delete(`${API_BASE}/mirrors/${mirrorId}`, {
      headers: { Authorization: `Bearer ${t}` },
    });
    await ctx.close();
  });

  test("list page shows the mirror", async ({ page }) => {
    await page.goto("/mirrors/all");
    await expect(page.getByRole("heading", { name: "Mirrors" })).toBeVisible();
    // Slug appears in the table.
    await expect(page.getByText(slug)).toBeVisible({ timeout: 10_000 });
  });

  test("detail page renders fields and history", async ({ page }) => {
    await page.goto(`/mirrors/${mirrorId}`);
    await expect(page.getByText("E2E Smoke Mirror")).toBeVisible();
    // Definition fields render.
    await expect(page.getByText("Package family")).toBeVisible();
    await expect(page.getByText("Distribution")).toBeVisible();
    await expect(page.getByText("Sync history")).toBeVisible();
    // Empty-state shown initially (no syncs yet).
    await expect(page.getByText("No sync runs yet.")).toBeVisible();
  });

  test("sync-now button is disabled when source_mode=imported_offline", async ({
    page,
  }) => {
    // Flip via API to validate disabled state in the UI.
    const t = await apiAuth(page);
    const flip = await page.request.patch(`${API_BASE}/mirrors/${mirrorId}`, {
      headers: {
        Authorization: `Bearer ${t}`,
        "Content-Type": "application/json",
      },
      data: { source_mode: "imported_offline" },
    });
    expect(flip.ok(), await flip.text()).toBeTruthy();

    await page.goto(`/mirrors/${mirrorId}`);
    const syncBtn = page.getByRole("button", { name: /sync now/i });
    await expect(syncBtn).toBeVisible();
    await expect(syncBtn).toBeDisabled();

    // Flip back so other tests can use it.
    await page.request.patch(`${API_BASE}/mirrors/${mirrorId}`, {
      headers: {
        Authorization: `Bearer ${t}`,
        "Content-Type": "application/json",
      },
      data: { source_mode: "upstream_sync" },
    });
  });
});
