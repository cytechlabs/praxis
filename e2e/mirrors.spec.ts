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

import { adminApi } from "./support/api";
import { API_BASE } from "./support/env";



test.describe("Mirrors UI smoke (PRA-157 #5)", () => {
  const slug = `e2e-mirror-${Date.now()}`;
  let mirrorId: number | null = null;

  test.beforeAll(async ({ playwright }) => {
    const api = await adminApi(playwright);
    try {
      // Create the test mirror via API.
      const res = await api.post(`${API_BASE}/mirrors`, {
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
    } finally {
      await api.dispose();
    }
  });

  test.afterAll(async ({ playwright }) => {
    if (mirrorId == null) return;
    const api = await adminApi(playwright);
    try {
      const removed = await api.delete(`${API_BASE}/mirrors/${mirrorId}`);
      expect(removed.ok(), await removed.text()).toBeTruthy();
      const gone = await api.get(`${API_BASE}/mirrors/${mirrorId}`);
      expect(gone.status(), "mirror still present after teardown").toBe(404);
    } finally {
      await api.dispose();
    }
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
    playwright,
  }) => {
    // Flip via API to validate disabled state in the UI.
    const api = await adminApi(playwright);
    try {
      const flip = await api.patch(`${API_BASE}/mirrors/${mirrorId}`, {
        data: { source_mode: "imported_offline" },
      });
      expect(flip.ok(), await flip.text()).toBeTruthy();

      await page.goto(`/mirrors/${mirrorId}`);
      const syncBtn = page.getByRole("button", { name: /sync now/i });
      await expect(syncBtn).toBeVisible();
      await expect(syncBtn).toBeDisabled();
    } finally {
      // Flip back so other tests can use it.
      const restore = await api.patch(`${API_BASE}/mirrors/${mirrorId}`, {
        data: { source_mode: "upstream_sync" },
      });
      expect(restore.ok(), await restore.text()).toBeTruthy();
      await api.dispose();
    }
  });
});
