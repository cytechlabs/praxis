/**
 * PRA-173 closeout: rollback panel smoke E2E.
 *
 * Verifies the rollback panel UI shell renders the expected
 * controls + data-testid hooks. A full happy-path E2E (evaluate →
 * request approval → vote → start → dispatch-next → verify-due)
 * would require backend fixture seeding that the existing E2E
 * suite doesn't currently provide; this smoke spec pins the panel
 * surface so any regression in the data-testid contract or the
 * top-level state-machine wiring trips the suite. The full
 * happy-path can be wired in a follow-up that seeds an approved
 * rollback via the backend API.
 *
 * Pre-requisites: the seeded synthetic fleet (e2e/README.md), which provides
 * a plan with a succeeded execution.
 */

import { test, expect } from "@playwright/test";

import { adminApi } from "./support/api";
import { API_BASE } from "./support/env";

const SEEDED_PLAN = "Demo baseline patch plan";

test.describe("rollback panel", () => {
  const decoyName = `e2e-decoy-plan-${Date.now()}`;
  let decoyId: number | null = null;

  // A second plan with no execution is present so the spec has to select the
  // seeded plan by name rather than take whatever link comes first.
  test.beforeAll(async ({ playwright }) => {
    const api = await adminApi(playwright);
    try {
      const policies = await api.get(`${API_BASE}/patch/policies`);
      expect(policies.ok(), await policies.text()).toBeTruthy();
      const body = await policies.json();
      const rows: Array<{ id: number; name: string }> = Array.isArray(body)
        ? body
        : (body.items ?? []);
      const policy = rows.find((p) => p.name === "Demo baseline patch policy");
      if (!policy) {
        throw new Error(
          "seeded patch policy is missing; run e2e/fixtures/seed-demo.sh",
        );
      }
      const created = await api.post(`${API_BASE}/patch/update-plans/dry-run`, {
        data: { policy_id: policy.id, name: decoyName },
      });
      expect(created.ok(), await created.text()).toBeTruthy();
      decoyId = ((await created.json()) as { id: number }).id;
    } finally {
      await api.dispose();
    }
  });

  test.afterAll(async ({ playwright }) => {
    if (decoyId == null) return;
    const api = await adminApi(playwright);
    try {
      const removed = await api.delete(
        `${API_BASE}/patch/update-plans/${decoyId}`,
      );
      expect(removed.ok(), await removed.text()).toBeTruthy();
      const gone = await api.get(`${API_BASE}/patch/update-plans/${decoyId}`);
      expect(gone.status(), "decoy plan still present after teardown").toBe(404);
    } finally {
      await api.dispose();
    }
  });

  test("the seeded plan with a succeeded execution offers rollback evaluation", async ({
    page,
  }) => {
    // The seeded fleet (see e2e/README.md) includes an approved plan with a
    // succeeded execution and no rollback evaluation yet, so the panel must
    // offer "Evaluate rollback". A missing plan, panel or control is a
    // failure, not a skip.
    await page.goto("/patch-update-plans/all");
    await expect(page.getByText(decoyName)).toBeVisible({ timeout: 15_000 });
    const seededLink = page.getByRole("link", { name: SEEDED_PLAN, exact: true });
    await expect(seededLink).toBeVisible();
    await seededLink.click();
    await expect(page).toHaveURL(/\/patch-update-plans\/\d+/);
    await expect(
      page.getByRole("heading", { name: SEEDED_PLAN }).first(),
    ).toBeVisible();

    const panel = page.getByTestId("rollback-panel");
    await expect(panel).toBeVisible({ timeout: 15_000 });
    await expect(panel.getByTestId("rollback-evaluate")).toBeVisible();
    for (const id of [
      "rollback-request-approval",
      "rollback-vote-approve",
      "rollback-vote-reject",
      "rollback-start",
      "rollback-dispatch-next",
      "rollback-cancel",
      "rollback-verify-due",
    ]) {
      await expect(panel.getByTestId(id)).toHaveCount(0);
    }
  });

  test("a plan without an execution does not show the rollback panel", async ({
    page,
  }) => {
    expect(decoyId).not.toBeNull();
    await page.goto(`/patch-update-plans/${decoyId}`);
    await expect(page.getByText(decoyName).first()).toBeVisible({
      timeout: 15_000,
    });
    await expect(page.getByTestId("rollback-panel")).toHaveCount(0);
  });
});
