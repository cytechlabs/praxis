/**
 * Praxis E2E smoke tests (PRA-53).
 *
 * Auth state is pre-loaded from auth.setup.ts — no per-test login needed.
 * Runs against the running prod-parity stack via Caddy (E2E_BASE_URL, default
 * https://localhost — see playwright.config.ts). Bring the stack up with
 * `--profile bundled --profile proxy` first.
 */

import { test, expect } from "@playwright/test";

const ADMIN_USER = process.env.E2E_USERNAME ?? "admin";
const ADMIN_PASS = process.env.E2E_PASSWORD ?? "admin";

// ── Helpers ─────────────────────────────────────────────────────────────

/** Open a workspace drawer and select one of its destinations. */
async function navigateViaWorkspace(
  page: import("@playwright/test").Page,
  workspaceLabel: string,
  itemLabel: string,
) {
  await page
    .getByRole("navigation", { name: "Workspaces" })
    .getByRole("button", { name: workspaceLabel, exact: true })
    .click();
  await page
    .getByRole("group", { name: `${workspaceLabel} navigation` })
    .getByRole("link", { name: itemLabel, exact: true })
    .click();
}

// ── Auth (no storageState — tests against unauthenticated browser) ──────

test.describe("Authentication", () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test("unauthenticated user is redirected to /login", async ({ page }) => {
    await page.goto("/");
    await expect(page).toHaveURL(/\/login/);
  });

  test("login with wrong password shows error", async ({ page }) => {
    await page.goto("/login");
    await page.fill("#username", ADMIN_USER);
    await page.fill("#password", "wrongpassword");
    await page.click('button[type="submit"]');
    await expect(
      page.getByText(/incorrect|invalid|login failed|credentials/i).first(),
    ).toBeVisible({ timeout: 5_000 });
    await expect(page).toHaveURL(/\/login/);
  });

  test("login with valid credentials lands on dashboard", async ({ page }) => {
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
  });
});

// ── Navigation (pre-authenticated via storageState) ─────────────────────

test.describe("Workspace navigation", () => {
  test("navigate to Fleet Dashboard", async ({ page }) => {
    await page.goto("/");
    await navigateViaWorkspace(page, "Operate", "Dashboard");
    await page.waitForURL("**/fleet-dashboard", { timeout: 10_000 });
    await expect(page.locator("#__next")).toBeVisible();
  });

  test("navigate to All Systems", async ({ page }) => {
    await page.goto("/");
    await navigateViaWorkspace(page, "Operate", "All Systems");
    await page.waitForURL("**/system-management/all-systems", {
      timeout: 10_000,
    });
    await expect(page.locator("#__next")).toBeVisible();
  });

  test("navigate to All Credentials", async ({ page }) => {
    await page.goto("/");
    await navigateViaWorkspace(page, "Secure", "All Credentials");
    await page.waitForURL("**/credentials/all", { timeout: 10_000 });
    await expect(page.locator("#__next")).toBeVisible();
  });

  test("navigate to Scheduled Jobs", async ({ page }) => {
    await page.goto("/");
    await navigateViaWorkspace(page, "Automate", "Scheduled Jobs");
    await page.waitForURL("**/job-scheduling/scheduled-jobs", {
      timeout: 10_000,
    });
    await expect(page.locator("#__next")).toBeVisible();
  });

  test("navigate to Config Audit", async ({ page }) => {
    await page.goto("/");
    await navigateViaWorkspace(page, "Report", "Config Audit");
    await page.waitForURL("**/monitoring-reporting/audit-logs", {
      timeout: 10_000,
    });
    await expect(page.locator("#__next")).toBeVisible();
  });
});

// ── Credential CRUD (pre-authenticated) ─────────────────────────────────

test.describe("Credential CRUD", () => {
  const credName = `e2e-cred-${Date.now()}`;

  test("create a password credential", async ({ page }) => {
    await page.goto("/credentials/add");
    await page.waitForLoadState("networkidle");

    await page.fill('input[name="name"]', credName);
    await page.fill('input[name="username"]', "testuser");
    await page.fill('input[name="password"]', "testpass");

    await page.click('button[type="submit"]');

    await page.waitForURL("**/credentials/all", { timeout: 10_000 });
    await expect(page.getByText("Credential created")).toBeVisible({
      timeout: 5_000,
    });
  });

  test("created credential appears in the list", async ({ page }) => {
    await page.goto("/credentials/all");
    await page.waitForLoadState("networkidle");
    await expect(page.getByText(credName)).toBeVisible();
  });

  test("delete credential via edit page", async ({ page }) => {
    await page.goto("/credentials/all");
    await page.waitForLoadState("networkidle");

    const row = page.locator("tr", { hasText: credName });
    await row.getByText("Edit").click();
    await page.waitForLoadState("networkidle");

    // Click Delete button in the page header
    await page.locator("button", { hasText: "Delete" }).first().click();
    await page.waitForTimeout(500);

    // Confirm in the modal
    const modal = page.locator("div.fixed, [role='dialog']");
    await modal.locator("button", { hasText: "Delete" }).click();

    await page.waitForURL("**/credentials/all", { timeout: 10_000 });
    await page.waitForLoadState("networkidle");
    await expect(page.getByText(credName)).toHaveCount(0);
  });
});

// ── System pages (pre-authenticated) ────────────────────────────────────

test.describe("System pages", () => {
  test("register page loads with form fields", async ({ page }) => {
    await page.goto("/system-management/register");
    await page.waitForLoadState("networkidle");
    await expect(page.locator('input[name="hostname"]')).toBeVisible();
    await expect(page.locator('input[name="ip_address"]')).toBeVisible();
    await expect(page.locator('select[name="distro_id"]')).toBeVisible();
    await expect(page.locator('select[name="credentials_id"]')).toBeVisible();
  });

  test("all-systems page renders its inventory state", async ({ page }) => {
    await page.goto("/system-management/all-systems");
    await page.waitForLoadState("networkidle");
    await expect(
      page.getByRole("heading", { name: "All Systems", exact: true }),
    ).toBeVisible();
    await expect(
      page.locator("table").or(
        page.getByRole("heading", {
          name: "No systems registered yet",
          exact: true,
        }),
      ),
    ).toBeVisible();
  });
});

// ── Activation tokens (PRA-154 #1e) ─────────────────────────────────────

test.describe("Activation tokens settings tab", () => {
  test("admin can open the activation tokens tab and reach the create dialog", async ({
    page,
  }) => {
    await page.goto("/settings");
    await page.waitForLoadState("networkidle");
    await page.getByRole("button", { name: "Activation Tokens" }).click();
    await expect(
      page.getByRole("heading", { name: "Activation tokens" }),
    ).toBeVisible();
    await page.getByRole("button", { name: /New token/i }).click();
    // Modal renders the form fields. Don't submit — that requires a
    // pre-registered target system, which #1f's integration test
    // covers end-to-end. #1e just proves the surface mounts.
    await expect(page.getByLabel("Name")).toBeVisible();
    await expect(page.getByText(/target system/i)).toBeVisible();
    await expect(
      page.getByRole("button", { name: /Create token/i }),
    ).toBeVisible();
  });
});
