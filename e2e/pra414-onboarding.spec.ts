import { expect, test, type Page } from "@playwright/test";

/**
 * PRA-414: guided onboarding, walked in a browser at desktop and at 390px.
 *
 * These are layout and behavior checks, not a substitute for the backend
 * suites: they exist to catch what unit tests cannot, namely controls that
 * clip, overlap, or read as success when nothing succeeded.
 *
 * Run against a stack with the wizard reachable:
 *   E2E_BASE_URL=http://localhost:3010 npx playwright test e2e/pra414-onboarding.spec.ts
 */

const USERNAME = process.env.E2E_USERNAME ?? "praxisadmin";
const PASSWORD = process.env.E2E_PASSWORD ?? "PraxisDemo!2026";

const DESKTOP = { width: 1440, height: 900 };
const MOBILE = { width: 390, height: 844 };
// The narrowest width the application actually supports (PRA-272).
const NARROW_SUPPORTED = { width: 1280, height: 900 };

async function login(page: Page) {
  await page.goto("/login");
  await page.fill("#username", USERNAME);
  await page.fill("#password", PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForURL((url) => !url.pathname.includes("/login"), {
    timeout: 20_000,
  });
}

/** Nothing may spill sideways: a horizontal scrollbar at 390px is a defect. */
async function expectNoHorizontalOverflow(page: Page) {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    return doc.scrollWidth - doc.clientWidth;
  });
  expect(overflow, "page must not scroll horizontally").toBeLessThanOrEqual(1);
}

/** Every interactive control must be big enough to hit and not clipped. */
async function expectControlsUsable(page: Page) {
  const controls = page.locator(
    "button:visible, a[href]:visible, input:visible, select:visible, textarea:visible",
  );
  const count = await controls.count();
  expect(count).toBeGreaterThan(0);

  for (let i = 0; i < count; i += 1) {
    const control = controls.nth(i);
    const box = await control.boundingBox();
    if (!box) continue;
    const label = (await control.getAttribute("aria-label")) ?? (await control.innerText().catch(() => "")) ?? "";
    expect(box.height, `control "${label.slice(0, 40)}" is too short to use`).toBeGreaterThanOrEqual(16);
    expect(
      box.x + box.width,
      `control "${label.slice(0, 40)}" extends past the viewport`,
    ).toBeLessThanOrEqual((page.viewportSize()?.width ?? 0) + 1);
  }
}

test.describe("PRA-414 guided onboarding", () => {
  // This spec signs in itself, so it does not use the suite-wide stored
  // session. Starting signed out is also what an operator adding their
  // first host actually does.
  test.use({ storageState: { cookies: [], origins: [] } });

  test("desktop: the wizard opens on Connect and asks for an address first", async ({
    page,
  }) => {
    await page.setViewportSize(DESKTOP);
    await login(page);
    await page.goto("/system-management/onboard");

    await expect(page.getByRole("heading", { name: /where is this host/i })).toBeVisible();
    await expect(page.getByLabel("Address")).toBeVisible();
    await expect(page.getByLabel("SSH port")).toBeVisible();

    // Progress is real navigation, not decoration.
    const progress = page.getByRole("navigation", { name: /setup progress/i });
    await expect(progress).toBeVisible();
    await expect(progress.locator('[aria-current="step"]')).toContainText("Connect");

    await expectNoHorizontalOverflow(page);
    await expectControlsUsable(page);
    await page.screenshot({
      path: "test-results/pra414-connect-desktop.png",
      fullPage: true,
    });
  });

  test("desktop: Connect advances to Authenticate and Back returns", async ({ page }) => {
    await page.setViewportSize(DESKTOP);
    await login(page);
    await page.goto("/system-management/onboard");

    await page.getByLabel("Address").fill("198.51.100.24");
    await page.getByRole("button", { name: /^Next$/ }).click();

    await expect(page.getByRole("heading", { name: /how should praxis sign in/i })).toBeVisible();
    await expect(page.getByLabel("Credential")).toBeVisible();
    // The real Default policy is offered, not a placeholder.
    await expect(page.getByLabel("SSH policy")).toContainText("Default");
    await page.screenshot({
      path: "test-results/pra414-authenticate-desktop.png",
      fullPage: true,
    });

    await page.getByRole("button", { name: /^Back$/ }).click();
    await expect(page.getByRole("heading", { name: /where is this host/i })).toBeVisible();
    // Back does not discard what was entered.
    await expect(page.getByLabel("Address")).toHaveValue("198.51.100.24");
  });

  test("desktop: verification failure reports a reason, never a raw error", async ({
    page,
  }) => {
    test.setTimeout(90_000);
    await page.setViewportSize(DESKTOP);
    await login(page);
    await page.goto("/system-management/onboard");

    // An address with nothing behind it: verification must fail cleanly.
    await page.getByLabel("Address").fill("198.51.100.99");
    await page.getByRole("button", { name: /^Next$/ }).click();

    await page.getByLabel("Credential").selectOption({ index: 1 });
    await page.getByRole("button", { name: /^Next$/ }).click();

    await expect(page.getByRole("heading", { name: /check the connection/i })).toBeVisible();
    await page.getByRole("button", { name: /check the connection/i }).click();

    const report = page.getByRole("status").filter({
      hasText: /verification did not complete/i,
    });
    await expect(report.first()).toBeVisible({ timeout: 60_000 });

    // A structured code is shown; library/transport text is not.
    const body = await page.locator("body").innerText();
    expect(body).toMatch(/network_unreachable|connection_timeout|address_invalid/);
    expect(body).not.toMatch(/paramiko|Traceback|SSHException|errno/i);

    // Nothing may read as success.
    expect(body).not.toMatch(/successfully added|system added/i);

    await expectNoHorizontalOverflow(page);
    await page.screenshot({
      path: "test-results/pra414-verify-failure-desktop.png",
      fullPage: true,
    });
  });

  test("390px: the desktop boundary is shown, not a clipped wizard", async ({ page }) => {
    // Praxis 1.0 is a desktop operations console and gates the whole
    // application below MIN_SUPPORTED_WIDTH (1280px). At 390px the intended
    // result is the branded boundary shell, so that is what is asserted here:
    // a wizard rendering at this width would contradict that decision, not
    // satisfy it.
    // Sign in at a supported width first: the boundary gates the whole
    // application, sign-in included, so there is no way to reach the wizard
    // from a 390px viewport in the first place.
    await page.setViewportSize(DESKTOP);
    await login(page);
    await page.goto("/system-management/onboard");
    await expect(page.getByRole("heading", { name: /where is this host/i })).toBeVisible();

    await page.setViewportSize(MOBILE);
    await expect(page.getByRole("heading", { name: /optimized for desktop/i })).toBeVisible();
    await expectNoHorizontalOverflow(page);
    await page.screenshot({ path: "test-results/pra414-onboard-390.png", fullPage: true });
  });

  test("1280px: the wizard is usable at the narrowest supported width", async ({
    page,
  }) => {
    // The real narrow case for this application. Every control must fit and
    // stay hittable at the boundary itself.
    await page.setViewportSize(NARROW_SUPPORTED);
    await login(page);
    await page.goto("/system-management/onboard");

    await expect(page.getByRole("heading", { name: /where is this host/i })).toBeVisible();
    await expectNoHorizontalOverflow(page);
    await expectControlsUsable(page);
    await page.screenshot({
      path: "test-results/pra414-connect-1280.png",
      fullPage: true,
    });

    await page.getByLabel("Address").fill("198.51.100.24");
    await page.getByRole("button", { name: /^Next$/ }).click();
    await expect(page.getByRole("heading", { name: /how should praxis sign in/i })).toBeVisible();
    await expectNoHorizontalOverflow(page);
    await expectControlsUsable(page);
    await page.screenshot({
      path: "test-results/pra414-authenticate-1280.png",
      fullPage: true,
    });
  });

  test("keyboard: the wizard is operable without a mouse", async ({ page }) => {
    await page.setViewportSize(DESKTOP);
    await login(page);
    await page.goto("/system-management/onboard");

    const address = page.getByLabel("Address");
    await address.focus();
    await page.keyboard.type("198.51.100.24");
    await expect(address).toHaveValue("198.51.100.24");

    // Focus lands on the new step's heading rather than the top of the page.
    await page.getByRole("button", { name: /^Next$/ }).click();
    await expect(page.getByRole("heading", { name: /how should praxis sign in/i })).toBeFocused();
  });

  test("the old register deep link forwards here with its query intact", async ({
    page,
  }) => {
    // Adding a host moved to this flow, but bookmarks and runbook links still
    // point at the old page. They must land here without losing what they were
    // carrying.
    await page.setViewportSize(DESKTOP);
    await login(page);

    await page.goto("/system-management/register?hostname=web-01&ref=runbook");
    await page.waitForURL((u) => u.pathname.includes("/onboard"), {
      timeout: 20_000,
    });

    const url = new URL(page.url());
    expect(url.pathname).toBe("/system-management/onboard");
    expect(url.searchParams.get("hostname")).toBe("web-01");
    expect(url.searchParams.get("ref")).toBe("runbook");
    await expect(
      page.getByRole("heading", { name: /where is this host/i }),
    ).toBeVisible();
  });

  test("authorization is resolved before the form is shown", async ({ page }) => {
    await page.setViewportSize(DESKTOP);
    await login(page);
    await page.goto("/system-management/onboard");

    await page.getByLabel("Address").fill("198.51.100.24");
    await page.getByRole("button", { name: /^Next$/ }).click();

    // A tenant-wide admin is offered credential creation up front.
    await expect(page.getByRole("button", { name: /create a credential/i })).toBeVisible();
  });
});
