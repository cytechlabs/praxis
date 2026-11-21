/**
 * URL-backed filter navigation (PRA-259).
 *
 * The all-systems filters are backed by useUrlState. These specs drive real
 * browser history to prove that filters follow back/forward, survive reload,
 * keep unrelated query parameters, and that several filters set together do
 * not overwrite each other.
 */

import { expect, test, type Page } from "@playwright/test";

const PAGE = "/system-management/all-systems";

const search = (page: Page) => page.getByPlaceholder("Search systems...");
const status = (page: Page) => page.locator("select").filter({ hasText: "All Statuses" });
const trust = (page: Page) => page.locator('select[title="Zero-trust CA filter"]');

function params(page: Page): URLSearchParams {
  return new URL(page.url()).searchParams;
}

async function open(page: Page, query = ""): Promise<void> {
  await page.goto(`${PAGE}${query}`);
  await expect(search(page)).toBeVisible();
}

test.describe("all-systems URL-backed filters", () => {
  test("bookmarked query hydrates every filter and keeps unrelated params", async ({ page }) => {
    await open(page, "?status=Active&ca=enabled&search=web&keep=1");
    await expect(status(page)).toHaveValue("Active");
    await expect(trust(page)).toHaveValue("enabled");
    await expect(search(page)).toHaveValue("web");

    await status(page).selectOption("Inactive");
    await expect.poll(() => params(page).get("status")).toBe("Inactive");
    expect(params(page).get("keep")).toBe("1");
    expect(params(page).get("ca")).toBe("enabled");
    expect(params(page).get("search")).toBe("web");
  });

  test("default values leave a clean URL", async ({ page }) => {
    await open(page, "?keep=1");
    await status(page).selectOption("Active");
    await expect.poll(() => params(page).get("status")).toBe("Active");
    await status(page).selectOption("all");
    await expect.poll(() => params(page).has("status")).toBe(false);
    expect(params(page).get("keep")).toBe("1");
  });

  test("back and forward move the filters with the URL", async ({ page }) => {
    await open(page, "?status=Active");
    // Filter edits replace history, so push real entries through the router
    // (as a link would) and let the hook follow back/forward across them.
    await page.evaluate(() => {
      const w = window as unknown as {
        next: { router: { push: (u: string, a?: string, o?: object) => Promise<boolean> } };
      };
      return w.next.router.push("?status=Inactive&ca=off", undefined, { shallow: true });
    });
    await expect(status(page)).toHaveValue("Inactive");
    await page.goBack();
    await expect(status(page)).toHaveValue("Active");
    await page.goForward();
    await expect(status(page)).toHaveValue("Inactive");
    await expect(trust(page)).toHaveValue("off");

    await page.goBack();
    await expect(status(page)).toHaveValue("Active");
    await expect(trust(page)).toHaveValue("all");
  });

  test("filters changed in sequence all land in the URL", async ({ page }) => {
    await open(page, "?keep=1");
    await status(page).selectOption("Active");
    await trust(page).selectOption("enabled");
    await search(page).fill("db");
    await expect.poll(() => params(page).get("search")).toBe("db");
    expect(params(page).get("status")).toBe("Active");
    expect(params(page).get("ca")).toBe("enabled");
    expect(params(page).get("keep")).toBe("1");

    await page.reload();
    await expect(status(page)).toHaveValue("Active");
    await expect(trust(page)).toHaveValue("enabled");
    await expect(search(page)).toHaveValue("db");
  });

  test("typing issues one replace per keystroke and settles (no loop)", async ({ page }) => {
    await open(page);
    // Count router replacements: navigation events alone cannot bound them.
    await page.evaluate(() => {
      const w = window as unknown as {
        __replaces: number;
        next: { router: { replace: (...a: unknown[]) => Promise<boolean> } };
      };
      w.__replaces = 0;
      const orig = w.next.router.replace.bind(w.next.router);
      w.next.router.replace = (...a: unknown[]) => {
        w.__replaces += 1;
        return orig(...a);
      };
    });
    const replaces = () =>
      page.evaluate(() => (window as unknown as { __replaces: number }).__replaces);
    await search(page).pressSequentially("abcdef", { delay: 20 });
    await expect.poll(() => params(page).get("search")).toBe("abcdef");
    await expect(search(page)).toHaveValue("abcdef");
    const settled = await replaces();
    expect(settled).toBe(6);
    // A replace loop would keep rewriting the URL; give it time to show up.
    await page.waitForTimeout(1000);
    expect(await replaces()).toBe(settled);
    // Back/forward navigation must not write either.
    await page.evaluate(() => {
      const w = window as unknown as {
        next: { router: { push: (u: string, a?: string, o?: object) => Promise<boolean> } };
      };
      return w.next.router.push("?search=zzz", undefined, { shallow: true });
    });
    await expect(search(page)).toHaveValue("zzz");
    await page.goBack();
    await expect(search(page)).toHaveValue("abcdef");
    await page.waitForTimeout(500);
    expect(await replaces()).toBe(settled);
    expect(params(page).get("search")).toBe("abcdef");
  });
});

test.describe("available-updates URL-backed search", () => {
  const UPDATES = "/package-management/available-updates";
  const box = (page: Page) => page.getByPlaceholder("Search by package name, system, or type...");

  test("bookmark, edit, reload and back/forward keep search and URL in sync", async ({ page }) => {
    await page.goto(`${UPDATES}?search=openssl&keep=1`);
    await expect(box(page)).toHaveValue("openssl");

    await box(page).fill("curl");
    await expect.poll(() => params(page).get("search")).toBe("curl");
    expect(params(page).get("keep")).toBe("1");

    await page.reload();
    await expect(box(page)).toHaveValue("curl");

    await page.evaluate(() => {
      const w = window as unknown as {
        next: { router: { push: (u: string, a?: string, o?: object) => Promise<boolean> } };
      };
      return w.next.router.push("?search=bash&keep=1", undefined, { shallow: true });
    });
    await expect(box(page)).toHaveValue("bash");
    await page.goBack();
    await expect(box(page)).toHaveValue("curl");
    await page.goForward();
    await expect(box(page)).toHaveValue("bash");

    await box(page).fill("");
    await expect.poll(() => params(page).has("search")).toBe(false);
    expect(params(page).get("keep")).toBe("1");
  });
});
