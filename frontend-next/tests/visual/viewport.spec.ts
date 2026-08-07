import { test, expect } from '@playwright/test';

/**
 * PRA-272: screenshot + assertion coverage for the desktop support boundary.
 *
 * Keep these widths in sync with `src/config/viewport.ts`
 * (MIN_SUPPORTED_WIDTH = 1280). Duplicated here because this spec is excluded
 * from the app tsconfig (it is a standalone local gate, not part of the build).
 */
const MIN_SUPPORTED_WIDTH = 1280;

const WIDTHS = [
  { name: 'unsupported-390', width: 390, height: 844, supported: false },
  { name: 'boundary-1280', width: MIN_SUPPORTED_WIDTH, height: 900, supported: true },
  { name: 'wide-1600', width: 1600, height: 1000, supported: true },
];

for (const vp of WIDTHS) {
  test(`login shell @ ${vp.name}`, async ({ page }) => {
    await page.setViewportSize({ width: vp.width, height: vp.height });
    await page.goto('/login');

    const shell = page.getByRole('alert').filter({ hasText: 'Optimized for desktop' });

    if (vp.supported) {
      // Supported widths: the console/login is usable, the shell is hidden.
      await expect(shell).toBeHidden();
      await expect(page.getByRole('button', { name: /sign in/i })).toBeVisible();
    } else {
      // Unsupported widths: the branded shell replaces the app, no clipped chrome.
      await expect(shell).toBeVisible();
      await expect(page.getByRole('button', { name: /sign in/i })).toBeHidden();
    }

    await page.screenshot({ path: `tests/visual/__screenshots__/${vp.name}.png`, fullPage: true });
  });
}
