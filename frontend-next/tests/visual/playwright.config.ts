import { defineConfig } from '@playwright/test';

/**
 * PRA-272: local visual gate for the desktop support boundary.
 *
 * This is intentionally NOT wired into the CI frontend lane — CI has no browser
 * runtime and cannot fetch the Google Fonts that `next build`/`next dev` pull.
 * Run it locally with a working network:
 *
 *   npx playwright install chromium   # one-time
 *   npm run test:visual
 *
 * It boots the dev server, drives the login/unauthenticated shell at three
 * widths (unsupported / boundary / wide desktop), asserts the gate behavior, and
 * writes screenshots to tests/visual/__screenshots__/ (gitignored).
 */
export default defineConfig({
  testDir: '.',
  outputDir: './__results__',
  timeout: 60_000,
  use: {
    baseURL: 'http://127.0.0.1:3000',
  },
  webServer: {
    command: 'npm run dev',
    url: 'http://127.0.0.1:3000/login',
    reuseExistingServer: true,
    timeout: 120_000,
    cwd: process.cwd(),
  },
});
