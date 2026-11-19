import { defineConfig } from "@playwright/test";
import { BASE_URL, STORAGE_STATE } from "./e2e/support/env";

// Specs that read the seeded synthetic fleet (see e2e/README.md).
const FIXTURE_SPECS = /(demo-walkthrough|rollback|remediation)\.spec\.ts$/;

export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  retries: 0,
  workers: 1,
  // Run artifacts (traces, failure screenshots) go to an ignored directory
  // that is separate from the saved auth state under test-results/.auth, which
  // Playwright must not clear between runs.
  outputDir: "test-results/run",
  reporter: [
    ["list"],
    ["html", { open: "never", outputFolder: "playwright-report" }],
  ],

  use: {
    // The production-shaped stack publishes no direct frontend port; Caddy
    // (--profile proxy) is the browser ingress. E2E_BASE_URL selects the
    // origin (default https://localhost); see e2e/support/env.ts.
    baseURL: BASE_URL,
    headless: true,
    // Local Caddy uses an internal self-signed cert (PRAXIS_TLS_MODE=internal),
    // so accept it. E2E_BASE_URL pointing at a real ACME/BYO cert host works too.
    ignoreHTTPSErrors: true,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
  },

  projects: [
    {
      name: "setup",
      testMatch: /auth\.setup\.ts/,
    },
    {
      // Pure-logic unit specs that need no browser, no auth, and no
      // running stack. Kept out of the chromium project (below) so they don't
      // drag in the auth setup dependency. Run with:
      //   npx playwright test --project=unit
      name: "unit",
      testMatch: /\.unit\.spec\.ts$/,
    },
    {
      // Verifies the seeded synthetic fleet that the demo and rollback specs
      // read. It fails with the seeding command when the fixture is absent, so
      // a missing fixture is reported as a missing prerequisite rather than as
      // dozens of unrelated assertion failures.
      name: "fixtures",
      testMatch: /fixtures\.setup\.ts/,
      use: { storageState: STORAGE_STATE },
      dependencies: ["setup"],
    },
    {
      name: "chromium",
      testIgnore: [/\.unit\.spec\.ts$/, FIXTURE_SPECS],
      use: {
        browserName: "chromium",
        storageState: STORAGE_STATE,
      },
      dependencies: ["setup"],
    },
    {
      name: "chromium-fixtures",
      testMatch: FIXTURE_SPECS,
      use: {
        browserName: "chromium",
        storageState: STORAGE_STATE,
      },
      dependencies: ["fixtures"],
    },
  ],
});
