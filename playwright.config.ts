import { defineConfig } from "@playwright/test";
import path from "path";

const STORAGE_STATE = path.join(
  __dirname,
  "test-results",
  ".auth",
  "user.json",
);

export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  retries: 0,
  workers: 1,
  reporter: [["list"], ["html", { open: "never" }]],

  use: {
    // PRA-299: the prod-parity stack publishes no direct frontend port; Caddy
    // (--profile proxy) is the browser ingress at https://localhost. Override
    // with E2E_BASE_URL for other topologies.
    baseURL: process.env.E2E_BASE_URL ?? "https://localhost",
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
      // PRA-250: pure-logic unit specs that need no browser, no auth, and no
      // running stack. Kept out of the chromium project (below) so they don't
      // drag in the auth setup dependency. Run with:
      //   npx playwright test --project=unit
      name: "unit",
      testMatch: /\.unit\.spec\.ts$/,
    },
    {
      name: "chromium",
      testIgnore: /\.unit\.spec\.ts$/,
      use: {
        browserName: "chromium",
        storageState: STORAGE_STATE,
      },
      dependencies: ["setup"],
    },
  ],
});
