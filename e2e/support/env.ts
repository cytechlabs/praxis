/**
 * Shared environment contract for the browser suite.
 *
 * Every spec reads topology and credentials from here so a single set of
 * variables describes the stack under test:
 *
 *   E2E_BASE_URL     browser origin (default https://localhost, the Caddy ingress)
 *   PRAXIS_API_BASE  API origin including /api/backend (default derived from
 *                    E2E_BASE_URL)
 *   E2E_USERNAME     bootstrap administrator (default praxisadmin)
 *   E2E_PASSWORD     bootstrap administrator password (required, no default)
 *   E2E_EDITION      "free" (default) or "paid"; see support/edition.ts
 */

import path from "path";

/** Saved administrator session shared by every browser project. */
export const STORAGE_STATE = path.join(
  __dirname,
  "..",
  "..",
  "test-results",
  ".auth",
  "user.json",
);

export const BASE_URL = (process.env.E2E_BASE_URL ?? "https://localhost").replace(
  /\/+$/,
  "",
);

export const API_BASE = (
  process.env.PRAXIS_API_BASE ?? `${BASE_URL}/api/backend`
).replace(/\/+$/, "");

export const ADMIN_USER = process.env.E2E_USERNAME ?? "praxisadmin";

/** Fails with a clear message instead of a misleading authentication error. */
export function adminPassword(): string {
  const value = process.env.E2E_PASSWORD;
  if (!value) {
    throw new Error(
      "E2E_PASSWORD is not set. Provide the bootstrap administrator password " +
        "of the stack under test (see e2e/README.md).",
    );
  }
  return value;
}

/** Edition the stack under test is expected to run. */
export const EXPECTED_EDITION: "free" | "paid" =
  process.env.E2E_EDITION === "paid" ? "paid" : "free";
