import type {
  APIRequestContext,
  PlaywrightWorkerArgs,
} from "@playwright/test";

import { STORAGE_STATE } from "./env";

/**
 * API client that carries the suite's saved administrator session.
 *
 * Fixture setup and teardown use this instead of signing in again, so they
 * spend no login attempts against the rate-limited login endpoint.
 */
export async function adminApi(
  playwright: PlaywrightWorkerArgs["playwright"],
): Promise<APIRequestContext> {
  return playwright.request.newContext({
    storageState: STORAGE_STATE,
    ignoreHTTPSErrors: true,
  });
}
