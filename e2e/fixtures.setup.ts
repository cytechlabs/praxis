/**
 * Prerequisite check for the specs that read the seeded synthetic fleet.
 *
 * The fleet is created by the backend's idempotent, secret-free demo seeder
 * (see e2e/README.md). This check never creates data itself; it fails with the
 * exact command to run when the fixture is missing.
 */

import { test as setup, expect } from "@playwright/test";

import { API_BASE } from "./support/env";

export const DEMO_HOSTS = ["demo-web-01", "demo-db-01", "demo-edge-01"];

const SEED_HINT =
  "Seed the synthetic fleet first: e2e/fixtures/seed-demo.sh (see e2e/README.md).";

setup("synthetic demo fleet is seeded", async ({ request }) => {
  const res = await request.get(`${API_BASE}/systems/all`);
  expect(res.ok(), `GET /systems failed (${res.status()}). ${SEED_HINT}`).toBeTruthy();
  const body = await res.json();
  const rows: Array<{ hostname?: string }> = Array.isArray(body)
    ? body
    : (body.items ?? []);
  const present = new Set(rows.map((r) => r.hostname));
  for (const host of DEMO_HOSTS) {
    expect(present.has(host), `${host} is not registered. ${SEED_HINT}`).toBeTruthy();
  }
});
