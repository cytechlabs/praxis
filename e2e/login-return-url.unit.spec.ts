/**
 * PRA-250: pure-logic coverage for safeLoginReturnUrl.
 *
 * This is a browser-free, auth-free unit spec run under the Playwright "unit"
 * project (see playwright.config.ts) so it needs no running stack:
 *   npx playwright test --project=unit
 *
 * It proves the login return-URL sanitizer preserves legitimate same-origin
 * paths (including query/hash fragments) and collapses every open-redirect
 * vector — protocol, scheme-relative, backslash, encoded, array, and malformed
 * inputs — down to "/".
 */

import { test, expect } from "@playwright/test";

import { safeLoginReturnUrl } from "../frontend-next/src/utils/redirect";

// Legitimate same-origin destinations must pass through UNCHANGED so deep links
// with query strings and hashes still work after login.
const ALLOWED: string[] = [
  "/",
  "/fleet-dashboard",
  "/system-management/all-systems?status=Unreachable",
  "/hosts/123/session?join=observe&sid=456",
  "/path#fragment",
  "/fleet-dashboard?x=1#section",
  "/search?q=hello%20world", // encoded space in a query is fine
];

// Every one of these must collapse to "/". Covers protocol URLs,
// scheme-relative authorities, raw + encoded backslashes, encoded slash tricks,
// bare payloads, triple slash, and malformed percent-encoding.
const REJECTED: unknown[] = [
  "https://evil.example",
  "http://evil.example",
  "javascript:alert(1)",
  "//evil.example/path",
  "/%2f%2fevil.example",
  "%2f%2fevil.example",
  "/\\evil.example",
  "%5cevil.example",
  "/foo%5cbar",
  "\\\\evil.example",
  "///evil.example",
  "/%5cevil.example",
  "/\tevil.example", // raw tab -> browsers may fold into "//evil"
  "/%zz", // malformed percent-encoding
  "/%", // truncated percent-encoding
  "", // empty
  " ", // whitespace-only, not rooted
  "relative/path", // not rooted
  ["/fleet-dashboard"], // array-valued returnUrl
  ["/a", "/b"],
  undefined,
  null,
];

test.describe("safeLoginReturnUrl", () => {
  for (const value of ALLOWED) {
    test(`allows ${JSON.stringify(value)}`, () => {
      // Allowed inputs are returned verbatim (fragments preserved).
      expect(safeLoginReturnUrl(value)).toBe(value);
    });
  }

  for (const value of REJECTED) {
    test(`rejects ${JSON.stringify(value)} -> "/"`, () => {
      expect(
        safeLoginReturnUrl(value as string | string[] | undefined),
      ).toBe("/");
    });
  }

  test("never returns a value that leaves the app origin", () => {
    // Property check: for any input, the result resolved against a foreign
    // origin must stay on our dummy origin (i.e. it is a rooted internal path).
    const base = "http://app.local";
    const inputs = [...ALLOWED, ...REJECTED];
    for (const value of inputs) {
      const out = safeLoginReturnUrl(
        value as string | string[] | undefined,
      );
      const resolved = new URL(out, base);
      expect(resolved.origin).toBe(base);
      expect(out.startsWith("/")).toBe(true);
      expect(out.startsWith("//")).toBe(false);
    }
  });
});
