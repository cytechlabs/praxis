import { expect, test } from "@playwright/test";

import { sessionCookieFor, type SavedCookie } from "./support/api";

// Cookie selection is exercised directly, so a withheld token here comes from
// the matcher and not from the API-origin guard that runs before it.

const NOW = 1_000_000;

function cookie(overrides: Partial<SavedCookie>): SavedCookie {
  return {
    name: "access_token",
    value: "synthetic",
    domain: "app.example.test",
    path: "/",
    secure: true,
    expires: -1,
    ...overrides,
  };
}

function select(c: SavedCookie, url: string): string {
  return sessionCookieFor([c], new URL(url), NOW);
}

const TOKEN = "access_token=synthetic";

test.describe("session cookie domain matching", () => {
  test("host-only cookie matches its exact host", () => {
    expect(select(cookie({}), "https://app.example.test/x")).toBe(TOKEN);
  });

  test("host-only cookie is withheld from a subdomain", () => {
    expect(select(cookie({}), "https://sub.app.example.test/x")).toBe("");
  });

  test("domain cookie matches the host and a subdomain", () => {
    const domainCookie = cookie({ domain: ".app.example.test" });
    expect(select(domainCookie, "https://app.example.test/x")).toBe(TOKEN);
    expect(select(domainCookie, "https://sub.app.example.test/x")).toBe(TOKEN);
  });

  test("domain cookie is withheld from a suffix lookalike and a parent", () => {
    const domainCookie = cookie({ domain: ".app.example.test" });
    expect(select(domainCookie, "https://notapp.example.test/x")).toBe("");
    expect(select(domainCookie, "https://example.test/x")).toBe("");
  });
});

test.describe("session cookie path matching", () => {
  const scoped = cookie({ path: "/api" });

  test("a cookie scoped to /api matches /api and /api/credentials", () => {
    expect(select(scoped, "https://app.example.test/api")).toBe(TOKEN);
    expect(select(scoped, "https://app.example.test/api/credentials")).toBe(
      TOKEN,
    );
  });

  test("a cookie scoped to /api is withheld from /api-other", () => {
    expect(select(scoped, "https://app.example.test/api-other")).toBe("");
  });

  test("a cookie scoped to / matches a nested API path", () => {
    expect(
      select(cookie({ path: "/" }), "https://app.example.test/api/backend/credentials"),
    ).toBe(TOKEN);
  });
});

test.describe("session cookie other constraints", () => {
  test("only access_token is sent", () => {
    expect(
      select(cookie({ name: "other" }), "https://app.example.test/x"),
    ).toBe("");
  });

  test("an expired cookie is withheld and a future one is sent", () => {
    expect(
      select(cookie({ expires: NOW - 1 }), "https://app.example.test/x"),
    ).toBe("");
    expect(
      select(cookie({ expires: NOW + 1 }), "https://app.example.test/x"),
    ).toBe(TOKEN);
  });

  test("a Secure cookie is withheld from plain http", () => {
    expect(select(cookie({}), "http://app.example.test/x")).toBe("");
    expect(select(cookie({ secure: false }), "http://app.example.test/x")).toBe(
      TOKEN,
    );
  });
});
