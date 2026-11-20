import type {
  APIRequestContext,
  PlaywrightWorkerArgs,
} from "@playwright/test";

import { readFile } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";

import { API_BASE, STORAGE_STATE } from "./env";

/**
 * API client that carries the suite's saved administrator session.
 *
 * Fixture setup and teardown use this instead of signing in again, so they
 * spend no login attempts against the rate-limited login endpoint.
 */
export function adminApi(
  playwright: PlaywrightWorkerArgs["playwright"],
): Promise<APIRequestContext> {
  return playwright.request.newContext({
    storageState: STORAGE_STATE,
    ignoreHTTPSErrors: true,
  });
}

export interface SavedCookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  expires?: number;
}

const SESSION_COOKIE = "access_token";

/** Hosts where the local ingress serves its internal self-signed certificate. */
const LOCAL_INGRESS_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * A saved domain starting with a dot is a domain cookie and also covers
 * subdomains; one without is host-only and covers that exact host.
 */
function domainMatches(cookieDomain: string, hostname: string): boolean {
  if (!cookieDomain.startsWith(".")) return hostname === cookieDomain;
  const domain = cookieDomain.slice(1);
  return hostname === domain || hostname.endsWith(`.${domain}`);
}

/** Path matching per RFC 6265: a prefix that ends at a segment boundary. */
function pathMatches(cookiePath: string, requestPath: string): boolean {
  if (requestPath === cookiePath) return true;
  if (!requestPath.startsWith(cookiePath)) return false;
  return cookiePath.endsWith("/") || requestPath[cookiePath.length] === "/";
}

/**
 * The Cookie header value for the session cookie when one applies to the
 * request, otherwise an empty string. Exported for unit tests.
 */
export function sessionCookieFor(
  cookies: SavedCookie[],
  target: URL,
  nowSeconds: number,
): string {
  const match = cookies.find(
    (c) =>
      c.name === SESSION_COOKIE &&
      domainMatches(c.domain, target.hostname) &&
      pathMatches(c.path, target.pathname) &&
      (!c.secure || target.protocol === "https:") &&
      // Playwright stores a session cookie with expires -1.
      (c.expires === undefined || c.expires < 0 || c.expires > nowSeconds),
  );
  return match ? `${match.name}=${match.value}` : "";
}

/**
 * POST a JSON body with the saved administrator session, outside Playwright.
 *
 * Playwright records the body of every request it issues, including those from
 * `playwright.request.newContext`, in the trace and the retained failure
 * artifacts. Use this for a request that carries a secret (for example a
 * generated credential password) so the secret never reaches those artifacts.
 * It is not a general client: it only talks to the suite's API origin,
 * sends only the unexpired session cookie that applies to the request, trusts
 * a self-signed certificate only for the local ingress, and returns only the
 * status and raw body.
 */
export async function postJsonUntraced(
  url: string,
  data: unknown,
): Promise<{ status: number; body: string }> {
  const target = new URL(url);
  if (target.origin !== new URL(API_BASE).origin) {
    throw new Error(
      `refusing to send the session outside the API origin (${target.origin})`,
    );
  }
  const saved = JSON.parse(await readFile(STORAGE_STATE, "utf8")) as {
    cookies?: SavedCookie[];
  };
  const cookie = sessionCookieFor(
    saved.cookies ?? [],
    target,
    Date.now() / 1000,
  );
  const payload = JSON.stringify(data);
  const send = target.protocol === "https:" ? httpsRequest : httpRequest;

  return new Promise((resolve, reject) => {
    const req = send(
      target,
      {
        method: "POST",
        rejectUnauthorized: !LOCAL_INGRESS_HOSTS.has(target.hostname),
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(payload),
          ...(cookie ? { cookie } : {}),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf8"),
          }),
        );
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}
