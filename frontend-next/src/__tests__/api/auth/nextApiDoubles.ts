import type { NextApiRequest, NextApiResponse } from 'next';

// Minimal NextApiRequest/Response test doubles shared by the auth API-route
// tests. The handlers only touch req.method, req.body, req.cookies, and
// res.status().json() / res.setHeader().
export function makeReq(
  init: { method?: string; body?: unknown; cookies?: Record<string, string> } = {}
): NextApiRequest {
  return {
    method: init.method ?? 'POST',
    body: init.body ?? {},
    cookies: init.cookies ?? {},
  } as unknown as NextApiRequest;
}

export function makeRes() {
  const res = {
    statusCode: 0,
    body: undefined as unknown,
    headers: {} as Record<string, string | string[]>,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(payload: unknown) {
      this.body = payload;
      return this;
    },
    setHeader(name: string, value: string | string[]) {
      this.headers[name] = value;
    },
  };
  return res as typeof res & NextApiResponse;
}

export function jsonResponse(payload: unknown, ok = true, status = 200): Response {
  return {
    ok,
    status,
    json: async () => payload,
  } as unknown as Response;
}

/** Set-Cookie entries emitted by a handler, keyed by cookie name. */
export function setCookies(res: ReturnType<typeof makeRes>): Record<string, string> {
  const header = res.headers['Set-Cookie'];
  const entries = Array.isArray(header) ? header : header ? [header] : [];
  return Object.fromEntries(entries.map((cookie) => [cookie.split('=')[0], cookie]));
}

export function maxAgeOf(cookie: string): number {
  const match = /Max-Age=(-?\d+)/.exec(cookie);
  if (!match) throw new Error(`no Max-Age in cookie: ${cookie}`);
  return Number(match[1]);
}

/**
 * The security attributes every auth cookie must keep. NODE_ENV is not
 * "production" under test, so Secure is expected to be absent here; the
 * production-only Secure flag is covered by the cookies utility itself.
 */
export function expectSecurityAttrs(cookie: string): void {
  const attrs = cookie.split('; ').slice(1);
  if (!attrs.includes('Path=/')) throw new Error(`missing Path=/: ${cookie}`);
  if (!attrs.includes('HttpOnly')) throw new Error(`missing HttpOnly: ${cookie}`);
  if (!attrs.includes('SameSite=Lax')) throw new Error(`missing SameSite=Lax: ${cookie}`);
}

/** Signed-token stand-in: only the payload segment is ever read. */
export function jwtWithPayload(payload: unknown): string {
  const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  return `header.${body}.signature`;
}

export function jwtWithExp(expSeconds: number): string {
  return jwtWithPayload({ sub: 'admin', exp: expSeconds });
}
