import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { NextApiRequest, NextApiResponse } from 'next';

import handler from '@/pages/api/auth/logout';

// Minimal NextApiRequest/Response test doubles: the logout handler only touches
// req.method, req.cookies, res.status().json(), and res.setHeader(). Backend
// revocation goes through the global fetch, which we stub.
function makeReq(cookies: Record<string, string>, method = 'POST'): NextApiRequest {
  return { method, cookies } as unknown as NextApiRequest;
}

function makeRes() {
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

describe('logout API route (PRA-366)', () => {
  beforeEach(() => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true } as Response);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('calls backend revoke when a refresh cookie exists but no access cookie', async () => {
    const req = makeReq({ refresh_token: 'r-tok' });
    const res = makeRes();

    await handler(req, res);

    expect(global.fetch).toHaveBeenCalledTimes(1);
    const [url, init] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toContain('/auth/logout?token_refresh=r-tok');
    expect(init.method).toBe('POST');
    // No access token -> no Authorization header.
    expect(init.headers.Authorization).toBeUndefined();
    // Cookies still cleared, ok response.
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ ok: true });
    expect(res.headers['Set-Cookie']).toHaveLength(2);
  });

  it('calls backend revoke with bearer when both cookies exist', async () => {
    const req = makeReq({ access_token: 'a-tok', refresh_token: 'r-tok' });
    const res = makeRes();

    await handler(req, res);

    expect(global.fetch).toHaveBeenCalledTimes(1);
    const [, init] = (global.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(init.headers.Authorization).toBe('Bearer a-tok');
    expect(res.statusCode).toBe(200);
  });

  it('skips backend revoke but still clears cookies when no refresh cookie', async () => {
    const req = makeReq({ access_token: 'a-tok' });
    const res = makeRes();

    await handler(req, res);

    expect(global.fetch).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ ok: true });
    expect(res.headers['Set-Cookie']).toHaveLength(2);
  });

  it('still clears cookies and returns ok when backend revoke fails', async () => {
    global.fetch = vi.fn().mockRejectedValue(new Error('backend down'));
    const req = makeReq({ refresh_token: 'r-tok' });
    const res = makeRes();

    await handler(req, res);

    expect(global.fetch).toHaveBeenCalledTimes(1);
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ ok: true });
    expect(res.headers['Set-Cookie']).toHaveLength(2);
  });

  it('rejects non-POST methods', async () => {
    const req = makeReq({ refresh_token: 'r-tok' }, 'GET');
    const res = makeRes();

    await handler(req, res);

    expect(res.statusCode).toBe(405);
    expect(global.fetch).not.toHaveBeenCalled();
  });
});
