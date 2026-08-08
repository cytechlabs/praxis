import { describe, it, expect, vi, afterEach } from 'vitest';

import handler from '@/pages/api/auth/refresh';

import {
  expectSecurityAttrs,
  jsonResponse,
  makeReq,
  makeRes,
  maxAgeOf,
  setCookies,
} from './nextApiDoubles';

async function refresh(tokenPayload: Record<string, unknown>) {
  global.fetch = vi.fn().mockResolvedValueOnce(jsonResponse(tokenPayload));
  const res = makeRes();
  await handler(makeReq({ cookies: { refresh_token: 'old-r-tok' } }), res);
  return res;
}

describe('refresh API route cookie lifetimes', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('uses the lifetimes the backend reported for the rotated tokens', async () => {
    const res = await refresh({
      access_token: 'a-tok',
      refresh_token: 'new-r-tok',
      token_type: 'bearer',
      expires_in: 300,
      refresh_expires_in: 3 * 24 * 60 * 60,
    });

    const cookies = setCookies(res);
    expect(res.statusCode).toBe(200);
    expect(maxAgeOf(cookies.access_token)).toBe(300);
    expect(maxAgeOf(cookies.refresh_token)).toBe(3 * 24 * 60 * 60);
  });

  it('produces the historical 30-minute / 7-day cookies on backend defaults', async () => {
    const res = await refresh({
      access_token: 'a-tok',
      refresh_token: 'new-r-tok',
      token_type: 'bearer',
      expires_in: 30 * 60,
      refresh_expires_in: 7 * 24 * 60 * 60,
    });

    const cookies = setCookies(res);
    expect(maxAgeOf(cookies.access_token)).toBe(30 * 60);
    expect(maxAgeOf(cookies.refresh_token)).toBe(7 * 24 * 60 * 60);
  });

  it('falls back to the historical lifetimes when a backend omits the metadata', async () => {
    const res = await refresh({ access_token: 'a-tok', refresh_token: 'new-r-tok' });

    const cookies = setCookies(res);
    expect(maxAgeOf(cookies.access_token)).toBe(30 * 60);
    expect(maxAgeOf(cookies.refresh_token)).toBe(7 * 24 * 60 * 60);
  });

  it('ignores malformed metadata instead of minting unsafe cookies', async () => {
    const res = await refresh({
      access_token: 'a-tok',
      refresh_token: 'new-r-tok',
      expires_in: Number.NaN,
      refresh_expires_in: 10 * 365 * 24 * 60 * 60,
    });

    const cookies = setCookies(res);
    expect(maxAgeOf(cookies.access_token)).toBe(30 * 60);
    expect(maxAgeOf(cookies.refresh_token)).toBe(400 * 24 * 60 * 60);
  });

  it('rotates the refresh cookie and keeps the security attributes', async () => {
    const res = await refresh({
      access_token: 'a-tok',
      refresh_token: 'new-r-tok',
      expires_in: 900,
      refresh_expires_in: 1800,
    });

    const cookies = setCookies(res);
    expect(Object.keys(cookies).sort()).toEqual(['access_token', 'refresh_token']);
    expect(cookies.refresh_token.startsWith('refresh_token=new-r-tok; ')).toBe(true);
    expectSecurityAttrs(cookies.access_token);
    expectSecurityAttrs(cookies.refresh_token);
    expect(res.body).toEqual({ ok: true });
  });

  it('leaves the refresh cookie untouched when the backend returns no new one', async () => {
    const res = await refresh({ access_token: 'a-tok', expires_in: 900 });

    const cookies = setCookies(res);
    expect(Object.keys(cookies)).toEqual(['access_token']);
    expect(maxAgeOf(cookies.access_token)).toBe(900);
  });

  it('clears both cookies when the refresh token is rejected', async () => {
    global.fetch = vi.fn().mockResolvedValueOnce(jsonResponse({}, false, 401));
    const res = makeRes();

    await handler(makeReq({ cookies: { refresh_token: 'old-r-tok' } }), res);

    const cookies = setCookies(res);
    expect(res.statusCode).toBe(401);
    expect(maxAgeOf(cookies.access_token)).toBe(0);
    expect(maxAgeOf(cookies.refresh_token)).toBe(0);
    expectSecurityAttrs(cookies.access_token);
    expectSecurityAttrs(cookies.refresh_token);
  });

  it('rejects a request with no refresh cookie', async () => {
    global.fetch = vi.fn();
    const res = makeRes();

    await handler(makeReq({}), res);

    expect(res.statusCode).toBe(401);
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it('rejects non-POST methods', async () => {
    global.fetch = vi.fn();
    const res = makeRes();

    await handler(makeReq({ method: 'GET', cookies: { refresh_token: 'old-r-tok' } }), res);

    expect(res.statusCode).toBe(405);
    expect(global.fetch).not.toHaveBeenCalled();
  });
});
