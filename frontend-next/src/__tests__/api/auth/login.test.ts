import { describe, it, expect, vi, afterEach } from 'vitest';

import handler from '@/pages/api/auth/login';

import {
  expectSecurityAttrs,
  jsonResponse,
  makeReq,
  makeRes,
  maxAgeOf,
  setCookies,
} from './nextApiDoubles';

const CREDENTIALS = { username: 'admin', password: 'hunter2hunter2' };

function stubBackend(tokenPayload: Record<string, unknown>) {
  const fetchMock = vi
    .fn()
    .mockResolvedValueOnce(jsonResponse(tokenPayload))
    .mockResolvedValueOnce(jsonResponse({ id: 1, username: 'admin', roles: ['admin'] }));
  global.fetch = fetchMock;
  return fetchMock;
}

async function login(tokenPayload: Record<string, unknown>) {
  stubBackend(tokenPayload);
  const res = makeRes();
  await handler(makeReq({ body: CREDENTIALS }), res);
  return res;
}

describe('login API route cookie lifetimes', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('uses the lifetimes the backend reported for the tokens it minted', async () => {
    const res = await login({
      access_token: 'a-tok',
      refresh_token: 'r-tok',
      token_type: 'bearer',
      expires_in: 900,
      refresh_expires_in: 2 * 24 * 60 * 60,
    });

    const cookies = setCookies(res);
    expect(res.statusCode).toBe(200);
    expect(maxAgeOf(cookies.access_token)).toBe(900);
    expect(maxAgeOf(cookies.refresh_token)).toBe(2 * 24 * 60 * 60);
  });

  it('produces the historical 30-minute / 7-day cookies on backend defaults', async () => {
    const res = await login({
      access_token: 'a-tok',
      refresh_token: 'r-tok',
      token_type: 'bearer',
      expires_in: 30 * 60,
      refresh_expires_in: 7 * 24 * 60 * 60,
    });

    const cookies = setCookies(res);
    expect(maxAgeOf(cookies.access_token)).toBe(30 * 60);
    expect(maxAgeOf(cookies.refresh_token)).toBe(7 * 24 * 60 * 60);
  });

  it('falls back to the historical lifetimes when a backend omits the metadata', async () => {
    const res = await login({
      access_token: 'a-tok',
      refresh_token: 'r-tok',
      token_type: 'bearer',
    });

    const cookies = setCookies(res);
    expect(maxAgeOf(cookies.access_token)).toBe(30 * 60);
    expect(maxAgeOf(cookies.refresh_token)).toBe(7 * 24 * 60 * 60);
  });

  it('ignores malformed or negative metadata instead of minting unsafe cookies', async () => {
    const res = await login({
      access_token: 'a-tok',
      refresh_token: 'r-tok',
      token_type: 'bearer',
      expires_in: -1,
      refresh_expires_in: 'forever',
    });

    const cookies = setCookies(res);
    expect(maxAgeOf(cookies.access_token)).toBe(30 * 60);
    expect(maxAgeOf(cookies.refresh_token)).toBe(7 * 24 * 60 * 60);
  });

  it('keeps cookie names, values, and security attributes unchanged', async () => {
    const res = await login({
      access_token: 'a-tok',
      refresh_token: 'r-tok',
      token_type: 'bearer',
      expires_in: 900,
      refresh_expires_in: 1800,
    });

    const cookies = setCookies(res);
    expect(Object.keys(cookies).sort()).toEqual(['access_token', 'refresh_token']);
    expect(cookies.access_token.startsWith('access_token=a-tok; ')).toBe(true);
    expect(cookies.refresh_token.startsWith('refresh_token=r-tok; ')).toBe(true);
    expectSecurityAttrs(cookies.access_token);
    expectSecurityAttrs(cookies.refresh_token);
    expect(res.body).toEqual({ id: 1, username: 'admin', roles: ['admin'] });
  });

  it('sets no cookies when the backend rejects the credentials', async () => {
    global.fetch = vi.fn().mockResolvedValueOnce(jsonResponse({ detail: 'nope' }, false, 401));
    const res = makeRes();

    await handler(makeReq({ body: CREDENTIALS }), res);

    expect(res.statusCode).toBe(401);
    expect(res.headers['Set-Cookie']).toBeUndefined();
  });

  it('rejects non-POST methods', async () => {
    global.fetch = vi.fn();
    const res = makeRes();

    await handler(makeReq({ method: 'GET', body: CREDENTIALS }), res);

    expect(res.statusCode).toBe(405);
    expect(global.fetch).not.toHaveBeenCalled();
  });
});
