import { describe, it, expect, vi, afterEach } from 'vitest';

import handler from '@/pages/api/auth/oidc-complete';

import {
  expectSecurityAttrs,
  jsonResponse,
  jwtWithExp,
  jwtWithPayload,
  makeReq,
  makeRes,
  maxAgeOf,
  setCookies,
} from './nextApiDoubles';

const USER = { id: 1, username: 'sso-user', roles: ['viewer'] };

async function complete(body: Record<string, unknown>) {
  const fetchMock = vi.fn().mockResolvedValueOnce(jsonResponse(USER));
  global.fetch = fetchMock;
  const res = makeRes();
  await handler(makeReq({ body }), res);
  return { res, fetchMock };
}

function inSeconds(offset: number): number {
  return Math.floor(Date.now() / 1000) + offset;
}

describe('oidc-complete API route cookie lifetimes', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('derives each cookie lifetime from its own signed exp claim', async () => {
    const { res } = await complete({
      access_token: jwtWithExp(inSeconds(900)),
      refresh_token: jwtWithExp(inSeconds(3 * 24 * 60 * 60)),
    });

    const cookies = setCookies(res);
    expect(res.statusCode).toBe(200);
    expect(maxAgeOf(cookies.access_token)).toBeGreaterThan(890);
    expect(maxAgeOf(cookies.access_token)).toBeLessThanOrEqual(900);
    expect(maxAgeOf(cookies.refresh_token)).toBeGreaterThan(3 * 24 * 60 * 60 - 10);
    expect(maxAgeOf(cookies.refresh_token)).toBeLessThanOrEqual(3 * 24 * 60 * 60);
  });

  it('produces the historical lifetimes for backend-default token deadlines', async () => {
    const { res } = await complete({
      access_token: jwtWithExp(inSeconds(30 * 60)),
      refresh_token: jwtWithExp(inSeconds(7 * 24 * 60 * 60)),
    });

    const cookies = setCookies(res);
    expect(maxAgeOf(cookies.access_token)).toBeGreaterThan(30 * 60 - 10);
    expect(maxAgeOf(cookies.access_token)).toBeLessThanOrEqual(30 * 60);
    expect(maxAgeOf(cookies.refresh_token)).toBeGreaterThan(7 * 24 * 60 * 60 - 10);
    expect(maxAgeOf(cookies.refresh_token)).toBeLessThanOrEqual(7 * 24 * 60 * 60);
  });

  it('clamps a valid but absurdly distant exp instead of rejecting it', async () => {
    const { res } = await complete({
      access_token: jwtWithExp(inSeconds(50 * 365 * 24 * 60 * 60)),
      refresh_token: jwtWithExp(inSeconds(50 * 365 * 24 * 60 * 60)),
    });

    const cookies = setCookies(res);
    expect(res.statusCode).toBe(200);
    expect(maxAgeOf(cookies.access_token)).toBe(400 * 24 * 60 * 60);
    expect(maxAgeOf(cookies.refresh_token)).toBe(400 * 24 * 60 * 60);
  });

  it('keeps cookie names, values, and security attributes unchanged', async () => {
    const access = jwtWithExp(inSeconds(900));
    const refresh = jwtWithExp(inSeconds(1800));
    const { res } = await complete({ access_token: access, refresh_token: refresh });

    const cookies = setCookies(res);
    expect(Object.keys(cookies).sort()).toEqual(['access_token', 'refresh_token']);
    expect(cookies.access_token.startsWith(`access_token=${access}; `)).toBe(true);
    expect(cookies.refresh_token.startsWith(`refresh_token=${refresh}; `)).toBe(true);
    expectSecurityAttrs(cookies.access_token);
    expectSecurityAttrs(cookies.refresh_token);
    expect(res.body).toEqual(USER);
  });

  // A token without a readable deadline cannot be stored as a live session. The
  // route must refuse rather than substitute a default lifetime, so each case
  // below asserts both the 4xx and the absence of any Set-Cookie header.
  describe('refuses completion when a token carries no usable deadline', () => {
    const valid = () => jwtWithExp(inSeconds(900));

    const cases: Array<[string, Record<string, unknown>]> = [
      ['malformed access token', { access_token: 'not-a-jwt', refresh_token: valid() }],
      [
        'access payload that is not readable JSON',
        {
          access_token: `header.${Buffer.from('not-json', 'utf8').toString('base64url')}.sig`,
          refresh_token: valid(),
        },
      ],
      [
        'access token missing exp',
        { access_token: jwtWithPayload({ sub: 'sso-user' }), refresh_token: valid() },
      ],
      [
        'access token with a nonnumeric exp',
        { access_token: jwtWithPayload({ exp: 'tomorrow' }), refresh_token: valid() },
      ],
      [
        'expired access token',
        { access_token: jwtWithExp(inSeconds(-60)), refresh_token: valid() },
      ],
      [
        'valid access token paired with an expired refresh token',
        { access_token: valid(), refresh_token: jwtWithExp(inSeconds(-1)) },
      ],
      [
        'valid access token paired with a malformed refresh token',
        { access_token: valid(), refresh_token: 'opaque-refresh' },
      ],
      [
        'valid access token paired with a refresh token missing exp',
        { access_token: valid(), refresh_token: jwtWithPayload({ sub: 'sso-user' }) },
      ],
      [
        'valid access token paired with a nonnumeric refresh exp',
        { access_token: valid(), refresh_token: jwtWithPayload({ exp: null }) },
      ],
      [
        'both tokens unusable',
        { access_token: 'nope', refresh_token: jwtWithExp(inSeconds(-3600)) },
      ],
    ];

    it.each(cases)('%s', async (_label, body) => {
      const { res } = await complete(body);

      expect(res.statusCode).toBe(401);
      expect(res.headers['Set-Cookie']).toBeUndefined();
      expect(res.body).toEqual({ error: 'Invalid token' });
    });
  });

  it('does not call the backend when a deadline is unusable', async () => {
    const { fetchMock } = await complete({
      access_token: jwtWithExp(inSeconds(900)),
      refresh_token: jwtWithExp(inSeconds(-60)),
    });

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('sets no cookies when the backend rejects the access token', async () => {
    global.fetch = vi.fn().mockResolvedValueOnce(jsonResponse({}, false, 401));
    const res = makeRes();

    await handler(
      makeReq({
        body: {
          access_token: jwtWithExp(inSeconds(900)),
          refresh_token: jwtWithExp(inSeconds(1800)),
        },
      }),
      res
    );

    expect(res.statusCode).toBe(401);
    expect(res.headers['Set-Cookie']).toBeUndefined();
  });

  it('rejects a request missing either token', async () => {
    global.fetch = vi.fn();
    const res = makeRes();

    await handler(makeReq({ body: { access_token: jwtWithExp(inSeconds(900)) } }), res);

    expect(res.statusCode).toBe(400);
    expect(res.headers['Set-Cookie']).toBeUndefined();
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it('rejects non-POST methods', async () => {
    global.fetch = vi.fn();
    const res = makeRes();

    await handler(
      makeReq({ method: 'GET', body: { access_token: 'a', refresh_token: 'r' } }),
      res
    );

    expect(res.statusCode).toBe(405);
    expect(global.fetch).not.toHaveBeenCalled();
  });
});
