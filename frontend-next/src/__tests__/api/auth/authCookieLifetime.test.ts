import { describe, it, expect } from 'vitest';

import {
  DEFAULT_ACCESS_TOKEN_MAX_AGE,
  DEFAULT_REFRESH_TOKEN_MAX_AGE,
  maxAgeFromLifetime,
  maxAgeFromTokenExp,
} from '@/utils/authCookieLifetime';

const FALLBACK = 1234;
const MAX_COOKIE_MAX_AGE = 400 * 24 * 60 * 60;

function jwtWithPayload(payload: unknown): string {
  const body = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  return `header.${body}.signature`;
}

describe('maxAgeFromLifetime', () => {
  it('uses backend-reported seconds when they are sane', () => {
    expect(maxAgeFromLifetime(900, FALLBACK)).toBe(900);
  });

  it('preserves the historical defaults the backend defaults produce', () => {
    expect(maxAgeFromLifetime(1800, DEFAULT_ACCESS_TOKEN_MAX_AGE)).toBe(30 * 60);
    expect(maxAgeFromLifetime(604800, DEFAULT_REFRESH_TOKEN_MAX_AGE)).toBe(7 * 24 * 60 * 60);
  });

  it('falls back when the backend omits the metadata', () => {
    expect(maxAgeFromLifetime(undefined, FALLBACK)).toBe(FALLBACK);
    expect(maxAgeFromLifetime(null, FALLBACK)).toBe(FALLBACK);
  });

  it('falls back on malformed, zero, or negative metadata', () => {
    expect(maxAgeFromLifetime('1800', FALLBACK)).toBe(FALLBACK);
    expect(maxAgeFromLifetime(Number.NaN, FALLBACK)).toBe(FALLBACK);
    expect(maxAgeFromLifetime(Number.POSITIVE_INFINITY, FALLBACK)).toBe(FALLBACK);
    expect(maxAgeFromLifetime(0, FALLBACK)).toBe(FALLBACK);
    expect(maxAgeFromLifetime(-60, FALLBACK)).toBe(FALLBACK);
    expect(maxAgeFromLifetime({ seconds: 60 }, FALLBACK)).toBe(FALLBACK);
  });

  it('truncates fractional seconds to a whole-second Max-Age', () => {
    expect(maxAgeFromLifetime(90.9, FALLBACK)).toBe(90);
  });

  it('clamps absurdly long lifetimes instead of trusting them', () => {
    expect(maxAgeFromLifetime(50 * 365 * 24 * 60 * 60, FALLBACK)).toBe(MAX_COOKIE_MAX_AGE);
  });
});

describe('maxAgeFromTokenExp', () => {
  const now = 1_700_000_000;

  it('derives the remaining lifetime from the signed exp claim', () => {
    const token = jwtWithPayload({ sub: 'admin', exp: now + 600 });
    expect(maxAgeFromTokenExp(token, now)).toBe(600);
  });

  it('reports no usable deadline when the token is not a JWT', () => {
    expect(maxAgeFromTokenExp('opaque-token', now)).toBeNull();
    expect(maxAgeFromTokenExp('header.only', now)).toBeNull();
    expect(maxAgeFromTokenExp('', now)).toBeNull();
    expect(maxAgeFromTokenExp(undefined, now)).toBeNull();
    expect(maxAgeFromTokenExp(12345, now)).toBeNull();
  });

  it('reports no usable deadline when the payload is unparseable or not an object', () => {
    const notJson = `header.${Buffer.from('not-json', 'utf8').toString('base64url')}.sig`;
    expect(maxAgeFromTokenExp(notJson, now)).toBeNull();
    expect(maxAgeFromTokenExp(jwtWithPayload([1, 2, 3]), now)).toBeNull();
    expect(maxAgeFromTokenExp(jwtWithPayload(null), now)).toBeNull();
  });

  it('reports no usable deadline when exp is missing or not a number', () => {
    expect(maxAgeFromTokenExp(jwtWithPayload({ sub: 'admin' }), now)).toBeNull();
    expect(maxAgeFromTokenExp(jwtWithPayload({ exp: 'soon' }), now)).toBeNull();
    expect(maxAgeFromTokenExp(jwtWithPayload({ exp: null }), now)).toBeNull();
    expect(maxAgeFromTokenExp(jwtWithPayload({ exp: Number.NaN }), now)).toBeNull();
  });

  it('reports no usable deadline for an already-expired or just-expired token', () => {
    expect(maxAgeFromTokenExp(jwtWithPayload({ exp: now - 60 }), now)).toBeNull();
    expect(maxAgeFromTokenExp(jwtWithPayload({ exp: now }), now)).toBeNull();
  });

  it('clamps a valid but absurdly distant exp instead of rejecting it', () => {
    const token = jwtWithPayload({ exp: now + 50 * 365 * 24 * 60 * 60 });
    expect(maxAgeFromTokenExp(token, now)).toBe(MAX_COOKIE_MAX_AGE);
  });

  it('defaults to the current clock when no reference time is given', () => {
    const token = jwtWithPayload({ exp: Math.floor(Date.now() / 1000) + 3600 });
    const maxAge = maxAgeFromTokenExp(token);
    expect(maxAge).not.toBeNull();
    expect(maxAge as number).toBeGreaterThan(3500);
    expect(maxAge as number).toBeLessThanOrEqual(3600);
  });
});
