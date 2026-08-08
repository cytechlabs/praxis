// Token lifetime policy lives in the backend. These helpers translate what the
// backend reports about a token it just minted into a browser cookie Max-Age,
// so the auth API routes never restate the policy themselves.
//
// The backend is the authenticity boundary: it validates every token on every
// request. Nothing here verifies a signature, and a cookie Max-Age is only a
// storage hint. What these helpers do guarantee is that no auth cookie is ever
// given a lifetime that was not derived from a usable backend deadline.

// Kept only so a browser talking to a backend that predates the lifetime
// metadata still gets the historical session behavior instead of a session
// cookie. Transitional: remove once no supported backend omits the metadata.
export const DEFAULT_ACCESS_TOKEN_MAX_AGE = 30 * 60;
export const DEFAULT_REFRESH_TOKEN_MAX_AGE = 7 * 24 * 60 * 60;

// Browsers clamp cookie lifetimes to roughly 400 days, so anything beyond that
// is either a misconfiguration or a hostile value and is not worth honoring.
const MAX_COOKIE_MAX_AGE = 400 * 24 * 60 * 60;

function sanitizeSeconds(seconds: unknown): number | null {
  if (typeof seconds !== 'number' || !Number.isFinite(seconds)) return null;
  const whole = Math.floor(seconds);
  if (whole <= 0) return null;
  return Math.min(whole, MAX_COOKIE_MAX_AGE);
}

/**
 * Cookie Max-Age for a token whose remaining lifetime the backend reported
 * directly (the `expires_in` / `refresh_expires_in` fields of a token
 * response). Missing, malformed, zero, or negative metadata falls back, since
 * a backend predating that metadata is a supported upgrade path.
 */
export function maxAgeFromLifetime(lifetimeSeconds: unknown, fallbackSeconds: number): number {
  return sanitizeSeconds(lifetimeSeconds) ?? fallbackSeconds;
}

function decodeJwtPayload(token: unknown): Record<string, unknown> | null {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    const parsed: unknown = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null;
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

/**
 * Cookie Max-Age for an already-minted token, derived from the remaining time
 * on its `exp` claim. Used where the browser holds tokens without accompanying
 * response metadata, so the backend's own deadline stays the source of truth.
 *
 * Returns `null` when the token carries no usable deadline: not a JWT, an
 * unreadable payload, a missing or non-numeric `exp`, or an `exp` already in
 * the past. Callers must fail closed on `null` rather than substitute a default
 * lifetime, otherwise an expired token would be stored as a live session.
 * Valid but distant deadlines are clamped rather than rejected.
 */
export function maxAgeFromTokenExp(
  token: unknown,
  nowSeconds: number = Date.now() / 1000
): number | null {
  const payload = decodeJwtPayload(token);
  const exp = payload?.exp;
  if (typeof exp !== 'number' || !Number.isFinite(exp)) return null;
  return sanitizeSeconds(exp - nowSeconds);
}
