const IS_PRODUCTION = process.env.NODE_ENV === 'production';

interface CookieOptions {
  maxAge: number;
}

// PRA-226 FRONTEND-01: the security attributes shared by every auth cookie.
// Secure is added in production (deployed builds are served over HTTPS, incl.
// behind a TLS-terminating reverse proxy); SameSite=Lax preserves the OIDC
// top-level-redirect flow while blocking cross-site sends. clearCookie must use
// the SAME attributes as serializeCookie — a browser only overwrites a cookie
// when Path/Secure/SameSite match, so a clear that dropped Secure could leave a
// Secure httpOnly session cookie live after logout.
function securityAttrs(): string[] {
  const parts = ['Path=/', 'HttpOnly', 'SameSite=Lax'];
  if (IS_PRODUCTION) {
    parts.push('Secure');
  }
  return parts;
}

export function serializeCookie(name: string, value: string, opts: CookieOptions): string {
  return [
    `${name}=${encodeURIComponent(value)}`,
    ...securityAttrs(),
    `Max-Age=${opts.maxAge}`,
  ].join('; ');
}

export function clearCookie(name: string): string {
  return [`${name}=`, ...securityAttrs(), 'Max-Age=0'].join('; ');
}

export const BACKEND_URL = process.env.BACKEND_URL || 'http://backend:8000';
