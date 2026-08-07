/**
 * Fetch wrapper that automatically refreshes the access token on 401 responses.
 * Use this instead of fetch() for all /api/backend/ calls.
 */

let refreshPromise: Promise<boolean> | null = null;

async function refreshToken(): Promise<boolean> {
  // Deduplicate concurrent refresh attempts
  if (refreshPromise) {
    return refreshPromise;
  }

  refreshPromise = (async () => {
    try {
      const res = await fetch('/api/auth/refresh', { method: 'POST' });
      return res.ok;
    } catch {
      return false;
    } finally {
      refreshPromise = null;
    }
  })();

  return refreshPromise;
}

/**
 * Extract a human-readable error message from a FastAPI error response body.
 * Handles three shapes:
 *   - { detail: "string" }                    → "string"
 *   - { detail: [{ loc, msg, type }, ...] }   → "field: msg; field: msg"
 *   - { error: "string" }                     → "string"
 */
export function formatApiError(body: unknown, fallback = 'Request failed'): string {
  if (!body || typeof body !== 'object') return fallback;
  const b = body as Record<string, unknown>;

  if (typeof b.detail === 'string') return b.detail;
  if (Array.isArray(b.detail)) {
    const parts = b.detail
      .map((e) => {
        if (!e || typeof e !== 'object') return '';
        const err = e as Record<string, unknown>;
        const loc = Array.isArray(err.loc) ? err.loc.filter((x) => x !== 'body').join('.') : '';
        const msg = typeof err.msg === 'string' ? err.msg : '';
        return loc ? `${loc}: ${msg}` : msg;
      })
      .filter(Boolean);
    if (parts.length) return parts.join('; ');
  }
  if (typeof b.error === 'string') return b.error;
  return fallback;
}

export async function apiFetch(
  input: RequestInfo | URL,
  init?: RequestInit
): Promise<Response> {
  let response = await fetch(input, init);

  if (response.status === 401) {
    const refreshed = await refreshToken();

    if (refreshed) {
      // Retry the original request with the new cookie
      response = await fetch(input, init);
    } else {
      // Refresh failed — redirect to login
      if (typeof window !== 'undefined') {
        window.location.href = '/login';
      }
    }
  }

  return response;
}
