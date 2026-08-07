import type { NextApiRequest, NextApiResponse } from 'next';
import { clearCookie, BACKEND_URL } from '../../../utils/cookies';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const accessToken = req.cookies.access_token;
  const refreshToken = req.cookies.refresh_token;

  // Revoke server-side whenever a refresh token is present, even if the access
  // token is expired or missing — otherwise a stolen refresh token would survive
  // an explicit logout. The bearer header is attached only when available; the
  // backend revokes by the refresh-token value and does not require it.
  if (refreshToken) {
    try {
      const headers: Record<string, string> = {};
      if (accessToken) {
        headers.Authorization = `Bearer ${accessToken}`;
      }
      await fetch(`${BACKEND_URL}/auth/logout?token_refresh=${encodeURIComponent(refreshToken)}`, {
        method: 'POST',
        headers,
      });
    } catch {
      // Best-effort: clear cookies even if backend call fails
    }
  }

  res.setHeader('Set-Cookie', [clearCookie('access_token'), clearCookie('refresh_token')]);
  return res.status(200).json({ ok: true });
}
