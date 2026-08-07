import type { NextApiRequest, NextApiResponse } from 'next';
import { serializeCookie, clearCookie, BACKEND_URL } from '../../../utils/cookies';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const refreshToken = req.cookies.refresh_token;

  if (!refreshToken) {
    return res.status(401).json({ error: 'No refresh token' });
  }

  try {
    const refreshRes = await fetch(
      `${BACKEND_URL}/auth/refresh?token_refresh=${encodeURIComponent(refreshToken)}`,
      { method: 'POST' }
    );

    if (!refreshRes.ok) {
      res.setHeader('Set-Cookie', [clearCookie('access_token'), clearCookie('refresh_token')]);
      return res.status(401).json({ error: 'Refresh token expired' });
    }

    const tokenData = await refreshRes.json();

    const cookies = [
      serializeCookie('access_token', tokenData.access_token, { maxAge: 30 * 60 }),
    ];
    if (tokenData.refresh_token) {
      cookies.push(
        serializeCookie('refresh_token', tokenData.refresh_token, { maxAge: 7 * 24 * 60 * 60 })
      );
    }
    res.setHeader('Set-Cookie', cookies);
    return res.status(200).json({ ok: true });
  } catch (error) {
    console.error('Token refresh error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
