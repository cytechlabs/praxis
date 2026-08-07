import type { NextApiRequest, NextApiResponse } from 'next';
import { serializeCookie, BACKEND_URL } from '../../../utils/cookies';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { access_token, refresh_token } = req.body;

  if (!access_token || !refresh_token) {
    return res.status(400).json({ error: 'Tokens required' });
  }

  try {
    // Verify the token works by fetching user data
    const userRes = await fetch(`${BACKEND_URL}/auth/me`, {
      headers: { Authorization: `Bearer ${access_token}` },
    });

    if (!userRes.ok) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    const user = await userRes.json();

    // Set cookies
    res.setHeader('Set-Cookie', [
      serializeCookie('access_token', access_token, { maxAge: 30 * 60 }),
      serializeCookie('refresh_token', refresh_token, { maxAge: 7 * 24 * 60 * 60 }),
    ]);

    return res.status(200).json(user);
  } catch (error) {
    console.error('OIDC complete error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
