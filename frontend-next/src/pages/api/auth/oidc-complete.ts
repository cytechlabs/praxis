import type { NextApiRequest, NextApiResponse } from 'next';
import { serializeCookie, BACKEND_URL } from '../../../utils/cookies';
import { maxAgeFromTokenExp } from '../../../utils/authCookieLifetime';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { access_token, refresh_token } = req.body;

  if (!access_token || !refresh_token) {
    return res.status(400).json({ error: 'Tokens required' });
  }

  // These tokens arrive already minted, without the lifetime metadata a login
  // response carries, so each cookie is bounded by its own token's deadline.
  // Both must carry a usable one: storing a token whose deadline cannot be read,
  // or has already passed, would present an unusable session as a live one.
  const accessMaxAge = maxAgeFromTokenExp(access_token);
  const refreshMaxAge = maxAgeFromTokenExp(refresh_token);

  if (accessMaxAge === null || refreshMaxAge === null) {
    return res.status(401).json({ error: 'Invalid token' });
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

    res.setHeader('Set-Cookie', [
      serializeCookie('access_token', access_token, { maxAge: accessMaxAge }),
      serializeCookie('refresh_token', refresh_token, { maxAge: refreshMaxAge }),
    ]);

    return res.status(200).json(user);
  } catch (error) {
    console.error('OIDC complete error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
