import type { NextApiRequest, NextApiResponse } from 'next';
import { serializeCookie, BACKEND_URL } from '../../../utils/cookies';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    const loginRes = await fetch(`${BACKEND_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username, password }),
    });

    if (!loginRes.ok) {
      const error = await loginRes.json().catch(() => ({ detail: 'Login failed' }));
      return res.status(loginRes.status).json(error);
    }

    const tokenData = await loginRes.json();

    const userRes = await fetch(`${BACKEND_URL}/auth/me`, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });

    if (!userRes.ok) {
      return res.status(500).json({ error: 'Failed to fetch user data' });
    }

    const user = await userRes.json();

    res.setHeader('Set-Cookie', [
      serializeCookie('access_token', tokenData.access_token, { maxAge: 30 * 60 }),
      serializeCookie('refresh_token', tokenData.refresh_token, { maxAge: 7 * 24 * 60 * 60 }),
    ]);

    return res.status(200).json(user);
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
