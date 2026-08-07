import type { NextApiRequest, NextApiResponse } from 'next';

const BACKEND_URL = process.env.BACKEND_URL || 'http://backend:8000';

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const accessToken = req.cookies.access_token;

  if (!accessToken) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  try {
    const userRes = await fetch(`${BACKEND_URL}/auth/me`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!userRes.ok) {
      return res.status(userRes.status).json({ error: 'Session invalid' });
    }

    const user = await userRes.json();
    return res.status(200).json(user);
  } catch (error) {
    console.error('Session check error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
