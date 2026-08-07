import { apiFetch } from '../utils/api';

export interface AttachedSubscriber {
  sid: number;
  username: string;
  mode: 'owner' | 'observe' | 'participate';
  joined_at: string;
}

export interface InteractiveSession {
  id: number;
  user_id: number;
  system_id: number;
  hostname: string | null;
  fleet_role_id: number | null;
  fleet_role_name: string | null;
  login: string;
  status: 'opening' | 'active' | 'closed' | 'idle_kill' | 'max_duration' | 'admin_force' | 'errored';
  close_reason: string | null;
  started_at: string;
  last_activity_at: string | null;
  ended_at: string | null;
  max_expires_at: string;
  client_ip: string | null;
  live?: boolean;
  attached?: AttachedSubscriber[];
}

export type OpenSessionResult =
  | { status: 'success'; session: InteractiveSession }
  | { status: 'pending'; approval_id: number };

export const openSession = async (system_id: number, login?: string): Promise<OpenSessionResult> => {
  const res = await apiFetch('/api/backend/sessions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ system_id, login: login || null }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || 'Failed to open session');
  }
  const body = await res.json();
  if (body.status === 'pending') {
    return { status: 'pending', approval_id: body.approval_id };
  }
  return { status: 'success', session: body.session };
};

export const listSessions = async (params?: { active_only?: boolean; mine_only?: boolean }): Promise<InteractiveSession[]> => {
  const qs = new URLSearchParams();
  if (params?.active_only) qs.set('active_only', 'true');
  if (params?.mine_only === false) qs.set('mine_only', 'false');
  const res = await apiFetch(`/api/backend/sessions${qs.toString() ? `?${qs}` : ''}`);
  if (!res.ok) throw new Error('Failed to list sessions');
  return (await res.json()).sessions;
};

export const getSession = async (id: number): Promise<InteractiveSession> => {
  const res = await apiFetch(`/api/backend/sessions/${id}`);
  if (!res.ok) throw new Error((await res.json()).detail || 'Failed to get session');
  return (await res.json()).session;
};

export const getWsTicket = async (id: number): Promise<{ token: string; expires_in: number }> => {
  const res = await apiFetch(`/api/backend/sessions/${id}/ws-ticket`, { method: 'POST' });
  if (!res.ok) throw new Error((await res.json()).detail || 'Failed to mint WS ticket');
  const body = await res.json();
  return { token: body.token, expires_in: body.expires_in };
};

export const getJoinTicket = async (id: number, mode: 'observe' | 'participate'): Promise<{ token: string; expires_in: number; mode: string }> => {
  const res = await apiFetch(`/api/backend/sessions/${id}/join-ticket?mode=${mode}`, { method: 'POST' });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || 'Failed to mint join ticket');
  }
  const body = await res.json();
  return { token: body.token, expires_in: body.expires_in, mode: body.mode };
};

export const closeSession = async (id: number): Promise<InteractiveSession> => {
  const res = await apiFetch(`/api/backend/sessions/${id}/close`, { method: 'POST' });
  if (!res.ok) throw new Error((await res.json()).detail || 'Failed to close session');
  return (await res.json()).session;
};

export const forceCloseSession = async (id: number): Promise<InteractiveSession> => {
  const res = await apiFetch(`/api/backend/sessions/${id}/force-close`, { method: 'POST' });
  if (!res.ok) throw new Error((await res.json()).detail || 'Failed to force-close session');
  return (await res.json()).session;
};
