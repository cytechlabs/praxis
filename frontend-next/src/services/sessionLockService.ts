import { apiFetch } from '../utils/api';

export interface SessionLock {
  id: number;
  subject_user_id: number | null;
  subject_username: string | null;
  subject_app_role_id: number | null;
  subject_role_name: string | null;
  reason: string;
  created_by: number | null;
  created_by_username: string | null;
  created_at: string;
  released_at: string | null;
  released_by: number | null;
  released_by_username: string | null;
  active: boolean;
}

export const listLocks = async (activeOnly = false): Promise<SessionLock[]> => {
  const qs = activeOnly ? '?active_only=true' : '';
  const res = await apiFetch(`/api/backend/session-locks${qs}`);
  if (!res.ok) throw new Error('Failed to load session locks');
  return (await res.json()).locks;
};

export const createLock = async (payload: {
  reason: string;
  subject_user_id?: number;
  subject_username?: string;
  subject_app_role_id?: number;
  subject_role_name?: string;
}): Promise<SessionLock> => {
  const res = await apiFetch('/api/backend/session-locks', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    // FastAPI 422 returns detail as an array of validation errors;
    // surface the first one's msg instead of "[object Object]".
    const detail = body.detail;
    let msg: string;
    if (typeof detail === 'string') {
      msg = detail;
    } else if (Array.isArray(detail) && detail[0]?.msg) {
      const loc = (detail[0].loc || []).slice(-1)[0];
      msg = loc ? `${loc}: ${detail[0].msg}` : detail[0].msg;
    } else {
      msg = 'Failed to create lock';
    }
    throw new Error(msg);
  }
  return (await res.json()).lock;
};

export const releaseLock = async (id: number): Promise<SessionLock> => {
  const res = await apiFetch(`/api/backend/session-locks/${id}/release`, { method: 'POST' });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || 'Failed to release lock');
  }
  return (await res.json()).lock;
};
