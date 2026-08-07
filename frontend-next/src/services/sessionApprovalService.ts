import { apiFetch } from '../utils/api';

export type ApprovalState = 'pending' | 'granted' | 'denied' | 'expired' | 'consumed';

export interface SessionApproval {
  id: number;
  requester_id: number;
  requester_username: string | null;
  system_id: number;
  hostname: string | null;
  fleet_role_id: number;
  fleet_role_name: string | null;
  login: string;
  reason: string | null;
  state: ApprovalState;
  approver_id: number | null;
  approver_username: string | null;
  decision_reason: string | null;
  decided_at: string | null;
  expires_at: string | null;
  created_at: string;
}

export const listApprovals = async (params?: { state?: ApprovalState; mine_only?: boolean }): Promise<SessionApproval[]> => {
  const qs = new URLSearchParams();
  if (params?.state) qs.set('state', params.state);
  if (params?.mine_only) qs.set('mine_only', 'true');
  const res = await apiFetch(`/api/backend/session-approvals${qs.toString() ? `?${qs}` : ''}`);
  if (!res.ok) throw new Error('Failed to load approvals');
  return (await res.json()).approvals;
};

export const getApproval = async (id: number): Promise<SessionApproval> => {
  const res = await apiFetch(`/api/backend/session-approvals/${id}`);
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || 'Failed to load approval');
  }
  return (await res.json()).approval;
};

export const grantApproval = async (id: number, reason?: string): Promise<SessionApproval> => {
  const res = await apiFetch(`/api/backend/session-approvals/${id}/grant`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason: reason || null }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || 'Failed to grant');
  }
  return (await res.json()).approval;
};

export const denyApproval = async (id: number, reason?: string): Promise<SessionApproval> => {
  const res = await apiFetch(`/api/backend/session-approvals/${id}/deny`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason: reason || null }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || 'Failed to deny');
  }
  return (await res.json()).approval;
};
