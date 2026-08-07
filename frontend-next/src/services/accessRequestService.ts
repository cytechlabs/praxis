import { apiFetch } from '../utils/api';

export interface AccessRequest {
  id: number;
  requested_by: number;
  fleet_role_id: number;
  scope_group_id: number | null;
  scope_smart_group_id: number | null;
  justification: string | null;
  duration_seconds: number;
  status: 'pending' | 'approved' | 'rejected' | 'expired' | 'revoked';
  decided_by: number | null;
  decided_at: string | null;
  decision_comment: string | null;
  resulting_binding_id: number | null;
  requested_at: string;
}

export interface NewAccessRequest {
  fleet_role_id: number;
  scope_group_id?: number | null;
  scope_smart_group_id?: number | null;
  justification?: string | null;
  duration_seconds?: number;
}

export const listAccessRequests = async (params?: {
  mine_only?: boolean;
  status?: string;
}): Promise<AccessRequest[]> => {
  const qs = new URLSearchParams();
  if (params?.mine_only !== undefined) qs.set('mine_only', String(params.mine_only));
  if (params?.status) qs.set('status', params.status);
  const res = await apiFetch(`/api/backend/access/requests${qs.toString() ? `?${qs}` : ''}`);
  if (!res.ok) throw new Error('Failed to fetch access requests');
  return (await res.json()).requests;
};

export const createAccessRequest = async (payload: NewAccessRequest): Promise<AccessRequest> => {
  const res = await apiFetch('/api/backend/access/requests', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const detail = body?.detail;
    const msg = Array.isArray(detail) ? detail.map((d: { msg?: string }) => d.msg).join('; ') : detail;
    throw new Error(msg || 'Failed to submit request');
  }
  return (await res.json()).request;
};

export const approveAccessRequest = async (id: number, comment?: string): Promise<AccessRequest> => {
  const res = await apiFetch(`/api/backend/access/requests/${id}/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ comment: comment || null }),
  });
  if (!res.ok) throw new Error((await res.json()).detail || 'Approve failed');
  return (await res.json()).request;
};

export const rejectAccessRequest = async (id: number, comment?: string): Promise<AccessRequest> => {
  const res = await apiFetch(`/api/backend/access/requests/${id}/reject`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ comment: comment || null }),
  });
  if (!res.ok) throw new Error((await res.json()).detail || 'Reject failed');
  return (await res.json()).request;
};

export const revokeAccessRequest = async (id: number): Promise<AccessRequest> => {
  const res = await apiFetch(`/api/backend/access/requests/${id}/revoke`, { method: 'POST' });
  if (!res.ok) throw new Error((await res.json()).detail || 'Revoke failed');
  return (await res.json()).request;
};
