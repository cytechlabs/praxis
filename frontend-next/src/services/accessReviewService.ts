import { apiFetch } from '../utils/api';

export type ReviewState = 'pending' | 'completed' | 'expired';
export type ReviewAction = 'pending' | 'attest' | 'revoke' | 'extend';

export interface AccessReview {
  id: number;
  scope: 'all' | 'binding' | 'user' | 'role';
  scope_ref_id: number | null;
  state: ReviewState;
  due_at: string;
  completed_at: string | null;
  reviewer_id: number | null;
  summary: string | null;
  created_by: number | null;
  created_at: string;
  item_count: number;
}

export interface BindingSnapshot {
  binding_id: number;
  subject_user_id: number | null;
  subject_app_role_id: number | null;
  scope_group_id: number | null;
  scope_smart_group_id: number | null;
  fleet_role_id: number;
  enabled: boolean;
  expires_at: string | null;
  created_at: string;
}

export interface AccessReviewItem {
  id: number;
  review_id: number;
  binding_id: number | null;
  binding_snapshot: BindingSnapshot;
  action: ReviewAction;
  decided_at: string | null;
  decided_by: number | null;
  notes: string | null;
}

export const listReviews = async (): Promise<AccessReview[]> => {
  const res = await apiFetch('/api/backend/access-reviews');
  if (!res.ok) throw new Error('Failed to load access reviews');
  return (await res.json()).reviews;
};

export const getReview = async (id: number): Promise<{ review: AccessReview; items: AccessReviewItem[] }> => {
  const res = await apiFetch(`/api/backend/access-reviews/${id}`);
  if (!res.ok) throw new Error('Failed to load review');
  const body = await res.json();
  return { review: body.review, items: body.items };
};

export const createReview = async (payload: {
  scope?: 'all' | 'binding' | 'user' | 'role';
  scope_ref_id?: number;
  due_in_days?: number;
}): Promise<AccessReview> => {
  const res = await apiFetch('/api/backend/access-reviews', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || 'Failed to create review');
  }
  return (await res.json()).review;
};

export const attestItem = async (reviewId: number, itemId: number, notes?: string): Promise<AccessReviewItem> => {
  const res = await apiFetch(`/api/backend/access-reviews/${reviewId}/items/${itemId}/attest`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ notes: notes || null }),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || 'Attest failed');
  return (await res.json()).item;
};

export const revokeItem = async (reviewId: number, itemId: number, notes?: string): Promise<AccessReviewItem> => {
  const res = await apiFetch(`/api/backend/access-reviews/${reviewId}/items/${itemId}/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ notes: notes || null }),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || 'Revoke failed');
  return (await res.json()).item;
};

export const extendItem = async (reviewId: number, itemId: number, days?: number, notes?: string): Promise<AccessReviewItem> => {
  const res = await apiFetch(`/api/backend/access-reviews/${reviewId}/items/${itemId}/extend`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ notes: notes || null, days: days || null }),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || 'Extend failed');
  return (await res.json()).item;
};

export const completeReview = async (reviewId: number, summary?: string): Promise<AccessReview> => {
  const res = await apiFetch(`/api/backend/access-reviews/${reviewId}/complete`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ summary: summary || null }),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || 'Complete failed');
  return (await res.json()).review;
};

export const exportReviewCsvUrl = (reviewId: number): string =>
  `/api/backend/access-reviews/${reviewId}/export.csv`;
