/**
 * PRA-154 #1e: activation token CRUD client.
 *
 * The backend gates list/get/create/revoke behind the admin role; the
 * UI mirrors that gate so non-admins never reach this service.
 */
import { apiFetch, formatApiError } from '../utils/api';

export type ActivationTokenStatus = 'active' | 'expired' | 'exhausted' | 'revoked';

export interface ActivationToken {
  id: number;
  name: string;
  token_prefix: string;
  default_group_id: number;
  target_system_id: number;
  target_system_hostname: string | null;
  default_tag_ids: number[];
  ttl_expires_at: string;
  max_uses: number;
  uses_count: number;
  revoked_at: string | null;
  revoked_by_user_id: number | null;
  created_by_user_id: number;
  created_at: string;
  updated_at: string;
  status: ActivationTokenStatus;
}

export interface ActivationTokenCreated extends ActivationToken {
  /** Plaintext is returned exactly once and must not be persisted. */
  plaintext: string;
  /**
   * Pre-built `curl … | sudo … bash` snippet. Null when the control
   * plane has no PRAXIS_PUBLIC_URL configured; the token itself is
   * still valid in that case.
   */
  bootstrap_command: string | null;
  bootstrap_command_unavailable_reason: string | null;
}

export interface ActivationTokenCreateBody {
  name: string;
  default_group_id: number;
  target_system_id: number;
  default_tag_ids: number[];
  ttl_seconds: number;
  /**
   * Forced to 1 by the backend while link-only redemption is the
   * only enrollment path. Sending anything else returns 422 and is
   * not exposed in the UI.
   */
  max_uses: 1;
}

const BASE = '/api/backend/agent/activation-tokens';

async function unwrap<T>(res: Response, fallback: string): Promise<T> {
  if (res.ok) return res.json();
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    /* non-JSON body */
  }
  throw new Error(formatApiError(body, fallback));
}

export const listActivationTokens = async (): Promise<ActivationToken[]> => {
  const res = await apiFetch(BASE);
  return unwrap<ActivationToken[]>(res, 'Failed to load activation tokens');
};

export const getActivationToken = async (id: number): Promise<ActivationToken> => {
  const res = await apiFetch(`${BASE}/${id}`);
  return unwrap<ActivationToken>(res, 'Failed to load activation token');
};

export const createActivationToken = async (
  body: ActivationTokenCreateBody,
): Promise<ActivationTokenCreated> => {
  const res = await apiFetch(BASE, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return unwrap<ActivationTokenCreated>(res, 'Failed to create activation token');
};

export const revokeActivationToken = async (id: number): Promise<ActivationToken> => {
  const res = await apiFetch(`${BASE}/${id}/revoke`, { method: 'POST' });
  return unwrap<ActivationToken>(res, 'Failed to revoke activation token');
};

export const TTL_PRESETS: { label: string; seconds: number }[] = [
  { label: '1 hour', seconds: 60 * 60 },
  { label: '8 hours', seconds: 60 * 60 * 8 },
  { label: '24 hours', seconds: 60 * 60 * 24 },
  { label: '7 days', seconds: 60 * 60 * 24 * 7 },
  { label: '30 days', seconds: 60 * 60 * 24 * 30 },
];
