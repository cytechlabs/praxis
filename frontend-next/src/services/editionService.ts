import { apiFetch } from '../utils/api';

/**
 * PRA-132: edition / entitlement client. The backend exposes a read-only
 * `/edition` surface describing the active edition, which paid entitlement keys
 * are active, and the managed-host cap. The frontend uses this to render
 * locked/upgrade states for paid controls. Enforcement is server-side; this is
 * awareness only.
 */

// Keep these keys in sync with backend/app/core/entitlements.py.
export const ENTITLEMENTS = {
  HOSTS_OVER_FREE_CAP: 'hosts.over_free_cap',
  SESSION_LOCKS: 'access.session_locks',
  SESSION_APPROVALS: 'access.session_approvals',
  ACCESS_REVIEWS: 'access.access_reviews',
  COMMAND_APPROVALS: 'commands.approvals',
  COMMAND_METRICS: 'commands.metrics',
  COMPLIANCE_BULK_EXPORTS: 'compliance.bulk_exports',
  REPORTS_SCHEDULED_EXPORTS: 'reports.scheduled_exports',
} as const;

export type EntitlementKey = (typeof ENTITLEMENTS)[keyof typeof ENTITLEMENTS];

// Online license refresh status. Never includes the refresh token itself — the
// backend only ever reports whether one is configured plus last-attempt metadata.
export interface OnlineRefreshStatus {
  configured: boolean;
  last_attempt_at?: string | null;
  last_result?: string | null; // ok | not_configured | unavailable | rejected | error
  last_detail?: string | null;
}

export interface EditionInfo {
  edition: string;
  entitlements: Record<string, boolean>;
  host_cap: number | null; // null == unlimited
  issued_to: string | null;
  host_count?: number;
  hosts_over_cap?: boolean;
  // PRA-133 license fields.
  tier?: string;
  license_state?: string;
  license_id?: string | null;
  expires_at?: string | null;
  instance_id?: string;
  over_cap?: boolean;
  at_cap?: boolean;
  grace_until?: string | null;
  in_grace?: boolean;
  // Online license refresh (never carries the token).
  online_refresh?: OnlineRefreshStatus;
}

export interface RefreshResult {
  result: string; // ok | not_configured | unavailable | rejected | error
  detail?: string | null;
  status: EditionInfo;
}

export const getEdition = async (): Promise<EditionInfo> => {
  const res = await apiFetch('/api/backend/edition');
  if (!res.ok) throw new Error('Failed to load edition');
  return res.json();
};

/** Apply an offline license token (admin only). Throws with the backend message
 * on rejection so the UI can show why.
 *
 * An optional `refreshToken` enables online refresh: it is sent in the request
 * body only and stored SERVER-SIDE by the backend when the license is valid. It
 * is never placed in localStorage or any client-side store. */
export const applyLicense = async (
  token: string,
  refreshToken?: string,
): Promise<EditionInfo> => {
  const payload: { token: string; refresh_token?: string } = { token };
  const rt = refreshToken?.trim();
  if (rt) payload.refresh_token = rt;
  const res = await apiFetch('/api/backend/edition/license', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const detail = body?.detail;
    const msg =
      (detail && (detail.message || detail)) ||
      (Array.isArray(detail) ? detail[0]?.msg : null) ||
      'License was rejected';
    throw new Error(typeof msg === 'string' ? msg : 'License was rejected');
  }
  return res.json();
};

/** Refresh the applied license online via the EE bridge (admin only). Uses the
 * server-stored refresh token; returns the refresh result + updated status. The
 * response never contains the refresh token. */
export const refreshLicense = async (): Promise<RefreshResult> => {
  const res = await apiFetch('/api/backend/edition/license/refresh', {
    method: 'POST',
  });
  if (!res.ok) throw new Error('License refresh failed');
  return res.json();
};

/** Remove the applied license -> free edition (admin only). */
export const removeLicense = async (): Promise<EditionInfo> => {
  const res = await apiFetch('/api/backend/edition/license', { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to remove license');
  return res.json();
};

// PRA-266: purchase happens on the Praxis website, not in-app. "Buy / Upgrade"
// opens the website buy page with this install's server-owned instance_id
// prefilled; plan selection + checkout happen there. The app holds no price IDs.

/** The Praxis website buy URL with this install's instance_id prefilled. */
export const getBuyUrl = async (): Promise<string> => {
  const res = await apiFetch('/api/backend/edition/buy-url');
  if (!res.ok) throw new Error('Failed to load buy link');
  const body = await res.json();
  return body?.buy_url ?? '';
};
