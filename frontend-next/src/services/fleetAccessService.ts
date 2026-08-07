import { apiFetch } from '../utils/api';

export interface FleetRole {
  id: number;
  name: string;
  description: string | null;
  login_mode: 'per_user' | 'role_account';
  role_account_name: string | null;
  allowed_actions: string[];
  session_requires_approval: boolean;
  totp_required: boolean;
  idle_timeout_s: number;
  max_session_s: number;
  os_groups: string[];
  // PRA-282: retained for API compatibility (always null in 1.0). Praxis ships no
  // standing user-facing sudo; the field is never rendered or edited.
  sudoers_snippet?: string | null;
  is_builtin: boolean;
  created_at: string;
  updated_at: string;
}

export interface AccessBinding {
  id: number;
  fleet_role_id: number;
  subject_user_id: number | null;
  subject_app_role_id: number | null;
  scope_group_id: number | null;
  scope_smart_group_id: number | null;
  enabled: boolean;
  expires_at: string | null;
  created_by: number | null;
  created_at: string;
  updated_at: string;
}

export interface AccessGrant {
  id: number;
  user_id: number;
  system_id: number;
  fleet_role_id: number;
  login: string;
  via_binding_id: number | null;
  is_implicit_admin: boolean;
}

export interface HostUserState {
  id: number;
  system_id: number;
  login: string;
  mode: 'per_user' | 'role_account';
  state: 'pending' | 'provisioned' | 'pending_removal' | 'removed' | 'error';
  last_error: string | null;
  last_reconciled_at: string | null;
  home_archive_path: string | null;
}

export interface ReconcileCounts {
  provisioned: number;
  removed: number;
  errors: number;
  skipped: number;
  hosts?: number;
}

export interface NewBindingPayload {
  fleet_role_id: number;
  subject_user_id?: number | null;
  subject_app_role_id?: number | null;
  scope_group_id?: number | null;
  scope_smart_group_id?: number | null;
  enabled?: boolean;
  expires_at?: string | null;
}

// ---------- fleet roles ----------

export const listFleetRoles = async (): Promise<FleetRole[]> => {
  const res = await apiFetch('/api/backend/fleet/roles');
  if (!res.ok) throw new Error('Failed to fetch fleet roles');
  const data = await res.json();
  return data.roles;
};

export const createFleetRole = async (
  payload: Partial<FleetRole> & { name: string; login_mode: FleetRole['login_mode'] },
): Promise<FleetRole> => {
  const res = await apiFetch('/api/backend/fleet/roles', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error((await res.json()).detail || 'Failed to create role');
  return (await res.json()).role;
};

export const updateFleetRole = async (
  id: number,
  payload: Partial<FleetRole>,
): Promise<FleetRole> => {
  const res = await apiFetch(`/api/backend/fleet/roles/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error((await res.json()).detail || 'Failed to update role');
  return (await res.json()).role;
};

export const deleteFleetRole = async (id: number): Promise<void> => {
  const res = await apiFetch(`/api/backend/fleet/roles/${id}`, { method: 'DELETE' });
  if (!res.ok) throw new Error((await res.json()).detail || 'Failed to delete role');
};

// ---------- bindings ----------

export const listBindings = async (): Promise<AccessBinding[]> => {
  const res = await apiFetch('/api/backend/fleet/bindings');
  if (!res.ok) throw new Error('Failed to fetch bindings');
  return (await res.json()).bindings;
};

export const createBinding = async (payload: NewBindingPayload): Promise<AccessBinding> => {
  const res = await apiFetch('/api/backend/fleet/bindings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const detail = body?.detail;
    const msg = Array.isArray(detail) ? detail.map((d: { msg?: string }) => d.msg).join('; ') : detail;
    throw new Error(msg || 'Failed to create binding');
  }
  return (await res.json()).binding;
};

export const updateBinding = async (
  id: number,
  payload: Partial<Pick<AccessBinding, 'enabled' | 'expires_at' | 'fleet_role_id'>>,
): Promise<AccessBinding> => {
  const res = await apiFetch(`/api/backend/fleet/bindings/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error((await res.json()).detail || 'Failed to update binding');
  return (await res.json()).binding;
};

export const deleteBinding = async (id: number): Promise<void> => {
  const res = await apiFetch(`/api/backend/fleet/bindings/${id}`, { method: 'DELETE' });
  if (!res.ok) throw new Error((await res.json()).detail || 'Failed to delete binding');
};

// ---------- grants ----------

export const listGrants = async (params?: {
  user_id?: number;
  system_id?: number;
}): Promise<AccessGrant[]> => {
  const qs = new URLSearchParams();
  if (params?.user_id !== undefined) qs.set('user_id', String(params.user_id));
  if (params?.system_id !== undefined) qs.set('system_id', String(params.system_id));
  const res = await apiFetch(`/api/backend/fleet/grants${qs.toString() ? `?${qs}` : ''}`);
  if (!res.ok) throw new Error('Failed to fetch grants');
  return (await res.json()).grants;
};

export const recomputeGrants = async (): Promise<number> => {
  const res = await apiFetch('/api/backend/fleet/grants/recompute', { method: 'POST' });
  if (!res.ok) throw new Error('Failed to recompute grants');
  return (await res.json()).grant_count;
};

// ---------- reconcile ----------

export const reconcileAll = async (): Promise<ReconcileCounts> => {
  const res = await apiFetch('/api/backend/fleet/reconcile', { method: 'POST' });
  if (!res.ok) throw new Error('Failed to reconcile');
  return await res.json();
};

export const reconcileSystem = async (systemId: number): Promise<ReconcileCounts> => {
  const res = await apiFetch(`/api/backend/fleet/systems/${systemId}/reconcile`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to reconcile host');
  return await res.json();
};

export const listHostUsers = async (systemId: number): Promise<HostUserState[]> => {
  const res = await apiFetch(`/api/backend/fleet/systems/${systemId}/host-users`);
  if (!res.ok) throw new Error('Failed to fetch host users');
  return (await res.json()).host_users;
};

// ---------- effective access (PRA-303) ----------
// Read-only projection of CURRENT enforced access for one (user, system): what the
// identity can do right now and why, computed by the live authorization path. Not a
// what-if simulator; the endpoint performs no host/session/grant mutation.

export interface EACapability {
  action: string;
  requested_login: string | null;
  allowed: boolean;
  code: string | null;
  reason: string | null;
  login: string | null;
  cert_principal: string;
  login_mode?: 'per_user' | 'role_account';
  role_account_name?: string | null;
  fleet_role_id?: number;
  fleet_role_name?: string;
  requires_approval?: boolean;
  requires_totp?: boolean;
  idle_timeout_s?: number;
  max_session_s?: number;
  recording_retention_days?: number;
}

export interface EAGrant {
  grant_id: number;
  fleet_role_id: number;
  fleet_role_name: string | null;
  login: string;
  expires_at: string | null;
  expiry_state: 'active' | 'expired' | 'never_expires';
  is_implicit_admin: boolean;
}

export interface EAConflict {
  system_id: number;
  login: string;
  role_names: string[];
  differing_fields: string[];
}

export interface EAHostState {
  state: string;
  mode?: string;
  last_error?: string | null;
  last_reconciled_at?: string | null;
  privilege_reconcile_pending?: boolean;
  converged: boolean;
}

export interface EARevocationItem {
  id: number;
  reason: string;
  status: string;
  login: string | null;
  user_id: number | null;
  attempt_count: number;
  last_error: string | null;
  next_retry_at: string | null;
}

export interface EARevocation {
  pending: number;
  error: number;
  items: EARevocationItem[];
}

export interface EALoginDetail {
  login: string;
  login_mode: string | null;
  role_account_name: string | null;
  resolved_fleet_role_id: number | null;
  resolved_fleet_role_name: string | null;
  conflict: EAConflict | null;
  active_grants: EAGrant[];
  expired_grants: EAGrant[];
  expiry_state: string;
  nearest_active_expiry: string | null;
  host_state: EAHostState;
  revocation: EARevocation;
}

export interface EffectiveAccessSummary {
  generated_at: string;
  identity: {
    user_id: number;
    username: string;
    is_active: boolean;
    is_tenant_admin: boolean;
    cert_principal: string;
  };
  system: { system_id: number; hostname: string; status: string };
  scoped_api_access: { allowed: boolean; code: string | null; reason: string | null };
  capabilities: EACapability[];
  logins: EALoginDetail[];
  conflicts: EAConflict[];
  expiry: { overall_state: string; nearest_active_expiry: string | null };
  notes: string[];
}

export const getEffectiveAccess = async (params: {
  userId: number;
  systemId: number;
  login?: string;
}): Promise<EffectiveAccessSummary> => {
  const qs = new URLSearchParams({
    user_id: String(params.userId),
    system_id: String(params.systemId),
  });
  if (params.login) qs.set('login', params.login);
  const res = await apiFetch(`/api/backend/fleet/effective-access?${qs.toString()}`);
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body?.detail || 'Failed to load effective access');
  }
  return (await res.json()).summary;
};
