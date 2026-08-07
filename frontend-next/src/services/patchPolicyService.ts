/**
 * PRA-161 #1f: patch policy API client.
 *
 * The policy layer decides *what may be applied and when* — package
 * scope, reboot rules/windows, rollout cadence, failure behavior, and
 * approval governance — and how the effective policy is resolved for a
 * host (direct-host / static-group / smart-group / fleet-default
 * bindings). Apply, reboot, and rollback EXECUTION shipped in the M16
 * patch lifecycle (PRA-171/172/173) and are driven from the
 * update-plan surfaces, not this module. This module covers policy
 * CRUD, bindings, fleet-default, and effective-policy lookups; the
 * smart-group `patch.*` predicate catalog is exposed by the backend's
 * ``/smart-groups/field-catalog`` endpoint and rendered by the
 * smart-groups page.
 */
import { apiFetch } from '../utils/api';

// ---------------------------------------------------------------------------
// Locked vocabularies (mirror backend constants)
// ---------------------------------------------------------------------------

export type ScopeKind =
  | 'security_only'
  | 'full'
  | 'package_allowlist'
  | 'package_denylist';

export type RebootPolicy = 'never' | 'if_required' | 'always';
export type RolloutCadence = 'immediate' | 'staged';
export type FailurePolicy = 'continue' | 'pause_fleet';

export type ResolutionKind =
  | 'direct_host'
  | 'static_group'
  | 'smart_group'
  | 'fleet_default'
  | 'no_policy'
  | 'conflict';

export const SCOPE_KIND_VALUES: ScopeKind[] = [
  'security_only',
  'full',
  'package_allowlist',
  'package_denylist',
];
export const REBOOT_POLICY_VALUES: RebootPolicy[] = [
  'never',
  'if_required',
  'always',
];
export const ROLLOUT_CADENCE_VALUES: RolloutCadence[] = [
  'immediate',
  'staged',
];
export const FAILURE_POLICY_VALUES: FailurePolicy[] = [
  'continue',
  'pause_fleet',
];

// ---------------------------------------------------------------------------
// Read shapes
// ---------------------------------------------------------------------------

export interface PatchPolicy {
  id: number;
  slug: string;
  name: string;
  description: string | null;
  scope_kind: ScopeKind;
  scope_packages: string[];
  reboot_policy: RebootPolicy;
  reboot_window_id: number | null;
  maintenance_window_id: number | null;
  requires_approval: boolean;
  required_approvals: number;
  rollout_cadence: RolloutCadence;
  failure_policy: FailurePolicy;
  enabled: boolean;
  is_fleet_default: boolean;
  created_by: number;
  created_at: string;
  updated_at: string;
}

export interface PatchPolicyHostBinding {
  id: number;
  policy_id: number;
  system_id: number;
  created_by: number;
  created_at: string;
  updated_at: string;
}

export interface PatchPolicyGroupBinding {
  id: number;
  policy_id: number;
  group_id: number;
  created_by: number;
  created_at: string;
  updated_at: string;
}

export interface PatchPolicySmartGroupBinding {
  id: number;
  policy_id: number;
  smart_group_id: number;
  created_by: number;
  created_at: string;
  updated_at: string;
}

export interface PatchPolicyBindings {
  policy_id: number;
  hosts: PatchPolicyHostBinding[];
  groups: PatchPolicyGroupBinding[];
  smart_groups: PatchPolicySmartGroupBinding[];
}

export interface EffectivePolicyConflictDetail {
  error: 'effective_policy_conflict';
  tier: ResolutionKind;
  policies: { id: number; slug: string }[];
  message: string;
}

export interface EffectivePatchPolicy {
  system_id: number;
  resolution_kind: ResolutionKind;
  policy: PatchPolicy | null;
}

/**
 * Returned alongside `EffectivePatchPolicy` on the client side when
 * the backend returned 409 — the resolver could not pick a single
 * effective policy because the binding layer has duplicate enabled
 * policies at the same tier. Surfaced as a first-class "conflict"
 * state (NOT collapsed into "no_policy") per the slice 1f packet.
 */
export interface EffectivePolicyResolution {
  state: 'resolved' | 'no_policy' | 'conflict';
  effective: EffectivePatchPolicy | null;
  conflict: EffectivePolicyConflictDetail | null;
}

// ---------------------------------------------------------------------------
// Mutation shapes
// ---------------------------------------------------------------------------

export interface PatchPolicyCreateInput {
  slug: string;
  name: string;
  description?: string | null;
  scope_kind: ScopeKind;
  scope_packages?: string[] | null;
  reboot_policy?: RebootPolicy;
  reboot_window_id?: number | null;
  maintenance_window_id?: number | null;
  requires_approval?: boolean;
  required_approvals?: number;
  rollout_cadence?: RolloutCadence;
  failure_policy?: FailurePolicy;
  enabled?: boolean;
}

export type PatchPolicyUpdateInput = Partial<
  Omit<PatchPolicyCreateInput, 'slug'>
>;

// ---------------------------------------------------------------------------
// Error handling helper
// ---------------------------------------------------------------------------

async function _bodyDetail(res: Response): Promise<string> {
  try {
    const data = await res.clone().json();
    if (data && typeof data === 'object') {
      if (typeof data.detail === 'string') return data.detail;
      if (data.detail) return JSON.stringify(data.detail);
    }
  } catch {
    // fall through
  }
  try {
    return await res.text();
  } catch {
    return '';
  }
}

export class PatchPolicyApiError extends Error {
  status: number;
  detail: unknown;
  constructor(status: number, message: string, detail?: unknown) {
    super(message);
    this.status = status;
    this.detail = detail;
  }
}

async function _expect(res: Response, label: string): Promise<void> {
  if (res.ok) return;
  let detail: unknown = null;
  try {
    detail = await res.clone().json();
  } catch {
    detail = await _bodyDetail(res);
  }
  const msg =
    typeof detail === 'string'
      ? detail
      : (detail as { detail?: string } | null)?.detail ?? `${label} (${res.status})`;
  throw new PatchPolicyApiError(
    res.status,
    typeof msg === 'string' ? msg : `${label} (${res.status})`,
    detail,
  );
}

// ---------------------------------------------------------------------------
// Policy CRUD
// ---------------------------------------------------------------------------

export async function listPatchPolicies(opts: {
  enabled_only?: boolean;
  offset?: number;
  limit?: number;
} = {}): Promise<PatchPolicy[]> {
  const params = new URLSearchParams();
  if (opts.enabled_only) params.set('enabled_only', 'true');
  if (opts.offset !== undefined) params.set('offset', String(opts.offset));
  if (opts.limit !== undefined) params.set('limit', String(opts.limit));
  const qs = params.toString();
  const res = await apiFetch(`/api/backend/patch/policies${qs ? `?${qs}` : ''}`);
  await _expect(res, 'list patch policies failed');
  return res.json();
}

export async function getPatchPolicy(id: number): Promise<PatchPolicy> {
  const res = await apiFetch(`/api/backend/patch/policies/${id}`);
  await _expect(res, `get patch policy ${id} failed`);
  return res.json();
}

export async function createPatchPolicy(
  input: PatchPolicyCreateInput,
): Promise<PatchPolicy> {
  const res = await apiFetch('/api/backend/patch/policies', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
  await _expect(res, 'create patch policy failed');
  return res.json();
}

export async function updatePatchPolicy(
  id: number,
  updates: PatchPolicyUpdateInput,
): Promise<PatchPolicy> {
  const res = await apiFetch(`/api/backend/patch/policies/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(updates),
  });
  await _expect(res, 'update patch policy failed');
  return res.json();
}

export async function deletePatchPolicy(id: number): Promise<void> {
  const res = await apiFetch(`/api/backend/patch/policies/${id}`, { method: 'DELETE' });
  if (res.status === 204) return;
  await _expect(res, 'delete patch policy failed');
}

// ---------------------------------------------------------------------------
// Bindings
// ---------------------------------------------------------------------------

export async function listPatchPolicyBindings(
  policyId: number,
): Promise<PatchPolicyBindings> {
  const res = await apiFetch(`/api/backend/patch/policies/${policyId}/bindings`);
  await _expect(res, 'list patch policy bindings failed');
  return res.json();
}

export async function bindPatchPolicyHost(
  policyId: number,
  hostId: number,
): Promise<PatchPolicyHostBinding> {
  const res = await apiFetch(`/api/backend/patch/policies/${policyId}/bindings/hosts`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ host_id: hostId }),
  });
  await _expect(res, 'bind host failed');
  return res.json();
}

export async function unbindPatchPolicyHost(
  policyId: number,
  hostId: number,
): Promise<void> {
  const res = await apiFetch(
    `/api/backend/patch/policies/${policyId}/bindings/hosts/${hostId}`,
    { method: 'DELETE' },
  );
  if (res.status === 204) return;
  await _expect(res, 'unbind host failed');
}

export async function bindPatchPolicyGroup(
  policyId: number,
  groupId: number,
): Promise<PatchPolicyGroupBinding> {
  const res = await apiFetch(`/api/backend/patch/policies/${policyId}/bindings/groups`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ group_id: groupId }),
  });
  await _expect(res, 'bind group failed');
  return res.json();
}

export async function unbindPatchPolicyGroup(
  policyId: number,
  groupId: number,
): Promise<void> {
  const res = await apiFetch(
    `/api/backend/patch/policies/${policyId}/bindings/groups/${groupId}`,
    { method: 'DELETE' },
  );
  if (res.status === 204) return;
  await _expect(res, 'unbind group failed');
}

export async function bindPatchPolicySmartGroup(
  policyId: number,
  smartGroupId: number,
): Promise<PatchPolicySmartGroupBinding> {
  const res = await apiFetch(
    `/api/backend/patch/policies/${policyId}/bindings/smart-groups`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ smart_group_id: smartGroupId }),
    },
  );
  // 422 here is most-often the slice 1e cycle guard ("smart group ...
  // references patch.* predicates and cannot be bound as a patch-policy
  // target — this would create a feedback loop"). Surface verbatim so
  // operators see the exact reason.
  await _expect(res, 'bind smart group failed');
  return res.json();
}

export async function unbindPatchPolicySmartGroup(
  policyId: number,
  smartGroupId: number,
): Promise<void> {
  const res = await apiFetch(
    `/api/backend/patch/policies/${policyId}/bindings/smart-groups/${smartGroupId}`,
    { method: 'DELETE' },
  );
  if (res.status === 204) return;
  await _expect(res, 'unbind smart group failed');
}

// ---------------------------------------------------------------------------
// Fleet default
// ---------------------------------------------------------------------------

export async function setFleetDefaultPatchPolicy(
  policyId: number,
): Promise<PatchPolicy> {
  const res = await apiFetch(
    `/api/backend/patch/policies/${policyId}/fleet-default`,
    { method: 'POST' },
  );
  await _expect(res, 'set fleet-default failed');
  return res.json();
}

export async function clearFleetDefaultPatchPolicy(
  policyId: number,
): Promise<PatchPolicy> {
  const res = await apiFetch(
    `/api/backend/patch/policies/${policyId}/fleet-default`,
    { method: 'DELETE' },
  );
  await _expect(res, 'clear fleet-default failed');
  return res.json();
}

// ---------------------------------------------------------------------------
// Effective policy per host
// ---------------------------------------------------------------------------

/**
 * Returns the resolver result for a host. A 409 response is converted
 * into ``state="conflict"`` with the structured detail attached so
 * the UI can render the conflict as an explicit state (per the slice
 * 1f packet — DO NOT collapse conflicts into no_policy).
 */
export async function getEffectivePatchPolicy(
  systemId: number,
): Promise<EffectivePolicyResolution> {
  const res = await apiFetch(
    `/api/backend/systems/${systemId}/patch-policy/effective`,
  );

  if (res.status === 409) {
    let detail: EffectivePolicyConflictDetail | null = null;
    try {
      const body = (await res.json()) as { detail?: EffectivePolicyConflictDetail };
      detail = body?.detail ?? null;
    } catch {
      detail = null;
    }
    return { state: 'conflict', effective: null, conflict: detail };
  }

  await _expect(res, `get effective patch policy for ${systemId} failed`);
  const body = (await res.json()) as EffectivePatchPolicy;
  if (body.resolution_kind === 'no_policy' || body.policy === null) {
    return { state: 'no_policy', effective: body, conflict: null };
  }
  return { state: 'resolved', effective: body, conflict: null };
}

// ---------------------------------------------------------------------------
// Display helpers (kept here so list/detail pages share labels)
// ---------------------------------------------------------------------------

export const SCOPE_KIND_LABELS: Record<ScopeKind, string> = {
  security_only: 'Security only',
  full: 'Full',
  package_allowlist: 'Allowlist',
  package_denylist: 'Denylist',
};

export const REBOOT_POLICY_LABELS: Record<RebootPolicy, string> = {
  never: 'Never',
  if_required: 'If required',
  always: 'Always',
};

export const ROLLOUT_CADENCE_LABELS: Record<RolloutCadence, string> = {
  immediate: 'Immediate',
  staged: 'Staged (rings)',
};

export const FAILURE_POLICY_LABELS: Record<FailurePolicy, string> = {
  continue: 'Continue',
  pause_fleet: 'Pause fleet',
};

export const RESOLUTION_KIND_LABELS: Record<ResolutionKind, string> = {
  direct_host: 'Direct host binding',
  static_group: 'Static group binding',
  smart_group: 'Smart group binding',
  fleet_default: 'Fleet default',
  no_policy: 'No policy',
  conflict: 'Conflict',
};

export function scopeRequiresPackages(scope: ScopeKind): boolean {
  return scope === 'package_allowlist' || scope === 'package_denylist';
}
