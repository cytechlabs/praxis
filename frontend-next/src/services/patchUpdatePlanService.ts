/**
 * PRA-164 #4: patch update plan API client.
 *
 * Read-only / planning + approval + audit-export surface — Slice 1 + 2 +
 * 3 + 4 of PRA-164 cover plan creation, selection preview, preflight,
 * approval state machine, schedule (artifact metadata only), explicit
 * supersede, and the canonical JSON audit-export bundle. Plan
 * EXECUTION (live wave dispatch / probes / reboot / rollback) is owned
 * by PRA-171/172/173 and is NOT part of this surface.
 */
import { apiFetch } from '../utils/api';

// ---------------------------------------------------------------------------
// Locked vocabularies (mirror backend constants)
// ---------------------------------------------------------------------------

export type PlanState =
  | 'draft'
  | 'awaiting_approval'
  | 'approved'
  | 'scheduled'
  | 'blocked'
  | 'superseded'
  | 'canceled';

export const PLAN_STATE_VALUES: PlanState[] = [
  'draft',
  'awaiting_approval',
  'approved',
  'scheduled',
  'blocked',
  'superseded',
  'canceled',
];

export type PlanHostState = 'planned' | 'blocked';

export type SelectionState = 'selected' | 'excluded' | 'unresolvable';
export const SELECTION_STATE_VALUES: SelectionState[] = [
  'selected',
  'excluded',
  'unresolvable',
];

export type ContentAvailabilityState =
  | 'available'
  | 'unavailable'
  | 'profile_missing'
  | 'not_applicable';
export const CONTENT_AVAILABILITY_STATE_VALUES: ContentAvailabilityState[] = [
  'available',
  'unavailable',
  'profile_missing',
  'not_applicable',
];

export type PackageManagerFamily = 'apt' | 'dnf' | 'unknown';

// ---------------------------------------------------------------------------
// Read shapes
// ---------------------------------------------------------------------------

export interface PlanBlockReason {
  code: string;
  details: Record<string, unknown>;
}

export interface PlanRingSummary {
  ring_id: number;
  ring_slug: string;
  ring_name: string;
  sort_order: number;
  enabled: boolean;
}

export interface SelectionSummary {
  selected: number;
  excluded: number;
  unresolvable: number;
  inventory_missing: boolean;
}

export interface PreflightSummary {
  available: number;
  unavailable: number;
  profile_missing: number;
  not_applicable: number;
  installed_drift_count: number;
}

export interface PatchUpdatePlanHost {
  id: number;
  plan_id: number;
  system_id: number | null;
  system_hostname_snapshot: string | null;
  policy_id_snapshot: number | null;
  policy_slug_snapshot: string | null;
  policy_resolution_kind: string;
  ring_id_snapshot: number | null;
  ring_slug_snapshot: string | null;
  ring_name_snapshot: string | null;
  ring_sort_order_snapshot: number | null;
  ring_source_tier: string | null;
  ring_resolution_status: string;
  wave_index: number;
  content_profile_state: string;
  content_profile_id_snapshot: number | null;
  content_profile_slug_snapshot: string | null;
  content_profile_display_name_snapshot: string | null;
  content_profile_package_family_snapshot: string | null;
  content_profile_conflict_snapshot: Record<string, unknown>[];
  state: PlanHostState;
  block_reasons: PlanBlockReason[];
  selection_summary: SelectionSummary | null;
  preflight_summary: PreflightSummary | null;
  created_at: string;
  updated_at: string;
}

export interface PatchUpdatePlanApprovalView {
  approval_id: number;
  link_id: number;
  requested_by: number;
  requested_at: string | null;
  status: 'pending' | 'approved' | 'rejected' | 'expired';
  required_approvals: number;
  expires_at: string | null;
  decided_by: number | null;
  decided_at: string | null;
  subject_kind?: string;
  subject_id?: number;
}

export interface PatchUpdatePlan {
  id: number;
  // PRA-355: nullable once a policy with only archived links is deleted.
  policy_id: number | null;
  name: string;
  description: string | null;
  state: PlanState;
  scheduled_start_at: string | null;
  maintenance_window_id: number | null;
  reboot_window_id: number | null;
  policy_snapshot: Record<string, unknown>;
  ring_sequence_snapshot: PlanRingSummary[];
  request_snapshot: Record<string, unknown>;
  block_reasons: PlanBlockReason[];
  created_by: number;
  // PRA-355 archive/retire tombstone fields.
  archived_at: string | null;
  archived_by: number | null;
  archive_reason: string | null;
  // PRA-355: backend-authoritative cleanup affordances. Render Delete vs
  // Archive from these, never from `state` alone (a blocked plan with approval
  // history is NOT hard-deletable but IS archivable).
  has_lifecycle_history: boolean;
  can_hard_delete: boolean;
  can_archive: boolean;
  created_at: string;
  updated_at: string;
}

export interface PatchUpdatePlanDetail extends PatchUpdatePlan {
  hosts: PatchUpdatePlanHost[];
  approval: PatchUpdatePlanApprovalView | null;
}

export interface SelectedPackage {
  id: number;
  plan_host_id: number;
  package_name: string;
  installed_version_snapshot: string | null;
  available_version_snapshot: string | null;
  advisory_id_snapshot: number | null;
  advisory_source_kind_snapshot: string | null;
  advisory_class_snapshot: string | null;
  advisory_severity_snapshot: string | null;
  selection_reason: string;
  state: SelectionState;
  details: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface PreflightSnapshot {
  id: number;
  plan_host_id: number;
  package_name: string;
  installed_version_at_preflight: string | null;
  package_manager_family_snapshot: PackageManagerFamily;
  content_availability_state: ContentAvailabilityState;
  availability_details: Record<string, unknown>;
  evaluated_at: string;
  created_at: string;
  updated_at: string;
}

// ---------------------------------------------------------------------------
// Write shapes
// ---------------------------------------------------------------------------

export interface PlanCreateInput {
  policy_id: number;
  name: string;
  description?: string | null;
  target_system_ids?: number[] | null;
  scheduled_start_at?: string | null;
  maintenance_window_id?: number | null;
  reboot_window_id?: number | null;
}

export interface ApprovalRequestInput {
  expires_at?: string | null;
  comment?: string | null;
}

export interface ApprovalDecisionInput {
  comment?: string | null;
}

export interface ScheduleInput {
  scheduled_start_at: string;
  maintenance_window_id?: number | null;
  reboot_window_id?: number | null;
}

export interface SupersedeInput {
  comment?: string | null;
}

// ---------------------------------------------------------------------------
// Error helper
// ---------------------------------------------------------------------------

export class PatchUpdatePlanApiError extends Error {
  status: number;
  detail: unknown;
  constructor(status: number, message: string, detail?: unknown) {
    super(message);
    this.status = status;
    this.detail = detail;
  }
}

async function _bodyDetail(res: Response): Promise<unknown> {
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
  throw new PatchUpdatePlanApiError(
    res.status,
    typeof msg === 'string' ? msg : `${label} (${res.status})`,
    detail,
  );
}

// ---------------------------------------------------------------------------
// CRUD + state machine
// ---------------------------------------------------------------------------

export async function listPatchUpdatePlans(opts: {
  policy_id?: number;
  state?: PlanState;
  include_archived?: boolean;
  offset?: number;
  limit?: number;
} = {}): Promise<PatchUpdatePlan[]> {
  const params = new URLSearchParams();
  if (opts.policy_id !== undefined) params.set('policy_id', String(opts.policy_id));
  if (opts.state) params.set('state', opts.state);
  if (opts.include_archived) params.set('include_archived', 'true');
  if (opts.offset !== undefined) params.set('offset', String(opts.offset));
  if (opts.limit !== undefined) params.set('limit', String(opts.limit));
  const qs = params.toString();
  const res = await apiFetch(
    `/api/backend/patch/update-plans${qs ? `?${qs}` : ''}`,
  );
  await _expect(res, 'list patch update plans failed');
  return res.json();
}

export async function getPatchUpdatePlan(id: number): Promise<PatchUpdatePlanDetail> {
  const res = await apiFetch(`/api/backend/patch/update-plans/${id}`);
  await _expect(res, `get patch update plan ${id} failed`);
  return res.json();
}

export async function createPatchUpdatePlanDryRun(
  input: PlanCreateInput,
): Promise<PatchUpdatePlanDetail> {
  const res = await apiFetch('/api/backend/patch/update-plans/dry-run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
  await _expect(res, 'create patch update plan failed');
  return res.json();
}

export async function refreshPatchUpdatePlan(
  id: number,
): Promise<PatchUpdatePlanDetail> {
  const res = await apiFetch(`/api/backend/patch/update-plans/${id}/refresh`, {
    method: 'POST',
  });
  await _expect(res, `refresh patch update plan ${id} failed`);
  return res.json();
}

export async function cancelPatchUpdatePlan(id: number): Promise<PatchUpdatePlan> {
  const res = await apiFetch(`/api/backend/patch/update-plans/${id}/cancel`, {
    method: 'POST',
  });
  await _expect(res, `cancel patch update plan ${id} failed`);
  return res.json();
}

export async function deletePatchUpdatePlan(id: number): Promise<void> {
  const res = await apiFetch(`/api/backend/patch/update-plans/${id}`, {
    method: 'DELETE',
  });
  await _expect(res, `delete patch update plan ${id} failed`);
}

export async function archivePatchUpdatePlan(
  id: number,
  reason?: string,
): Promise<PatchUpdatePlanDetail> {
  const res = await apiFetch(`/api/backend/patch/update-plans/${id}/archive`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason: reason?.trim() ? reason.trim() : null }),
  });
  await _expect(res, `archive patch update plan ${id} failed`);
  return res.json();
}

export async function listSelectedPackages(
  planId: number,
  opts: { state?: SelectionState } = {},
): Promise<SelectedPackage[]> {
  const params = new URLSearchParams();
  if (opts.state) params.set('state', opts.state);
  const qs = params.toString();
  const res = await apiFetch(
    `/api/backend/patch/update-plans/${planId}/selected-packages${qs ? `?${qs}` : ''}`,
  );
  await _expect(res, 'list plan selected packages failed');
  return res.json();
}

export async function listHostSelectedPackages(
  planId: number,
  hostId: number,
): Promise<SelectedPackage[]> {
  const res = await apiFetch(
    `/api/backend/patch/update-plans/${planId}/hosts/${hostId}/selected-packages`,
  );
  await _expect(res, 'list host selected packages failed');
  return res.json();
}

export async function listPreflight(
  planId: number,
  opts: { content_availability_state?: ContentAvailabilityState } = {},
): Promise<PreflightSnapshot[]> {
  const params = new URLSearchParams();
  if (opts.content_availability_state)
    params.set('content_availability_state', opts.content_availability_state);
  const qs = params.toString();
  const res = await apiFetch(
    `/api/backend/patch/update-plans/${planId}/preflight${qs ? `?${qs}` : ''}`,
  );
  await _expect(res, 'list plan preflight failed');
  return res.json();
}

export async function listHostPreflight(
  planId: number,
  hostId: number,
): Promise<PreflightSnapshot[]> {
  const res = await apiFetch(
    `/api/backend/patch/update-plans/${planId}/hosts/${hostId}/preflight`,
  );
  await _expect(res, 'list host preflight failed');
  return res.json();
}

// ---------------------------------------------------------------------------
// Slice 4: approval / schedule / supersede
// ---------------------------------------------------------------------------

export async function requestPatchUpdatePlanApproval(
  id: number,
  input: ApprovalRequestInput = {},
): Promise<PatchUpdatePlanDetail> {
  const res = await apiFetch(
    `/api/backend/patch/update-plans/${id}/approval/request`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    },
  );
  await _expect(res, `request patch update plan ${id} approval failed`);
  return res.json();
}

export async function approvePatchUpdatePlan(
  id: number,
  input: ApprovalDecisionInput = {},
): Promise<PatchUpdatePlanDetail> {
  const res = await apiFetch(
    `/api/backend/patch/update-plans/${id}/approval/approve`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    },
  );
  await _expect(res, `approve patch update plan ${id} failed`);
  return res.json();
}

export async function rejectPatchUpdatePlan(
  id: number,
  input: ApprovalDecisionInput = {},
): Promise<PatchUpdatePlanDetail> {
  const res = await apiFetch(
    `/api/backend/patch/update-plans/${id}/approval/reject`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    },
  );
  await _expect(res, `reject patch update plan ${id} failed`);
  return res.json();
}

export async function schedulePatchUpdatePlan(
  id: number,
  input: ScheduleInput,
): Promise<PatchUpdatePlanDetail> {
  const res = await apiFetch(
    `/api/backend/patch/update-plans/${id}/schedule`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    },
  );
  await _expect(res, `schedule patch update plan ${id} failed`);
  return res.json();
}

export async function supersedePatchUpdatePlan(
  id: number,
  input: SupersedeInput = {},
): Promise<PatchUpdatePlanDetail> {
  const res = await apiFetch(
    `/api/backend/patch/update-plans/${id}/supersede`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    },
  );
  await _expect(res, `supersede patch update plan ${id} failed`);
  return res.json();
}

// Audit-export download. Returns the parsed JSON; use the
// triggerExportDownload helper below for browser-side download.
export async function exportPatchUpdatePlan(id: number): Promise<unknown> {
  const res = await apiFetch(`/api/backend/patch/update-plans/${id}/export`);
  await _expect(res, `export patch update plan ${id} failed`);
  return res.json();
}

/**
 * Browser-side download trigger for the audit-export bundle. Fetches the
 * file via the API client (so auth headers + JWT refresh are intact) and
 * triggers a download via an anchor + Blob URL. Backend sets the
 * Content-Disposition header but some browsers ignore it on fetch
 * responses, so we set the download attribute explicitly.
 */
export async function triggerExportDownload(id: number): Promise<void> {
  const res = await apiFetch(`/api/backend/patch/update-plans/${id}/export`);
  await _expect(res, `export patch update plan ${id} failed`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `patch-update-plan-${id}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
