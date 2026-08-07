/**
 * PRA-171 #1: patch update execution API client.
 *
 * Slice 1 covers the execution-run substrate + live-progress read
 * model. Backed by ``/patch/update-executions`` endpoints. Slice 1
 * is METADATA-ONLY — no package-manager dispatch, SSH, agent ops,
 * package mutation, history mutation, reboot, rollback, mirror
 * mutation, or airgap behavior. Real per-host execution lands in
 * later PRA-171 slices.
 */
import { apiFetch } from '../utils/api';

// ---------------------------------------------------------------------------
// Locked vocabularies (mirror backend constants)
// ---------------------------------------------------------------------------

export type ExecutionState =
  | 'pending'
  | 'running'
  | 'paused'
  | 'succeeded'
  | 'failed'
  | 'canceled';

export const EXECUTION_STATE_VALUES: ExecutionState[] = [
  'pending',
  'running',
  'paused',
  'succeeded',
  'failed',
  'canceled',
];

export type ExecutionHostState =
  | 'pending'
  | 'running'
  | 'succeeded'
  | 'failed'
  | 'skipped'
  | 'paused'
  | 'canceled';

export const EXECUTION_HOST_STATE_VALUES: ExecutionHostState[] = [
  'pending',
  'running',
  'succeeded',
  'failed',
  'skipped',
  'paused',
  'canceled',
];

// ---------------------------------------------------------------------------
// Read shapes
// ---------------------------------------------------------------------------

export interface ExecutionSkipReason {
  code: string;
  details: Record<string, unknown>;
}

export interface ExecutionWaveProgress {
  wave_index: number;
  host_count: number;
  selected_package_count: number;
  host_counts_by_state: Record<ExecutionHostState, number>;
}

export interface ExecutionProgress {
  host_count: number;
  host_counts_by_state: Record<ExecutionHostState, number>;
  selected_package_count: number;
  // Slice 2: per-package outcome rollup. Empty / zero counts before
  // the first dispatch-next call writes any rows.
  package_outcome_counts?: Record<string, number>;
  waves: ExecutionWaveProgress[];
  // Slice 3: wave indexes that have already had wave_completed
  // emitted. Empty before the first wave finishes.
  completed_wave_indexes?: number[];
  // Slice 3: structured failure-threshold breach context when the
  // dispatcher auto-paused. Null otherwise.
  threshold_pause?: ThresholdPauseContext | null;
}

export interface ThresholdPauseContext {
  code: string;
  failure_threshold_percent: number;
  failed_terminal_hosts: number;
  terminal_hosts: number;
  failure_percent: number;
}

export interface PatchUpdateExecutionHost {
  id: number;
  execution_id: number;
  plan_host_id: number;
  system_id_snapshot: number | null;
  system_hostname_snapshot: string | null;
  wave_index: number;
  state: ExecutionHostState;
  selected_package_count: number;
  skip_reasons: ExecutionSkipReason[];
  error_details: Record<string, unknown>;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface PatchUpdateExecution {
  id: number;
  plan_id: number;
  state: ExecutionState;
  started_by: number;
  started_at: string;
  completed_at: string | null;
  paused_at: string | null;
  canceled_at: string | null;
  max_parallel_per_wave: number;
  failure_threshold_percent: number | null;
  pause_reason: string | null;
  cancel_reason: string | null;
  plan_state_snapshot: string;
  policy_snapshot: Record<string, unknown>;
  execution_config_snapshot: Record<string, unknown>;
  progress_summary: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface PatchUpdateExecutionDetail extends PatchUpdateExecution {
  progress: ExecutionProgress;
  hosts: PatchUpdateExecutionHost[];
}

// ---------------------------------------------------------------------------
// Write shapes
// ---------------------------------------------------------------------------

export interface ExecutionStartInput {
  plan_id: number;
  max_parallel_per_wave?: number | null;
  failure_threshold_percent?: number | null;
}

export interface ExecutionPauseInput {
  pause_reason?: string | null;
}

export interface ExecutionCancelInput {
  cancel_reason?: string | null;
}

// ---------------------------------------------------------------------------
// Slice 2: per-package result + dispatch
// ---------------------------------------------------------------------------

export type PackageOutcome = 'succeeded' | 'failed' | 'skipped' | 'unknown';
export const PACKAGE_OUTCOME_VALUES: PackageOutcome[] = [
  'succeeded',
  'failed',
  'skipped',
  'unknown',
];

export interface ExecutionHostPackage {
  id: number;
  execution_host_id: number;
  package_name: string;
  requested_version_snapshot: string | null;
  installed_version_before: string | null;
  installed_version_after: string | null;
  package_manager_family_snapshot: string;
  outcome: PackageOutcome;
  error_code: string | null;
  details: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface DispatchHostOutcome {
  execution_host_id: number;
  system_id: number | null;
  outcome: string;
  exit_code: number | null;
  transport: string | null;
  error_code: string | null;
}

export interface DispatchBatchResult {
  execution_id: number;
  wave_index: number | null;
  dispatched_count: number;
  succeeded_count: number;
  failed_count: number;
  no_pending: boolean;
  pause_reason: string | null;
  host_outcomes: DispatchHostOutcome[];
  // Slice 3: wave indexes that emitted wave_completed during this call.
  completed_wave_indexes?: number[];
  // Slice 3: breach context when the dispatcher auto-paused for
  // failure_threshold breach in this call. Null otherwise.
  threshold_pause?: ThresholdPauseContext | null;
  // Slice 3: terminal state the execution flipped to during this call
  // ("succeeded" / "failed"); null when the execution is not yet
  // complete.
  finalized_state?: ExecutionState | null;
  execution: PatchUpdateExecutionDetail;
}

// ---------------------------------------------------------------------------
// Error helper
// ---------------------------------------------------------------------------

export class PatchUpdateExecutionApiError extends Error {
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
  throw new PatchUpdateExecutionApiError(
    res.status,
    typeof msg === 'string' ? msg : `${label} (${res.status})`,
    detail,
  );
}

// ---------------------------------------------------------------------------
// API surface
// ---------------------------------------------------------------------------

export async function startPatchUpdateExecution(
  input: ExecutionStartInput,
): Promise<PatchUpdateExecutionDetail> {
  const res = await apiFetch('/api/backend/patch/update-executions/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
  await _expect(res, 'start patch update execution failed');
  return res.json();
}

export async function getPatchUpdateExecution(
  id: number,
): Promise<PatchUpdateExecutionDetail> {
  const res = await apiFetch(`/api/backend/patch/update-executions/${id}`);
  await _expect(res, `get patch update execution ${id} failed`);
  return res.json();
}

/** Returns the latest execution for a plan. Throws a 404
 * `PatchUpdateExecutionApiError` when no execution has ever been
 * started for the plan; UI callers can catch the 404 and render the
 * "Start execution" affordance. */
export async function getLatestExecutionForPlan(
  planId: number,
): Promise<PatchUpdateExecutionDetail> {
  const res = await apiFetch(
    `/api/backend/patch/update-executions/by-plan/${planId}`,
  );
  await _expect(res, `get latest execution for plan ${planId} failed`);
  return res.json();
}

export async function pausePatchUpdateExecution(
  id: number,
  input: ExecutionPauseInput = {},
): Promise<PatchUpdateExecutionDetail> {
  const res = await apiFetch(
    `/api/backend/patch/update-executions/${id}/pause`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    },
  );
  await _expect(res, `pause patch update execution ${id} failed`);
  return res.json();
}

export async function resumePatchUpdateExecution(
  id: number,
): Promise<PatchUpdateExecutionDetail> {
  const res = await apiFetch(
    `/api/backend/patch/update-executions/${id}/resume`,
    { method: 'POST' },
  );
  await _expect(res, `resume patch update execution ${id} failed`);
  return res.json();
}

export async function cancelPatchUpdateExecution(
  id: number,
  input: ExecutionCancelInput = {},
): Promise<PatchUpdateExecutionDetail> {
  const res = await apiFetch(
    `/api/backend/patch/update-executions/${id}/cancel`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    },
  );
  await _expect(res, `cancel patch update execution ${id} failed`);
  return res.json();
}

// ---------------------------------------------------------------------------
// Slice 2: dispatch + per-package read
// ---------------------------------------------------------------------------

export async function dispatchNextPatchUpdateExecution(
  id: number,
): Promise<DispatchBatchResult> {
  const res = await apiFetch(
    `/api/backend/patch/update-executions/${id}/dispatch-next`,
    { method: 'POST' },
  );
  await _expect(res, `dispatch-next patch update execution ${id} failed`);
  return res.json();
}

export async function listExecutionHostPackages(
  executionId: number,
  hostId: number,
): Promise<ExecutionHostPackage[]> {
  const res = await apiFetch(
    `/api/backend/patch/update-executions/${executionId}/hosts/${hostId}/packages`,
  );
  await _expect(res, `list execution host packages failed`);
  return res.json();
}

// ---------------------------------------------------------------------------
// PRA-178 Slice 1: review-period export helpers.
//
// Bounded CSV/JSON download for the operator-facing report. The
// backend defaults `started_after` to the last 30 days when both bounds
// are omitted; oversized windows (> 366 days) and filter sets that
// would produce more than 50,000 rows raise HTTP 422 with operator-
// readable text.
// ---------------------------------------------------------------------------

export type PatchExecutionExportFormat = 'csv' | 'json';

export interface PatchExecutionExportFilters {
  started_after?: string; // ISO 8601 UTC
  started_before?: string; // ISO 8601 UTC
  plan_id?: number;
  state?: ExecutionState;
}

export const PATCH_EXECUTION_EXPORT_ENDPOINT =
  '/api/backend/patch/update-executions/export';

/** Stable wire-shape row produced by the patch execution export
 * (matches `patch_reports_service.EXPORT_CSV_COLUMNS`). Counts come
 * from the live ``progress_summary`` JSONB on the execution row; per-
 * host / per-package detail still lives behind the execution detail
 * routes. */
export interface PatchExecutionExportRow {
  id: number;
  plan_id: number;
  plan_name_snapshot: string | null;
  policy_slug_snapshot: string | null;
  state: ExecutionState;
  plan_state_snapshot: string;
  started_by_user_id: number | null;
  started_by_username: string | null;
  started_at: string | null;
  completed_at: string | null;
  paused_at: string | null;
  canceled_at: string | null;
  max_parallel_per_wave: number;
  failure_threshold_percent: number | null;
  pause_reason: string | null;
  cancel_reason: string | null;
  host_count: number;
  host_succeeded: number;
  host_failed: number;
  host_skipped: number;
  host_canceled: number;
  package_succeeded: number;
  package_failed: number;
  package_skipped: number;
  created_at: string | null;
  updated_at: string | null;
}

function _exportQueryParams(
  filters: PatchExecutionExportFilters,
  format: PatchExecutionExportFormat,
): Record<string, string> {
  const params: Record<string, string> = { format };
  if (filters.started_after) params.started_after = filters.started_after;
  if (filters.started_before) params.started_before = filters.started_before;
  if (filters.plan_id !== undefined) params.plan_id = String(filters.plan_id);
  if (filters.state) params.state = filters.state;
  return params;
}

/** Build the URL params that ``ExportButton`` should pass to its
 * `params` prop so the GET request encodes the review-window /
 * plan / state filters consistently with the backend contract. */
export function buildPatchExecutionExportParams(
  filters: PatchExecutionExportFilters,
): Record<string, string> {
  const params: Record<string, string> = {};
  if (filters.started_after) params.started_after = filters.started_after;
  if (filters.started_before) params.started_before = filters.started_before;
  if (filters.plan_id !== undefined) params.plan_id = String(filters.plan_id);
  if (filters.state) params.state = filters.state;
  return params;
}

/** Fetch the bounded review-period export as parsed JSON. Used by
 * tests + any operator UI that wants to inspect rows in-memory before
 * triggering a download. UI download flows should prefer
 * ``ExportButton`` so the file lands on disk via the browser. */
export async function fetchPatchExecutionExportJson(
  filters: PatchExecutionExportFilters = {},
): Promise<PatchExecutionExportRow[]> {
  const qs = new URLSearchParams(_exportQueryParams(filters, 'json'));
  const res = await apiFetch(`${PATCH_EXECUTION_EXPORT_ENDPOINT}?${qs.toString()}`);
  await _expect(res, 'export patch update executions failed');
  return res.json();
}
