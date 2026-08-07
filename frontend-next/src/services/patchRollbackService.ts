/**
 * PRA-173 closeout: patch rollback API client.
 *
 * Wraps the rollback feasibility / approval / dispatch / verify
 * endpoints shipped by PRA-173 Slices 1-4. All endpoints live
 * under ``/patch/update-executions/{id}/rollback/...`` and the
 * plan-scoped read under
 * ``/patch/update-plans/{plan_id}/rollback``.
 *
 * Wire shape mirrors the backend Pydantic schemas in
 * ``backend/app/api/schemas/patch_rollbacks.py``. Timestamps are
 * absolute UTC strings (``...Z``) per PRA-173 review lock #2.
 */
import { apiFetch } from '../utils/api';

// ---------------------------------------------------------------------------
// Locked vocabularies (mirror backend constants)
// ---------------------------------------------------------------------------

export type RollbackPlanState = 'evaluated' | 'refused';

export type RollbackHostState =
  | 'feasible'
  | 'partial_feasible'
  | 'infeasible';

export type RollbackPackageState = 'feasible' | 'infeasible';

export type RollbackApprovalStatus =
  | 'pending'
  | 'approved'
  | 'rejected'
  | 'expired';

export type RollbackDispatchRunState =
  | 'pending'
  | 'running'
  | 'paused'
  | 'succeeded'
  | 'failed'
  | 'canceled';

export type RollbackDispatchHostState =
  | 'pending'
  | 'running'
  | 'succeeded'
  | 'failed'
  | 'skipped'
  | 'canceled';

export type RollbackDispatchPackageOutcome =
  | 'pending'
  | 'succeeded'
  | 'failed'
  | 'skipped'
  | 'unknown';

// Known refusal codes (operator-facing labels live in the UI).
export type RollbackRefusalCode =
  | 'execution_not_terminal'
  | 'host_not_succeeded'
  | 'package_not_succeeded'
  | 'missing_before_version'
  | 'missing_after_version'
  | 'version_unchanged'
  | 'unsupported_package_family'
  | 'content_profile_missing'
  | 'content_evidence_missing'
  | 'old_version_unavailable'
  | string;

// ---------------------------------------------------------------------------
// Read shapes
// ---------------------------------------------------------------------------

export interface RollbackFeasibilitySummary {
  host_count: number;
  host_counts_by_state: Record<RollbackHostState, number>;
  package_count: number;
  package_counts_by_state: Record<RollbackPackageState, number>;
  refusal_counts: Record<string, number>;
}

export interface RollbackRead {
  id: number;
  execution_id: number;
  plan_id_snapshot: number;
  execution_state_snapshot: string;
  state: RollbackPlanState;
  refusal_reason: RollbackRefusalCode | null;
  refusal_details: Record<string, unknown>;
  feasibility_summary: RollbackFeasibilitySummary;
  evaluated_at: string;
  created_at: string;
  updated_at: string;
}

export interface RollbackHostRead {
  id: number;
  rollback_id: number;
  execution_host_id: number;
  plan_host_id_snapshot: number;
  system_id_snapshot: number | null;
  system_hostname_snapshot: string | null;
  wave_index: number;
  execution_host_state_snapshot: string;
  state: RollbackHostState;
  refusal_reason: RollbackRefusalCode | null;
  refusal_details: Record<string, unknown>;
  content_profile_snapshot: Record<string, unknown>;
  package_summary: Record<string, unknown>;
  evaluated_at: string;
  created_at: string;
  updated_at: string;
}

export interface RollbackPackageRead {
  id: number;
  rollback_host_id: number;
  execution_host_package_id: number | null;
  package_name: string;
  package_manager_family_snapshot: string;
  installed_version_before_snapshot: string | null;
  installed_version_after_snapshot: string | null;
  requested_version_snapshot: string | null;
  target_rollback_version: string | null;
  package_outcome_snapshot: string;
  state: RollbackPackageState;
  refusal_reason: RollbackRefusalCode | null;
  refusal_details: Record<string, unknown>;
  content_evidence: Record<string, unknown>;
  command_plan: Record<string, unknown> | null;
  evaluated_at: string;
  created_at: string;
  updated_at: string;
}

export interface RollbackApprovalSummary {
  rollback_approval_link_id: number;
  approval_id: number;
  status: RollbackApprovalStatus | null;
  required_approvals: number | null;
  expires_at: string | null;
  decided_by: number | null;
  decided_at: string | null;
  requested_by: number;
  requested_at: string;
  frozen_plan_snapshot: Record<string, unknown>;
}

export interface RollbackDetail {
  execution_id: number;
  execution_state: string;
  plan_id: number;
  rollback: RollbackRead | null;
  hosts: RollbackHostRead[];
  packages: RollbackPackageRead[];
  approval: RollbackApprovalSummary | null;
}

// ---------------------------------------------------------------------------
// Dispatch read shapes (Slice 3)
// ---------------------------------------------------------------------------

export interface RollbackDispatchRunRead {
  id: number;
  rollback_id: number;
  rollback_approval_link_id: number;
  state: RollbackDispatchRunState;
  started_by: number;
  started_at: string;
  completed_at: string | null;
  paused_at: string | null;
  canceled_at: string | null;
  max_parallel: number;
  pause_reason: string | null;
  cancel_reason: string | null;
  progress_summary: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface RollbackDispatchHostRead {
  id: number;
  rollback_dispatch_run_id: number;
  rollback_host_id: number;
  system_id_snapshot: number | null;
  system_hostname_snapshot: string | null;
  state: RollbackDispatchHostState;
  error_details: Record<string, unknown>;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface RollbackDispatchHostPackageRead {
  id: number;
  rollback_dispatch_host_id: number;
  rollback_package_id: number | null;
  package_name: string;
  package_manager_family_snapshot: string;
  target_rollback_version_snapshot: string | null;
  installed_version_before: string | null;
  installed_version_after: string | null;
  outcome: RollbackDispatchPackageOutcome;
  error_code: string | null;
  details: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface RollbackDispatchDetail {
  execution_id: number;
  execution_state: string;
  plan_id: number;
  run: RollbackDispatchRunRead | null;
  hosts: RollbackDispatchHostRead[];
  packages: RollbackDispatchHostPackageRead[];
}

export interface RollbackDispatchHostOutcome {
  rollback_dispatch_host_id: number;
  rollback_host_id: number;
  system_id: number | null;
  state: RollbackDispatchHostState;
  succeeded_package_count: number;
  failed_package_count: number;
  skipped_package_count: number;
  error_code: string | null;
}

export interface RollbackDispatchBatchResult {
  rollback_dispatch_run_id: number;
  dispatched_count: number;
  succeeded_count: number;
  failed_count: number;
  no_pending: boolean;
  finalized_state: RollbackDispatchRunState | null;
  host_outcomes: RollbackDispatchHostOutcome[];
  dispatch: RollbackDispatchDetail;
}

// ---------------------------------------------------------------------------
// Verify-due result (Slice 4)
// ---------------------------------------------------------------------------

export interface RollbackVerifyHostOutcome {
  rollback_dispatch_host_id: number;
  system_id: number | null;
  reachable: boolean;
  verified_package_count: number;
  package_history_written_count: number;
  reason: string | null;
}

export interface RollbackVerifyResult {
  rollback_dispatch_run_id: number;
  attempted_host_count: number;
  reachable_host_count: number;
  unreachable_host_count: number;
  no_due: boolean;
  verification_complete: boolean;
  host_outcomes: RollbackVerifyHostOutcome[];
  dispatch: RollbackDispatchDetail;
}

// ---------------------------------------------------------------------------
// Write shapes
// ---------------------------------------------------------------------------

export interface RollbackRequestApprovalInput {
  required_approvals?: number;
  expires_at?: string | null;
  comment?: string | null;
}

export interface RollbackVoteInput {
  decision: 'approve' | 'reject';
  comment?: string | null;
}

export interface RollbackVoteResult {
  execution_id: number;
  rollback_id: number;
  rollback_approval_link_id: number;
  approval_id: number;
  status: RollbackApprovalStatus | null;
  approves: number | null;
  required: number | null;
}

export interface RollbackDispatchStartInput {
  max_parallel?: number | null;
}

export interface RollbackDispatchCancelInput {
  cancel_reason?: string | null;
}

// ---------------------------------------------------------------------------
// Plan-scoped read shape
// ---------------------------------------------------------------------------

export interface PlanRollbackSummary {
  execution_count: number;
  evaluated_count: number;
  host_count: number;
  host_counts_by_state: Record<RollbackHostState, number>;
  package_count: number;
  package_counts_by_state: Record<RollbackPackageState, number>;
  refusal_counts: Record<string, number>;
}

export interface PlanRollbackExecutionRef {
  execution_id: number;
  execution_state: string;
  started_at: string;
  completed_at: string | null;
  rollback: RollbackRead | null;
}

export interface PlanRollbackRead {
  plan_id: number;
  plan_state: string;
  summary: PlanRollbackSummary;
  executions: PlanRollbackExecutionRef[];
}

// ---------------------------------------------------------------------------
// Error helper
// ---------------------------------------------------------------------------

export class PatchRollbackApiError extends Error {
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
    try {
      detail = await res.text();
    } catch {
      detail = '';
    }
  }
  const msg =
    typeof detail === 'string'
      ? detail
      : ((detail as { detail?: string } | null)?.detail ??
        `${label} (${res.status})`);
  throw new PatchRollbackApiError(
    res.status,
    typeof msg === 'string' ? msg : `${label} (${res.status})`,
    detail,
  );
}

// ---------------------------------------------------------------------------
// API surface — feasibility (Slice 1)
// ---------------------------------------------------------------------------

export async function getExecutionRollback(
  executionId: number,
): Promise<RollbackDetail> {
  const res = await apiFetch(
    `/api/backend/patch/update-executions/${executionId}/rollback`,
  );
  await _expect(res, `get rollback for execution ${executionId} failed`);
  return res.json();
}

export async function evaluateExecutionRollback(
  executionId: number,
): Promise<RollbackDetail> {
  const res = await apiFetch(
    `/api/backend/patch/update-executions/${executionId}/rollback/evaluate`,
    { method: 'POST' },
  );
  await _expect(res, `evaluate rollback for execution ${executionId} failed`);
  return res.json();
}

export async function getPlanRollback(
  planId: number,
): Promise<PlanRollbackRead> {
  const res = await apiFetch(
    `/api/backend/patch/update-plans/${planId}/rollback`,
  );
  await _expect(res, `get plan rollback for ${planId} failed`);
  return res.json();
}

// ---------------------------------------------------------------------------
// API surface — approval (Slice 2)
// ---------------------------------------------------------------------------

export async function requestRollbackApproval(
  executionId: number,
  input: RollbackRequestApprovalInput = {},
): Promise<RollbackDetail> {
  const res = await apiFetch(
    `/api/backend/patch/update-executions/${executionId}/rollback/request-approval`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    },
  );
  await _expect(
    res,
    `request rollback approval for execution ${executionId} failed`,
  );
  return res.json();
}

export async function voteRollbackApproval(
  executionId: number,
  input: RollbackVoteInput,
): Promise<RollbackVoteResult> {
  const res = await apiFetch(
    `/api/backend/patch/update-executions/${executionId}/rollback/vote`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    },
  );
  await _expect(
    res,
    `vote on rollback approval for execution ${executionId} failed`,
  );
  return res.json();
}

// ---------------------------------------------------------------------------
// API surface — dispatch (Slice 3)
// ---------------------------------------------------------------------------

export async function getExecutionRollbackDispatch(
  executionId: number,
): Promise<RollbackDispatchDetail> {
  const res = await apiFetch(
    `/api/backend/patch/update-executions/${executionId}/rollback/dispatch`,
  );
  await _expect(
    res,
    `get rollback dispatch for execution ${executionId} failed`,
  );
  return res.json();
}

export async function startExecutionRollbackDispatch(
  executionId: number,
  input: RollbackDispatchStartInput = {},
): Promise<RollbackDispatchDetail> {
  const res = await apiFetch(
    `/api/backend/patch/update-executions/${executionId}/rollback/start`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    },
  );
  await _expect(
    res,
    `start rollback dispatch for execution ${executionId} failed`,
  );
  return res.json();
}

export async function dispatchNextExecutionRollback(
  executionId: number,
): Promise<RollbackDispatchBatchResult> {
  const res = await apiFetch(
    `/api/backend/patch/update-executions/${executionId}/rollback/dispatch-next`,
    { method: 'POST' },
  );
  await _expect(
    res,
    `dispatch-next rollback for execution ${executionId} failed`,
  );
  return res.json();
}

export async function cancelExecutionRollbackDispatch(
  executionId: number,
  input: RollbackDispatchCancelInput = {},
): Promise<RollbackDispatchDetail> {
  const res = await apiFetch(
    `/api/backend/patch/update-executions/${executionId}/rollback/cancel`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    },
  );
  await _expect(
    res,
    `cancel rollback dispatch for execution ${executionId} failed`,
  );
  return res.json();
}

// ---------------------------------------------------------------------------
// API surface — verify (Slice 4)
// ---------------------------------------------------------------------------

export async function verifyDueExecutionRollback(
  executionId: number,
): Promise<RollbackVerifyResult> {
  const res = await apiFetch(
    `/api/backend/patch/update-executions/${executionId}/rollback/verify-due`,
    { method: 'POST' },
  );
  await _expect(
    res,
    `verify-due rollback for execution ${executionId} failed`,
  );
  return res.json();
}
