/**
 * PRA-165: compliance API client.
 *
 * Wraps the backend surfaces from PRA-165 Slice 1 / 2 / 3:
 *
 *   - Slice 1: policy + check CRUD, starter-pack preview/seed.
 *   - Slice 2: evaluation runner (server-driven; no client trigger).
 *   - Slice 3: paginated evidence reads, per-policy + fleet summary,
 *     JSONL/CSV exports under ``/compliance/exports``.
 *
 * Slice 4 wires this client into the Praxis frontend. Export
 * downloads are intentionally handled as plain browser GETs (the
 * `exportEvidenceHref` helper below returns the URL with filters
 * encoded) so multi-million-row windows stream to disk rather than
 * memory.
 */
import { apiFetch } from '../utils/api';

// ---------------------------------------------------------------------------
// Locked vocabularies (mirror backend constants)
// ---------------------------------------------------------------------------

export type ComplianceSeverity = 'low' | 'medium' | 'high' | 'critical';

export type ComplianceCheckKind =
  | 'package_installed'
  | 'package_absent'
  | 'package_version_min'
  | 'fact_equals'
  | 'fact_present'
  | 'fact_absent'
  | 'file_exists'
  | 'file_sha256'
  | 'command_stdout_contains'
  | 'command_exit_code';

export const COMPLIANCE_SEVERITIES: ComplianceSeverity[] = [
  'low',
  'medium',
  'high',
  'critical',
];

export const SEVERITY_LABELS: Record<ComplianceSeverity, string> = {
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
};

export const COMPLIANCE_CHECK_KINDS: ComplianceCheckKind[] = [
  'package_installed',
  'package_absent',
  'package_version_min',
  'fact_equals',
  'fact_present',
  'fact_absent',
  'file_exists',
  'file_sha256',
  'command_stdout_contains',
  'command_exit_code',
];

export const CHECK_KIND_LABELS: Record<ComplianceCheckKind, string> = {
  package_installed: 'Package installed',
  package_absent: 'Package absent',
  package_version_min: 'Package version ≥',
  fact_equals: 'Fact equals',
  fact_present: 'Fact present',
  fact_absent: 'Fact absent',
  file_exists: 'File exists',
  file_sha256: 'File SHA-256',
  command_stdout_contains: 'Command stdout contains',
  command_exit_code: 'Command exit code',
};

// Safe label for a check kind that may arrive as a plain string (e.g. from a
// remediation snapshot). Falls back to a humanized form, never a raw enum.
export function checkKindLabel(kind: string): string {
  const known = (CHECK_KIND_LABELS as Record<string, string>)[kind];
  if (known) return known;
  return kind.replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase());
}

export type Verdict = 'pass' | 'fail' | 'error';
export const VERDICTS: Verdict[] = ['pass', 'fail', 'error'];

// Human labels for the raw verdict enum (used where only the raw verdict is
// available, e.g. remediation snapshots).
export const VERDICT_LABELS: Record<Verdict, string> = {
  pass: 'Pass',
  fail: 'Fail',
  error: 'Error',
};

export function verdictLabel(v: string): string {
  return (VERDICT_LABELS as Record<string, string>)[v] ?? 'Error';
}

// PRA-346: backend-derived product status that splits the single `error`
// verdict into distinguishable, actionable states.
export type EvidenceStatus =
  | 'pass'
  | 'fail'
  | 'error'
  | 'coverage_pending'
  | 'awaiting_scan'
  | 'unsupported';

export type RunnerOwner =
  | 'deferred_to_pra165_slice_2'
  | 'deferred_to_pra166'
  | 'unknown';

export type RunnerStatus = 'runner_executed' | 'runner_deferred';

// ---------------------------------------------------------------------------
// Read shapes
// ---------------------------------------------------------------------------

export interface CompliancePolicy {
  id: number;
  slug: string;
  name: string;
  description: string | null;
  severity: ComplianceSeverity;
  category: string;
  schedule_interval_hours: number;
  evidence_retention_days: number;
  remediation_guidance: string | null;
  enabled: boolean;
  version: number;
  built_in: boolean;
  starter_pack_key: string | null;
  created_by: number;
  created_at: string;
  updated_at: string;
  // PRA-312 run-status surface.
  last_run_at: string | null;
  next_run_at: string | null;
  last_run_status: 'success' | 'error' | null;
  never_run: boolean;
}

export interface ComplianceCheck {
  id: number;
  policy_id: number;
  slug: string;
  title: string;
  description: string | null;
  kind: ComplianceCheckKind;
  definition: Record<string, unknown>;
  severity_override: ComplianceSeverity | null;
  remediation_guidance: string | null;
  enabled: boolean;
  display_order: number;
  runner_status: string;
  runner_owner: string;
  // PRA-346: product-facing siblings.
  runner_status_label: string;
  runner_label: string;
  created_at: string;
  updated_at: string;
}

export interface CompliancePolicyDetail extends CompliancePolicy {
  checks: ComplianceCheck[];
}

export interface ComplianceEvidenceRow {
  id: number;
  policy_id: number;
  check_id: number | null;
  system_id: number;
  policy_slug: string;
  policy_version: number;
  check_slug: string;
  check_kind: ComplianceCheckKind;
  verdict: Verdict;
  verdict_reason: string | null;
  observed_value: string | null;
  expected_value: string | null;
  severity: ComplianceSeverity;
  runner_owner: string;
  runner_status: string;
  // PRA-346: product-facing siblings. Render these, not the raw enums above.
  status: EvidenceStatus;
  status_label: string;
  verdict_reason_label: string | null;
  runner_label: string;
  evaluation_run_id: string;
  evaluated_at: string;
  created_at: string;
  updated_at: string;
}

export interface ComplianceEvidencePage {
  items: ComplianceEvidenceRow[];
  total: number;
  offset: number;
  limit: number;
  next_offset: number | null;
}

export interface CompliancePerCheckCount {
  check_id: number | null;
  check_slug: string;
  check_kind: ComplianceCheckKind;
  runner_owner: string;
  runner_label: string;
  pass_count: number;
  fail_count: number;
  error_count: number;
}

export interface CompliancePerHostCount {
  system_id: number;
  // PRA-312 follow-up: display name; null when the System row is gone (fall back to id).
  hostname?: string | null;
  pass_count: number;
  fail_count: number;
  error_count: number;
}

export interface CompliancePolicySummary {
  policy_id: number;
  policy_slug: string;
  severity: ComplianceSeverity;
  enabled: boolean;
  schedule_interval_hours: number;
  latest_run_id: string | null;
  latest_run_at: string | null;
  pass_count: number;
  fail_count: number;
  error_count: number;
  per_check: CompliancePerCheckCount[];
  per_host: CompliancePerHostCount[];
}

export interface CompliancePerPolicyFleetCount {
  policy_id: number;
  policy_slug: string;
  severity: ComplianceSeverity;
  enabled: boolean;
  schedule_interval_hours: number;
  last_run_at: string | null;
  next_run_at: string | null;
  last_run_status: 'success' | 'error' | null;
  never_run: boolean;
  stale: boolean;
  pass_count: number;
  fail_count: number;
  error_count: number;
}

export interface CompliancePolicyRunResult {
  policy_id: number;
  policy_slug: string;
  run_id: string;
  evaluated_at: string;
  counts: Record<string, number>;
  evidence_count: number;
  last_run_status: 'success' | 'error';
}

export interface CompliancePerSeverityFleetCount {
  severity: ComplianceSeverity;
  pass_count: number;
  fail_count: number;
  error_count: number;
}

export interface ComplianceFleetSummary {
  generated_at: string;
  policy_count: number;
  enabled_policy_count: number;
  host_count: number;
  pass_count: number;
  fail_count: number;
  error_count: number;
  per_policy: CompliancePerPolicyFleetCount[];
  per_severity: CompliancePerSeverityFleetCount[];
  per_host: CompliancePerHostCount[];
}

export interface StarterPackEntry {
  starter_pack_key: string;
  slug: string;
  name: string;
  category: string;
  severity: ComplianceSeverity;
  description: string | null;
  check_count: number;
  runner_owners: string[];
  // PRA-346: product-facing evaluator families + honest coverage signalling.
  runner_labels: string[];
  coverage_pending_count: number;
  has_coverage_pending: boolean;
}

export interface StarterPackSeedResult {
  seeded: string[];
  skipped: string[];
}

// ---------------------------------------------------------------------------
// Mutation shapes
// ---------------------------------------------------------------------------

export interface CompliancePolicyCreateInput {
  slug: string;
  name: string;
  description?: string | null;
  severity?: ComplianceSeverity;
  category?: string;
  schedule_interval_hours?: number;
  evidence_retention_days?: number;
  remediation_guidance?: string | null;
  enabled?: boolean;
}

export type CompliancePolicyUpdateInput = Partial<
  Omit<CompliancePolicyCreateInput, 'slug'>
>;

export interface ComplianceCheckCreateInput {
  slug: string;
  title: string;
  kind: ComplianceCheckKind;
  definition: Record<string, unknown>;
  description?: string | null;
  severity_override?: ComplianceSeverity | null;
  remediation_guidance?: string | null;
  enabled?: boolean;
  display_order?: number;
}

export type ComplianceCheckUpdateInput = Partial<
  Omit<ComplianceCheckCreateInput, 'slug' | 'kind'>
>;

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

export class ComplianceApiError extends Error {
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
      detail = null;
    }
  }
  const msg =
    typeof detail === 'string'
      ? detail
      : ((detail as { detail?: string } | null)?.detail ?? `${label} (${res.status})`);
  throw new ComplianceApiError(
    res.status,
    typeof msg === 'string' ? msg : `${label} (${res.status})`,
    detail,
  );
}

// ---------------------------------------------------------------------------
// Policy CRUD
// ---------------------------------------------------------------------------

export async function listCompliancePolicies(opts: {
  enabled_only?: boolean;
  built_in_only?: boolean;
  offset?: number;
  limit?: number;
} = {}): Promise<CompliancePolicy[]> {
  const params = new URLSearchParams();
  if (opts.enabled_only) params.set('enabled_only', 'true');
  if (opts.built_in_only) params.set('built_in_only', 'true');
  if (opts.offset !== undefined) params.set('offset', String(opts.offset));
  if (opts.limit !== undefined) params.set('limit', String(opts.limit));
  const qs = params.toString();
  const res = await apiFetch(
    `/api/backend/compliance/policies${qs ? `?${qs}` : ''}`,
  );
  await _expect(res, 'list compliance policies failed');
  return res.json();
}

export async function getCompliancePolicy(
  id: number,
): Promise<CompliancePolicyDetail> {
  const res = await apiFetch(`/api/backend/compliance/policies/${id}`);
  await _expect(res, `get compliance policy ${id} failed`);
  return res.json();
}

export async function createCompliancePolicy(
  input: CompliancePolicyCreateInput,
): Promise<CompliancePolicy> {
  const res = await apiFetch('/api/backend/compliance/policies', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
  await _expect(res, 'create compliance policy failed');
  return res.json();
}

export async function updateCompliancePolicy(
  id: number,
  updates: CompliancePolicyUpdateInput,
): Promise<CompliancePolicy> {
  const res = await apiFetch(`/api/backend/compliance/policies/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(updates),
  });
  await _expect(res, 'update compliance policy failed');
  return res.json();
}

export async function setCompliancePolicyEnabled(
  id: number,
  enabled: boolean,
): Promise<CompliancePolicy> {
  const res = await apiFetch(
    `/api/backend/compliance/policies/${id}/enabled`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled }),
    },
  );
  await _expect(res, 'toggle compliance policy enabled failed');
  return res.json();
}

/**
 * PRA-312: trigger an immediate fleet evaluation of a policy so operators don't wait
 * for the next 15-minute scheduler sweep. Synchronous on the backend (existing facts
 * + inventory), so the promise resolves once the run has produced evidence.
 */
export async function runCompliancePolicy(
  id: number,
): Promise<CompliancePolicyRunResult> {
  const res = await apiFetch(`/api/backend/compliance/policies/${id}/run`, {
    method: 'POST',
  });
  await _expect(res, 'run compliance policy failed');
  return res.json();
}

export async function deleteCompliancePolicy(id: number): Promise<void> {
  const res = await apiFetch(`/api/backend/compliance/policies/${id}`, {
    method: 'DELETE',
  });
  if (res.status === 204) return;
  await _expect(res, 'delete compliance policy failed');
}

// ---------------------------------------------------------------------------
// Check CRUD
// ---------------------------------------------------------------------------

export async function listPolicyChecks(
  policyId: number,
): Promise<ComplianceCheck[]> {
  const res = await apiFetch(
    `/api/backend/compliance/policies/${policyId}/checks`,
  );
  await _expect(res, 'list compliance checks failed');
  return res.json();
}

export async function addPolicyCheck(
  policyId: number,
  input: ComplianceCheckCreateInput,
): Promise<ComplianceCheck> {
  const res = await apiFetch(
    `/api/backend/compliance/policies/${policyId}/checks`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    },
  );
  await _expect(res, 'add compliance check failed');
  return res.json();
}

export async function updatePolicyCheck(
  checkId: number,
  updates: ComplianceCheckUpdateInput,
): Promise<ComplianceCheck> {
  const res = await apiFetch(`/api/backend/compliance/checks/${checkId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(updates),
  });
  await _expect(res, 'update compliance check failed');
  return res.json();
}

export async function deletePolicyCheck(checkId: number): Promise<void> {
  const res = await apiFetch(`/api/backend/compliance/checks/${checkId}`, {
    method: 'DELETE',
  });
  if (res.status === 204) return;
  await _expect(res, 'delete compliance check failed');
}

// ---------------------------------------------------------------------------
// Evidence + summaries
// ---------------------------------------------------------------------------

export interface ListEvidenceOpts {
  system_id?: number;
  policy_id?: number;
  verdict?: Verdict;
  evaluated_after?: string;
  evaluated_before?: string;
  offset?: number;
  limit?: number;
}

function _evidenceQuery(opts: ListEvidenceOpts): string {
  const params = new URLSearchParams();
  if (opts.system_id !== undefined)
    params.set('system_id', String(opts.system_id));
  if (opts.policy_id !== undefined)
    params.set('policy_id', String(opts.policy_id));
  if (opts.verdict) params.set('verdict', opts.verdict);
  if (opts.evaluated_after) params.set('evaluated_after', opts.evaluated_after);
  if (opts.evaluated_before) params.set('evaluated_before', opts.evaluated_before);
  if (opts.offset !== undefined) params.set('offset', String(opts.offset));
  if (opts.limit !== undefined) params.set('limit', String(opts.limit));
  return params.toString();
}

export async function listPolicyEvidence(
  policyId: number,
  opts: Omit<ListEvidenceOpts, 'policy_id'> = {},
): Promise<ComplianceEvidencePage> {
  const qs = _evidenceQuery(opts);
  const res = await apiFetch(
    `/api/backend/compliance/policies/${policyId}/evidence${qs ? `?${qs}` : ''}`,
  );
  await _expect(res, 'list policy evidence failed');
  return res.json();
}

export async function listSystemEvidence(
  systemId: number,
  opts: Omit<ListEvidenceOpts, 'system_id'> = {},
): Promise<ComplianceEvidencePage> {
  const qs = _evidenceQuery(opts);
  const res = await apiFetch(
    `/api/backend/compliance/systems/${systemId}/evidence${qs ? `?${qs}` : ''}`,
  );
  await _expect(res, 'list system evidence failed');
  return res.json();
}

export async function getPolicySummary(
  policyId: number,
): Promise<CompliancePolicySummary> {
  const res = await apiFetch(
    `/api/backend/compliance/policies/${policyId}/summary`,
  );
  await _expect(res, 'get policy summary failed');
  return res.json();
}

export async function getFleetSummary(): Promise<ComplianceFleetSummary> {
  const res = await apiFetch('/api/backend/compliance/fleet/summary');
  await _expect(res, 'get fleet summary failed');
  return res.json();
}

// ---------------------------------------------------------------------------
// Starter pack
// ---------------------------------------------------------------------------

export async function getStarterPack(): Promise<StarterPackEntry[]> {
  const res = await apiFetch('/api/backend/compliance/starter-pack');
  await _expect(res, 'get starter pack failed');
  return res.json();
}

export async function seedStarterPack(): Promise<StarterPackSeedResult> {
  const res = await apiFetch('/api/backend/compliance/starter-pack/seed', {
    method: 'POST',
  });
  await _expect(res, 'seed starter pack failed');
  return res.json();
}

// ---------------------------------------------------------------------------
// Exports — direct browser GETs, NOT fetch-into-memory.
// ---------------------------------------------------------------------------

export interface ExportEvidenceOpts {
  format: 'jsonl' | 'csv';
  policy_id?: number;
  system_id?: number;
  verdict?: Verdict;
  evaluated_after?: string;
  evaluated_before?: string;
}

/**
 * Build a URL the browser can hit directly via a normal anchor link.
 * Auth cookies travel with the GET, so the download streams through
 * the Next.js proxy without ever buffering the full response on the
 * client.
 */
export function exportEvidenceHref(opts: ExportEvidenceOpts): string {
  const params = new URLSearchParams();
  if (opts.policy_id !== undefined)
    params.set('policy_id', String(opts.policy_id));
  if (opts.system_id !== undefined)
    params.set('system_id', String(opts.system_id));
  if (opts.verdict) params.set('verdict', opts.verdict);
  if (opts.evaluated_after) params.set('evaluated_after', opts.evaluated_after);
  if (opts.evaluated_before) params.set('evaluated_before', opts.evaluated_before);
  const qs = params.toString();
  const ext = opts.format === 'csv' ? 'evidence.csv' : 'evidence.jsonl';
  return `/api/backend/compliance/exports/${ext}${qs ? `?${qs}` : ''}`;
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

// Map severity → Badge variant supported by the shared Badge
// component. See ``components/ui/Badge.tsx`` for the canonical set.
export function severityBadgeVariant(
  sev: ComplianceSeverity,
): 'neutral' | 'warning' | 'orange' | 'danger' {
  switch (sev) {
    case 'low':
      return 'neutral';
    case 'medium':
      return 'warning';
    case 'high':
      return 'orange';
    case 'critical':
      return 'danger';
  }
}

export function verdictBadgeVariant(
  v: Verdict,
): 'success' | 'danger' | 'warning' {
  switch (v) {
    case 'pass':
      return 'success';
    case 'fail':
      return 'danger';
    case 'error':
      return 'warning';
  }
}

// PRA-346: badge variant for the product status. Distinguishes a genuine error
// (orange) from "facts not collected yet" (info) and "coverage pending"
// (neutral) so a deferred/unavailable check never reads as a red failure.
export function statusBadgeVariant(
  s: EvidenceStatus,
): 'success' | 'danger' | 'warning' | 'orange' | 'info' | 'neutral' {
  switch (s) {
    case 'pass':
      return 'success';
    case 'fail':
      return 'danger';
    case 'error':
      return 'orange';
    case 'awaiting_scan':
      return 'warning';
    case 'coverage_pending':
      return 'info';
    case 'unsupported':
      return 'neutral';
    default:
      return 'neutral';
  }
}

/**
 * Human-friendly text for the fleet-summary stale flag. The slice
 * locks wording: never "compliance failure" — say "evaluation
 * overdue" or "not yet evaluated".
 */
export function staleLabel(row: CompliancePerPolicyFleetCount): string {
  if (!row.stale) return 'Up to date';
  if (row.last_run_at === null) return 'Not yet evaluated';
  return 'Evaluation overdue';
}

export function isDeferredRunner(runnerOwner: string): boolean {
  return runnerOwner === 'deferred_to_pra166';
}

// ---------------------------------------------------------------------------
// PRA-167 / PRA-176 remediation — read-only surfaces.
//
// Slice 1 of PRA-177 ships TYPED READ COVERAGE ONLY for the existing
// PRA-167/PRA-176 backend surfaces. No request creation, approve/reject,
// plan build/refresh, plan acknowledgement, execution-attempt creation,
// or dispatch helpers are added here — those land in later slices.
// ---------------------------------------------------------------------------

export type RemediationRequestState =
  | 'requested'
  | 'approved'
  | 'rejected'
  | 'cancelled';

export const REMEDIATION_REQUEST_STATES: RemediationRequestState[] = [
  'requested',
  'approved',
  'rejected',
  'cancelled',
];

export type RemediationPlanState = 'planned' | 'unsupported' | 'failed';

export const REMEDIATION_PLAN_STATES: RemediationPlanState[] = [
  'planned',
  'unsupported',
  'failed',
];

export type RemediationPlanKind =
  | 'package_install_preview'
  | 'package_remove_preview'
  | 'package_upgrade_preview'
  | 'facts_review_required'
  | 'file_review_required'
  | 'command_review_required'
  | 'unsupported';

export const REMEDIATION_PLAN_KINDS: RemediationPlanKind[] = [
  'package_install_preview',
  'package_remove_preview',
  'package_upgrade_preview',
  'facts_review_required',
  'file_review_required',
  'command_review_required',
  'unsupported',
];

export const PLAN_KIND_LABELS: Record<RemediationPlanKind, string> = {
  package_install_preview: 'Install package',
  package_remove_preview: 'Remove package',
  package_upgrade_preview: 'Upgrade package',
  facts_review_required: 'Facts review required',
  file_review_required: 'File review required',
  command_review_required: 'Command review required',
  unsupported: 'Unsupported',
};

export const EXECUTABLE_PLAN_KINDS: ReadonlySet<RemediationPlanKind> = new Set([
  'package_install_preview',
  'package_remove_preview',
  'package_upgrade_preview',
]);

export type RemediationExecutionState =
  | 'pending'
  | 'dispatched'
  | 'succeeded'
  | 'failed'
  | 'cancelled';

export const REMEDIATION_EXECUTION_STATES: RemediationExecutionState[] = [
  'pending',
  'dispatched',
  'succeeded',
  'failed',
  'cancelled',
];

export interface RemediationRequestRead {
  id: number;
  policy_id: number;
  check_id: number | null;
  system_id: number;
  evidence_id: number | null;
  policy_slug: string;
  policy_version: number;
  check_slug: string;
  check_kind: string;
  runner_owner: string;
  // PRA-346: product-facing siblings for the carried-forward evidence snapshot.
  runner_label: string;
  verdict_label: string;
  verdict_reason_snapshot_label: string | null;
  evaluation_run_id: string | null;
  verdict_snapshot: string;
  verdict_reason_snapshot: string | null;
  severity_snapshot: ComplianceSeverity;
  remediation_guidance_snapshot: string | null;
  state: RemediationRequestState;
  justification: string | null;
  requested_by: number;
  decided_by: number | null;
  decided_at: string | null;
  decided_reason: string | null;
  created_at: string;
  updated_at: string;
}

export interface RemediationRequestPage {
  items: RemediationRequestRead[];
  total: number;
  offset: number;
  limit: number;
  next_offset: number | null;
}

export interface RemediationPlanStep {
  action_intent?: string;
  target?: Record<string, unknown>;
  expected?: unknown;
  safety_notes?: string;
  [key: string]: unknown;
}

export interface RemediationPlanRead {
  id: number;
  request_id: number;
  policy_id: number;
  check_id: number | null;
  system_id: number;
  policy_slug: string;
  policy_version: number;
  check_slug: string;
  check_kind: string;
  severity_snapshot: ComplianceSeverity;
  state: RemediationPlanState;
  plan_kind: RemediationPlanKind;
  plan_steps: RemediationPlanStep[];
  unsupported_reason: string | null;
  error_message: string | null;
  check_definition_fingerprint: string | null;
  is_current: boolean;
  superseded_by_plan_id: number | null;
  acknowledged_at: string | null;
  acknowledged_by: number | null;
  is_stale: boolean;
  ready_for_execution: boolean;
  created_by: number;
  created_at: string;
  updated_at: string;
}

export interface RemediationPlanPage {
  items: RemediationPlanRead[];
  total: number;
  offset: number;
  limit: number;
  next_offset: number | null;
}

export interface RemediationExecutionAttemptRead {
  id: number;
  request_id: number;
  plan_id: number | null;
  policy_id: number;
  check_id: number | null;
  system_id: number;
  policy_slug: string;
  policy_version: number;
  check_slug: string;
  check_kind: string;
  severity_snapshot: ComplianceSeverity;
  plan_kind_snapshot: RemediationPlanKind | string;
  package_name: string | null;
  package_version_target: string | null;
  approval_decided_by: number | null;
  approval_decided_at: string | null;
  state: RemediationExecutionState;
  transport: string | null;
  failure_reason: string | null;
  error_message: string | null;
  exit_code: number | null;
  duration_ms: number | null;
  stdout_summary: string | null;
  stderr_summary: string | null;
  dispatched_at: string | null;
  completed_at: string | null;
  created_by: number;
  created_at: string;
  updated_at: string;
}

export interface RemediationExecutionAttemptPage {
  items: RemediationExecutionAttemptRead[];
  total: number;
  offset: number;
  limit: number;
  next_offset: number | null;
}

export interface RemediationExecutionRequestRollup {
  request_id: number;
  system_id: number;
  generated_at: string;
  offset: number;
  limit: number;
  returned_count: number;
  total_attempts: number;
  next_offset: number | null;
  has_more: boolean;
  counts_by_state: Record<string, number>;
  counts_by_failure_reason: Record<string, number>;
  page_counts_by_state: Record<string, number>;
  page_counts_by_failure_reason: Record<string, number>;
  attempts: RemediationExecutionAttemptRead[];
}

export interface RemediationPerSeverityCount {
  severity: ComplianceSeverity | string;
  requested: number;
  approved: number;
  rejected: number;
  cancelled: number;
  total: number;
}

export interface RemediationFleetSummary {
  generated_at: string;
  request_total: number;
  request_counts_by_state: Record<string, number>;
  current_plan_total: number;
  current_plan_counts_by_state: Record<string, number>;
  current_plan_acknowledged_count: number;
  current_plan_unacknowledged_count: number;
  current_plan_ready_count: number;
  current_plan_not_ready_count: number;
  current_plan_stale_count: number;
  current_plan_not_stale_count: number;
  per_severity: RemediationPerSeverityCount[];
}

export interface RemediationHostInventory {
  system_id: number;
  generated_at: string;
  open_requests: RemediationRequestPage;
  approved_requests: RemediationRequestPage;
  current_plans: RemediationPlanPage;
  ready_plans: RemediationPlanPage;
  superseded_history: RemediationPlanPage;
}

// ---------------------------------------------------------------------------
// Remediation read calls — no mutation methods in this slice.
// ---------------------------------------------------------------------------

export interface ListRemediationRequestsOpts {
  policy_id?: number;
  system_id?: number;
  state?: RemediationRequestState;
  offset?: number;
  limit?: number;
}

export async function listRemediationRequests(
  opts: ListRemediationRequestsOpts = {},
): Promise<RemediationRequestPage> {
  const params = new URLSearchParams();
  if (opts.policy_id !== undefined) params.set('policy_id', String(opts.policy_id));
  if (opts.system_id !== undefined) params.set('system_id', String(opts.system_id));
  if (opts.state) params.set('state', opts.state);
  if (opts.offset !== undefined) params.set('offset', String(opts.offset));
  if (opts.limit !== undefined) params.set('limit', String(opts.limit));
  const qs = params.toString();
  const res = await apiFetch(
    `/api/backend/compliance/remediation-requests${qs ? `?${qs}` : ''}`,
  );
  await _expect(res, 'list remediation requests failed');
  return res.json();
}

export async function getRemediationRequest(
  id: number,
): Promise<RemediationRequestRead> {
  const res = await apiFetch(
    `/api/backend/compliance/remediation-requests/${id}`,
  );
  await _expect(res, `get remediation request ${id} failed`);
  return res.json();
}

export async function getRemediationPlanForRequest(
  requestId: number,
): Promise<RemediationPlanRead | null> {
  const res = await apiFetch(
    `/api/backend/compliance/remediation-requests/${requestId}/plan`,
  );
  // The backend returns 404 when no plan preview has been built yet.
  // That is a normal not-ready state in the read flow, not an error.
  if (res.status === 404) return null;
  await _expect(res, `get remediation plan for request ${requestId} failed`);
  return res.json();
}

export interface ListRemediationPlansOpts {
  state?: RemediationPlanState;
  plan_kind?: RemediationPlanKind;
  system_id?: number;
  is_current?: boolean;
  acknowledged?: boolean;
  ready_for_execution?: boolean;
  offset?: number;
  limit?: number;
}

export async function listRemediationPlans(
  opts: ListRemediationPlansOpts = {},
): Promise<RemediationPlanPage> {
  const params = new URLSearchParams();
  if (opts.state) params.set('state', opts.state);
  if (opts.plan_kind) params.set('plan_kind', opts.plan_kind);
  if (opts.system_id !== undefined) params.set('system_id', String(opts.system_id));
  if (opts.is_current !== undefined) params.set('is_current', String(opts.is_current));
  if (opts.acknowledged !== undefined)
    params.set('acknowledged', String(opts.acknowledged));
  if (opts.ready_for_execution !== undefined)
    params.set('ready_for_execution', String(opts.ready_for_execution));
  if (opts.offset !== undefined) params.set('offset', String(opts.offset));
  if (opts.limit !== undefined) params.set('limit', String(opts.limit));
  const qs = params.toString();
  const res = await apiFetch(
    `/api/backend/compliance/remediation-plans${qs ? `?${qs}` : ''}`,
  );
  await _expect(res, 'list remediation plans failed');
  return res.json();
}

export async function getRemediationPlan(id: number): Promise<RemediationPlanRead> {
  const res = await apiFetch(`/api/backend/compliance/remediation-plans/${id}`);
  await _expect(res, `get remediation plan ${id} failed`);
  return res.json();
}

export interface ListRemediationExecutionsOpts {
  request_id?: number;
  plan_id?: number;
  system_id?: number;
  state?: RemediationExecutionState;
  offset?: number;
  limit?: number;
}

export async function listRemediationExecutions(
  opts: ListRemediationExecutionsOpts = {},
): Promise<RemediationExecutionAttemptPage> {
  const params = new URLSearchParams();
  if (opts.request_id !== undefined)
    params.set('request_id', String(opts.request_id));
  if (opts.plan_id !== undefined) params.set('plan_id', String(opts.plan_id));
  if (opts.system_id !== undefined)
    params.set('system_id', String(opts.system_id));
  if (opts.state) params.set('state', opts.state);
  if (opts.offset !== undefined) params.set('offset', String(opts.offset));
  if (opts.limit !== undefined) params.set('limit', String(opts.limit));
  const qs = params.toString();
  const res = await apiFetch(
    `/api/backend/compliance/remediation-executions${qs ? `?${qs}` : ''}`,
  );
  await _expect(res, 'list remediation executions failed');
  return res.json();
}

export async function getRemediationExecution(
  id: number,
): Promise<RemediationExecutionAttemptRead> {
  const res = await apiFetch(
    `/api/backend/compliance/remediation-executions/${id}`,
  );
  await _expect(res, `get remediation execution ${id} failed`);
  return res.json();
}

export async function getRemediationRequestExecutions(
  requestId: number,
  opts: { offset?: number; limit?: number } = {},
): Promise<RemediationExecutionRequestRollup> {
  const params = new URLSearchParams();
  if (opts.offset !== undefined) params.set('offset', String(opts.offset));
  if (opts.limit !== undefined) params.set('limit', String(opts.limit));
  const qs = params.toString();
  const res = await apiFetch(
    `/api/backend/compliance/remediation-requests/${requestId}/executions${qs ? `?${qs}` : ''}`,
  );
  await _expect(res, `get remediation request ${requestId} executions failed`);
  return res.json();
}

export async function getRemediationFleetSummary(): Promise<RemediationFleetSummary> {
  const res = await apiFetch(
    '/api/backend/compliance/remediation/fleet-summary',
  );
  await _expect(res, 'get remediation fleet summary failed');
  return res.json();
}

export interface SystemRemediationOpts {
  limit?: number;
  open_offset?: number;
  approved_offset?: number;
  current_plans_offset?: number;
  ready_plans_offset?: number;
  superseded_offset?: number;
}

export async function getSystemRemediationInventory(
  systemId: number,
  opts: SystemRemediationOpts = {},
): Promise<RemediationHostInventory> {
  const params = new URLSearchParams();
  if (opts.limit !== undefined) params.set('limit', String(opts.limit));
  if (opts.open_offset !== undefined)
    params.set('open_offset', String(opts.open_offset));
  if (opts.approved_offset !== undefined)
    params.set('approved_offset', String(opts.approved_offset));
  if (opts.current_plans_offset !== undefined)
    params.set('current_plans_offset', String(opts.current_plans_offset));
  if (opts.ready_plans_offset !== undefined)
    params.set('ready_plans_offset', String(opts.ready_plans_offset));
  if (opts.superseded_offset !== undefined)
    params.set('superseded_offset', String(opts.superseded_offset));
  const qs = params.toString();
  const res = await apiFetch(
    `/api/backend/compliance/systems/${systemId}/remediation${qs ? `?${qs}` : ''}`,
  );
  await _expect(res, `get system ${systemId} remediation inventory failed`);
  return res.json();
}

// ---------------------------------------------------------------------------
// Display helpers for remediation
// ---------------------------------------------------------------------------

export function remediationRequestStateBadgeVariant(
  state: RemediationRequestState | string,
): 'success' | 'warning' | 'danger' | 'info' | 'neutral' {
  switch (state) {
    case 'approved':
      return 'success';
    case 'requested':
      return 'warning';
    case 'rejected':
      return 'danger';
    case 'cancelled':
      return 'neutral';
    default:
      return 'info';
  }
}

export function remediationPlanStateBadgeVariant(
  state: RemediationPlanState | string,
): 'success' | 'warning' | 'danger' | 'neutral' {
  switch (state) {
    case 'planned':
      return 'success';
    case 'unsupported':
      return 'warning';
    case 'failed':
      return 'danger';
    default:
      return 'neutral';
  }
}

export function remediationExecutionStateBadgeVariant(
  state: RemediationExecutionState | string,
): 'success' | 'warning' | 'danger' | 'info' | 'neutral' {
  switch (state) {
    case 'succeeded':
      return 'success';
    case 'pending':
      return 'warning';
    case 'dispatched':
      return 'info';
    case 'failed':
      return 'danger';
    case 'cancelled':
      return 'neutral';
    default:
      return 'neutral';
  }
}

// ---------------------------------------------------------------------------
// PRA-177 Slice 2 — remediation request lifecycle mutation methods.
//
// Add minimal client wrappers around the existing backend routes:
//
//   POST /compliance/remediation-requests
//   POST /compliance/remediation-requests/{id}/approve
//   POST /compliance/remediation-requests/{id}/reject
//   POST /compliance/remediation-requests/{id}/cancel
//
// Mutation is intentionally limited to the Slice 1 request substrate;
// plan build/refresh/acknowledge and execution attempt creation /
// dispatch helpers remain absent (Slice 3 and 4).
// ---------------------------------------------------------------------------

export interface CreateRemediationRequestInput {
  evidence_id: number;
  justification?: string | null;
}

export async function createRemediationRequest(
  input: CreateRemediationRequestInput,
): Promise<RemediationRequestRead> {
  const body: Record<string, unknown> = { evidence_id: input.evidence_id };
  if (input.justification !== undefined && input.justification !== null) {
    body.justification = input.justification;
  }
  const res = await apiFetch('/api/backend/compliance/remediation-requests', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  await _expect(res, 'create remediation request failed');
  return res.json();
}

async function _postRemediationDecision(
  requestId: number,
  action: 'approve' | 'reject' | 'cancel',
  decided_reason: string | null | undefined,
  label: string,
): Promise<RemediationRequestRead> {
  const body: Record<string, unknown> = {};
  if (decided_reason !== undefined && decided_reason !== null) {
    body.decided_reason = decided_reason;
  }
  const res = await apiFetch(
    `/api/backend/compliance/remediation-requests/${requestId}/${action}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    },
  );
  await _expect(res, `${label} remediation request ${requestId} failed`);
  return res.json();
}

export async function approveRemediationRequest(
  requestId: number,
  decided_reason?: string | null,
): Promise<RemediationRequestRead> {
  return _postRemediationDecision(requestId, 'approve', decided_reason, 'approve');
}

export async function rejectRemediationRequest(
  requestId: number,
  decided_reason?: string | null,
): Promise<RemediationRequestRead> {
  return _postRemediationDecision(requestId, 'reject', decided_reason, 'reject');
}

export async function cancelRemediationRequest(
  requestId: number,
  decided_reason?: string | null,
): Promise<RemediationRequestRead> {
  return _postRemediationDecision(requestId, 'cancel', decided_reason, 'cancel');
}

// ---------------------------------------------------------------------------
// PRA-177 Slice 3 — remediation plan build / refresh / acknowledge methods.
//
// Wrap the existing PRA-167 plan substrate routes:
//
//   POST /compliance/remediation-requests/{request_id}/plan
//   POST /compliance/remediation-requests/{request_id}/plan/acknowledge
//
// Both endpoints are idempotent-friendly metadata flips: building a
// plan never runs commands on a host; acknowledgement only records
// operator intent and feeds the read-only `ready_for_execution`
// gate. Execution-attempt creation and dispatch remain absent in
// this slice.
// ---------------------------------------------------------------------------

export async function buildRemediationPlan(
  requestId: number,
): Promise<RemediationPlanRead> {
  const res = await apiFetch(
    `/api/backend/compliance/remediation-requests/${requestId}/plan`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    },
  );
  await _expect(res, `build remediation plan for request ${requestId} failed`);
  return res.json();
}

export async function acknowledgeRemediationPlan(
  requestId: number,
): Promise<RemediationPlanRead> {
  const res = await apiFetch(
    `/api/backend/compliance/remediation-requests/${requestId}/plan/acknowledge`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    },
  );
  await _expect(
    res,
    `acknowledge remediation plan for request ${requestId} failed`,
  );
  return res.json();
}

// ---------------------------------------------------------------------------
// PRA-177 Slice 4 — execution-attempt creation + single / batch dispatch.
//
// Wrap the existing PRA-176 routes:
//
//   POST /compliance/remediation-executions               (create attempt)
//   POST /compliance/remediation-executions/{id}/dispatch (single dispatch)
//   POST /compliance/remediation-requests/{id}/dispatch-executions?limit=
//                                                         (bounded batch)
//
// Creation persists a durable attempt audit row and re-checks the
// readiness gate but never dispatches. Dispatch invokes the existing
// governed PRA-171 patch transport via the backend; no new transport
// surface is introduced here.
// ---------------------------------------------------------------------------

/**
 * Mirror of the backend `MAX_BATCH_SIZE` constant for the
 * request-scoped batch dispatch route. Surfacing this in the client
 * lets the confirmation modal show the operator the upper bound
 * without making a second round-trip.
 */
export const REMEDIATION_BATCH_DISPATCH_MAX = 500;

export async function createRemediationExecutionAttempt(
  planId: number,
): Promise<RemediationExecutionAttemptRead> {
  const res = await apiFetch(
    '/api/backend/compliance/remediation-executions',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ plan_id: planId }),
    },
  );
  await _expect(res, `create remediation execution attempt failed`);
  return res.json();
}

export async function dispatchRemediationExecution(
  attemptId: number,
): Promise<RemediationExecutionAttemptRead> {
  const res = await apiFetch(
    `/api/backend/compliance/remediation-executions/${attemptId}/dispatch`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    },
  );
  await _expect(
    res,
    `dispatch remediation execution attempt ${attemptId} failed`,
  );
  return res.json();
}

export interface RemediationBatchDispatchOpts {
  /** Optional cap on the number of `pending` attempts the backend
   *  considers in this dispatch pass. The backend enforces
   *  `1..MAX_BATCH_SIZE` (500). */
  limit?: number;
}

export interface RemediationExecutionBatchRefusal {
  attempt_id: number;
  outcome: string;
  reason: string;
}

export interface RemediationExecutionBatchItem
  extends RemediationExecutionAttemptRead {
  batch_outcome: 'succeeded' | 'failed' | 'refused' | string;
  batch_refusal_reason: string | null;
}

export interface RemediationExecutionBatchResult {
  request_id: number;
  generated_at: string;
  limit: number;
  total_eligible: number;
  dispatched_count: number;
  succeeded_count: number;
  failed_count: number;
  refused_count: number;
  failure_breakdown_by_reason: Record<string, number>;
  refusals: RemediationExecutionBatchRefusal[];
  items: RemediationExecutionBatchItem[];
}

export async function dispatchRemediationRequestExecutions(
  requestId: number,
  opts: RemediationBatchDispatchOpts = {},
): Promise<RemediationExecutionBatchResult> {
  const params = new URLSearchParams();
  if (opts.limit !== undefined) params.set('limit', String(opts.limit));
  const qs = params.toString();
  const res = await apiFetch(
    `/api/backend/compliance/remediation-requests/${requestId}/dispatch-executions${qs ? `?${qs}` : ''}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    },
  );
  await _expect(
    res,
    `batch dispatch remediation request ${requestId} failed`,
  );
  return res.json();
}

/**
 * Human explanation for the not-ready state of a remediation plan.
 * Returns null when the plan IS ready for execution. The wording is
 * locked: never imply that Praxis will auto-execute on its own; the
 * "future execution slice" framing matches the public docs.
 */
export function planNotReadyExplanation(plan: RemediationPlanRead): string | null {
  if (plan.ready_for_execution) return null;
  if (!plan.is_current) {
    return 'Plan is superseded by a newer current plan.';
  }
  if (plan.state === 'unsupported') {
    return (
      plan.unsupported_reason ??
      'No automated remediation preview is available for this check kind.'
    );
  }
  if (plan.state === 'failed') {
    return (
      plan.error_message ??
      'Plan build failed. Rebuild the plan preview from the source request.'
    );
  }
  if (plan.is_stale) {
    return (
      'Live check definition changed since this plan was built. Rebuild ' +
      'and re-acknowledge before this plan can be executed.'
    );
  }
  if (plan.acknowledged_at === null) {
    return 'Plan has not been acknowledged yet.';
  }
  if (!EXECUTABLE_PLAN_KINDS.has(plan.plan_kind as RemediationPlanKind)) {
    return (
      'Plan kind requires manual operator review — no automated execution ' +
      'shape is available.'
    );
  }
  return 'Plan is not yet ready for execution.';
}

// ---------------------------------------------------------------------------
// PRA-178 Slice 1: compliance remediation request review-period export.
//
// Bounded CSV/JSON download for the operator-facing report. Defaults
// to the last 30 days when both bounds are omitted; the backend
// rejects windows > 366 days and filter sets that would produce more
// than 50,000 rows with HTTP 422.
// ---------------------------------------------------------------------------

export type RemediationRequestExportFormat = 'csv' | 'json';

export interface RemediationRequestExportFilters {
  created_after?: string; // ISO 8601 UTC
  created_before?: string; // ISO 8601 UTC
  policy_id?: number;
  system_id?: number;
  state?: RemediationRequestState;
}

export const REMEDIATION_REQUEST_EXPORT_ENDPOINT =
  '/api/backend/compliance/exports/remediation-requests';

/** Stable wire-shape row produced by the remediation request export
 * (matches `compliance_remediation_export_service.EXPORT_CSV_COLUMNS`). */
export interface RemediationRequestExportRow {
  id: number;
  state: RemediationRequestState;
  policy_id: number;
  policy_slug: string;
  policy_version: number;
  check_id: number | null;
  check_slug: string;
  check_kind: string;
  severity: ComplianceSeverity;
  verdict_snapshot: string;
  verdict_reason_snapshot: string | null;
  system_id: number;
  system_hostname: string | null;
  evidence_id: number | null;
  evaluation_run_id: string | null;
  requested_by_user_id: number | null;
  requested_by_username: string | null;
  decided_by_user_id: number | null;
  decided_by_username: string | null;
  decided_at: string | null;
  decided_reason: string | null;
  justification: string | null;
  created_at: string | null;
  updated_at: string | null;
}

/** Build the URL params an ``ExportButton`` should pass to its
 * `params` prop so the GET request encodes the review-window /
 * policy / system / state filters consistently with the backend
 * contract. */
export function buildRemediationRequestExportParams(
  filters: RemediationRequestExportFilters,
): Record<string, string> {
  const params: Record<string, string> = {};
  if (filters.created_after) params.created_after = filters.created_after;
  if (filters.created_before) params.created_before = filters.created_before;
  if (filters.policy_id !== undefined) params.policy_id = String(filters.policy_id);
  if (filters.system_id !== undefined) params.system_id = String(filters.system_id);
  if (filters.state) params.state = filters.state;
  return params;
}

function _remediationExportQueryParams(
  filters: RemediationRequestExportFilters,
  format: RemediationRequestExportFormat,
): Record<string, string> {
  const params: Record<string, string> = { format };
  if (filters.created_after) params.created_after = filters.created_after;
  if (filters.created_before) params.created_before = filters.created_before;
  if (filters.policy_id !== undefined) params.policy_id = String(filters.policy_id);
  if (filters.system_id !== undefined) params.system_id = String(filters.system_id);
  if (filters.state) params.state = filters.state;
  return params;
}

/** Fetch the bounded review-period export as parsed JSON. Used by
 * tests + any operator UI that wants to inspect rows in-memory before
 * triggering a download. UI download flows should prefer
 * ``ExportButton`` so the file lands on disk via the browser. */
export async function fetchRemediationRequestExportJson(
  filters: RemediationRequestExportFilters = {},
): Promise<RemediationRequestExportRow[]> {
  const qs = new URLSearchParams(
    _remediationExportQueryParams(filters, 'json'),
  );
  const res = await apiFetch(
    `${REMEDIATION_REQUEST_EXPORT_ENDPOINT}?${qs.toString()}`,
  );
  await _expect(res, 'export compliance remediation requests failed');
  return res.json();
}
