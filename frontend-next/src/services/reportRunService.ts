/**
 * PRA-178 Slice 2: durable report-run history client.
 *
 * Backed by ``GET /reports/runs``. Slice 2 ships read-only: the
 * Slice 1 manual export routes write report-run rows under the hood
 * when an operator triggers an export, and this surface lists them
 * back. The scheduler that would write
 * ``triggered_by='system_scheduled'`` rows is intentionally deferred
 * to a later slice.
 */
import { apiFetch } from '../utils/api';

// ---------------------------------------------------------------------------
// Locked vocabularies (mirror backend constants)
// ---------------------------------------------------------------------------

export type ReportKind =
  | 'patch_executions'
  | 'compliance_remediation_requests'
  | 'compliance_evidence'
  | 'patch_update_plans'
  | 'patch_reboot_queues'
  | 'patch_rollback_runs'
  | 'compliance_remediation_plans'
  | 'compliance_remediation_executions'
  // PRA-358: package posture reports.
  | 'package_outdated'
  | 'package_compliance';

export const REPORT_KIND_VALUES: ReportKind[] = [
  'patch_executions',
  'compliance_remediation_requests',
  'compliance_evidence',
  'patch_update_plans',
  'patch_reboot_queues',
  'patch_rollback_runs',
  'compliance_remediation_plans',
  'compliance_remediation_executions',
  'package_outdated',
  'package_compliance',
];

export const REPORT_KIND_LABELS: Record<ReportKind, string> = {
  patch_executions: 'Patch executions',
  compliance_remediation_requests: 'Compliance remediation requests',
  compliance_evidence: 'Compliance evidence',
  patch_update_plans: 'Patch update plans',
  patch_reboot_queues: 'Patch reboot queues',
  patch_rollback_runs: 'Patch rollback runs',
  compliance_remediation_plans: 'Compliance remediation plans',
  compliance_remediation_executions: 'Compliance remediation executions',
  package_outdated: 'Outdated packages',
  package_compliance: 'Update compliance',
};

export type ReportRunTriggeredBy = 'user' | 'system_scheduled';

export const REPORT_RUN_TRIGGERED_BY_VALUES: ReportRunTriggeredBy[] = [
  'user',
  'system_scheduled',
];

export type ReportRunState = 'started' | 'succeeded' | 'failed';

export const REPORT_RUN_STATE_VALUES: ReportRunState[] = [
  'started',
  'succeeded',
  'failed',
];

export type ReportRunFormat = 'csv' | 'json' | 'jsonl';

// ---------------------------------------------------------------------------
// Read shape
// ---------------------------------------------------------------------------

export interface ReportRun {
  id: number;
  report_kind: ReportKind;
  triggered_by: ReportRunTriggeredBy;
  triggered_by_user_id: number | null;
  triggered_by_username: string | null;
  format: ReportRunFormat | null;
  filters_snapshot: Record<string, unknown>;
  row_count: number | null;
  state: ReportRunState;
  error_message: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface ReportRunPage {
  items: ReportRun[];
  total: number;
  offset: number;
  limit: number;
  next_offset: number | null;
}

export interface ListReportRunsParams {
  report_kind?: ReportKind;
  triggered_by?: ReportRunTriggeredBy;
  state?: ReportRunState;
  since?: string; // ISO 8601 UTC
  until?: string; // ISO 8601 UTC
  offset?: number;
  limit?: number;
}

// ---------------------------------------------------------------------------
// Error helper
// ---------------------------------------------------------------------------

export class ReportRunApiError extends Error {
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
      : (detail as { detail?: string } | null)?.detail ?? `${label} (${res.status})`;
  throw new ReportRunApiError(
    res.status,
    typeof msg === 'string' ? msg : `${label} (${res.status})`,
    detail,
  );
}

// ---------------------------------------------------------------------------
// API surface
// ---------------------------------------------------------------------------

export async function listReportRuns(
  params: ListReportRunsParams = {},
): Promise<ReportRunPage> {
  const qs = new URLSearchParams();
  if (params.report_kind) qs.set('report_kind', params.report_kind);
  if (params.triggered_by) qs.set('triggered_by', params.triggered_by);
  if (params.state) qs.set('state', params.state);
  if (params.since) qs.set('since', params.since);
  if (params.until) qs.set('until', params.until);
  if (params.offset !== undefined) qs.set('offset', String(params.offset));
  if (params.limit !== undefined) qs.set('limit', String(params.limit));

  const url =
    qs.toString().length > 0
      ? `/api/backend/reports/runs?${qs.toString()}`
      : '/api/backend/reports/runs';
  const res = await apiFetch(url);
  await _expect(res, 'list report runs failed');
  return res.json();
}

// ---------------------------------------------------------------------------
// PRA-178 Slice 5: scheduled report runs.
// ---------------------------------------------------------------------------

export type ReportCadence = 'daily' | 'weekly' | 'monthly';

export const REPORT_CADENCE_VALUES: ReportCadence[] = [
  'daily',
  'weekly',
  'monthly',
];

export const REPORT_CADENCE_LABELS: Record<ReportCadence, string> = {
  daily: 'Daily',
  weekly: 'Weekly',
  monthly: 'Monthly (~30 days)',
};

export interface ReportSchedule {
  id: number;
  name: string;
  report_kind: ReportKind;
  cadence: ReportCadence;
  filters_snapshot: Record<string, unknown>;
  format: 'csv' | 'json';
  enabled: boolean;
  next_run_at: string | null;
  last_run_at: string | null;
  last_run_id: number | null;
  last_run_state: ReportRunState | null;
  created_by_user_id: number | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface ReportSchedulePage {
  items: ReportSchedule[];
  total: number;
  offset: number;
  limit: number;
  next_offset: number | null;
}

export interface CreateReportScheduleBody {
  name: string;
  report_kind: ReportKind;
  cadence: ReportCadence;
  filters_snapshot?: Record<string, unknown>;
  format?: 'csv' | 'json';
  enabled?: boolean;
  first_run_at?: string;
}

export interface UpdateReportScheduleBody {
  name?: string;
  cadence?: ReportCadence;
  filters_snapshot?: Record<string, unknown>;
  format?: 'csv' | 'json';
  enabled?: boolean;
  next_run_at?: string | null;
}

export async function listReportSchedules(): Promise<ReportSchedulePage> {
  const res = await apiFetch('/api/backend/reports/schedules');
  await _expect(res, 'list report schedules failed');
  return res.json();
}

export async function createReportSchedule(
  body: CreateReportScheduleBody,
): Promise<ReportSchedule> {
  const res = await apiFetch('/api/backend/reports/schedules', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  await _expect(res, 'create report schedule failed');
  return res.json();
}

export async function updateReportSchedule(
  scheduleId: number,
  body: UpdateReportScheduleBody,
): Promise<ReportSchedule> {
  const res = await apiFetch(`/api/backend/reports/schedules/${scheduleId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  await _expect(res, 'update report schedule failed');
  return res.json();
}

export async function deleteReportSchedule(scheduleId: number): Promise<void> {
  const res = await apiFetch(`/api/backend/reports/schedules/${scheduleId}`, {
    method: 'DELETE',
  });
  await _expect(res, 'delete report schedule failed');
}
