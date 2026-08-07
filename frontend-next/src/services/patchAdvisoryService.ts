/**
 * Patch advisory API client.
 *
 * Operator surface over native distribution advisories: read/list/detail,
 * fleet + per-host applicability, an operator-triggered host applicability
 * recompute, and operator-triggered advisory import (raw native payloads)
 * plus import-run history.
 *
 * All routes go through the `/api/backend/...` proxy prefix.
 */
import { apiFetch } from '../utils/api';

// ---------------------------------------------------------------------------
// Locked vocabularies (mirror backend constants)
// ---------------------------------------------------------------------------

export type AdvisorySourceKind =
  | 'ubuntu_usn'
  | 'debian_security'
  | 'redhat_updateinfo';

export type AdvisoryClass =
  | 'security'
  | 'bugfix'
  | 'enhancement'
  | 'other';

export type AdvisorySeverity =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'negligible'
  | 'unknown';

export type AdvisoryDistroFamily = 'debian' | 'rhel';

export type ApplicabilityState =
  | 'applicable'
  | 'fixed'
  | 'not_applicable'
  | 'unknown';

export const ADVISORY_SOURCE_KIND_VALUES: AdvisorySourceKind[] = [
  'ubuntu_usn',
  'debian_security',
  'redhat_updateinfo',
];
export const ADVISORY_CLASS_VALUES: AdvisoryClass[] = [
  'security',
  'bugfix',
  'enhancement',
  'other',
];
export const ADVISORY_SEVERITY_VALUES: AdvisorySeverity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'negligible',
  'unknown',
];
export const ADVISORY_DISTRO_FAMILY_VALUES: AdvisoryDistroFamily[] = [
  'debian',
  'rhel',
];
export const APPLICABILITY_STATE_VALUES: ApplicabilityState[] = [
  'applicable',
  'fixed',
  'not_applicable',
  'unknown',
];

// ---------------------------------------------------------------------------
// Read shapes (mirror backend Pydantic schemas)
// ---------------------------------------------------------------------------

export interface PatchAdvisory {
  id: number;
  source_kind: AdvisorySourceKind;
  source_advisory_id: string;
  advisory_class: AdvisoryClass;
  severity: AdvisorySeverity;
  title: string;
  summary: string | null;
  distro_family: AdvisoryDistroFamily;
  published_at: string | null;
  source_updated_at: string | null;
  cve_ids: string[] | null;
  external_refs: string[] | null;
  raw: Record<string, unknown> | null;
  digest: string;
  created_at: string;
  updated_at: string;
}

export interface PatchAdvisoryFixedPackage {
  id: number;
  advisory_id: number;
  distro_id: string;
  distro_release: string;
  package_name: string;
  fixed_version: string | null;
  created_at: string;
  updated_at: string;
}

export interface PatchAdvisoryDetail extends PatchAdvisory {
  fixed_packages: PatchAdvisoryFixedPackage[];
}

export interface HostAdvisoryRow {
  id: number;
  system_id: number;
  advisory_id: number;
  fixed_package_id: number | null;
  package_name: string;
  installed_version: string | null;
  required_version: string | null;
  state: ApplicabilityState;
  reason: string | null;
  evaluated_at: string;
  advisory: PatchAdvisory;
}

export interface HostAdvisoryCounts {
  system_id: number;
  counts: Record<ApplicabilityState, number>;
  /**
   * Slice 4-a: true iff the host has no usable
   * `HostFacts.distro_id_facts` / `HostFacts.distro_release` — same
   * predicate the Slice 2 resolver uses to short-circuit
   * applicability computation. Surfaced on the counts endpoint so
   * the per-host card can render the facts-missing callout on
   * initial load (before any operator-triggered recompute).
   */
  host_facts_missing: boolean;
}

export interface FleetAdvisoryCounts {
  severity: Record<AdvisorySeverity, number>;
  advisory_class: Record<AdvisoryClass, number>;
  total: number;
}

export interface ApplicabilityResultBody {
  system_id: number;
  counts: Record<ApplicabilityState, number>;
  rows_added: number;
  rows_updated: number;
  rows_removed: number;
  advisories_touched: number;
  host_facts_missing: boolean;
  changed: boolean;
}

export type AdvisoryImportStatus = 'success' | 'partial' | 'failed';
export type AdvisoryImportAction =
  | 'imported'
  | 'refreshed'
  | 'unchanged'
  | 'error';

export interface PatchAdvisoryImportRun {
  id: number;
  source_kind: AdvisorySourceKind;
  status: AdvisoryImportStatus;
  started_at: string;
  finished_at: string | null;
  imported_count: number;
  refreshed_count: number;
  unchanged_count: number;
  error_count: number;
  error_details: Array<{ source_advisory_id?: string; error?: string }> | null;
  created_by: number;
  created_at: string;
}

export interface AdvisoryImportOutcome {
  source_advisory_id: string;
  action: AdvisoryImportAction;
  advisory_id: number | null;
  error: string | null;
}

export interface AdvisoryImportResponse {
  run: PatchAdvisoryImportRun;
  outcomes: AdvisoryImportOutcome[];
}

// ---------------------------------------------------------------------------
// Error handling
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

export class PatchAdvisoryApiError extends Error {
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
  throw new PatchAdvisoryApiError(
    res.status,
    typeof msg === 'string' ? msg : `${label} (${res.status})`,
    detail,
  );
}

// ---------------------------------------------------------------------------
// Advisory list / detail / fleet counts
// ---------------------------------------------------------------------------

export interface ListAdvisoriesOpts {
  source_kind?: AdvisorySourceKind;
  advisory_class?: AdvisoryClass;
  severity?: AdvisorySeverity;
  distro_family?: AdvisoryDistroFamily;
  offset?: number;
  limit?: number;
}

export async function listPatchAdvisories(
  opts: ListAdvisoriesOpts = {},
): Promise<PatchAdvisory[]> {
  const params = new URLSearchParams();
  if (opts.source_kind) params.set('source_kind', opts.source_kind);
  if (opts.advisory_class) params.set('advisory_class', opts.advisory_class);
  if (opts.severity) params.set('severity', opts.severity);
  if (opts.distro_family) params.set('distro_family', opts.distro_family);
  if (opts.offset !== undefined) params.set('offset', String(opts.offset));
  if (opts.limit !== undefined) params.set('limit', String(opts.limit));
  const qs = params.toString();
  const res = await apiFetch(
    `/api/backend/patch/advisories${qs ? `?${qs}` : ''}`,
  );
  await _expect(res, 'list patch advisories failed');
  return res.json();
}

export async function getPatchAdvisory(
  id: number,
): Promise<PatchAdvisoryDetail> {
  const res = await apiFetch(`/api/backend/patch/advisories/${id}`);
  await _expect(res, `get patch advisory ${id} failed`);
  return res.json();
}

export async function getFleetAdvisoryCounts(): Promise<FleetAdvisoryCounts> {
  const res = await apiFetch('/api/backend/patch/advisories/counts');
  await _expect(res, 'fetch fleet advisory counts failed');
  return res.json();
}

// ---------------------------------------------------------------------------
// Per-host advisories
// ---------------------------------------------------------------------------

export async function listHostAdvisories(
  systemId: number,
  opts: { state?: ApplicabilityState; offset?: number; limit?: number } = {},
): Promise<HostAdvisoryRow[]> {
  const params = new URLSearchParams();
  if (opts.state) params.set('state', opts.state);
  if (opts.offset !== undefined) params.set('offset', String(opts.offset));
  if (opts.limit !== undefined) params.set('limit', String(opts.limit));
  const qs = params.toString();
  const res = await apiFetch(
    `/api/backend/systems/${systemId}/patch-advisories${qs ? `?${qs}` : ''}`,
  );
  await _expect(res, `list host ${systemId} advisories failed`);
  return res.json();
}

export async function getHostAdvisoryCounts(
  systemId: number,
): Promise<HostAdvisoryCounts> {
  const res = await apiFetch(
    `/api/backend/systems/${systemId}/patch-advisories/counts`,
  );
  await _expect(res, `fetch host ${systemId} advisory counts failed`);
  return res.json();
}

export async function recomputeHostAdvisories(
  systemId: number,
): Promise<ApplicabilityResultBody> {
  const res = await apiFetch(
    `/api/backend/systems/${systemId}/patch-advisories/recompute`,
    { method: 'POST' },
  );
  await _expect(res, `recompute host ${systemId} advisories failed`);
  return res.json();
}

// ---------------------------------------------------------------------------
// Operator import + import-run history
// ---------------------------------------------------------------------------

export async function listAdvisoryImportRuns(
  opts: { source_kind?: AdvisorySourceKind; limit?: number } = {},
): Promise<PatchAdvisoryImportRun[]> {
  const params = new URLSearchParams();
  if (opts.source_kind) params.set('source_kind', opts.source_kind);
  if (opts.limit !== undefined) params.set('limit', String(opts.limit));
  const qs = params.toString();
  const res = await apiFetch(
    `/api/backend/patch/advisories/imports${qs ? `?${qs}` : ''}`,
  );
  await _expect(res, 'list advisory import runs failed');
  return res.json();
}

/**
 * Import one or more raw native advisory payloads. `payloads` are the
 * raw source shapes (Ubuntu USN / Debian security / Red Hat updateinfo
 * JSON); the backend normalizes them before storage. Admin/maintainer
 * only — read-only users get a 403.
 */
export async function importAdvisories(
  sourceKind: AdvisorySourceKind,
  payloads: Record<string, unknown>[],
): Promise<AdvisoryImportResponse> {
  const res = await apiFetch('/api/backend/patch/advisories/imports', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ source_kind: sourceKind, payloads }),
  });
  await _expect(res, 'import advisories failed');
  return res.json();
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

export const SOURCE_KIND_LABELS: Record<AdvisorySourceKind, string> = {
  ubuntu_usn: 'Ubuntu USN',
  debian_security: 'Debian DSA',
  redhat_updateinfo: 'Red Hat updateinfo',
};

export const ADVISORY_CLASS_LABELS: Record<AdvisoryClass, string> = {
  security: 'Security',
  bugfix: 'Bugfix',
  enhancement: 'Enhancement',
  other: 'Other',
};

export const SEVERITY_LABELS: Record<AdvisorySeverity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  negligible: 'Negligible',
  unknown: 'Unknown',
};

export const DISTRO_FAMILY_LABELS: Record<AdvisoryDistroFamily, string> = {
  debian: 'Debian family',
  rhel: 'RHEL family',
};

export const APPLICABILITY_STATE_LABELS: Record<ApplicabilityState, string> = {
  applicable: 'Applicable',
  fixed: 'Fixed',
  not_applicable: 'Not applicable',
  unknown: 'Unknown',
};

// Tailwind accent classes per severity for the dashboard tile + per-row
// chips. Keep these in one place so list / detail / dashboard stay in
// visual lockstep.
export const SEVERITY_ACCENT: Record<AdvisorySeverity, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-500',
  negligible: 'bg-gray-500',
  unknown: 'bg-gray-600',
};

export const APPLICABILITY_STATE_ACCENT: Record<ApplicabilityState, string> = {
  applicable: 'bg-orange-500',
  fixed: 'bg-emerald-500',
  not_applicable: 'bg-gray-500',
  unknown: 'bg-yellow-500',
};
