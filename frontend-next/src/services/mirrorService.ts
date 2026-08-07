/**
 * PRA-157 #5 / PRA-312 Slice 2: mirror engine API client.
 *
 * Read surface: list / detail / runs / manifest / browse + the on-demand sync
 * trigger + signing-key management. PRA-312 Slice 2 adds the create / update /
 * delete write functions so mirrors are operator-managed from the UI instead of
 * API-only. All write ops are admin/maintainer-gated by the backend.
 */
import { apiFetch, formatApiError } from '../utils/api';

export type MirrorSyncStatus = 'idle' | 'running' | 'ok' | 'failed';
export type MirrorSourceMode = 'upstream_sync' | 'imported_offline';
export type MirrorPackageFamily = 'deb' | 'rpm';
export type MirrorRunStatus = 'running' | 'ok' | 'failed';

export type MirrorSigningStatus =
  | 'no_key_yet'
  | 'key_ready'
  | 'rotation_in_progress'
  | 'signed_ok'
  | 'signing_failed'
  | 'upstream_invalid';

export type MirrorSigningKeyStatus =
  | 'active'
  | 'pending_cutover'
  | 'rotating_out'
  | 'retired';

export interface MirrorRepo {
  id: number;
  slug: string;
  display_name: string;
  package_family: MirrorPackageFamily;
  upstream_url: string;
  distribution: string;
  components: string[];
  architectures: string[];
  sync_schedule_cron: string;
  enabled: boolean;
  source_mode: MirrorSourceMode;
  verify_upstream_signature: boolean;
  retention_keep_count: number;
  retention_keep_within_days: number;
  disk_budget_bytes: number | null;
  last_sync_started_at: string | null;
  last_sync_finished_at: string | null;
  last_sync_status: MirrorSyncStatus;
  last_sync_error: string | null;
  current_disk_bytes: number;
  deleted_at: string | null;
  created_at: string;
  updated_at: string;
  signing_status: MirrorSigningStatus;
}

export interface MirrorSigningKeyDetail {
  id: number;
  mirror_repo_id: number;
  status: MirrorSigningKeyStatus;
  gpg_fingerprint: string;
  key_uid: string;
  cutover_at: string | null;
  retired_at: string | null;
  created_at: string;
  public_key_armored: string;
}

export interface CutoverPreview {
  pending_fingerprint: string;
  hosts_missing_pending: number[];
  hosts_never_installed: number[];
  hosts_stale_trust_record: number[];
}

export interface CutoverBlocked {
  detail: string;
  preview: CutoverPreview;
}

export interface MirrorSigningKeyBootstrapResponse {
  created: boolean;
  mirror_signing_status: 'no_key_yet' | 'key_ready';
  key: MirrorSigningKeyDetail;
}

export interface TrustBundleEntry {
  id: number;
  fingerprint: string;
  uid: string;
  status: MirrorSigningKeyStatus;
  armored: string;
}

export interface TrustBundle {
  mirror_id: number;
  mirror_slug: string;
  active_fingerprint: string | null;
  keys: TrustBundleEntry[];
}

export interface MirrorSyncRun {
  id: number;
  mirror_repo_id: number;
  started_at: string;
  finished_at: string | null;
  status: MirrorRunStatus;
  byte_count: number | null;
  package_count: number | null;
  manifest_sha256: string | null;
  manifest_path: string | null;
  error_text: string | null;
  estimate_unavailable: boolean;
  created_at: string;
}

export interface MirrorBrowseEntry {
  name: string;
  type: 'file' | 'dir';
  size: number | null;
}

export interface MirrorBrowseResponse {
  path: string;
  parent: string | null;
  entries: MirrorBrowseEntry[];
}

export interface MirrorManifestFile {
  filename: string;
  sha256: string;
  size: number;
  package: string | null;
  version: string | null;
  arch: string | null;
}

export interface MirrorManifest {
  praxis_mirror_manifest: string;
  mirror_slug: string;
  run_id: number;
  package_family: string;
  generated_at: string;
  byte_count: number;
  package_count: number;
  files: MirrorManifestFile[];
}

export interface MirrorSyncQueuedResponse {
  mirror_repo_id: number;
  queued: boolean;
  message: string;
}

const BASE = '/api/backend/mirrors';

async function unwrap<T>(res: Response, fallback: string): Promise<T> {
  if (res.ok) return res.json() as Promise<T>;
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    /* swallow */
  }
  throw new Error(formatApiError(body, fallback));
}

export async function listMirrors(): Promise<MirrorRepo[]> {
  const res = await apiFetch(BASE);
  return unwrap<MirrorRepo[]>(res, 'Failed to load mirrors');
}

export async function getMirror(id: number): Promise<MirrorRepo> {
  const res = await apiFetch(`${BASE}/${id}`);
  return unwrap<MirrorRepo>(res, 'Failed to load mirror');
}

export async function listMirrorRuns(
  id: number,
  opts: { limit?: number; offset?: number } = {}
): Promise<MirrorSyncRun[]> {
  const params = new URLSearchParams();
  if (opts.limit !== undefined) params.set('limit', String(opts.limit));
  if (opts.offset !== undefined) params.set('offset', String(opts.offset));
  const qs = params.toString();
  const res = await apiFetch(`${BASE}/${id}/runs${qs ? `?${qs}` : ''}`);
  return unwrap<MirrorSyncRun[]>(res, 'Failed to load run history');
}

export async function getMirrorRun(
  mirrorId: number,
  runId: number
): Promise<MirrorSyncRun> {
  const res = await apiFetch(`${BASE}/${mirrorId}/runs/${runId}`);
  return unwrap<MirrorSyncRun>(res, 'Failed to load run');
}

export async function getMirrorRunManifest(
  mirrorId: number,
  runId: number
): Promise<MirrorManifest> {
  const res = await apiFetch(`${BASE}/${mirrorId}/runs/${runId}/manifest`);
  return unwrap<MirrorManifest>(res, 'Failed to load manifest');
}

export async function browseMirror(
  id: number,
  path: string = ''
): Promise<MirrorBrowseResponse> {
  const params = new URLSearchParams();
  if (path) params.set('path', path);
  const qs = params.toString();
  const res = await apiFetch(`${BASE}/${id}/browse${qs ? `?${qs}` : ''}`);
  return unwrap<MirrorBrowseResponse>(res, 'Failed to browse mirror');
}

export async function triggerMirrorSync(id: number): Promise<MirrorSyncQueuedResponse> {
  const res = await apiFetch(`${BASE}/${id}/sync`, { method: 'POST' });
  return unwrap<MirrorSyncQueuedResponse>(res, 'Failed to queue sync');
}

// PRA-312 Slice 2: mirror write surface. Fields mirror the backend
// MirrorRepoCreate / MirrorRepoUpdate schemas (slug is immutable, so it is not
// part of the update input).
export interface MirrorRepoCreateInput {
  slug: string;
  display_name: string;
  package_family: MirrorPackageFamily;
  upstream_url: string;
  distribution: string;
  components?: string[];
  architectures: string[];
  sync_schedule_cron: string;
  enabled?: boolean;
  source_mode?: MirrorSourceMode;
  verify_upstream_signature?: boolean;
  retention_keep_count?: number;
  retention_keep_within_days?: number;
  disk_budget_bytes?: number | null;
}

export type MirrorRepoUpdateInput = Partial<Omit<MirrorRepoCreateInput, 'slug'>>;

export async function createMirror(
  input: MirrorRepoCreateInput
): Promise<MirrorRepo> {
  const res = await apiFetch(BASE, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
  return unwrap<MirrorRepo>(res, 'Failed to create mirror');
}

export async function updateMirror(
  id: number,
  updates: MirrorRepoUpdateInput
): Promise<MirrorRepo> {
  const res = await apiFetch(`${BASE}/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(updates),
  });
  return unwrap<MirrorRepo>(res, 'Failed to update mirror');
}

export async function deleteMirror(id: number): Promise<void> {
  const res = await apiFetch(`${BASE}/${id}`, { method: 'DELETE' });
  if (res.status === 204 || res.ok) return;
  await unwrap<void>(res, 'Failed to delete mirror');
}

/**
 * Map mirror sync status to the variant our shared Badge component
 * supports. Centralized so detail page and list page stay
 * consistent.
 */
export function syncStatusVariant(
  status: MirrorSyncStatus | MirrorRunStatus
): 'neutral' | 'info' | 'success' | 'danger' {
  switch (status) {
    case 'ok':
      return 'success';
    case 'running':
      return 'info';
    case 'failed':
      return 'danger';
    case 'idle':
    default:
      return 'neutral';
  }
}

/**
 * PRA-158 #5c: map signing_status to a Badge variant for the trust
 * column on the mirror list and the panel header on the detail page.
 */
export function signingStatusVariant(
  status: MirrorSigningStatus
): 'neutral' | 'info' | 'success' | 'warning' | 'danger' {
  switch (status) {
    case 'signed_ok':
      return 'success';
    case 'rotation_in_progress':
      return 'info';
    case 'key_ready':
      return 'neutral';
    case 'signing_failed':
    case 'upstream_invalid':
      return 'danger';
    case 'no_key_yet':
    default:
      return 'warning';
  }
}

export function signingStatusLabel(status: MirrorSigningStatus): string {
  switch (status) {
    case 'signed_ok':
      return 'Signed';
    case 'rotation_in_progress':
      return 'Rotation in progress';
    case 'key_ready':
      return 'Key ready';
    case 'signing_failed':
      return 'Signing failed';
    case 'upstream_invalid':
      return 'Upstream invalid';
    case 'no_key_yet':
    default:
      return 'No signing key';
  }
}

// ---------------------------------------------------------------------------
// PRA-158 signing-key + rotation API
// ---------------------------------------------------------------------------

export async function getActiveSigningKey(
  mirrorId: number
): Promise<MirrorSigningKeyDetail | null> {
  const res = await apiFetch(`${BASE}/${mirrorId}/signing-key`);
  if (res.status === 404) return null;
  return unwrap<MirrorSigningKeyDetail>(res, 'Failed to load signing key');
}

export async function bootstrapSigningKey(
  mirrorId: number
): Promise<MirrorSigningKeyBootstrapResponse> {
  const res = await apiFetch(`${BASE}/${mirrorId}/signing-key`, {
    method: 'POST',
  });
  return unwrap<MirrorSigningKeyBootstrapResponse>(
    res,
    'Failed to bootstrap signing key'
  );
}

export async function getTrustBundle(mirrorId: number): Promise<TrustBundle> {
  const res = await apiFetch(`${BASE}/${mirrorId}/trust-bundle`);
  return unwrap<TrustBundle>(res, 'Failed to load trust bundle');
}

export async function rotatePrepare(
  mirrorId: number
): Promise<MirrorSigningKeyDetail> {
  const res = await apiFetch(`${BASE}/${mirrorId}/signing-key/rotate-prepare`, {
    method: 'POST',
  });
  return unwrap<MirrorSigningKeyDetail>(res, 'Failed to prepare rotation');
}

export async function getCutoverPreview(
  mirrorId: number
): Promise<CutoverPreview> {
  const res = await apiFetch(`${BASE}/${mirrorId}/signing-key/cutover-preview`);
  return unwrap<CutoverPreview>(res, 'Failed to load cutover preview');
}

/**
 * Cutover with explicit force flag. Returns the new active key on
 * success, or throws ``CutoverBlockedError`` carrying the structured
 * preview so the UI can show which hosts are blocking. Other 409s
 * (e.g. no pending key) surface as a plain Error.
 */
export class CutoverBlockedError extends Error {
  preview: CutoverPreview;

  constructor(message: string, preview: CutoverPreview) {
    super(message);
    this.name = 'CutoverBlockedError';
    this.preview = preview;
  }
}

export async function cutover(
  mirrorId: number,
  opts: { force?: boolean } = {}
): Promise<MirrorSigningKeyDetail> {
  const res = await apiFetch(`${BASE}/${mirrorId}/signing-key/cutover`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ force: !!opts.force }),
  });
  if (res.ok) {
    return res.json() as Promise<MirrorSigningKeyDetail>;
  }
  if (res.status === 409) {
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      /* swallow */
    }
    // Flat shape (PRA-158 #5-b): {detail, preview} at the top level.
    if (
      body &&
      typeof body === 'object' &&
      'preview' in (body as Record<string, unknown>)
    ) {
      const blocked = body as CutoverBlocked;
      throw new CutoverBlockedError(blocked.detail, blocked.preview);
    }
    throw new Error(formatApiError(body, 'Cutover refused'));
  }
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    /* swallow */
  }
  throw new Error(formatApiError(body, 'Failed to cut over'));
}

export async function retireKey(
  mirrorId: number,
  keyId: number
): Promise<MirrorSigningKeyDetail> {
  const res = await apiFetch(
    `${BASE}/${mirrorId}/signing-key/retire/${keyId}`,
    { method: 'POST' }
  );
  return unwrap<MirrorSigningKeyDetail>(res, 'Failed to retire key');
}
