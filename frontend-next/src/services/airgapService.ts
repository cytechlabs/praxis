/**
 * PRA-196: airgap bundle signing-key rotation API client.
 *
 * Two surfaces:
 *   - Bundle signing keys (export/connected side): bootstrap, rotate,
 *     retire. Rotation mints a NEW active key; the old one moves to
 *     ``rotating_out`` and stays valid for verifying already-exported
 *     bundles until it is retired.
 *   - Import trust pins (airgapped/import side): the set of public keys
 *     the import-side instance trusts when verifying incoming bundles.
 *
 * The backend gates the mutating operations (bootstrap / rotate /
 * retire / add-pin / remove-pin) behind the admin role.
 */
import { apiFetch, formatApiError } from '../utils/api';

export type BundleSigningKeyStatus = 'active' | 'rotating_out' | 'retired';

export interface BundleSigningKey {
  id: number;
  fingerprint: string;
  key_uid: string;
  status: BundleSigningKeyStatus;
  armored_public_key: string | null;
  created_at: string;
  updated_at: string;
}

export interface BundleSigningKeyBootstrap {
  fingerprint: string;
  key_uid: string;
  status: string;
  created: boolean;
}

export interface ImportTrustKey {
  id: number;
  gpg_fingerprint: string;
  key_uid: string;
  added_at: string;
  deleted_at: string | null;
}

const BASE = '/api/backend/airgap';

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

// ---------------------------------------------------------------------------
// Bundle signing keys (export / connected side)
// ---------------------------------------------------------------------------

export async function listSigningKeys(): Promise<BundleSigningKey[]> {
  const res = await apiFetch(`${BASE}/signing-keys`);
  return unwrap<BundleSigningKey[]>(res, 'Failed to load signing keys');
}

export async function bootstrapSigningKey(): Promise<BundleSigningKeyBootstrap> {
  const res = await apiFetch(`${BASE}/signing-key`, { method: 'POST' });
  return unwrap<BundleSigningKeyBootstrap>(res, 'Failed to bootstrap signing key');
}

export async function rotateSigningKey(): Promise<{
  old: BundleSigningKey;
  new: BundleSigningKey;
}> {
  const res = await apiFetch(`${BASE}/signing-keys/rotate`, { method: 'POST' });
  return unwrap<{ old: BundleSigningKey; new: BundleSigningKey }>(
    res,
    'Failed to rotate signing key'
  );
}

export async function retireSigningKey(id: number): Promise<BundleSigningKey> {
  const res = await apiFetch(`${BASE}/signing-keys/${id}/retire`, {
    method: 'POST',
  });
  return unwrap<BundleSigningKey>(res, 'Failed to retire signing key');
}

// ---------------------------------------------------------------------------
// Import trust pins (airgapped / import side)
// ---------------------------------------------------------------------------

export async function listImportTrustKeys(
  includeDeleted = false
): Promise<ImportTrustKey[]> {
  const res = await apiFetch(
    `${BASE}/import-trust?include_deleted=${includeDeleted}`
  );
  return unwrap<ImportTrustKey[]>(res, 'Failed to load import trust pins');
}

export async function addImportTrustKey(
  armored_public_key: string
): Promise<ImportTrustKey> {
  const res = await apiFetch(`${BASE}/import-trust`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ armored_public_key }),
  });
  return unwrap<ImportTrustKey>(res, 'Failed to add import trust pin');
}

export async function removeImportTrustKey(id: number): Promise<ImportTrustKey> {
  const res = await apiFetch(`${BASE}/import-trust/${id}`, { method: 'DELETE' });
  return unwrap<ImportTrustKey>(res, 'Failed to remove import trust pin');
}

/**
 * Map a bundle signing-key status to the shared Badge component variant.
 */
export function signingKeyStatusVariant(
  status: BundleSigningKeyStatus
): 'success' | 'warning' | 'neutral' {
  switch (status) {
    case 'active':
      return 'success';
    case 'rotating_out':
      return 'warning';
    case 'retired':
    default:
      return 'neutral';
  }
}

export function signingKeyStatusLabel(status: BundleSigningKeyStatus): string {
  switch (status) {
    case 'active':
      return 'Active';
    case 'rotating_out':
      return 'Rotating out';
    case 'retired':
    default:
      return 'Retired';
  }
}
