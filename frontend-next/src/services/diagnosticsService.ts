import { apiFetch } from '../utils/api';

export type SupportBundleRange = '24h' | '72h' | '7d';

export interface SupportBundleResult {
  bytes: number;
  generatedAt: string;
}

/**
 * Generate and download the admin-only diagnostic support bundle. POSTs to the
 * backend (which builds a redacted, bounded, compressed zip on the fly — nothing is
 * stored server-side) and triggers a browser download via an anchor + Blob URL.
 * Returns the downloaded size + timestamp for the "last generated" display.
 */
export async function downloadSupportBundle(
  range: SupportBundleRange,
): Promise<SupportBundleResult> {
  const res = await apiFetch(
    `/api/backend/diagnostics/bundle?time_range=${range}`,
    { method: 'POST' },
  );
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body?.detail || 'Failed to generate support bundle');
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `praxis-support-bundle-${range}.zip`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  return { bytes: blob.size, generatedAt: new Date().toISOString() };
}
