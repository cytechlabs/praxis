import type { JobResultEntry } from '@/services/jobService';

/**
 * Presentation for a job run's per-system results.
 *
 * The API decodes the stored result payload before returning it, so both views
 * receive a `JobResultEntry[]` or `null` and neither parses JSON.
 */

/** Compact cell text for a run's results; a run with no results reads as a dash. */
export function summarizeJobResult(result: JobResultEntry[] | null): string {
  if (!result) return '-';
  return `${result.length} systems updated`;
}

/** Expanded detail text, or null when the run recorded no results. */
export function formatJobResultDetail(result: JobResultEntry[] | null): string | null {
  if (!result) return null;
  return JSON.stringify(result, null, 2);
}
