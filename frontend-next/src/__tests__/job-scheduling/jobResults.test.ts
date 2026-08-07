import { describe, it, expect } from 'vitest';
import { summarizeJobResult, formatJobResultDetail } from '@/utils/jobResults';
import type { JobResultEntry } from '@/services/jobService';

// The API decodes the stored result payload, so the only shapes these helpers
// ever see are a per-system entry array and null.
const decoded: JobResultEntry[] = [
  {
    system_id: 4,
    hostname: 'web-01.test',
    result: {
      status: 'success',
      packages_updated: 12,
      packages_skipped: 0,
      applied_at: '2026-08-01T10:00:00',
    },
  },
  {
    system_id: 9,
    hostname: 'db-01.test',
    result: { status: 'error', message: 'Security update failed: locked dpkg' },
  },
];

describe('summarizeJobResult', () => {
  it('counts the per-system entries in a decoded result array', () => {
    expect(summarizeJobResult(decoded)).toBe('2 systems updated');
  });

  it('renders a dash for a run with no recorded result', () => {
    expect(summarizeJobResult(null)).toBe('-');
  });

  it('reports zero for a run that recorded an empty entry list', () => {
    expect(summarizeJobResult([])).toBe('0 systems updated');
  });
});

describe('formatJobResultDetail', () => {
  it('pretty-prints the decoded entries, preserving per-system detail', () => {
    const detail = formatJobResultDetail(decoded);
    expect(detail).not.toBeNull();
    expect(JSON.parse(detail as string)).toEqual(decoded);
    // Indented, so the expanded detail block stays readable.
    expect(detail).toContain('\n  {');
    expect(detail).toContain('"hostname": "db-01.test"');
    expect(detail).toContain('locked dpkg');
  });

  it('returns null for a run with no recorded result', () => {
    expect(formatJobResultDetail(null)).toBeNull();
  });
});
