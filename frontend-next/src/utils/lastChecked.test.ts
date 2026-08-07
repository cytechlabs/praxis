import { describe, it, expect } from 'vitest';

import { deriveLastChecked, type AuditedSystem } from './lastChecked';

const SYSTEMS: AuditedSystem[] = [
  { id: 1, last_audited: '2026-08-04T21:24:56' },
  { id: 2, last_audited: null },
  { id: 3, last_audited: '2026-08-05T10:00:00' },
];

describe('deriveLastChecked', () => {
  it('rehydrates a specific system from its backend last_audited', () => {
    // The bug: navigation reset this to Never; now it comes from loaded systems.
    expect(deriveLastChecked(SYSTEMS, 1)).toBe('2026-08-04T21:24:56');
  });

  it('returns null (Never) for a system that was never scanned', () => {
    expect(deriveLastChecked(SYSTEMS, 2)).toBeNull();
  });

  it('returns null (Never) for an unknown system id', () => {
    expect(deriveLastChecked(SYSTEMS, 999)).toBeNull();
  });

  it('for All Systems shows the most recent scan across loaded hosts', () => {
    expect(deriveLastChecked(SYSTEMS, 'all')).toBe('2026-08-05T10:00:00');
  });

  it('for All Systems returns null only when nothing has been scanned', () => {
    expect(deriveLastChecked([{ id: 1 }, { id: 2, last_audited: null }], 'all')).toBeNull();
  });

  it('reflects a post-scan update when the system last_audited is refreshed', () => {
    // Simulates handleScan updating the matching system in memory.
    const scanned = SYSTEMS.map((s) =>
      s.id === 2 ? { ...s, last_audited: '2026-08-06T08:30:00' } : s,
    );
    expect(deriveLastChecked(scanned, 2)).toBe('2026-08-06T08:30:00');
    // and it becomes the latest for All Systems
    expect(deriveLastChecked(scanned, 'all')).toBe('2026-08-06T08:30:00');
  });

  it('does not mutate the input array', () => {
    const input = [...SYSTEMS];
    deriveLastChecked(input, 'all');
    expect(input).toEqual(SYSTEMS);
  });
});
