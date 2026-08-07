import { describe, it, expect } from 'vitest';
import { groupAttentionByHost, type DashboardAttention } from './fleetHealthService';

const row = (
  system_id: number,
  hostname: string,
  reason: string,
  detail = '',
): DashboardAttention => ({ system_id, hostname, reason, detail });

describe('groupAttentionByHost', () => {
  it('collapses multiple reasons for one host into a single row', () => {
    const grouped = groupAttentionByHost([
      row(1, 'web-01', 'unreachable', 'no heartbeat'),
      row(1, 'web-01', 'stale_facts', 'facts 3d old'),
      row(2, 'db-01', 'stale_facts', 'facts 2d old'),
    ]);

    expect(grouped).toHaveLength(2);
    expect(grouped[0]).toMatchObject({ system_id: 1, hostname: 'web-01' });
    expect(grouped[0].reasons.map((r) => r.reason)).toEqual(['unreachable', 'stale_facts']);
    expect(grouped[1]).toMatchObject({ system_id: 2, hostname: 'db-01' });
    expect(grouped[1].reasons).toHaveLength(1);
  });

  it('preserves first-seen host order', () => {
    const grouped = groupAttentionByHost([
      row(5, 'e', 'a'),
      row(3, 'c', 'a'),
      row(5, 'e', 'b'),
    ]);
    expect(grouped.map((g) => g.system_id)).toEqual([5, 3]);
  });

  it('de-duplicates exact reason/detail repeats for the same host', () => {
    const grouped = groupAttentionByHost([
      row(1, 'web-01', 'unreachable', 'no heartbeat'),
      row(1, 'web-01', 'unreachable', 'no heartbeat'),
    ]);
    expect(grouped).toHaveLength(1);
    expect(grouped[0].reasons).toHaveLength(1);
  });

  it('returns an empty array for no attention rows', () => {
    expect(groupAttentionByHost([])).toEqual([]);
  });
});
