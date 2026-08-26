import { describe, it, expect } from 'vitest';
import {
  describeSecurityPosture,
  groupAttentionByHost,
  securityPostureHeadline,
  type DashboardAttention,
  type SecurityPosture,
  type SecurityPostureState,
} from './fleetHealthService';

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

const posture = (
  state: SecurityPostureState,
  overrides: Partial<SecurityPosture> = {},
): SecurityPosture => ({
  state,
  coverage_complete: state === 'complete',
  counts_trustworthy: state === 'complete',
  systems_total: 4,
  systems_scanned: state === 'complete' ? 4 : 1,
  systems_partial: 0,
  systems_failed: 0,
  systems_scanning: 0,
  systems_never_scanned: state === 'complete' ? 0 : 3,
  last_successful_scan_at: null,
  last_scan_at: null,
  last_failure_detail: null,
  coverage_detail: 'detail',
  systems_with_security_updates: 0,
  pending_security_updates: 0,
  ...overrides,
});

describe('describeSecurityPosture', () => {
  it('renders a trustworthy zero only after a completed scan', () => {
    expect(describeSecurityPosture(posture('complete'))).toEqual({
      value: '0',
      tone: 'healthy',
      showsCount: true,
    });
  });

  it('renders the count when a completed scan found updates', () => {
    const display = describeSecurityPosture(
      posture('complete', { systems_with_security_updates: 3 }),
    );
    expect(display).toEqual({ value: '3', tone: 'critical', showsCount: true });
  });

  it('never renders an unscanned fleet as a number', () => {
    const display = describeSecurityPosture(posture('not_scanned'));
    expect(display.showsCount).toBe(false);
    expect(display.value).toBe('Not scanned');
    expect(display.tone).not.toBe('healthy');
  });

  it('never renders a failed scan as a number', () => {
    const display = describeSecurityPosture(
      posture('failed', { systems_failed: 4, systems_never_scanned: 0 }),
    );
    expect(display.showsCount).toBe(false);
    expect(display.value).toBe('Scan failed');
    expect(display.tone).toBe('warning');
  });

  it('reports an in-flight scan without a count', () => {
    const display = describeSecurityPosture(posture('scanning', { systems_scanning: 2 }));
    expect(display).toEqual({ value: 'Scanning', tone: 'unknown', showsCount: false });
  });

  it('marks a partially covered count as a floor', () => {
    expect(
      describeSecurityPosture(posture('partial', { systems_with_security_updates: 2 })),
    ).toEqual({ value: '2+', tone: 'critical', showsCount: true });
  });

  it('does not show a zero for partial coverage with no findings yet', () => {
    const display = describeSecurityPosture(posture('partial'));
    expect(display.showsCount).toBe(false);
    expect(display.value).toBe('Partial scan');
  });

  it('falls back to unknown when the payload carries no posture', () => {
    expect(describeSecurityPosture()).toEqual({
      value: 'Unknown',
      tone: 'unknown',
      showsCount: false,
    });
  });
});

describe('securityPostureHeadline', () => {
  it('names each state without implying a clean fleet', () => {
    expect(securityPostureHeadline(posture('not_scanned'))).toContain('unknown');
    expect(securityPostureHeadline(posture('scanning'))).toContain('in progress');
    expect(securityPostureHeadline(posture('failed'))).toContain('failed');
    expect(securityPostureHeadline(posture('partial'))).toBe(
      'Security scan covers 1 of 4 systems',
    );
    expect(securityPostureHeadline(posture('complete'))).toBe('Security scan complete');
  });
});
