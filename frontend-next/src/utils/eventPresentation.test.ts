import { describe, it, expect } from 'vitest';

import {
  eventVariant,
  eventTextClass,
  eventDotClass,
  eventCardClass,
  eventLabel,
  type EventLike,
} from './eventPresentation';

describe('eventVariant — acceptance cases', () => {
  it('package scan completion is NOT danger (calm success, never red)', () => {
    const v = eventVariant({ type: 'package_scan_complete', severity: 'info' });
    expect(v).not.toBe('danger');
    expect(v).toBe('success');
  });

  it('package scan failure is danger', () => {
    expect(eventVariant({ type: 'package_scan_failure', severity: 'error' })).toBe('danger');
  });

  it('host unreachable is danger (operator attention)', () => {
    expect(eventVariant({ type: 'system_unreachable', severity: 'error' })).toBe('danger');
  });

  it('host recovered is success/neutral, never danger', () => {
    const v = eventVariant({ type: 'system_recovered', severity: 'info' });
    expect(v).toBe('success');
    expect(v).not.toBe('danger');
  });
});

describe('eventVariant — job events', () => {
  it('job_completed -> success', () => {
    expect(eventVariant({ type: 'job_completed', severity: 'info' })).toBe('success');
  });
  it('job_failed -> danger', () => {
    expect(eventVariant({ type: 'job_failed', severity: 'error' })).toBe('danger');
  });
  it('job_cancelled -> warning', () => {
    expect(eventVariant({ type: 'job_cancelled', severity: 'warning' })).toBe('warning');
  });
});

describe('eventVariant — priority order (type > severity > source)', () => {
  it('type wins over a mismatched severity', () => {
    // A success type must stay success even if severity is mislabeled error.
    expect(eventVariant({ type: 'package_scan_complete', severity: 'error' })).toBe('success');
  });

  it('falls back to severity when the type is unknown', () => {
    expect(eventVariant({ type: 'some_new_event', severity: 'error' })).toBe('danger');
    expect(eventVariant({ type: 'some_new_event', severity: 'warning' })).toBe('warning');
    expect(eventVariant({ type: 'some_new_event', severity: 'info' })).toBe('info');
  });

  it('source alone never implies danger/red — unknown reads neutral', () => {
    expect(eventVariant({ source: 'notification' })).toBe('neutral');
    expect(eventVariant({ source: 'notification' })).not.toBe('danger');
    expect(eventVariant({})).toBe('neutral');
  });
});

describe('eventVariant — keyword heuristics for unenumerated types', () => {
  it('a *_failed / unreachable type still reads danger', () => {
    expect(eventVariant({ type: 'mirror_sync_failed' })).toBe('danger');
    expect(eventVariant({ type: 'host_unreachable_again' })).toBe('danger');
  });
  it('a *_recovered / completed type still reads success', () => {
    expect(eventVariant({ type: 'mirror_sync_completed' })).toBe('success');
    expect(eventVariant({ type: 'link_restored' })).toBe('success');
  });
  it('"update" does not falsely match the "up" success keyword', () => {
    // event_type "update" (package op) has no severity -> neutral, not success.
    expect(eventVariant({ type: 'update' })).toBe('neutral');
  });
});

describe('equivalent events map identically across surfaces', () => {
  // Every surface calls the same helper; a notification-shaped input and an
  // activity-feed-shaped input for the same event must yield the same variant.
  const cases: Array<[string, EventLike, EventLike]> = [
    [
      'package scan complete',
      { type: 'package_scan_complete', severity: 'info' }, // TopBar / Alerts notification
      { type: 'package_scan_complete', severity: 'info', source: 'notification' }, // feed item
    ],
    [
      'system unreachable',
      { type: 'system_unreachable', severity: 'error' },
      { type: 'system_unreachable', severity: 'error', source: 'notification' },
    ],
    [
      'system recovered',
      { type: 'system_recovered', severity: 'info' },
      { type: 'system_recovered', severity: 'info', source: 'notification' },
    ],
  ];
  for (const [name, a, b] of cases) {
    it(`${name} is consistent`, () => {
      expect(eventVariant(a)).toBe(eventVariant(b));
    });
  }
});

describe('presentation class helpers', () => {
  it('danger uses Signal-Red tokens; success/neutral do not', () => {
    expect(eventTextClass('danger')).toBe('text-danger');
    expect(eventDotClass('danger')).toBe('bg-danger');
    expect(eventCardClass('danger')).toContain('danger');

    expect(eventTextClass('success')).toBe('text-success');
    expect(eventTextClass('success')).not.toContain('danger');
    expect(eventCardClass('neutral')).not.toContain('danger');
    expect(eventDotClass('neutral')).toBe('bg-content-muted');
  });

  it('label reserves "Alert" for danger only', () => {
    expect(eventLabel('danger')).toBe('Alert');
    expect(eventLabel('success')).not.toBe('Alert');
    expect(eventLabel('info')).not.toBe('Alert');
    expect(eventLabel('neutral')).not.toBe('Alert');
  });
});
