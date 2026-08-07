import { describe, it, expect } from 'vitest';
import { statusToBadgeVariant } from './Badge';

describe('statusToBadgeVariant (PRA-271 one convention)', () => {
  it('maps healthy/positive states to success', () => {
    for (const s of ['active', 'connected', 'enrolled', 'compliant', 'passed', 'ok']) {
      expect(statusToBadgeVariant(s)).toBe('success');
    }
  });

  it('maps failure/critical states to danger', () => {
    for (const s of ['failed', 'unreachable', 'rollback_attempted_failed', 'critical', 'expired', 'offline']) {
      expect(statusToBadgeVariant(s)).toBe('danger');
    }
  });

  it('maps attention/transient-problem states to warning', () => {
    for (const s of ['pending', 'auth_failed', 'degraded', 'stale', 'rollback_attempted']) {
      expect(statusToBadgeVariant(s)).toBe('warning');
    }
  });

  it('maps in-flight states to info', () => {
    for (const s of ['running', 'in_progress', 'reconciling', 'syncing']) {
      expect(statusToBadgeVariant(s)).toBe('info');
    }
  });

  it('is case-insensitive and defaults unknown to neutral', () => {
    expect(statusToBadgeVariant('Unreachable')).toBe('danger'); // casing must not matter
    expect(statusToBadgeVariant('CONNECTED')).toBe('success');
    expect(statusToBadgeVariant('not_applicable')).toBe('neutral');
    expect(statusToBadgeVariant('some_unknown_state')).toBe('neutral');
  });
});
