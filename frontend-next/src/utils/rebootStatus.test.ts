import { describe, it, expect } from 'vitest';
import { notifyRebootStatus, rebootStatusNotice } from './rebootStatus';
import type { ApplyUpdatesResult, RebootEvidence } from '@/services/packageService';

const result = (evidence?: Partial<RebootEvidence>): ApplyUpdatesResult => ({
  system_id: 7,
  hostname: 'web-01.example.com',
  status: 'success',
  packages_updated: 3,
  reboot_required: evidence ? (evidence.value ?? null) : undefined,
  reboot_evidence: evidence
    ? {
        value: null,
        source: 'debian_reboot_required_marker',
        outcome: 'success',
        collected_at: '2026-08-25T12:00:00Z',
        ...evidence,
      }
    : undefined,
});

describe('rebootStatusNotice', () => {
  it('reports a reboot as required when the host said it needs one', () => {
    const notice = rebootStatusNotice(result({ value: true, outcome: 'success' }));
    expect(notice?.tone).toBe('required');
    expect(notice?.message).toContain('web-01.example.com');
    expect(notice?.message).toContain('needs a reboot');
  });

  it('reports no reboot needed only when the host actually said so', () => {
    const notice = rebootStatusNotice(result({ value: false, outcome: 'success' }));
    expect(notice?.tone).toBe('notRequired');
    expect(notice?.message).toContain('does not need a reboot');
  });

  it.each([
    ['unsupported', 'dnf-utils'],
    ['timeout', 'timed out'],
    ['transport_error', 'could not be reached'],
    ['malformed_output', 'could not be read'],
    ['probe_failed', 'failed to run'],
  ])('reports %s as unknown rather than as no reboot needed', (outcome, hint) => {
    const notice = rebootStatusNotice(result({ value: null, outcome }));
    expect(notice?.tone).toBe('unknown');
    expect(notice?.message).toContain('Could not determine');
    expect(notice?.message).toContain(hint);
  });

  it('never reads a null value from a successful-looking outcome as "no reboot"', () => {
    // A value of null can only mean the observation did not conclude.
    const notice = rebootStatusNotice(result({ value: null, outcome: 'success' }));
    expect(notice?.tone).toBe('unknown');
  });

  it('says nothing when no observation was taken', () => {
    // No package changed, so no probe ran. Reporting "unknown" here would
    // invent a problem out of a no-op.
    expect(rebootStatusNotice(result())).toBeNull();
  });

  it('falls back to the system id when the response carries no hostname', () => {
    const withoutHostname = { ...result({ value: true, outcome: 'success' }), hostname: '' };
    expect(rebootStatusNotice(withoutHostname)?.message).toContain('system #7');
  });

  it('describes an unrecognized outcome without claiming an answer', () => {
    const notice = rebootStatusNotice(result({ value: null, outcome: 'something_new' }));
    expect(notice?.tone).toBe('unknown');
    expect(notice?.message).toContain('did not return an answer');
  });
});

describe('notifyRebootStatus', () => {
  const spyToast = () => {
    const calls: Array<{ level: 'info' | 'warning'; message: string }> = [];
    return {
      calls,
      info: (message: string) => calls.push({ level: 'info', message }),
      warning: (message: string) => calls.push({ level: 'warning', message }),
    };
  };

  it('warns when the host needs a reboot', () => {
    const toast = spyToast();
    notifyRebootStatus(result({ value: true, outcome: 'success' }), toast);
    expect(toast.calls).toHaveLength(1);
    expect(toast.calls[0].level).toBe('warning');
  });

  it('warns, rather than informs, when the reboot state is unknown', () => {
    // An unknown state must not be presented as reassuringly as a "no".
    const toast = spyToast();
    notifyRebootStatus(result({ value: null, outcome: 'unsupported' }), toast);
    expect(toast.calls[0].level).toBe('warning');
    expect(toast.calls[0].message).toContain('Could not determine');
  });

  it('informs when the host does not need a reboot', () => {
    const toast = spyToast();
    notifyRebootStatus(result({ value: false, outcome: 'success' }), toast);
    expect(toast.calls[0].level).toBe('info');
  });

  it('shows nothing when no observation was taken', () => {
    const toast = spyToast();
    expect(notifyRebootStatus(result(), toast)).toBeNull();
    expect(toast.calls).toHaveLength(0);
  });
});
