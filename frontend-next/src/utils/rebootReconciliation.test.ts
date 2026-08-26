import { describe, it, expect } from 'vitest';
import { rebootReconciliationNotice } from './rebootReconciliation';
import type { RebootReconciliation } from '@/services/patchExecutionService';

const reconciliation = (
  over: Partial<RebootReconciliation> = {},
): RebootReconciliation => ({
  status: 'ok',
  action_required: false,
  succeeded_host_count: 4,
  reboot_row_count: 4,
  missing_row_count: 0,
  last_failure: null,
  ...over,
});

describe('rebootReconciliationNotice', () => {
  it('says nothing when the queue is a complete account of the run', () => {
    expect(rebootReconciliationNotice(reconciliation())).toBeNull();
  });

  it('says nothing when the reconciliation block is absent', () => {
    expect(rebootReconciliationNotice(null)).toBeNull();
    expect(rebootReconciliationNotice(undefined)).toBeNull();
  });

  it('warns that the counts are incomplete when hosts have no queue row', () => {
    const notice = rebootReconciliationNotice(
      reconciliation({
        status: 'incomplete',
        action_required: true,
        reboot_row_count: 2,
        missing_row_count: 2,
      }),
    );
    expect(notice).not.toBeNull();
    expect(notice?.body).toContain('2 hosts');
    expect(notice?.body).toContain('not a complete account');
    expect(notice?.body).toContain('Re-run the reboot reconcile');
  });

  it('singularizes a lone missing host', () => {
    const notice = rebootReconciliationNotice(
      reconciliation({ status: 'incomplete', action_required: true, missing_row_count: 1 }),
    );
    expect(notice?.body).toContain('1 host finished patching');
  });

  it('distinguishes a failed pass from an incomplete one and names the reason', () => {
    const notice = rebootReconciliationNotice(
      reconciliation({
        status: 'failed',
        action_required: true,
        last_failure: { phase: 'auto_reconcile', reason: 'connection pool exhausted' },
      }),
    );
    expect(notice?.body).toContain('reconcile pass failed');
    expect(notice?.body).toContain('connection pool exhausted');
    expect(notice?.body).toContain('Re-run the reboot reconcile');
    // The incomplete wording must not be reused for a failure.
    expect(notice?.body).not.toContain('finished patching without');
  });

  it('still warns on a failed pass that recorded no reason', () => {
    const notice = rebootReconciliationNotice(
      reconciliation({ status: 'failed', action_required: true, last_failure: null }),
    );
    expect(notice?.body).toContain('reconcile pass failed');
    expect(notice?.body).not.toContain('Last failure:');
  });

  it('stays silent when a status looks bad but no action is required', () => {
    // action_required is the contract the API states; the notice follows it
    // rather than second-guessing the status string.
    expect(
      rebootReconciliationNotice(reconciliation({ status: 'failed', action_required: false })),
    ).toBeNull();
  });
});
