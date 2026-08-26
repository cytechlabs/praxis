import type { RebootReconciliation } from '@/services/patchExecutionService';

export interface RebootReconciliationNotice {
  /** Short heading for the warning. */
  title: string;
  /** What is wrong with the queue, and what the operator should do. */
  body: string;
}

/**
 * Describe an incomplete or failed reboot queue, or return null when the
 * queue is a complete account of the run.
 *
 * The reboot queue answers "what still has to reboot". When a reconcile
 * pass failed or left hosts uncovered, its counts are not that answer, and
 * an operator reading them as "nothing outstanding" would be wrong. This
 * notice exists to say so on the surface that shows those counts.
 */
export function rebootReconciliationNotice(
  reconciliation?: RebootReconciliation | null,
): RebootReconciliationNotice | null {
  if (!reconciliation || !reconciliation.action_required) return null;

  const reconcileAction =
    'Re-run the reboot reconcile for this execution to rebuild it.';

  if (reconciliation.status === 'failed') {
    const reason = reconciliation.last_failure?.reason;
    const because = reason ? ` Last failure: ${reason}` : '';
    return {
      title: 'Reboot queue incomplete',
      body:
        'A reboot reconcile pass failed, so the counts below are not a complete ' +
        `account of which hosts still need a reboot.${because} ${reconcileAction}`,
    };
  }

  const missing = reconciliation.missing_row_count;
  const hosts = missing === 1 ? 'host' : 'hosts';
  return {
    title: 'Reboot queue incomplete',
    body:
      `${missing} ${hosts} finished patching without a reboot queue row, so the ` +
      'counts below are not a complete account of which hosts still need a ' +
      `reboot. ${reconcileAction}`,
  };
}
