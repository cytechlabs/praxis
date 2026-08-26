import React from 'react';
import type { RebootReconciliation } from '@/services/patchExecutionService';
import { rebootReconciliationNotice } from '@/utils/rebootReconciliation';

/**
 * Warns that an execution's reboot queue is not a complete account of the
 * run, so the queue counts shown beside it cannot be read as "nothing left
 * to reboot". Renders nothing when the queue is complete.
 */
const RebootReconciliationWarning: React.FC<{
  reconciliation: RebootReconciliation | null | undefined;
}> = ({ reconciliation }) => {
  const notice = rebootReconciliationNotice(reconciliation);
  if (!notice) return null;
  return (
    <div
      className="rounded-md border border-amber-300 bg-amber-50 p-3 text-xs text-amber-900"
      data-testid="reboot-reconciliation-warning"
      role="status"
    >
      <div className="font-semibold">{notice.title}</div>
      <p className="mt-1">{notice.body}</p>
    </div>
  );
};

export default RebootReconciliationWarning;
