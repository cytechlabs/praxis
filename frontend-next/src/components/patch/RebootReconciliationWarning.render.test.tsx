// @vitest-environment jsdom
//
// The reboot queue answers "what still has to reboot". When a reconcile pass
// failed or left hosts uncovered, its counts are not that answer, and the
// surface that shows them has to say so.
import { describe, it, expect, afterEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/react';

import RebootReconciliationWarning from './RebootReconciliationWarning';
import type { RebootReconciliation } from '@/services/patchExecutionService';

afterEach(cleanup);

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

describe('RebootReconciliationWarning', () => {
  it('renders nothing when the queue is complete', () => {
    const { container } = render(
      <RebootReconciliationWarning reconciliation={reconciliation()} />,
    );
    expect(container.innerHTML).toBe('');
  });

  it('renders nothing when no reconciliation block was returned', () => {
    const { container } = render(<RebootReconciliationWarning reconciliation={null} />);
    expect(container.innerHTML).toBe('');
  });

  it('warns that counts are incomplete when hosts have no queue row', () => {
    render(
      <RebootReconciliationWarning
        reconciliation={reconciliation({
          status: 'incomplete',
          action_required: true,
          reboot_row_count: 2,
          missing_row_count: 2,
        })}
      />,
    );
    const text = screen.getByTestId('reboot-reconciliation-warning').textContent ?? '';
    expect(text).toContain('Reboot queue incomplete');
    expect(text).toContain('2 hosts finished patching');
    expect(text).toContain('not a complete account');
    expect(text).toContain('Re-run the reboot reconcile');
  });

  it('distinguishes a failed pass and names the recorded reason', () => {
    render(
      <RebootReconciliationWarning
        reconciliation={reconciliation({
          status: 'failed',
          action_required: true,
          last_failure: { phase: 'auto_reconcile', reason: 'connection pool exhausted' },
        })}
      />,
    );
    const text = screen.getByTestId('reboot-reconciliation-warning').textContent ?? '';
    expect(text).toContain('reconcile pass failed');
    expect(text).toContain('connection pool exhausted');
    expect(text).not.toContain('finished patching without');
  });
});
