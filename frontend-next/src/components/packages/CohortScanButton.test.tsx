// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react';
import CohortScanButton from './CohortScanButton';
import { scanScope } from '@/services/packageService';

vi.mock('@/services/packageService', () => ({ scanScope: vi.fn() }));
vi.mock('sonner', () => ({
  toast: { success: vi.fn(), warning: vi.fn(), error: vi.fn() },
}));

const mockScan = scanScope as unknown as ReturnType<typeof vi.fn>;

const groupScope = { type: 'group' as const, id: 5 };

function resultFixture(over = {}) {
  return {
    scope_type: 'group',
    scope_id: 5,
    security: false,
    total: 2,
    success_count: 1,
    failure_count: 1,
    skipped_count: 0,
    results: [
      { system_id: 1, hostname: 'web-01', status: 'success' },
      { system_id: 2, hostname: 'db-01', status: 'error', message: 'ssh failed' },
    ],
    fleet_operation_id: 99,
    ...over,
  };
}

beforeEach(() => mockScan.mockReset());
afterEach(cleanup);

describe('CohortScanButton', () => {
  it('confirms with the scope name, host count, and no-apply guarantee', () => {
    render(
      <CohortScanButton scope={groupScope} scopeName="Prod" hostCount={2} label="Refresh inventory" />,
    );
    fireEvent.click(screen.getByRole('button', { name: /Refresh inventory/ }));
    // Confirmation names the cohort, count, and that no updates are applied.
    expect(screen.getByText(/2 hosts in group "Prod"/)).toBeTruthy();
    expect(screen.getByText(/no\s+updates are applied/i)).toBeTruthy();
  });

  it('runs the cohort scan and shows per-host results', async () => {
    mockScan.mockResolvedValue(resultFixture());
    const onComplete = vi.fn();
    render(
      <CohortScanButton
        scope={groupScope}
        scopeName="Prod"
        hostCount={2}
        label="Refresh inventory"
        onComplete={onComplete}
      />,
    );
    fireEvent.click(screen.getByRole('button', { name: /Refresh inventory/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));

    await waitFor(() => expect(mockScan).toHaveBeenCalledWith(groupScope, { security: false }));
    // Per-host results are surfaced (host + status).
    await waitFor(() => expect(screen.getByText('web-01')).toBeTruthy());
    expect(screen.getByText('db-01')).toBeTruthy();
    expect(screen.getByText('ssh failed')).toBeTruthy();
    expect(screen.getByText('Refreshed')).toBeTruthy();
    expect(screen.getByText('Failed')).toBeTruthy();
    expect(onComplete).toHaveBeenCalled();
  });

  it('passes the security flag through', async () => {
    mockScan.mockResolvedValue(resultFixture({ security: true }));
    render(
      <CohortScanButton
        scope={groupScope}
        scopeName="Prod"
        hostCount={2}
        label="Scan for security updates"
        security
      />,
    );
    fireEvent.click(screen.getByRole('button', { name: /Scan for security updates/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    await waitFor(() => expect(mockScan).toHaveBeenCalledWith(groupScope, { security: true }));
  });

  it('is disabled (no scan) when the cohort has zero hosts', () => {
    render(
      <CohortScanButton scope={groupScope} scopeName="Empty" hostCount={0} label="Refresh inventory" />,
    );
    const btn = screen.getByRole('button', { name: /Refresh inventory/ }) as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
    fireEvent.click(btn);
    // Disabled -> no confirmation dialog opens.
    expect(screen.queryByRole('button', { name: 'Refresh' })).toBeNull();
    expect(mockScan).not.toHaveBeenCalled();
  });
});
