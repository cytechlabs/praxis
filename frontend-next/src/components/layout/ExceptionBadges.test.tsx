// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import ExceptionBadges from './ExceptionBadges';
import { fetchFleetHealth } from '@/services/fleetHealthService';
import { fetchAllSecurityUpdates } from '@/services/packageService';
import { fetchFailedJobs } from '@/services/jobService';

vi.mock('@/services/fleetHealthService', () => ({ fetchFleetHealth: vi.fn() }));
vi.mock('@/services/packageService', () => ({ fetchAllSecurityUpdates: vi.fn() }));
vi.mock('@/services/jobService', () => ({ fetchFailedJobs: vi.fn() }));

const mockHealth = vi.mocked(fetchFleetHealth);
const mockSecurity = vi.mocked(fetchAllSecurityUpdates);
const mockFailed = vi.mocked(fetchFailedJobs);

describe('ExceptionBadges', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });
  afterEach(cleanup);

  it('renders exception badges from the destination-page count sources', async () => {
    mockHealth.mockResolvedValue({ unreachable: 2 } as never);
    mockSecurity.mockResolvedValue([{}, {}, {}, {}, {}] as never); // page uses .length
    mockFailed.mockResolvedValue({ total: 3 } as never);

    render(<ExceptionBadges />);

    const systems = await screen.findByRole('link', { name: /unreachable/i });
    expect(systems.getAttribute('href')).toBe('/system-management/all-systems?status=Unreachable');
    const critical = await screen.findByRole('link', { name: /critical updates/i });
    expect(critical.getAttribute('href')).toBe('/package-management/security-updates');
    const failed = await screen.findByRole('link', { name: /failed jobs/i });
    expect(failed.getAttribute('href')).toBe('/job-scheduling/failed-jobs');

    // Never an active-jobs badge.
    expect(screen.queryByRole('link', { name: /active job/i })).toBeNull();
  });

  it('shows quiet all-clear telemetry and no badge links when there are no exceptions', async () => {
    mockHealth.mockResolvedValue({ unreachable: 0 } as never);
    mockSecurity.mockResolvedValue([] as never);
    mockFailed.mockResolvedValue({ total: 0 } as never);

    const { container } = render(<ExceptionBadges />);
    await waitFor(() => expect(mockHealth).toHaveBeenCalled());
    // Restrained healthy-state telemetry — populated, no exception links.
    expect(screen.getByText(/no action needed/i)).toBeTruthy();
    expect(container.querySelector('a')).toBeNull();
  });
});
