// @vitest-environment jsdom
import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup } from '@testing-library/react';
import JobHistory from '@/pages/job-scheduling/job-history';
import FailedJobs from '@/pages/job-scheduling/failed-jobs';
import {
  fetchAllJobHistory,
  fetchFailedJobs,
  type JobHistoryItem,
  type JobResultEntry,
} from '@/services/jobService';

// Chrome the two views share; none of it participates in result presentation.
vi.mock('next/head', () => ({ default: () => null }));
vi.mock('@/components/MainLayout', () => ({
  default: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));
vi.mock('@/components/ExportButton', () => ({ default: () => null }));
vi.mock('@/components/help/HelpLink', () => ({ default: () => null }));
vi.mock('sonner', () => ({ toast: { error: vi.fn(), success: vi.fn() } }));
vi.mock('@/context/TimestampPreferencesContext', () => ({
  useFormatTimestamp: () => (value: string) => value,
}));
vi.mock('@/services/jobService', () => ({
  fetchAllJobHistory: vi.fn(),
  fetchFailedJobs: vi.fn(),
  runJob: vi.fn(),
  rollbackJobHistory: vi.fn(),
}));

const mockHistory = vi.mocked(fetchAllJobHistory);
const mockFailed = vi.mocked(fetchFailedJobs);

const decoded: JobResultEntry[] = [
  {
    system_id: 4,
    hostname: 'web-01.test',
    result: { status: 'success', packages_updated: 12, packages_skipped: 1 },
  },
  {
    system_id: 9,
    hostname: 'db-01.test',
    result: { status: 'error', message: 'Security update failed: locked dpkg' },
  },
];

const historyItem = (over: Partial<JobHistoryItem>): JobHistoryItem => ({
  id: 1,
  job_id: 10,
  job_name: 'run-with-results',
  job_type: 'security_update',
  start_time: '2026-08-01T10:00:00',
  end_time: '2026-08-01T10:01:00',
  status: 'failed',
  result: decoded,
  error_message: null,
  systems_targeted: 2,
  systems_completed: 1,
  systems_failed: 1,
  created_at: '2026-08-01T10:00:00',
  ...over,
});

/** The row grid that owns a job-name cell carrying `name` as its title. */
const rowFor = (name: string): HTMLElement =>
  screen.getByTitle(name).parentElement as HTMLElement;

describe('job history result column', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFailed.mockResolvedValue({ total: 0, limit: 25, offset: 0, history: [] });
  });
  afterEach(cleanup);

  it('summarizes a decoded entry array and dashes a run with no result', async () => {
    mockHistory.mockResolvedValue({
      total: 2,
      limit: 25,
      offset: 0,
      history: [
        historyItem({ id: 1, job_name: 'run-with-results', result: decoded }),
        historyItem({ id: 2, job_name: 'run-without-results', result: null }),
      ],
    });

    render(<JobHistory />);

    // Column order: name, type, status, systems, started, duration, result, error.
    const withResults = await screen.findByTitle('run-with-results');
    expect((withResults.parentElement as HTMLElement).children[6].textContent).toBe(
      '2 systems updated'
    );
    expect(rowFor('run-without-results').children[6].textContent).toBe('-');

    // The summary is also the cell tooltip for the populated row only.
    expect(screen.getByTitle('2 systems updated')).toBeTruthy();
  });
});

describe('failed jobs detailed results', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockHistory.mockResolvedValue({ total: 0, limit: 25, offset: 0, history: [] });
  });
  afterEach(cleanup);

  it('renders the decoded entries in the expanded detail block', async () => {
    mockFailed.mockResolvedValue({
      total: 1,
      limit: 25,
      offset: 0,
      history: [historyItem({ id: 3, job_name: 'failed-with-results', result: decoded })],
    });

    render(<FailedJobs />);
    await screen.findByTitle('failed-with-results');

    fireEvent.click(screen.getByTitle('Toggle Details'));

    expect(screen.getByText('Detailed Results')).toBeTruthy();
    const pre = document.querySelector('pre') as HTMLElement;
    expect(JSON.parse(pre.textContent as string)).toEqual(decoded);
    expect(pre.textContent).toContain('db-01.test');
    expect(pre.textContent).toContain('locked dpkg');
  });

  it('omits the detail block for a failed run with no recorded result', async () => {
    mockFailed.mockResolvedValue({
      total: 1,
      limit: 25,
      offset: 0,
      history: [historyItem({ id: 4, job_name: 'failed-no-results', result: null })],
    });

    render(<FailedJobs />);
    await screen.findByTitle('failed-no-results');

    fireEvent.click(screen.getByTitle('Toggle Details'));

    // The expansion happened, but there is no result payload to show.
    expect(screen.getByText('Systems Targeted')).toBeTruthy();
    expect(screen.queryByText('Detailed Results')).toBeNull();
    expect(document.querySelector('pre')).toBeNull();
  });
});
