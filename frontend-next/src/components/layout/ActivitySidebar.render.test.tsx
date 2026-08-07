// @vitest-environment jsdom
//
// PRA-350: verify a real surface consumes the shared event-presentation helper —
// a host-unreachable notification renders with the danger color, a package scan
// completion does NOT, and notifications are no longer labeled "Alert".
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, cleanup } from '@testing-library/react';

const apiFetch = vi.fn();

vi.mock('@/utils/api', () => ({
  apiFetch: (...args: unknown[]) => apiFetch(...args),
}));

vi.mock('@/context/AuthContext', () => ({
  useAuth: () => ({ user: { id: 1, username: 'admin' } }),
}));

// framer-motion animates via effects that are noisy in jsdom; render children
// straight through so the panel content is present synchronously.
vi.mock('framer-motion', () => ({
  AnimatePresence: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  motion: new Proxy(
    {},
    {
      get:
        () =>
        ({ children, ...props }: { children?: React.ReactNode } & Record<string, unknown>) =>
          <div {...(props as Record<string, unknown>)}>{children}</div>,
    },
  ),
}));

import ActivitySidebar from './ActivitySidebar';

const ITEMS = [
  {
    id: 'notification-1',
    source: 'notification',
    event_type: 'system_unreachable',
    description: 'Host unreachable: praxis-tserver01',
    user_id: null,
    username: null,
    system_id: 5,
    system_hostname: 'praxis-tserver01',
    timestamp: '2026-08-04T21:24:56Z',
    details: { severity: 'error' },
  },
  {
    id: 'notification-2',
    source: 'notification',
    event_type: 'package_scan_complete',
    description: 'Package scan complete: praxis-tserver01',
    user_id: null,
    username: null,
    system_id: 5,
    system_hostname: 'praxis-tserver01',
    timestamp: '2026-08-04T21:20:00Z',
    details: { severity: 'info' },
  },
  {
    id: 'notification-3',
    source: 'notification',
    event_type: 'system_recovered',
    description: 'Host recovered: praxis-tserver01',
    user_id: null,
    username: null,
    system_id: 5,
    system_hostname: 'praxis-tserver01',
    timestamp: '2026-08-04T21:25:00Z',
    details: { severity: 'info' },
  },
];

function iconClassFor(description: string): string {
  const link = screen.getByText(description).closest('a');
  const svg = link?.querySelector('svg');
  return svg?.getAttribute('class') ?? '';
}

beforeEach(() => {
  apiFetch.mockReset();
  apiFetch.mockResolvedValue({ ok: true, json: async () => ({ items: ITEMS }) });
  window.localStorage.setItem('praxis-activity-sidebar-open', '1');
});
afterEach(() => {
  cleanup();
  window.localStorage.clear();
});

describe('ActivitySidebar event semantics (PRA-350)', () => {
  it('renders host-unreachable in danger, scan-complete and recovered not in danger', async () => {
    render(<ActivitySidebar />);

    await waitFor(() =>
      expect(screen.getByText('Host unreachable: praxis-tserver01')).toBeTruthy(),
    );

    expect(iconClassFor('Host unreachable: praxis-tserver01')).toContain('text-danger');

    const complete = iconClassFor('Package scan complete: praxis-tserver01');
    expect(complete).not.toContain('text-danger');
    expect(complete).toContain('text-success');

    const recovered = iconClassFor('Host recovered: praxis-tserver01');
    expect(recovered).not.toContain('text-danger');
    expect(recovered).toContain('text-success');
  });

  it('no longer labels notifications "Alert"', async () => {
    render(<ActivitySidebar />);
    await waitFor(() =>
      expect(screen.getByText('Package scan complete: praxis-tserver01')).toBeTruthy(),
    );
    expect(screen.queryByText('Alert')).toBeNull();
    // the neutral category label is used instead
    expect(screen.getAllByText('Notification').length).toBeGreaterThan(0);
  });
});
