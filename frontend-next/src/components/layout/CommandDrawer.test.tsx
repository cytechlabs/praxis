// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup } from '@testing-library/react';
import CommandDrawer from './CommandDrawer';
import type { Workspace } from '@/config/workspaces';

const usePathname = vi.fn();
vi.mock('next/navigation', () => ({ usePathname: () => usePathname() }));

const icon = <svg data-testid="icon" />;

const workspace: Workspace = {
  id: 'update',
  label: 'Update',
  pages: [
    { id: 'p1', label: 'Security Updates', path: '/updates/security', icon },
    { id: 'p2', label: 'Pro Feature', path: '/updates/pro', icon, paid: true },
  ],
  actions: [{ id: 'a1', label: 'Run Scan', path: '/updates/scan', icon }],
  activity: [],
};

describe('CommandDrawer accessibility (PRA-357)', () => {
  beforeEach(() => usePathname.mockReturnValue('/fleet-dashboard'));
  afterEach(cleanup);

  it('exposes a labelled navigation group, not an ARIA menu', () => {
    render(<CommandDrawer workspace={workspace} onClose={() => {}} />);

    const group = screen.getByRole('group', { name: 'Update navigation' });
    expect(group).toBeTruthy();
    expect(group.getAttribute('id')).toBe('workspace-drawer-update');

    // The drawer must NOT claim menu semantics its plain links can't honor.
    expect(screen.queryByRole('menu')).toBeNull();
    expect(screen.queryAllByRole('menuitem')).toHaveLength(0);
  });

  it('renders each section, with an empty section showing "None"', () => {
    render(<CommandDrawer workspace={workspace} onClose={() => {}} />);
    expect(screen.getByText('Pages')).toBeTruthy();
    expect(screen.getByText('Actions')).toBeTruthy();
    expect(screen.getByText('Activity')).toBeTruthy();
    // Activity is empty in the fixture.
    expect(screen.getByText('None')).toBeTruthy();
  });

  it('groups items into lists labelled by their section heading', () => {
    render(<CommandDrawer workspace={workspace} onClose={() => {}} />);
    // Accessible name of each list resolves via aria-labelledby -> heading text.
    const pages = screen.getByRole('list', { name: 'Pages' });
    expect(pages).toBeTruthy();
    // Two page items -> two list items.
    expect(pages.querySelectorAll('li')).toHaveLength(2);
    expect(screen.getByRole('list', { name: 'Actions' })).toBeTruthy();
  });

  it('renders items as focusable route links (standard Tab/Enter model)', () => {
    render(<CommandDrawer workspace={workspace} onClose={() => {}} />);
    const link = screen.getByRole('link', { name: /Security Updates/ });
    expect(link.getAttribute('href')).toBe('/updates/security');
    // In the normal tab order — no roving tabindex removing it from focus.
    expect(link.getAttribute('tabindex')).not.toBe('-1');
    // Paid item still surfaces its Pro marker.
    expect(screen.getByText('Pro')).toBeTruthy();
  });

  it('marks the active route with aria-current', () => {
    usePathname.mockReturnValue('/updates/security');
    render(<CommandDrawer workspace={workspace} onClose={() => {}} />);
    const active = screen.getByRole('link', { name: /Security Updates/ });
    expect(active.getAttribute('aria-current')).toBe('page');
    const inactive = screen.getByRole('link', { name: /Run Scan/ });
    expect(inactive.getAttribute('aria-current')).toBeNull();
  });

  it('closes the drawer when a link is selected', () => {
    const onClose = vi.fn();
    render(<CommandDrawer workspace={workspace} onClose={onClose} />);
    const group = screen.getByRole('group', { name: 'Update navigation' });
    // The links are real anchors; stop jsdom from attempting a real navigation
    // (unimplemented) while still exercising the onClick -> onClose contract.
    group.addEventListener('click', (e) => e.preventDefault());
    fireEvent.click(screen.getByRole('link', { name: /Run Scan/ }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
