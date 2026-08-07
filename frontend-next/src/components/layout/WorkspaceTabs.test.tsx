// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup } from '@testing-library/react';
import WorkspaceTabs from './WorkspaceTabs';

const usePathname = vi.fn();
vi.mock('next/navigation', () => ({ usePathname: () => usePathname() }));

describe('WorkspaceTabs + floating drawer', () => {
  beforeEach(() => usePathname.mockReturnValue('/fleet-dashboard'));
  afterEach(cleanup);

  it('renders the six workspace tabs and no Configure', () => {
    render(<WorkspaceTabs />);
    for (const label of ['Operate', 'Update', 'Secure', 'Automate', 'Verify', 'Report']) {
      expect(screen.getByRole('button', { name: label })).toBeTruthy();
    }
    expect(screen.queryByRole('button', { name: /configure/i })).toBeNull();
  });

  it('opens a floating navigation drawer with Pages/Actions/Activity on tab click', () => {
    render(<WorkspaceTabs />);
    // Drawer closed initially.
    expect(screen.queryByRole('group', { name: /navigation/i })).toBeNull();

    const tab = screen.getByRole('button', { name: 'Update' });
    // Disclosure, not a menu: no aria-haspopup, collapsed to start.
    expect(tab.getAttribute('aria-haspopup')).toBeNull();
    expect(tab.getAttribute('aria-expanded')).toBe('false');
    expect(tab.getAttribute('aria-controls')).toBe('workspace-drawer-update');

    fireEvent.click(tab);

    // PRA-357: the drawer is a labelled navigation panel (group), not role="menu".
    const drawer = screen.getByRole('group', { name: /Update navigation/i });
    expect(drawer).toBeTruthy();
    expect(drawer.getAttribute('id')).toBe('workspace-drawer-update');
    expect(screen.getByText('Pages')).toBeTruthy();
    expect(screen.getByText('Actions')).toBeTruthy();
    expect(screen.getByText('Activity')).toBeTruthy();
    // Children are plain route links (standard Tab/Enter model), not menuitems.
    expect(screen.getByRole('link', { name: /Security Updates/ })).toBeTruthy();
    expect(screen.queryByRole('menuitem')).toBeNull();
    // The tab reports expanded state.
    expect(tab.getAttribute('aria-expanded')).toBe('true');
  });

  it('toggles the drawer closed when the active tab is clicked again', () => {
    render(<WorkspaceTabs />);
    const tab = screen.getByRole('button', { name: 'Secure' });
    fireEvent.click(tab);
    expect(screen.getByRole('group', { name: /Secure navigation/i })).toBeTruthy();
    fireEvent.click(tab);
    expect(screen.queryByRole('group', { name: /navigation/i })).toBeNull();
  });
});
