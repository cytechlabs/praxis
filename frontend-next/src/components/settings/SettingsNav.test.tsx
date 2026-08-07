// @vitest-environment jsdom
import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup } from '@testing-library/react';
import SettingsNav, { buildSettingsGroups } from './SettingsNav';

afterEach(cleanup);

function allIds(isAdmin: boolean, isAuditor: boolean): string[] {
  return buildSettingsGroups(isAdmin, isAuditor).flatMap((g) => g.items.map((i) => i.id));
}

describe('buildSettingsGroups permission gating (PRA-276 / PRA-257)', () => {
  it('shows every section for an admin', () => {
    const ids = allIds(true, false);
    for (const id of [
      'general', 'alert-config', 'connection-settings', 'user-management',
      'identity-provider', 'auth-logs', 'fleet-access', 'ssh-identity',
      'activation-tokens', 'audit-export', 'license', 'diagnostics',
    ]) {
      expect(ids).toContain(id);
    }
  });

  it('hides admin/auditor-only sections from a plain user', () => {
    const ids = allIds(false, false);
    expect(ids).not.toContain('auth-logs');
    expect(ids).not.toContain('activation-tokens');
    expect(ids).not.toContain('diagnostics');
    // Non-gated sections still present.
    expect(ids).toContain('general');
    expect(ids).toContain('user-management');
  });

  it('shows Auth Logs to an auditor but not admin-only sections', () => {
    const ids = allIds(false, true);
    expect(ids).toContain('auth-logs');
    expect(ids).not.toContain('activation-tokens');
    expect(ids).not.toContain('diagnostics');
  });

  it('never emits an empty group and keeps partially-gated groups present', () => {
    // "Agents & Connectivity" holds ssh-identity (always) + activation-tokens
    // (admin-only). For a non-admin the admin item is gated out, but ssh-identity
    // keeps the group non-empty, so it stays; the empty-group filter still holds.
    const groups = buildSettingsGroups(false, false);
    expect(groups.every((g) => g.items.length > 0)).toBe(true);
    expect(groups.map((g) => g.label)).toContain('Agents & Connectivity');
  });
});

describe('SettingsNav', () => {
  const groups = buildSettingsGroups(true, false);

  it('renders a labelled nav with grouped section buttons', () => {
    render(<SettingsNav groups={groups} active="general" onSelect={() => {}} />);
    expect(screen.getByRole('navigation', { name: 'Settings sections' })).toBeTruthy();
    // Group headings present.
    expect(screen.getByText('Access & Identity')).toBeTruthy();
    // Every section is reachable as a button.
    expect(screen.getByRole('button', { name: 'License' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Support / Diagnostics' })).toBeTruthy();
  });

  it('marks the active section with aria-current="page"', () => {
    render(<SettingsNav groups={groups} active="license" onSelect={() => {}} />);
    expect(screen.getByRole('button', { name: 'License' }).getAttribute('aria-current')).toBe('page');
    expect(screen.getByRole('button', { name: 'General' }).getAttribute('aria-current')).toBeNull();
  });

  it('calls onSelect with the section id when a section is clicked', () => {
    const onSelect = vi.fn();
    render(<SettingsNav groups={groups} active="general" onSelect={onSelect} />);
    fireEvent.click(screen.getByRole('button', { name: 'Audit Export' }));
    expect(onSelect).toHaveBeenCalledWith('audit-export');
  });
});
