// @vitest-environment jsdom
import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup } from '@testing-library/react';
import PackageScopeControl from './PackageScopeControl';
import { ALL_SCOPE } from '@/services/packageScope';

const systems = [
  { id: 1, hostname: 'web-01' },
  { id: 2, hostname: 'db-01' },
];
const groups = [
  { id: 10, name: 'Prod', member_count: 8 },
  { id: 11, name: 'Staging', member_count: 3 },
];
const smartGroups = [{ id: 20, name: 'Debian hosts', member_count: 4 }];

afterEach(cleanup);

function renderControl(value = ALL_SCOPE, onChange = vi.fn(), extra = {}) {
  render(
    <PackageScopeControl
      value={value}
      onChange={onChange}
      systems={systems}
      groups={groups}
      smartGroups={smartGroups}
      {...extra}
    />,
  );
  return onChange;
}

describe('PackageScopeControl', () => {
  it('shows only the scope-type select for the fleet-wide default', () => {
    renderControl();
    expect(screen.getByRole('combobox', { name: 'Package scope' })).toBeTruthy();
    expect(screen.queryByRole('combobox', { name: 'Select group' })).toBeNull();
    expect(screen.queryByRole('combobox', { name: 'Select system' })).toBeNull();
  });

  it('selecting the group scope defaults to the first group', () => {
    const onChange = renderControl();
    fireEvent.change(screen.getByRole('combobox', { name: 'Package scope' }), {
      target: { value: 'group' },
    });
    expect(onChange).toHaveBeenCalledWith({ type: 'group', id: 10 });
  });

  it('selecting the smart-group scope defaults to the first smart group', () => {
    const onChange = renderControl();
    fireEvent.change(screen.getByRole('combobox', { name: 'Package scope' }), {
      target: { value: 'smart_group' },
    });
    expect(onChange).toHaveBeenCalledWith({ type: 'smart_group', id: 20 });
  });

  it('renders a group target select and reports target changes', () => {
    const onChange = renderControl({ type: 'group', id: 10 });
    const groupSel = screen.getByRole('combobox', { name: 'Select group' });
    expect(groupSel).toBeTruthy();
    fireEvent.change(groupSel, { target: { value: '11' } });
    expect(onChange).toHaveBeenCalledWith({ type: 'group', id: 11 });
  });

  it('labels smart groups with their member count', () => {
    renderControl({ type: 'smart_group', id: 20 });
    expect(screen.getByRole('option', { name: 'Debian hosts (4)' })).toBeTruthy();
  });

  it('omits the single-system scope when includeSystem is false', () => {
    renderControl(ALL_SCOPE, vi.fn(), { includeSystem: false });
    expect(screen.queryByRole('option', { name: 'Single system' })).toBeNull();
    expect(screen.getByRole('option', { name: 'Group' })).toBeTruthy();
  });

  it('shows the group cohort real member count, not a result-row count', () => {
    // The control has no way to receive result-row counts; the summary reflects
    // the selected group's membership (8), never the number of packages/updates
    // currently displayed on the page.
    renderControl({ type: 'group', id: 10 });
    expect(screen.getByText('8 systems in scope')).toBeTruthy();
    expect(screen.queryByText('2 systems in scope')).toBeNull();
  });

  it('shows the smart-group member count in the summary', () => {
    renderControl({ type: 'smart_group', id: 20 });
    expect(screen.getByText('4 systems in scope')).toBeTruthy();
  });
});
