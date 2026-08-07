// @vitest-environment jsdom
import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup } from '@testing-library/react';
import SystemPicker from './SystemPicker';

const SYSTEMS = [
  { id: 1, hostname: 'web-01' },
  { id: 2, hostname: 'web-02' },
  { id: 3, hostname: 'db-01' },
];

afterEach(cleanup);

function search(): HTMLInputElement {
  return screen.getByRole('textbox', { name: /search systems by hostname/i }) as HTMLInputElement;
}

describe('SystemPicker', () => {
  it('lists every system as an add button when nothing is selected', () => {
    render(<SystemPicker systems={SYSTEMS} selectedIds={[]} onToggle={() => {}} />);
    expect(screen.getByRole('button', { name: 'Add web-01' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Add web-02' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Add db-01' })).toBeTruthy();
  });

  it('filters the available list by hostname substring', () => {
    render(<SystemPicker systems={SYSTEMS} selectedIds={[]} onToggle={() => {}} />);
    fireEvent.change(search(), { target: { value: 'web' } });
    expect(screen.getByRole('button', { name: 'Add web-01' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Add web-02' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Add db-01' })).toBeNull();
  });

  it('is case-insensitive', () => {
    render(<SystemPicker systems={SYSTEMS} selectedIds={[]} onToggle={() => {}} />);
    fireEvent.change(search(), { target: { value: 'DB' } });
    expect(screen.getByRole('button', { name: 'Add db-01' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Add web-01' })).toBeNull();
  });

  it('shows an empty state with a working clear-filter action', () => {
    render(<SystemPicker systems={SYSTEMS} selectedIds={[]} onToggle={() => {}} />);
    fireEvent.change(search(), { target: { value: 'zzz' } });
    expect(screen.getByText(/No systems match "zzz"\./)).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Clear filter' }));
    expect(search().value).toBe('');
    // Full list is back.
    expect(screen.getByRole('button', { name: 'Add web-01' })).toBeTruthy();
  });

  it('keeps selected systems visible and removable even when the search hides them', () => {
    const onToggle = vi.fn();
    render(<SystemPicker systems={SYSTEMS} selectedIds={[1]} onToggle={onToggle} />);

    // web-01 is selected -> shown in the Selected row, excluded from Available.
    expect(screen.getByText('Selected (1)')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Remove web-01' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Add web-01' })).toBeNull();

    // Search for something web-01 does NOT match; it stays in the Selected row.
    fireEvent.change(search(), { target: { value: 'db' } });
    expect(screen.getByRole('button', { name: 'Add db-01' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Add web-02' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Remove web-01' })).toBeTruthy();

    // Still removable.
    fireEvent.click(screen.getByRole('button', { name: 'Remove web-01' }));
    expect(onToggle).toHaveBeenCalledWith(1);
  });

  it('calls onToggle when an available system is added', () => {
    const onToggle = vi.fn();
    render(<SystemPicker systems={SYSTEMS} selectedIds={[]} onToggle={onToggle} />);
    fireEvent.click(screen.getByRole('button', { name: 'Add db-01' }));
    expect(onToggle).toHaveBeenCalledWith(3);
  });

  it('reports when all systems are already selected', () => {
    render(<SystemPicker systems={SYSTEMS} selectedIds={[1, 2, 3]} onToggle={() => {}} />);
    expect(screen.getByText('All systems are selected.')).toBeTruthy();
  });
});
