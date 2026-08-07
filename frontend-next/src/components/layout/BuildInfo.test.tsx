// @vitest-environment jsdom
import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup } from '@testing-library/react';
import BuildInfo from './BuildInfo';

vi.mock('@/config/buildInfo', () => ({
  BUILD_INFO: {
    version: '0.9.1',
    buildDate: '2026-08-02T09:00:00Z',
    buildDateCompact: '20260802',
    environment: 'production',
    deploymentMode: 'Docker',
  },
}));

describe('BuildInfo', () => {
  afterEach(cleanup);

  it('shows the compact version badge and opens the About panel', () => {
    render(<BuildInfo />);

    // Compact footer badge is just the product version (no commit).
    const badge = screen.getByRole('button', { name: 'Praxis 0.9.1' });
    expect(badge).toBeTruthy();

    // Panel is closed until clicked.
    expect(screen.queryByRole('dialog')).toBeNull();
    fireEvent.click(badge);

    const dialog = screen.getByRole('dialog', { name: /About Praxis/i });
    expect(dialog).toBeTruthy();
    expect(screen.getByText('0.9.1')).toBeTruthy();
    expect(screen.getByText(/20260802/)).toBeTruthy();
    expect(screen.getByText('Docker')).toBeTruthy();
    // Commit and branch are intentionally not exposed anywhere.
    expect(screen.queryByText(/Commit/i)).toBeNull();
    expect(screen.queryByText(/Branch/i)).toBeNull();
  });
});
