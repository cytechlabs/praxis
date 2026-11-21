// @vitest-environment jsdom
import { describe, it, expect, afterEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/react';
import AptMetadataBanner from './AptMetadataBanner';
import { AptMetadataFreshness } from '@/services/packageService';

afterEach(cleanup);

const fmt = (value: string) => `at ${value}`;

function row(over: Partial<AptMetadataFreshness>): AptMetadataFreshness {
  return {
    system_id: 1,
    hostname: 'web-01',
    state: 'fresh',
    verified: true,
    refreshed_at: '2026-11-19T08:00:00Z',
    checked_at: '2026-11-19T08:00:00Z',
    detail: null,
    ...over,
  };
}

describe('AptMetadataBanner', () => {
  it('renders nothing when every recorded host is verified or unknown', () => {
    const { container } = render(
      <AptMetadataBanner
        rows={[
          row({}),
          row({ system_id: 2, hostname: 'new-01', state: 'unknown', verified: false, refreshed_at: null, checked_at: null }),
        ]}
        formatTimestamp={fmt}
      />,
    );
    expect(container.firstChild).toBeNull();
  });

  it('shows a failed check next to the last verified refresh', () => {
    render(
      <AptMetadataBanner
        rows={[
          row({
            state: 'partial',
            verified: false,
            checked_at: '2026-11-20T08:00:00Z',
            detail: '1 source(s) failed to refresh: enterprise.example.com (401 Unauthorized).',
          }),
        ]}
        formatTimestamp={fmt}
      />,
    );
    expect(screen.getByTestId('apt-metadata-banner')).toBeTruthy();
    expect(screen.getByText('web-01')).toBeTruthy();
    expect(screen.getByText('Partially refreshed')).toBeTruthy();
    expect(screen.getByText('Last verified refresh at 2026-11-19T08:00:00Z')).toBeTruthy();
    expect(screen.getByText(/401 Unauthorized/)).toBeTruthy();
  });

  it('says never verified when no refresh has ever succeeded', () => {
    render(
      <AptMetadataBanner
        rows={[row({ state: 'cached', verified: false, refreshed_at: null })]}
        formatTimestamp={fmt}
      />,
    );
    expect(screen.getByText('Cached only')).toBeTruthy();
    expect(screen.getByText('Never verified')).toBeTruthy();
  });

  it('bounds the host list and counts the rest', () => {
    const rows = Array.from({ length: 8 }, (_, i) =>
      row({ system_id: i + 1, hostname: `h-${i + 1}`, state: 'failed', verified: false }),
    );
    render(<AptMetadataBanner rows={rows} formatTimestamp={fmt} />);
    expect(screen.getByText(/8 hosts have update counts/)).toBeTruthy();
    expect(screen.getByText('and 3 more')).toBeTruthy();
    expect(screen.queryByText('h-8')).toBeNull();
  });
});
