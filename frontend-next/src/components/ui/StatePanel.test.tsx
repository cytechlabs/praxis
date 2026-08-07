// @vitest-environment jsdom
import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup } from '@testing-library/react';
import { LoadingState, ErrorState, NotFoundState, EmptyState } from './index';
import PaidFeatureLock from '../PaidFeatureLock';

describe('PRA-274 shared states', () => {
  afterEach(cleanup);

  it('LoadingState uses the block-cursor motif (no spinner) and announces itself', () => {
    const { container } = render(<LoadingState label="Loading drift" />);
    const status = screen.getByRole('status');
    expect(status.textContent).toContain('Loading drift');
    // block-cursor motif present; no spinner svg.
    expect(container.querySelector('.praxis-cursor')).toBeTruthy();
    expect(container.querySelector('svg.animate-spin')).toBeNull();
  });

  it('ErrorState shows operator copy (not raw) and a working Retry', () => {
    const onRetry = vi.fn();
    render(<ErrorState title="Couldn’t load policies" onRetry={onRetry} />);
    expect(screen.getByText('Couldn’t load policies')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: /retry/i }));
    expect(onRetry).toHaveBeenCalledOnce();
  });

  it('NotFoundState renders a title + action inside chrome', () => {
    render(<NotFoundState title="Page not found" action={<button>Back</button>} />);
    expect(screen.getByText('Page not found')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Back' })).toBeTruthy();
  });

  it('EmptyState distinguishes not-configured from no-results (filtered-to-zero)', () => {
    render(<EmptyState variant="not-configured" />);
    expect(screen.getByText(/not configured/i)).toBeTruthy();
    cleanup();
    render(<EmptyState variant="no-results" />);
    expect(screen.getByText(/no matches/i)).toBeTruthy();
  });

  it('PaidFeatureLock is a calm commercial surface: feature + benefits + View plans CTA', () => {
    render(
      <PaidFeatureLock
        feature="Session Locks"
        value="Coordinate exclusive host access."
        benefits={['Prevent concurrent changes', 'Full audit trail']}
      />,
    );
    expect(screen.getByText('Session Locks')).toBeTruthy();
    expect(screen.getByText('Prevent concurrent changes')).toBeTruthy();
    const cta = screen.getByRole('link', { name: /view plans/i });
    expect(cta.getAttribute('href')).toBe('/settings?tab=license');
  });
});
