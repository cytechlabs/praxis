// @vitest-environment jsdom
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import UnsupportedViewport from './UnsupportedViewport';
import { MIN_SUPPORTED_WIDTH } from '@/config/viewport';

describe('UnsupportedViewport', () => {
  it('renders a branded, accessible desktop-only shell', () => {
    render(<UnsupportedViewport />);

    // Official brand mark is present.
    expect(screen.getByRole('img', { name: 'Praxis' })).toBeTruthy();

    // Announced to assistive tech.
    const alert = screen.getByRole('alert');
    expect(alert).toBeTruthy();
    expect(alert.className).toContain('viewport-unsupported');

    // Explains the boundary and gives concise recovery guidance with the exact
    // supported minimum width.
    expect(screen.getByText('Optimized for desktop')).toBeTruthy();
    expect(screen.getByText(new RegExp(`${MIN_SUPPORTED_WIDTH}px`))).toBeTruthy();
  });
});
