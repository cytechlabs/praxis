// @vitest-environment jsdom
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import ViewportGate from './ViewportGate';

describe('ViewportGate', () => {
  it('renders the app inside the gated container alongside the fallback shell', () => {
    const { container } = render(
      <ViewportGate>
        <div>console content</div>
      </ViewportGate>,
    );

    // App content lives inside the CSS-gated container (hidden below the boundary
    // by the media query, not removed from the DOM).
    const app = container.querySelector('.viewport-app');
    expect(app).toBeTruthy();
    expect(app?.textContent).toContain('console content');

    // The branded unsupported shell is always mounted; CSS decides visibility.
    expect(screen.getByRole('alert').className).toContain('viewport-unsupported');
  });
});
