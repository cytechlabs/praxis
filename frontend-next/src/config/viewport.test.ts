import { readFileSync } from 'fs';
import { describe, it, expect } from 'vitest';
import {
  MIN_SUPPORTED_WIDTH,
  MAX_UNSUPPORTED_WIDTH,
  TABLET_LANDSCAPE_WIDTH,
  isSupportedWidth,
} from './viewport';

describe('viewport support boundary', () => {
  it('pins the 1.0 desktop support minimum', () => {
    expect(MIN_SUPPORTED_WIDTH).toBe(1280);
    expect(MAX_UNSUPPORTED_WIDTH).toBe(MIN_SUPPORTED_WIDTH - 1);
  });

  it('treats tablet landscape (1024px) as unsupported for 1.0', () => {
    expect(TABLET_LANDSCAPE_WIDTH).toBe(1024);
    expect(TABLET_LANDSCAPE_WIDTH).toBeLessThan(MIN_SUPPORTED_WIDTH);
    expect(isSupportedWidth(TABLET_LANDSCAPE_WIDTH)).toBe(false);
  });

  it('classifies widths against the boundary', () => {
    expect(isSupportedWidth(390)).toBe(false);
    expect(isSupportedWidth(MAX_UNSUPPORTED_WIDTH)).toBe(false);
    expect(isSupportedWidth(MIN_SUPPORTED_WIDTH)).toBe(true);
    expect(isSupportedWidth(1600)).toBe(true);
  });

  it('keeps the CSS-only gate in sync with the constant', () => {
    // globals.css cannot import the TS constant; guard the hardcoded boundary so
    // the two never drift apart.
    const css = readFileSync(new URL('../app/globals.css', import.meta.url), 'utf8');
    expect(css).toContain(`max-width: ${MAX_UNSUPPORTED_WIDTH}px`);
    expect(css).toContain('.viewport-app');
    expect(css).toContain('.viewport-unsupported');
  });
});
