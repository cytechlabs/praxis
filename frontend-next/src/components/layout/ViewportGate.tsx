import React, { ReactNode } from 'react';
import UnsupportedViewport from './UnsupportedViewport';

/**
 * PRA-272: enforces the desktop support boundary around the whole app.
 *
 * Renders the app inside `.viewport-app` alongside the branded
 * `<UnsupportedViewport>` fallback. The CSS-only gate in globals.css swaps which
 * is visible at the boundary (`MIN_SUPPORTED_WIDTH`), so below the supported
 * width the operator sees the intentional shell instead of clipped chrome -
 * with no JS, resize listener, or hydration flash.
 */
export default function ViewportGate({ children }: { children: ReactNode }) {
  return (
    <>
      <div className="viewport-app">{children}</div>
      <UnsupportedViewport />
    </>
  );
}
