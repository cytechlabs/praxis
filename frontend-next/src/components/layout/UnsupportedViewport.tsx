import React from 'react';
import { BrandIcon } from '../ui/BrandLogo';
import { MIN_SUPPORTED_WIDTH } from '@/config/viewport';

/**
 * PRA-272: the branded fallback shown below the desktop support boundary.
 *
 * Praxis 1.0 is a desktop operations console. Below `MIN_SUPPORTED_WIDTH` we show
 * this deliberate shell instead of clipped, partially-usable product chrome. The
 * copy is intentionally concise recovery guidance - the one place in the app that
 * carries "how to continue" prose (constraint: no general tutorial copy
 * elsewhere).
 *
 * Visibility is driven by the CSS-only viewport gate (`.viewport-unsupported` in
 * globals.css), not JS - so it is SSR/hydration-safe and deterministic.
 */

/** The brand + guidance content, reused by `/design` in a bounded preview box. */
export function UnsupportedViewportContent() {
  return (
    <div className="mx-auto flex max-w-sm flex-col items-center px-6 text-center">
      <BrandIcon size={48} className="mb-5" />

      {/* Block-cursor terminal motif (>█). */}
      <div className="mb-4 flex items-center gap-1 font-mono text-content">
        <span aria-hidden="true">&gt;</span>
        <span className="praxis-cursor" aria-hidden="true" />
      </div>

      <h1 className="text-lg font-semibold text-content">Optimized for desktop</h1>
      <p className="mt-2 text-sm text-content-muted">
        Praxis is a desktop operations console. This viewport is narrower than the
        supported minimum, so the console is hidden to avoid a broken layout.
      </p>
      <p className="mt-4 text-sm text-content-muted">
        Please reopen Praxis in a desktop browser at{' '}
        <span className="font-medium text-content">{MIN_SUPPORTED_WIDTH}px</span> or
        wider, or widen this window.
      </p>
    </div>
  );
}

export default function UnsupportedViewport() {
  return (
    <div
      className="viewport-unsupported fixed inset-0 z-[100] flex-col items-center justify-center bg-surface text-content"
      role="alert"
      aria-live="polite"
    >
      <UnsupportedViewportContent />
    </div>
  );
}
