/**
 * PRA-272: the single source of truth for the Praxis 1.0 desktop support
 * boundary. Shell CSS, the viewport gate, tests, and docs all reference these
 * numbers so the promise stays consistent.
 *
 * Praxis 1.0 is a desktop operations console. Below `MIN_SUPPORTED_WIDTH` we show
 * a deliberate branded "optimized for desktop" shell (see
 * `components/layout/UnsupportedViewport`) instead of clipped, partially-usable
 * product chrome.
 *
 * NOTE: the same boundary is expressed as a CSS media query in
 * `app/globals.css` (`.viewport-app` / `.viewport-unsupported`). CSS cannot import
 * a TS constant, so the media query hardcodes `MIN_SUPPORTED_WIDTH - 1` with a
 * comment pointing back here. Keep the two in sync — `viewport.test.ts` documents
 * the contract.
 */

/** Minimum viewport width (CSS px) at which the full Praxis app is supported. */
export const MIN_SUPPORTED_WIDTH = 1280;

/**
 * Tablet-landscape width. Praxis may render at this width, but 1024–1279px is
 * NOT part of the 1.0 desktop support promise — it falls into the unsupported
 * shell. Documented in `docs/browser-support.md`.
 */
export const TABLET_LANDSCAPE_WIDTH = 1024;

/** The largest width below which the unsupported shell is shown (px). */
export const MAX_UNSUPPORTED_WIDTH = MIN_SUPPORTED_WIDTH - 1;

/** True when a given viewport width is within the 1.0 desktop support promise. */
export function isSupportedWidth(width: number): boolean {
  return width >= MIN_SUPPORTED_WIDTH;
}
