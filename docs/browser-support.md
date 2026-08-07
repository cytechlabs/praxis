# Praxis 1.0 Browser & Viewport Support

This document defines the official **operator browser** support boundary for the
Praxis 1.0 web console — the browser and viewport an admin uses to *view* Praxis.

> **Scope.** This is about the **console UI**, not the managed fleet (for the
> Linux hosts Praxis manages, see [support-matrix.md](support-matrix.md)) and not
> the control-plane deployment (see
> [production-hardening.md](production-hardening.md)).

The boundary here is enforced in code, not aspiration: the supported minimum
width lives in `frontend-next/src/config/viewport.ts`
(`MIN_SUPPORTED_WIDTH`) and is enforced by the viewport gate
(`frontend-next/src/components/layout/ViewportGate.tsx`).

## Supported browsers

Praxis 1.0 targets current, evergreen desktop browsers. "Current" means the
latest stable release and the one before it.

| Browser | Status |
|---|---|
| Google Chrome (desktop) | Supported |
| Microsoft Edge (Chromium, desktop) | Supported |
| Mozilla Firefox (desktop) | Supported |
| Safari (macOS, desktop) | Supported |
| Any mobile browser | Unsupported (see below) |
| Internet Explorer / legacy Edge | Unsupported |

## Viewport support

Praxis is a **desktop operations console**. It is designed for a wide, stable
desktop viewport where the top bar, navigation, status bar, tables, and content
can all be present at once without collision.

| Viewport width | Status | Behavior |
|---|---|---|
| **≥ 1280px** | **Supported** | Full console. This is the 1.0 promise. |
| 1024–1279px (incl. tablet landscape) | **Not supported** | Renders the branded *"Optimized for desktop"* shell, not the console. Praxis *may* be usable in this band on a future release, but it is **not** part of the 1.0 support promise. |
| < 1024px (phones, tablet portrait) | **Not supported** | Same branded shell. Praxis 1.0 is not a mobile product. |

### The 1024px tablet-landscape caveat

A common tablet-landscape width is **1024px**. Praxis 1.0 does **not** support
this width: 1024px is below `MIN_SUPPORTED_WIDTH` (1280px), so a device at 1024px
sees the unsupported-viewport shell. The underlying layout may happen to render
acceptably at 1024px, but we do not validate it and do not promise it for 1.0.
Operators on a tablet should use it in a context that reports ≥ 1280px, or use a
desktop.

## What "unsupported" looks like

Below the supported minimum, Praxis does **not** show a clipped, half-usable
version of the console. Instead the viewport gate renders a deliberate branded
shell (`UnsupportedViewport`) with:

- the official Praxis mark and the `>█` terminal motif,
- a short "Optimized for desktop" explanation, and
- concise recovery guidance (reopen at ≥ 1280px, or widen the window).

This is the **only** place in the app that carries "how to continue" recovery
prose; the rest of the console avoids general tutorial copy.

The gate is **CSS-only** (a media query at `MIN_SUPPORTED_WIDTH - 1`), so it has
no JavaScript resize listener, is SSR- and hydration-safe, and switches
instantly and deterministically.

## Loading & auth transitions

While the console boots or resolves authentication, Praxis renders a shared
**branded loading shell** (`BrandedLoadingScreen`) — the official wordmark plus
the block-cursor motif on a full-viewport surface — rather than a blank page or a
bare "Loading…" string. This reserves stable geometry so there is no black flash
or layout jump between the shell and the resolved page.

## Verifying the boundary

- Automated component coverage (runs in CI): `viewport.test.ts`,
  `UnsupportedViewport.test.tsx`, `ViewportGate.test.tsx`.
- Screenshot coverage (local visual gate, see
  `frontend-next/tests/visual/`): captures the console/shell at an unsupported
  width (390px), the exact supported minimum (1280px), and a wide desktop
  (1600px). Run with `npm run test:visual` (requires a local Playwright install;
  it is intentionally **not** in the CI lane, which has no browser runtime).
