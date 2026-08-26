# Praxis Shared UI Primitives

The shared frontend primitives that page sweeps build on, so pages migrate
consistently instead of inventing feature-local UI. All primitives consume the
semantic tokens (see `docs/design/ui-foundation.md`), never raw `red-*`/`blue-*`.
Import from `@/components/ui`.

Live examples for every primitive, in **forced dark and forced light**, are at
`/design`. Component tests: `src/components/ui/*.test.tsx`,
`src/utils/humanize.test.ts`.

## Content rules (all primitives)

- **Sentence case**, not Title Case. Use `humanizeStatus` / `humanizeLabel`
  (`@/utils/humanize`) for any machine enum; don't hand-write `.replace(/_/g)`.
- Operator-focused: compact, scannable, stable dimensions. **No nested cards**,
  no marketing/hero treatment, no decorative color.
- Signal Red only for brand / active-nav / destructive. Neutral everywhere else.

## Button

Variants: `primary` (neutral action), `secondary` (neutral bordered; `outline` is
a back-compat alias), `ghost`, `danger` (Signal Red), `link` (neutral underlined,
red hover). Sizes `sm|md|lg`. `loading` shows a spinner and disables the button.
`iconOnly` renders a square control, so **an accessible name is required**
(`aria-label` or `title`); dev warns if missing.

- **Do** put the primary action on the right in a `FormActions` row; use `danger`
  only for destructive actions.
- **Don't** use `link` for a real action button, or two `primary` buttons in one
  group.
- **Keyboard**: native `<button>`, so Space/Enter activate; visible neutral focus ring.

## Badge / StatusBadge

`Badge` takes a `variant` (`success|warning|danger|info|neutral|orange`). For
statuses prefer **`StatusBadge`**: `<StatusBadge status="in_progress" />` maps the
raw status to a variant (`statusToBadgeVariant`) and a humanized label
("In progress") in one step, so the same enum reads identically everywhere.

- **Do** pass raw statuses to `StatusBadge`. **Don't** hardcode a color per page.

## DataTable

Replaces hand-rolled `<table>`s. Props: `columns` (`{key, header, render?, align?}`),
`rows`, `rowKey`, `density` (`compact|normal`), `loading` (skeleton), `empty`
(defaults to a `no-results` EmptyState), `onRowClick`, `rowActions`, `selectable`
+ `selectedKeys`/`onSelectionChange`, `toolbar` (search/filters slot), `minWidth`
(explicit horizontal overflow), `stickyHeader`, `pagination`.

- **Overflow**: set `minWidth` (e.g. `min-w-[720px]`) so columns **scroll**
  horizontally at the desktop minimum instead of squishing.
- Search/filters go in the `toolbar` slot; DataTable owns layout and states, the
  page owns filter logic.
- **Keyboard**: with `onRowClick`, rows are focusable and Enter/Space activate;
  the selection/actions cells stop propagation so they don't trigger the row.
- **Do** give every column a stable `header`; use `render` for badges/actions.
- **Don't** nest a DataTable inside a Card header or squish columns below `minWidth`.

## Forms

- `Input` (label/error/icon), `SearchInput`, `Select`: labelled, token-styled,
  neutral focus, `aria-invalid`/`aria-describedby` on error.
- `FormField`: wraps any control with a label, **required** marker, helper text,
  and error (error suppresses helper). Use for checkboxes/radios/custom controls.
- `FormActions`: a right-aligned button row; put a `loading` submit `Button` for
  submitting feedback.

## Empty / Loading / Error / Not-found states

`EmptyState` variants: `default` (nothing yet), `no-activity`, `no-results`
(zero-filter), `error` (danger tone), `restricted` (permission), `locked` (paid).
`title`/`description`/`action` override the preset.

`StatePanel` exports `LoadingState` (spinner + label, `role="status"`),
`ErrorState` (error EmptyState + optional Retry), `NotFoundState`.

- **Do** use `no-results` when a filter matched nothing, `no-activity` when a
  working feature has no data yet, `restricted` for permission gaps, `locked` for
  entitlement gaps.

## Accessibility (WCAG AA)

- Every control has a name (label / `aria-label`). Icon-only buttons require one.
- Neutral, visible focus ring (`focus-visible:ring-focusring`), ≥2px.
- Tables use `<th scope>`; selection checkboxes are labelled; `caption` is
  available (visually hidden).
- Loading uses `role="status"`; errors surface actionable copy + retry.

## Adding a raw color?

The color-drift guardrail (`npm run check:colors`) blocks raw `red-*`/`blue-*` in
`ui/`, `layout/`, globals, and tailwind config. For an unavoidable functional
case, append `// praxis-color-exception: <reason>` on the line (see
`docs/design/ui-foundation.md`).
