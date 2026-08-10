# Praxis 1.0 UI Foundation

The design foundation: brand assets, semantic color tokens, enforced
color rules, and theme behavior. Downstream UI cleanup builds on this;
it is not a page-by-page rewrite.

## Color rules (design locks)

- **Signal Red `#CE1B2B`** is used for **only three things**: the PRAXIS brand,
  the **active navigation** state, and **destructive/critical** states. It is
  never a generic accent. (The retired `#DC2626` is gone.)
- **Primary and secondary actions are neutral** (Ink/Paper) — never blue.
- **Ink `#141414`** and **Paper `#FAFAF8`** are the core neutrals.
- **Links** are neutral underlined text with a Signal Red hover.
- **Focus and selection are neutral**, never red.
- **Cards/panels use neutral chrome** — no glow, no red top-edge gradient.

## Semantic tokens

Tokens are CSS custom properties (RGB channel triplets, so Tailwind opacity
modifiers work) defined in `src/app/globals.css` and exposed as Tailwind colors
in `tailwind.config.ts`. Use the token utilities, not raw colors.

| Role | Tailwind | Notes |
| --- | --- | --- |
| App background | `bg-surface` | |
| Card / panel | `bg-surface-raised` | |
| Modal / popover / hover | `bg-surface-overlay` | |
| Input / well | `bg-surface-sunken` | |
| Primary text | `text-content` | |
| Secondary text | `text-content-muted` | |
| Tertiary / placeholder | `text-content-subtle` | |
| Border | `border-border` / `border-border-strong` | |
| Primary action (neutral) | `bg-action text-action-fg hover:bg-action-hover` | never red/blue |
| Secondary action | `bg-action-secondary text-content border-border` | |
| Brand / active nav | `text-brand`, `bg-brand text-brand-fg`, `bg-brand/10` | Signal Red |
| Destructive | `bg-danger text-danger-fg`, `text-danger`, `bg-danger/15` | Signal Red |
| Success / warning | `text-success bg-success/15`, `text-warning bg-warning/15` | muted |
| Info / neutral | `text-info bg-info/15` | neutral, never blue |
| Link | `text-link hover:text-link-hover underline` | |
| Focus ring | `focus-visible:ring-2 focus-visible:ring-focusring` | neutral |

## Theme behavior

- **Dark is the 1.0 default runtime theme** (`<html data-theme="dark">`).
- **Light mode is fully defined** at the token level and switched by
  `data-theme="light"` (scopable to any subtree). Dark tokens live on
  `:root, [data-theme="dark"]`; light on `[data-theme="light"]`.
- The theme **mechanism** exists, and the shell + shared `ui/` primitives are
  theme-aware, but a **global user-facing toggle is deferred**: ~130 feature
  pages still hardcode dark surfaces, so exposing a toggle now would ship a
  mixed/broken light app. The page sweeps migrate pages to tokens;
  the toggle lands once they do.
- **Verify both modes** at `/design` — the showcase renders the tokens and
  representative components in forced dark and light panels side by side.

## Brand assets

Official assets live in `frontend-next/brand_gfx/`; the ones the app uses are
copied into `frontend-next/public/` (favicons at the root, logos/app-icons under
`public/brand/`). Do not hand-build the wordmark — use `BrandWordmark` /
`BrandIcon` from `@/components/ui/BrandLogo`, which render the theme-appropriate
official mark. Favicons, apple-touch icon, and the web manifest are wired in
`src/pages/_document.tsx` + `public/manifest.webmanifest`.

## Color-drift guardrail

`npm run check:colors` (CI: the "Color-drift guardrail" step in `frontend-checks`)
fails the build if a raw `red-*`/`blue-*` utility or `#DC2626` appears in the
**foundation surfaces** this guardrail owns:

- `src/components/ui/`
- `src/components/layout/`
- `src/components/MainLayout.tsx`
- `src/app/globals.css`
- `tailwind.config.ts`

Feature pages are **not** scanned (they carry ~845 legacy usages migrated by the
page sweeps). To keep the guardrail useful without baseline churn, the scope
is intentionally narrow.

**Exception path:** for an unavoidable functional color case, append a same-line
comment:

```tsx
className="fill-red-500" // praxis-color-exception: brand-red chart series
```

The guardrail skips any line containing `praxis-color-exception`. Use it
sparingly and say why.
