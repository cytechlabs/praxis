import type { Config } from "tailwindcss";
import colors from "tailwindcss/colors";

// PRA-268: semantic color tokens. Each maps to an RGB-channel CSS var defined in
// src/app/globals.css, wrapped so Tailwind opacity modifiers (bg-surface/50)
// work. Themes switch via `data-theme` on <html> (dark is the 1.0 default).
const token = (name: string) => `rgb(var(--${name}) / <alpha-value>)`;

export default {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['var(--font-inter)', 'Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'sans-serif'],
      },
      colors: {
        // Remap stock `gray` (cool/blue-tinted) to `zinc` (true neutral) so every
        // bg-gray-* / text-gray-* / border-gray-* across the app stays color-neutral.
        gray: colors.zinc,

        background: "var(--background)",
        foreground: "var(--foreground)",

        // ---- PRA-268 semantic tokens (theme-aware) ----
        // Brand: Signal Red — brand / active nav / destructive only.
        brand: {
          DEFAULT: token('brand'),
          hover: token('brand-hover'),
          fg: token('brand-fg'),
        },
        // Surfaces (app bg -> raised cards -> overlays -> sunken inputs).
        surface: {
          DEFAULT: token('surface'),
          raised: token('surface-raised'),
          overlay: token('surface-overlay'),
          sunken: token('surface-sunken'),
        },
        // Text.
        content: {
          DEFAULT: token('content'),
          muted: token('content-muted'),
          subtle: token('content-subtle'),
        },
        // Borders (also feeds the `border-border` utility).
        border: {
          DEFAULT: token('border'),
          strong: token('border-strong'),
        },
        // Neutral primary/secondary actions (never blue).
        action: {
          DEFAULT: token('action'),
          fg: token('action-fg'),
          hover: token('action-hover'),
          secondary: token('action-secondary'),
          'secondary-fg': token('action-secondary-fg'),
        },
        // Links: neutral text, Signal Red hover.
        link: {
          DEFAULT: token('link'),
          hover: token('link-hover'),
        },
        focusring: token('focus'),
        // Status roles.
        danger: {
          DEFAULT: token('danger'),
          fg: token('danger-fg'),
        },
        success: {
          DEFAULT: token('success'),
          fg: token('success-fg'),
        },
        warning: {
          DEFAULT: token('warning'),
          fg: token('warning-fg'),
        },
        // "info" is a NEUTRAL role (never blue).
        info: {
          DEFAULT: token('info'),
          fg: token('info-fg'),
        },

        // PRA-235 legacy `praxis-*` family, retained so out-of-scope pages keep
        // rendering (dark-only for now; migrated to tokens by the page sweeps).
        // PRA-268: the blue link/primary are RETIRED for neutral values — no
        // standalone blue in a semantic role.
        praxis: {
          bg: '#0d0d0f',            // app dark background (= surface)
          surface: '#151518',       // raised card surface
          'surface-2': '#1c1c20',   // secondary/hover surface
          border: '#27272a',        // zinc-800 dark border
          text: '#f4f4f5',          // zinc-100 primary text
          'text-muted': '#a1a1aa',  // zinc-400 muted labels
          link: '#d4d4d8',          // neutral link text (was blue #60a5fa)
          primary: '#e4e4e7',       // neutral primary (was blue #2563eb)
        },
      },
      ringColor: {
        DEFAULT: token('focus'),
      },
      outlineColor: {
        DEFAULT: token('focus'),
      },
    },
  },
  plugins: [],
} satisfies Config;
