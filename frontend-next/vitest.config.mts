import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

// PRA-256: vitest for co-located unit tests under src/.
// PRA-258: the react plugin transforms JSX/TSX so component/provider tests can
// import .tsx modules; those tests opt into jsdom via a
// `// @vitest-environment jsdom` docblock. Pure-logic tests stay in the default
// node environment. This config is separate from `next build`, `eslint src`,
// and `tsc --noEmit`, so it doesn't affect them.
// PRA-269: resolve the `@/` alias (matches tsconfig paths) so primitives that
// import via `@/utils/...` work under test.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts', 'src/**/*.test.tsx'],
    coverage: {
      provider: 'v8',
      reporter: ['text-summary', 'lcovonly'],
      reportsDirectory: 'coverage',
      // LCOV records the paths exactly as they appear here, relative to this
      // workspace; CI rewrites them to repository-relative form before upload.
      // Every shipped module under src/ is measured, not only the modules a
      // test happens to import, so the reported percentage describes the app
      // rather than the tested subset.
      include: ['src/**/*.ts', 'src/**/*.tsx'],
      exclude: ['src/**/*.test.ts', 'src/**/*.test.tsx', 'src/**/*.d.ts', 'src/__tests__/**'],
    },
  },
});
