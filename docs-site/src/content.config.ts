import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { docsSchema } from '@astrojs/starlight/schema';

import { CONTENT_PATTERNS } from './published.mjs';

/**
 * Documentation content lives in `docs/` at the repository root, not inside
 * this package. `docs/` is the single source for the public site, the copy
 * bundled into the application image, and the Markdown people read in the
 * repository.
 *
 * Only top-level `docs/*.md` files are routed. Subdirectories such as
 * `docs/assets/`, `docs/audits/`, and `docs/ui-review/` are never published,
 * so notes and raw data cannot reach the public site by being dropped into
 * the tree. `src/published.mjs` also names the top-level files that stay
 * unpublished, and `scripts/check-docs-public-content.mjs` re-checks the
 * resulting route set against `docs-site/published-routes.json`.
 */
export const collections = {
  docs: defineCollection({
    loader: glob({
      base: '../docs',
      pattern: CONTENT_PATTERNS,
      // Keep the route identical to the file name. The default slugifier
      // rewrites characters such as the dot in "upgrade-notes-1-0", which
      // would silently move a URL and break the one-to-one mapping the link
      // rewriter and the bundled-output checks rely on.
      generateId: ({ entry }) => entry.replace(/\.md$/, ''),
    }),
    schema: docsSchema(),
  }),
};
