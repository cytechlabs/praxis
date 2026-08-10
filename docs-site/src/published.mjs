import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Shared definition of what the documentation site publishes.
 *
 * The content collection, the Markdown link rewriter, and the validation
 * scripts all read this module so there is exactly one answer to "is this
 * page public?".
 */

export const DOCS_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  'docs',
);

/**
 * Top-level `docs/*.md` files that are deliberately not routed.
 *
 * Only top-level Markdown is considered at all, so subdirectories such as
 * `docs/assets/`, `docs/audits/`, and `docs/ui-review/` are excluded
 * structurally rather than by name.
 */
export const UNPUBLISHED = [
  // Directory index for people browsing the repository. `docs/index.md` is
  // the site's home page instead.
  'README.md',
  // Contributor workflow and internal design reference.
  'branching-model.md',
  'documentation-boundaries.md',
  'ui-foundation.md',
  'ui-primitives.md',
  // A local working artifact that is not part of the repository. Naming it
  // here keeps the routed set identical whether or not a given checkout has
  // a copy on disk, so the site cannot build differently for two people.
  'product-overview.md',
  // Maintainer release runbooks. The operator-facing half of the release
  // contract, the artifact names and the verification commands, is published
  // as `verify-release-artifacts.md`.
  'agent-release.md',
  'ghcr-release-operations.md',
  'public-import-checklist.md',
  'release-checklist.md',
  'release-notes-template.md',
];

/** Glob patterns for the content collection loader. */
export const CONTENT_PATTERNS = [
  '*.md',
  ...UNPUBLISHED.map((file) => `!${file}`),
];

/** Every slug the site routes, sorted, read from disk. */
export function listPublishedSlugs(docsDir = DOCS_DIR) {
  return fs
    .readdirSync(docsDir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith('.md'))
    .map((entry) => entry.name)
    .filter((name) => !UNPUBLISHED.includes(name))
    .map((name) => name.slice(0, -'.md'.length))
    .sort();
}

/** Normalise a configured base into "" or "/prefix". */
export function normaliseBase(base) {
  if (!base || base === '/') return '';
  return base.endsWith('/') ? base.slice(0, -1) : base;
}

/** The site-absolute URL for a slug under a given base. */
export function routeForSlug(slug, base) {
  const prefix = normaliseBase(base);
  if (slug === 'index') return prefix === '' ? '/' : prefix;
  return `${prefix}/${slug}`;
}
