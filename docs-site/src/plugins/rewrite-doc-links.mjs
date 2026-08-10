import path from 'node:path';

import { visit } from 'unist-util-visit';

import { DOCS_DIR, listPublishedSlugs, routeForSlug } from '../published.mjs';

const EXTERNAL = /^(?:[a-z][a-z0-9+.-]*:|\/\/)/i;

/**
 * Rewrites relative Markdown links to site routes.
 *
 * Pages in `docs/` are read in two places: on the documentation site and as
 * plain Markdown in the repository. Links are therefore authored the way
 * Markdown expects them, pointing at the neighbouring file:
 *
 *     [Backup and restore](backup-restore.md#restoring)
 *
 * which stays clickable in the repository, and which this plugin turns into
 * the routed, base-aware URL the site needs:
 *
 *     /help/backup-restore#restoring
 *
 * Links to files that are not published fail the build rather than shipping
 * a dead link, and site-absolute links are rejected because they cannot be
 * correct at both mount points.
 */
export function rewriteDocLinks({ base } = {}) {
  const published = new Set(listPublishedSlugs());

  return function transformer(tree, file) {
    const sourcePath = file?.history?.[0] ?? file?.path;
    const sourceDir = sourcePath ? path.dirname(sourcePath) : DOCS_DIR;
    const describe = () =>
      sourcePath ? path.relative(DOCS_DIR, sourcePath) : 'unknown document';

    visit(tree, 'element', (node) => {
      if (node.tagName !== 'a') return;

      const href = node.properties?.href;
      if (typeof href !== 'string' || href === '') return;
      if (href.startsWith('#') || EXTERNAL.test(href)) return;

      if (href.startsWith('/')) {
        throw new Error(
          `${describe()}: site-absolute link "${href}" cannot resolve from both ` +
            'the public site and the bundled copy. Link to the neighbouring ' +
            'Markdown file instead, for example "other-page.md".',
        );
      }

      const match = /^([^#?]*\.md)(#.*)?$/.exec(href);
      if (!match) {
        throw new Error(
          `${describe()}: relative link "${href}" does not point at a Markdown ` +
            'file. Use "other-page.md" so the link works in the repository ' +
            'and on the site.',
        );
      }

      const [, target, fragment = ''] = match;
      const absolute = path.resolve(sourceDir, target);
      const relative = path.relative(DOCS_DIR, absolute);

      if (relative.startsWith('..') || path.dirname(relative) !== '.') {
        throw new Error(
          `${describe()}: link "${href}" points outside the published page set.`,
        );
      }

      const slug = path.basename(relative, '.md');
      if (!published.has(slug)) {
        throw new Error(
          `${describe()}: link "${href}" points at "${slug}", which the site ` +
            'does not publish.',
        );
      }

      node.properties.href = `${routeForSlug(slug, base)}${fragment}`;
    });
  };
}
