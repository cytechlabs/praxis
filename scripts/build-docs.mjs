#!/usr/bin/env node
/**
 * Builds the documentation site.
 *
 * One content source in `docs/` produces two outputs, which differ only in the
 * URL prefix they are served from:
 *
 *   docs-site/dist            the public site, served at /
 *   frontend-next/public/help the copy shipped in the frontend image, at /help
 *
 * The bundled copy is committed. It has to be, because the frontend image is
 * built with `frontend-next/` as its Docker context and cannot reach `docs/`.
 * `check-docs-bundle.mjs` rebuilds it and fails if the committed bytes differ,
 * so a stale bundle cannot ship.
 *
 * Usage:
 *   node scripts/build-docs.mjs            build both outputs
 *   node scripts/build-docs.mjs --public   build only the public site
 *   node scripts/build-docs.mjs --bundled  build only the bundled copy
 */

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DOCS_SITE = path.join(REPO, 'docs-site');

export const PUBLIC_OUT = path.join(DOCS_SITE, 'dist');
export const BUNDLED_OUT = path.join(REPO, 'frontend-next', 'public', 'help');
export const BUNDLED_BASE = '/help';

/**
 * The public origin. Set for the public build only, where it produces
 * canonical URLs and a sitemap. The bundled copy is served from an operator's
 * own deployment and must carry neither.
 */
export const PUBLIC_SITE = 'https://docs.praxisfleet.com';

/** Where Starlight puts a page's own rendered Markdown. */
const CONTENT_MARKER = 'class="sl-markdown-content">';

/** Every emitted file under a directory. */
function walk(dir, found = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, found);
    else found.push(full);
  }
  return found;
}

/**
 * Fails the build if any page came out with no content.
 *
 * A page whose Markdown cannot be rendered does not stop Astro. The content
 * loader reports the failure and carries on, so the build writes a page with
 * an empty body and exits successfully. Publishing a blank page is worse than
 * not publishing, and the site is built by its host from this command alone,
 * so the check belongs here rather than in a gate that only CI runs.
 */
function assertPagesHaveContent(outDir) {
  const empty = [];

  for (const file of walk(outDir)) {
    if (!file.endsWith('.html')) continue;
    // The 404 page is built from the theme rather than from a document, so its
    // Markdown container is empty by design.
    if (path.basename(file) === '404.html') continue;

    const html = fs.readFileSync(file, 'utf8');
    const at = html.indexOf(CONTENT_MARKER);
    // A page with no Markdown container is not making a claim this can check.
    if (at === -1) continue;

    if (html.slice(at + CONTENT_MARKER.length).trimStart().startsWith('</div>')) {
      empty.push(path.relative(outDir, file));
    }
  }

  if (empty.length > 0) {
    throw new Error(
      `${empty.length} page(s) were emitted with no content, which means their ` +
        `source failed to render:\n  ${empty.join('\n  ')}\n` +
        'The build log above says why.',
    );
  }
}

/** Build one variant into `outDir`. Returns the absolute output path. */
export function buildDocs({
  base = '/',
  site,
  outDir,
  cacheDir,
  diagramCache,
  diagramManifest,
  quiet = false,
} = {}) {
  if (!outDir) throw new Error('buildDocs requires an outDir');

  // Astro empties its own output directory, but only the one it is told
  // about. Clearing here as well means a removed page cannot survive in a
  // directory that a previous run wrote to.
  fs.rmSync(outDir, { recursive: true, force: true });

  execFileSync('npx', ['astro', 'build'], {
    cwd: DOCS_SITE,
    stdio: quiet ? 'pipe' : 'inherit',
    env: {
      ...process.env,
      PRAXIS_DOCS_BASE: base,
      // Explicitly cleared rather than omitted, so an inherited value from the
      // shell cannot leak the public origin into the bundled build.
      PRAXIS_DOCS_SITE: site ?? '',
      PRAXIS_DOCS_OUTDIR: outDir,
      // Empty means "use the default cache", which is what a normal build
      // wants; the clean-build gate points this at a fresh directory.
      PRAXIS_DOCS_CACHE_DIR: cacheDir ?? '',
      // Diagrams are read from the committed directory, so an ordinary build
      // needs no browser. Empty means the default location; the regeneration
      // and freshness paths in build-docs-diagrams.mjs redirect it.
      PRAXIS_DOCS_DIAGRAM_CACHE: diagramCache ?? '',
      // Set only by regeneration, which needs the build to report which
      // diagrams the documentation actually contains. Empty for every build
      // whose pages are kept.
      PRAXIS_DOCS_DIAGRAM_MANIFEST: diagramManifest ?? '',
      // Astro writes a build timestamp into its own telemetry, not into the
      // output, but disabling it keeps builds from touching the network.
      ASTRO_TELEMETRY_DISABLED: '1',
    },
  });

  assertPagesHaveContent(outDir);

  return outDir;
}

function main() {
  const args = process.argv.slice(2);
  const only = args.find((a) => a === '--public' || a === '--bundled');

  if (only !== '--bundled') {
    console.log(`Building the public documentation site for ${PUBLIC_SITE}...`);
    buildDocs({ base: '/', site: PUBLIC_SITE, outDir: PUBLIC_OUT });
    console.log(`  -> ${path.relative(REPO, PUBLIC_OUT)}`);
  }

  if (only !== '--public') {
    console.log(`Building the bundled copy at ${BUNDLED_BASE}...`);
    buildDocs({ base: BUNDLED_BASE, outDir: BUNDLED_OUT });
    console.log(`  -> ${path.relative(REPO, BUNDLED_OUT)}`);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
