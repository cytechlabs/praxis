#!/usr/bin/env node
/**
 * Proves the documentation site builds the same route set on a fresh checkout.
 *
 * Astro persists the content collection in its cache directory, so a working
 * tree that has built before can keep resolving pages that a clean checkout
 * would never find, and a page present only on one machine looks like part of
 * the site. That is a build that passes locally and fails in CI.
 *
 * This builds into a throwaway output directory with the cache redirected to a
 * fresh temporary location, so every page is rediscovered from disk, and then
 * asserts the emitted routes are exactly the reviewed inventory in
 * docs-site/published-routes.json. The inventory is checked in, so the
 * comparison is against a fixed expectation rather than against whatever
 * happens to be on this machine.
 *
 * Usage:
 *   node scripts/check-docs-clean-build.mjs
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildDocs } from './build-docs.mjs';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const INVENTORY = path.join(REPO, 'docs-site', 'published-routes.json');

/** Routes emitted by a build: `<slug>/index.html`, plus the root page. */
function emittedRoutes(distDir) {
  const routes = [];

  const walk = (dir, prefix) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        walk(path.join(dir, entry.name), prefix ? `${prefix}/${entry.name}` : entry.name);
      } else if (entry.name === 'index.html') {
        routes.push(prefix === '' ? 'index' : prefix);
      }
    }
  };

  walk(distDir, '');
  return routes.sort();
}

function main() {
  const expected = JSON.parse(fs.readFileSync(INVENTORY, 'utf8')).routes.slice().sort();
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-docs-clean-'));

  try {
    const outDir = path.join(scratch, 'dist');
    const cacheDir = path.join(scratch, 'cache');

    buildDocs({ base: '/', outDir, cacheDir, quiet: true });

    const actual = emittedRoutes(outDir);
    const missing = expected.filter((slug) => !actual.includes(slug));
    const unexpected = actual.filter((slug) => !expected.includes(slug));

    if (missing.length > 0 || unexpected.length > 0) {
      console.error('Clean build produced the wrong route set:\n');
      for (const slug of missing) {
        console.error(
          `  "${slug}" is in the reviewed inventory but a clean build does not produce it. ` +
            `If docs/${slug}.md exists only on this machine, it is not part of the site.`,
        );
      }
      for (const slug of unexpected) {
        console.error(`  "${slug}" was built but is not in the reviewed inventory`);
      }
      process.exit(1);
    }

    if (actual.length === 0) {
      console.error('Clean build produced no routes at all.');
      process.exit(1);
    }

    console.log(
      `Clean build OK: ${actual.length} routes built from a cold cache, ` +
        'matching the reviewed inventory exactly.',
    );
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

main();
