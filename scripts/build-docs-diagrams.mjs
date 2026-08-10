#!/usr/bin/env node
/**
 * Renders the documentation's Mermaid diagrams into the committed directory.
 *
 * Rendering Mermaid needs a headless browser, and the documentation site's
 * hosting cannot be assumed to provide one, so the browser runs here and a site
 * build reads what this wrote. `docs-site/src/diagram-cache.mjs` covers why.
 *
 * It works in two passes, because neither half can do the other's job:
 *
 *   1. A throwaway site build reports every Mermaid fence it encountered, with
 *      the exact text it would key that diagram by. Only the build knows how
 *      Markdown turned a fence into text, and a second guess at that would
 *      store diagrams under names the build never looks for.
 *   2. Each reported diagram is rendered here, under plain Node. It cannot be
 *      rendered inside pass 1: the build's imports are served by Vite's module
 *      runner, which is torn down before pages render, so a renderer reached
 *      from there is gone by the time a page would use it.
 *
 * Usage:
 *   node scripts/build-docs-diagrams.mjs           regenerate, in place
 *   node scripts/build-docs-diagrams.mjs --check   fail if the committed files
 *                                                  are not what the source
 *                                                  renders to
 *
 * Both need the browser, which is not needed to build the site. Install it once:
 *   cd docs-site && npx playwright install chromium
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  CACHE_DIR,
  diagramPath,
  readManifest,
  storedKeys,
  writeDiagram,
} from '../docs-site/src/diagram-cache.mjs';
import { renderDiagramSource } from '../docs-site/src/diagram-render.mjs';
import { buildDocs } from './build-docs.mjs';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const sha256 = (file) =>
  crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');

/**
 * Pass 1. Builds the site purely to learn which diagrams it contains.
 *
 * The build reads the committed directory as usual, and a missing diagram is
 * tolerated here rather than fatal, which is what lets this run against an
 * empty directory. Its pages are discarded.
 */
function collect(scratch) {
  const manifest = path.join(scratch, 'diagrams.jsonl');
  fs.writeFileSync(manifest, '');

  buildDocs({
    base: '/',
    outDir: path.join(scratch, 'site'),
    cacheDir: path.join(scratch, 'astro-cache'),
    diagramManifest: manifest,
    quiet: true,
  });

  return readManifest(manifest);
}

/** Pass 2. Renders every collected diagram into `cacheDir`. */
async function render(diagrams, cacheDir) {
  for (const { key, source } of diagrams) {
    writeDiagram(key, await renderDiagramSource(source), cacheDir);
  }
}

/** Regenerates in place, reporting what changed. */
async function regenerate() {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-diagrams-'));

  try {
    const diagrams = collect(scratch);
    const before = storedKeys(CACHE_DIR);

    // Rendering only fills gaps, so a diagram that is no longer referenced
    // would survive. Starting empty makes the directory a statement about the
    // current documentation rather than an accumulation.
    fs.rmSync(CACHE_DIR, { recursive: true, force: true });
    await render(diagrams, CACHE_DIR);

    const after = storedKeys(CACHE_DIR);
    const added = after.filter((key) => !before.includes(key));
    const removed = before.filter((key) => !after.includes(key));

    console.log(
      `Rendered ${after.length} diagram(s) into ${path.relative(REPO, CACHE_DIR)}.`,
    );
    for (const key of added) console.log(`  + ${key}.svg`);
    for (const key of removed) console.log(`  - ${key}.svg (no longer referenced)`);
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

/** Re-renders into a scratch directory and compares with what is committed. */
async function check() {
  const problems = [];
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-diagram-check-'));
  const fresh = path.join(scratch, 'diagrams');

  try {
    const diagrams = collect(scratch);
    await render(diagrams, fresh);

    const committed = storedKeys(CACHE_DIR);
    const rendered = storedKeys(fresh);

    for (const key of rendered) {
      if (!committed.includes(key)) {
        problems.push(`the documentation contains a diagram "${key}" that is not committed`);
      }
    }
    for (const key of committed) {
      if (!rendered.includes(key)) {
        problems.push(`"${key}.svg" is committed but no diagram in the documentation uses it`);
      }
    }
    for (const key of committed) {
      if (!rendered.includes(key)) continue;
      if (sha256(diagramPath(key, CACHE_DIR)) !== sha256(diagramPath(key, fresh))) {
        problems.push(`"${key}.svg" differs from what its source renders to`);
      }
    }

    if (problems.length > 0) {
      console.error(`Rendered diagrams are out of date (${problems.length} problems):\n`);
      for (const problem of problems) console.error(`  ${problem}`);
      console.error('\nRegenerate with: node scripts/build-docs-diagrams.mjs');
      process.exit(1);
    }

    console.log(
      `Rendered diagrams OK: ${committed.length} file(s) in ` +
        `${path.relative(REPO, CACHE_DIR)} reproduce byte for byte.`,
    );
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

await (process.argv.includes('--check') ? check() : regenerate());
