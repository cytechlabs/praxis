#!/usr/bin/env node
/**
 * Proves the search index does not depend on the order pages are discovered.
 *
 * Pagefind numbers pages as they are added and encodes those numbers into its
 * index chunks, so chunk bytes, their content-hashed filenames, the metadata
 * file, and `pagefind-entry.json` all shift with insertion order. Page
 * fragments do not. Indexing in filesystem order therefore produces a
 * different bundle on a different filesystem, because directory iteration
 * order is not portable, and a bundle generated on one machine fails a parity
 * rebuild on another.
 *
 * `writeSearchIndex` is the boundary that neutralises this. This gate hands it
 * three genuinely different raw orders and requires the emitted trees to be
 * byte identical.
 *
 * Two controls keep the assertion honest:
 *
 *   - the raw orders are asserted to differ from each other before indexing,
 *     so the comparison cannot pass by feeding the same sequence twice; and
 *   - one tree is built by driving Pagefind directly in reversed order,
 *     bypassing the boundary, and is required to differ. That proves the tree
 *     comparison detects order effects rather than being insensitive to them.
 *
 * Usage:
 *   node scripts/check-docs-search-order.mjs <dist-dir>
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  collectPages,
  writeSearchIndex,
} from '../docs-site/src/integrations/deterministic-pagefind.mjs';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function treeOf(dir) {
  const files = new Map();
  const walk = (d, prefix = '') => {
    for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
      const full = path.join(d, entry.name);
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) walk(full, rel);
      else files.set(rel, crypto.createHash('sha256').update(fs.readFileSync(full)).digest('hex'));
    }
  };
  walk(dir);
  return files;
}

function differences(a, b) {
  const problems = [];
  for (const [rel, hash] of a) {
    if (!b.has(rel)) problems.push(`only the first ordering produced "${rel}"`);
    else if (b.get(rel) !== hash) problems.push(`"${rel}" differs between orderings`);
  }
  for (const rel of b.keys()) {
    if (!a.has(rel)) problems.push(`only the second ordering produced "${rel}"`);
  }
  return problems;
}

/** A fixed permutation, so the run is reproducible but the order is not sorted. */
function interleave(pages) {
  const out = [];
  for (let i = 0, j = pages.length - 1; i <= j; i += 1, j -= 1) {
    out.push(pages[j]);
    if (i !== j) out.push(pages[i]);
  }
  return out;
}

/**
 * Pagefind is a dependency of the documentation package, not of the
 * repository root where this script lives, so it is loaded from there through
 * the entry point that package declares.
 */
async function loadPagefind() {
  const dir = path.join(REPO, 'docs-site', 'node_modules', 'pagefind');
  const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
  const entry = manifest.exports?.['.']?.import ?? manifest.main;
  if (!entry) throw new Error('pagefind does not declare an entry point');
  return import(pathToFileURL(path.join(dir, entry)).href);
}

/** Index without the boundary, to prove the comparison notices order. */
async function writeUnordered({ distDir, pages, outputPath }) {
  const pagefind = await loadPagefind();

  try {
    const { index } = await pagefind.createIndex();
    for (const page of pages) {
      await index.addHTMLFile({
        sourcePath: page,
        content: fs.readFileSync(path.join(distDir, page), 'utf8'),
      });
    }
    await index.writeFiles({ outputPath });
  } finally {
    await pagefind.close();
  }
}

async function main() {
  const distArg = process.argv[2];
  if (!distArg) {
    console.error('usage: check-docs-search-order.mjs <dist-dir>');
    process.exit(2);
  }

  const distDir = path.resolve(distArg);
  if (!fs.existsSync(distDir)) {
    console.error(`No build at ${path.relative(REPO, distDir)}. Run scripts/build-docs.mjs first.`);
    process.exit(1);
  }

  const discovered = collectPages(distDir);
  if (discovered.length < 2) {
    console.error(`Need at least two pages under ${path.relative(REPO, distDir)} to test ordering.`);
    process.exit(1);
  }

  const orders = {
    discovered,
    reversed: [...discovered].reverse(),
    interleaved: interleave(discovered),
  };

  // Control: the raw inputs must genuinely differ, or byte identity downstream
  // would prove nothing. This is what the previous version of this gate got
  // wrong; it re-sorted both inputs into the same sequence before comparing.
  const names = Object.keys(orders);
  for (let i = 0; i < names.length; i += 1) {
    for (let j = i + 1; j < names.length; j += 1) {
      if (orders[names[i]].join('\n') === orders[names[j]].join('\n')) {
        console.error(
          `Control failed: raw orders "${names[i]}" and "${names[j]}" are identical, ` +
            'so this test would pass without the ordering boundary doing anything.',
        );
        process.exit(1);
      }
    }
  }

  // Every order must contain the same pages; only the sequence may differ.
  const canonical = [...discovered].sort().join('\n');
  for (const [name, pages] of Object.entries(orders)) {
    if ([...pages].sort().join('\n') !== canonical) {
      console.error(`Control failed: raw order "${name}" does not contain the same pages.`);
      process.exit(1);
    }
  }

  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-pf-order-'));

  try {
    const trees = {};
    for (const [name, pages] of Object.entries(orders)) {
      const out = path.join(scratch, name);
      await writeSearchIndex({ distDir, pages, outputPath: out });
      trees[name] = treeOf(out);
    }

    const problems = [];
    for (const name of names.slice(1)) {
      for (const problem of differences(trees.discovered, trees[name])) {
        problems.push(`${name}: ${problem}`);
      }
    }

    if (problems.length > 0) {
      console.error(
        `Search index is order dependent (${problems.length} differences). ` +
          'It will not reproduce on another filesystem:\n',
      );
      for (const problem of problems.slice(0, 20)) console.error(`  ${problem}`);
      process.exit(1);
    }

    // Control: bypassing the boundary with a reversed order must change the
    // tree. If it does not, the comparison above is not measuring anything.
    const bypass = path.join(scratch, 'bypass');
    await writeUnordered({ distDir, pages: orders.reversed, outputPath: bypass });
    const bypassDifferences = differences(trees.discovered, treeOf(bypass));

    if (bypassDifferences.length === 0) {
      console.error(
        'Control failed: indexing in reversed order without the ordering boundary ' +
          'produced an identical tree, so this test cannot detect order dependence.',
      );
      process.exit(1);
    }

    console.log(
      `Search index order OK: ${discovered.length} pages in ${names.length} different raw ` +
        `orders all produce the same ${trees.discovered.size} files, byte for byte. ` +
        `Bypassing the ordering boundary changes ${bypassDifferences.length} of them, ` +
        'so the comparison is meaningful.',
    );
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}

await main();
