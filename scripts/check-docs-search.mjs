#!/usr/bin/env node
/**
 * Verifies the Pagefind search index shipped with a documentation build.
 *
 * Search has to work with no network, so the index, the WebAssembly module,
 * and the fragments are all part of the build output. This checks that they
 * are present, that the index covers every page, that its URLs carry the
 * mount point the build was made for, and that representative operator terms
 * are actually findable rather than merely indexed to an empty document.
 *
 * Usage:
 *   node scripts/check-docs-search.mjs <dist-dir> [--base /help]
 */

import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';

/** Terms an operator would plausibly search for, drawn from separate pages. */
const REPRESENTATIVE_TERMS = [
  'activation token',
  'maintenance window',
  'rollback',
  'installation ID',
  'smart group',
  'airgap',
  'attestation',
  'host cap',
];

const REQUIRED_FILES = [
  'pagefind/pagefind-entry.json',
  'pagefind/pagefind.js',
  'pagefind/pagefind-ui.js',
];

/** Resolves the command line into the directory to check and its mount point. */
function parseArguments(argv) {
  const [distArg, ...rest] = argv;
  if (!distArg) {
    console.error('usage: check-docs-search.mjs <dist-dir> [--base /help]');
    process.exit(2);
  }

  const baseFlag = rest.indexOf('--base');
  const rawBase = baseFlag === -1 ? '/' : rest[baseFlag + 1];
  const base = !rawBase || rawBase === '/' ? '' : rawBase.replace(/\/$/, '');

  return { dist: path.resolve(distArg), base };
}

/** The files search cannot run without, reported as problems when absent. */
function missingRequiredFiles(dist) {
  return REQUIRED_FILES.filter((rel) => !fs.existsSync(path.join(dist, rel))).map(
    (rel) => `missing ${rel}`,
  );
}

/** Reads the index entry point. Without it there is nothing left to check. */
function readEntry(dist) {
  const entryPath = path.join(dist, 'pagefind', 'pagefind-entry.json');
  if (!fs.existsSync(entryPath)) {
    console.error('Search index check failed: no Pagefind entry point. Build the site first.');
    process.exit(1);
  }
  return JSON.parse(fs.readFileSync(entryPath, 'utf8'));
}

/**
 * The WebAssembly modules that make search work offline; the application CSP
 * grants 'wasm-unsafe-eval' specifically for them.
 */
function wasmModules(dist) {
  return fs.readdirSync(path.join(dist, 'pagefind')).filter((f) => f.endsWith('.pagefind'));
}

/** Every routable page the build emitted. Pagefind skips the 404 page. */
function emittedPages(dist) {
  const pages = [];

  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name === 'index.html') pages.push(full);
    }
  };

  walk(dist);
  return pages;
}

/**
 * Decompresses the fragments, which carry both the searchable content and the
 * URLs a result navigates to.
 */
function readFragments(dist, base) {
  const fragmentDir = path.join(dist, 'pagefind', 'fragment');
  if (!fs.existsSync(fragmentDir)) {
    return { present: false, corpus: '', fragmentCount: 0, badUrls: [] };
  }

  let corpus = '';
  let fragmentCount = 0;
  const badUrls = [];

  for (const name of fs.readdirSync(fragmentDir)) {
    const raw = zlib.gunzipSync(fs.readFileSync(path.join(fragmentDir, name)));
    const text = raw.toString('utf8');
    fragmentCount += 1;
    corpus += ` ${text}`;

    // Indexed URLs are deliberately mount-independent: Pagefind stores
    // "/page/" and the search UI prepends the base at runtime. An indexed
    // URL that already carried the base would be doubled up when clicked.
    for (const match of text.matchAll(/"url":"([^"]+)"/g)) {
      const url = match[1];
      if (!url.startsWith('/')) badUrls.push(url);
      else if (base && url.startsWith(`${base}/`)) badUrls.push(url);
    }
  }

  return { present: true, corpus, fragmentCount, badUrls };
}

/**
 * The base is applied by the search UI, so the emitted bootstrap has to carry
 * the base this build was made for. Without this, search would return results
 * that navigate outside the documentation. Returns null when it is wired.
 */
function bootstrapProblem(dist, base) {
  const astroDir = path.join(dist, '_astro');
  const searchScripts = fs.existsSync(astroDir)
    ? fs.readdirSync(astroDir).filter((f) => f.startsWith('Search.') && f.endsWith('.js'))
    : [];

  if (searchScripts.length === 0) return 'no search bootstrap script was emitted';

  const expected = base === '' ? '/' : base;
  const wired = searchScripts.some((name) => {
    const js = fs.readFileSync(path.join(astroDir, name), 'utf8');
    return js.includes(`baseUrl:\`${expected}\``) || js.includes(`baseUrl:"${expected}"`);
  });

  return wired ? null : `the search bootstrap is not wired to base "${expected}"`;
}

/** Representative operator terms must be findable, not merely indexed. */
function missingTerms(corpus) {
  const haystack = corpus.toLowerCase();
  return REPRESENTATIVE_TERMS.filter((term) => !haystack.includes(term.toLowerCase())).map(
    (term) => `"${term}" is not present in the search index`,
  );
}

function main() {
  const { dist, base } = parseArguments(process.argv.slice(2));
  const problems = missingRequiredFiles(dist);

  const entry = readEntry(dist);
  const languages = Object.values(entry.languages ?? {});
  if (languages.length === 0) problems.push('the index declares no languages');

  const indexedPages = languages.reduce((sum, lang) => sum + (lang.page_count ?? 0), 0);

  const wasm = wasmModules(dist);
  if (wasm.length === 0) problems.push('no WebAssembly module was emitted');

  const htmlPages = emittedPages(dist);
  if (indexedPages !== htmlPages.length) {
    problems.push(
      `the index covers ${indexedPages} pages but the build produced ${htmlPages.length}`,
    );
  }

  const fragments = readFragments(dist, base);
  if (!fragments.present) problems.push('no fragment directory; nothing is searchable');

  if (fragments.badUrls.length > 0) {
    problems.push(
      `${fragments.badUrls.length} indexed URLs are not mount-independent, ` +
        `for example "${fragments.badUrls[0]}"`,
    );
  }

  const bootstrap = bootstrapProblem(dist, base);
  if (bootstrap) problems.push(bootstrap);

  problems.push(...missingTerms(fragments.corpus));

  if (problems.length > 0) {
    console.error(`Search index check failed (${problems.length} problems):\n`);
    for (const problem of problems) console.error(`  ${problem}`);
    process.exit(1);
  }

  console.log(
    `Search index OK: ${indexedPages} pages indexed, ${fragments.fragmentCount} fragments, ` +
      `${wasm.length} WebAssembly modules, base "${base || '/'}".`,
  );
}

main();
