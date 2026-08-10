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

function main() {
  const [distArg, ...rest] = process.argv.slice(2);
  if (!distArg) {
    console.error('usage: check-docs-search.mjs <dist-dir> [--base /help]');
    process.exit(2);
  }

  const baseFlag = rest.indexOf('--base');
  const rawBase = baseFlag === -1 ? '/' : rest[baseFlag + 1];
  const base = !rawBase || rawBase === '/' ? '' : rawBase.replace(/\/$/, '');

  const dist = path.resolve(distArg);
  const problems = [];

  for (const rel of REQUIRED_FILES) {
    if (!fs.existsSync(path.join(dist, rel))) problems.push(`missing ${rel}`);
  }

  const entryPath = path.join(dist, 'pagefind', 'pagefind-entry.json');
  if (!fs.existsSync(entryPath)) {
    console.error('Search index check failed: no Pagefind entry point. Build the site first.');
    process.exit(1);
  }

  const entry = JSON.parse(fs.readFileSync(entryPath, 'utf8'));
  const languages = Object.values(entry.languages ?? {});
  if (languages.length === 0) problems.push('the index declares no languages');

  const indexedPages = languages.reduce((sum, lang) => sum + (lang.page_count ?? 0), 0);

  // The WebAssembly module is what makes search work offline; the application
  // CSP grants 'wasm-unsafe-eval' specifically for it.
  const wasm = fs
    .readdirSync(path.join(dist, 'pagefind'))
    .filter((f) => f.endsWith('.pagefind'));
  if (wasm.length === 0) problems.push('no WebAssembly module was emitted');

  // Every routable page should be indexed. Pagefind skips the 404 page.
  const htmlPages = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.name === 'index.html') htmlPages.push(full);
    }
  };
  walk(dist);

  if (indexedPages !== htmlPages.length) {
    problems.push(
      `the index covers ${indexedPages} pages but the build produced ${htmlPages.length}`,
    );
  }

  // Decompress the fragments to confirm real content, and correct URLs.
  const fragmentDir = path.join(dist, 'pagefind', 'fragment');
  let corpus = '';
  let fragmentCount = 0;
  const badUrls = [];

  if (!fs.existsSync(fragmentDir)) {
    problems.push('no fragment directory; nothing is searchable');
  } else {
    for (const name of fs.readdirSync(fragmentDir)) {
      const raw = zlib.gunzipSync(fs.readFileSync(path.join(fragmentDir, name)));
      const text = raw.toString('utf8');
      fragmentCount += 1;
      corpus += ` ${text}`;

      // Indexed URLs are deliberately mount-independent: Pagefind stores
      // "/page/" and the search UI prepends the base at runtime. An indexed
      // URL that already carried the base would be doubled up when clicked.
      for (const m of text.matchAll(/"url":"([^"]+)"/g)) {
        const url = m[1];
        if (!url.startsWith('/')) badUrls.push(url);
        else if (base && url.startsWith(`${base}/`)) badUrls.push(url);
      }
    }
  }

  if (badUrls.length > 0) {
    problems.push(
      `${badUrls.length} indexed URLs are not mount-independent, ` +
        `for example "${badUrls[0]}"`,
    );
  }

  // The base is applied by the search UI, so the emitted bootstrap has to
  // carry the base this build was made for. Without this, search would return
  // results that navigate outside the documentation.
  const astroDir = path.join(dist, '_astro');
  const searchScripts = fs.existsSync(astroDir)
    ? fs.readdirSync(astroDir).filter((f) => f.startsWith('Search.') && f.endsWith('.js'))
    : [];

  if (searchScripts.length === 0) {
    problems.push('no search bootstrap script was emitted');
  } else {
    const expected = base === '' ? '/' : base;
    const wired = searchScripts.some((f) => {
      const js = fs.readFileSync(path.join(astroDir, f), 'utf8');
      return js.includes(`baseUrl:\`${expected}\``) || js.includes(`baseUrl:"${expected}"`);
    });
    if (!wired) {
      problems.push(`the search bootstrap is not wired to base "${expected}"`);
    }
  }

  const haystack = corpus.toLowerCase();
  for (const term of REPRESENTATIVE_TERMS) {
    if (!haystack.includes(term.toLowerCase())) {
      problems.push(`"${term}" is not present in the search index`);
    }
  }

  if (problems.length > 0) {
    console.error(`Search index check failed (${problems.length} problems):\n`);
    for (const problem of problems) console.error(`  ${problem}`);
    process.exit(1);
  }

  console.log(
    `Search index OK: ${indexedPages} pages indexed, ${fragmentCount} fragments, ` +
      `${wasm.length} WebAssembly modules, base "${base || '/'}".`,
  );
}

main();
