#!/usr/bin/env node
/**
 * Validates the built documentation site: internal links, heading anchors,
 * and every asset a page references.
 *
 * This runs over the compiled HTML rather than the Markdown source, so it sees
 * what a reader would actually follow, including links the Markdown rewriter
 * produced and anchors generated from headings.
 *
 * Usage:
 *   node scripts/check-docs-links.mjs <dist-dir> [--base /help]
 */

import fs from 'node:fs';
import path from 'node:path';

const EXTERNAL = /^(?:[a-z][a-z0-9+.-]*:|\/\/)/i;

function walk(dir, found = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, found);
    else found.push(full);
  }
  return found;
}

/** Route -> the set of element ids that route's page defines. */
function indexPages(distDir, base) {
  const pages = new Map();

  for (const file of walk(distDir)) {
    if (!file.endsWith('.html')) continue;

    const html = fs.readFileSync(file, 'utf8');
    const relative = path.relative(distDir, file).split(path.sep).join('/');

    let route;
    if (relative === 'index.html') route = base === '' ? '/' : base;
    else if (relative.endsWith('/index.html')) {
      route = `${base}/${relative.slice(0, -'/index.html'.length)}`;
    } else {
      route = `${base}/${relative}`;
    }

    const ids = new Set();
    for (const m of html.matchAll(/\sid="([^"]+)"/g)) ids.add(m[1]);
    for (const m of html.matchAll(/\sname="([^"]+)"/g)) ids.add(m[1]);

    pages.set(route, { file, html, ids });
  }

  return pages;
}

function main() {
  const [distArg, ...rest] = process.argv.slice(2);
  if (!distArg) {
    console.error('usage: check-docs-links.mjs <dist-dir> [--base /help]');
    process.exit(2);
  }

  const baseFlag = rest.indexOf('--base');
  const rawBase = baseFlag === -1 ? '/' : rest[baseFlag + 1];
  const base = !rawBase || rawBase === '/' ? '' : rawBase.replace(/\/$/, '');

  const distDir = path.resolve(distArg);
  const pages = indexPages(distDir, base);

  if (pages.size === 0) {
    console.error(`No HTML found in ${distDir}. Build the site first.`);
    process.exit(1);
  }

  const assets = new Set(
    walk(distDir).map((f) => {
      const rel = path.relative(distDir, f).split(path.sep).join('/');
      return `${base}/${rel}`;
    }),
  );

  const problems = [];
  let checkedLinks = 0;
  let checkedAssets = 0;

  for (const [route, page] of pages) {
    const where = path.relative(distDir, page.file);

    for (const m of page.html.matchAll(/<a\b[^>]*\shref="([^"]*)"/g)) {
      const href = m[1];
      if (!href || EXTERNAL.test(href) || href.startsWith('mailto:')) continue;
      checkedLinks += 1;

      if (!href.startsWith('/')) {
        if (href.startsWith('#')) {
          const anchor = decodeURIComponent(href.slice(1));
          if (anchor && !page.ids.has(anchor)) {
            problems.push(`${where}: anchor "#${anchor}" has no matching id`);
          }
          continue;
        }
        problems.push(`${where}: relative link "${href}" is not base-safe`);
        continue;
      }

      const [target, fragment] = href.split('#');
      const clean = target.replace(/\/$/, '') || '/';

      if (base && !(clean === base || clean.startsWith(`${base}/`))) {
        problems.push(`${where}: link "${href}" escapes the base "${base}"`);
        continue;
      }

      if (pages.has(clean)) {
        if (fragment && !pages.get(clean).ids.has(decodeURIComponent(fragment))) {
          problems.push(`${where}: "${href}" targets a heading that does not exist`);
        }
        continue;
      }

      if (assets.has(clean)) continue;

      problems.push(`${where}: link "${href}" does not resolve to a page or asset`);
    }

    for (const m of page.html.matchAll(/<(?:img|script)\b[^>]*\ssrc="([^"]*)"/g)) {
      const src = m[1];
      if (!src || EXTERNAL.test(src) || src.startsWith('data:')) continue;
      checkedAssets += 1;
      if (!assets.has(src.split('?')[0])) {
        problems.push(`${where}: asset "${src}" is missing from the build`);
      }
    }

    for (const m of page.html.matchAll(/<link\b[^>]*\shref="([^"]*)"/g)) {
      const href = m[1];
      if (!href || EXTERNAL.test(href) || href.startsWith('data:')) continue;
      checkedAssets += 1;
      if (!assets.has(href.split('?')[0])) {
        problems.push(`${where}: stylesheet or icon "${href}" is missing from the build`);
      }
    }
  }

  if (problems.length > 0) {
    console.error(`Documentation link check failed (${problems.length} problems):\n`);
    for (const problem of problems) console.error(`  ${problem}`);
    process.exit(1);
  }

  console.log(
    `Documentation links OK: ${pages.size} pages, ` +
      `${checkedLinks} internal links, ${checkedAssets} asset references, base "${base || '/'}".`,
  );
}

main();
