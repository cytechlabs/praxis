#!/usr/bin/env node
/**
 * Proves the committed bundled documentation is the same build as the public
 * site, and that both are reproducible.
 *
 * `docs/` is the only source. It produces two outputs because Astro bakes the
 * mount point into every emitted URL, and the public site is served at / while
 * the application serves its copy at /help. A single byte-identical artifact
 * therefore cannot serve both. What is guaranteed instead, and checked here,
 * is stronger than "two directories exist":
 *
 *   determinism  rebuilding either output reproduces it byte for byte, so the
 *                committed bundle is exactly what the source produces and two
 *                machines publishing the same commit publish the same bytes;
 *   parity       the public and bundled outputs have the same routes, the same
 *                assets, and the same rendered text, differing only by the
 *                mount-point prefix.
 *
 * Together those mean the two cannot drift: neither can change without the
 * shared source changing, and a stale committed bundle fails the build.
 *
 * Usage:
 *   node scripts/check-docs-bundle.mjs
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  buildDocs,
  BUNDLED_BASE,
  BUNDLED_OUT,
  PUBLIC_OUT,
  PUBLIC_SITE,
} from './build-docs.mjs';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/**
 * Delivery metadata the public site carries and the bundled copy must not.
 * A sitemap of public URLs is meaningless inside an operator's deployment,
 * and a canonical pointing at the public origin would be wrong there. These
 * are the only permitted inventory differences; rendered content and links
 * are still compared page by page.
 */
const PUBLIC_ONLY_FILES = new Set(['sitemap-index.xml', 'sitemap-0.xml']);

function walk(dir, prefix = '', found = new Map()) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
    a.name < b.name ? -1 : 1,
  )) {
    const full = path.join(dir, entry.name);
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) walk(full, rel, found);
    else found.set(rel, full);
  }
  return found;
}

const sha256 = (file) =>
  crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');

/**
 * Strips everything that legitimately differs between the two mount points:
 * the base prefix on every URL, and the content hashes of assets whose bytes
 * embed that prefix. What is left is the rendered document.
 */
function normalise(html, base) {
  let out = html;
  if (base) out = out.split(base).join('');
  // Asset filenames carry a content hash; the base is an input to the bundles,
  // so the hash of a script legitimately differs between the two builds.
  out = out.replace(/\.[A-Za-z0-9_-]{8,}\.(js|css|png|svg|woff2?)/g, '.HASH.$1');
  out = out.replace(/_[A-Za-z0-9_-]{5,}\.(png|svg|jpg|jpeg|webp)/g, '_HASH.$1');
  return out;
}

/**
 * Collapses the content hash out of a generated filename.
 *
 * Asset and search-index filenames are hashes of their own bytes, and the
 * mount point is one of those bytes, so the same source file is named
 * differently in the two builds. Comparing the collapsed names compares which
 * assets exist rather than what they happen to be called.
 */
function assetKey(rel) {
  return rel
    .replace(/\.[A-Za-z0-9_-]{8,}\.(js|css|png|svg|jpg|jpeg|webp|woff2?)$/, '.HASH.$1')
    .replace(/_[A-Za-z0-9_-]{5,}\.(png|svg|jpg|jpeg|webp)$/, '_HASH.$1')
    .replace(/en_[0-9a-f]{6,}\.(pf_fragment|pf_index|pf_meta)$/, 'en_HASH.$1')
    .replace(/\.en_[0-9a-f]{6,}\.(pf_meta)$/, '.en_HASH.$1')
    .replace(/wasm[._][A-Za-z0-9_.-]+\.pagefind$/, 'wasm.HASH.pagefind');
}

/** Counts per collapsed name, so a set of hashed siblings still compares. */
function inventory(files) {
  const counts = new Map();
  for (const rel of files.keys()) {
    const key = assetKey(rel);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return counts;
}

function textOf(html) {
  return html
    .replace(/<script\b[\s\S]*?<\/script>/g, '')
    .replace(/<style\b[\s\S]*?<\/style>/g, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Rebuilds one variant into a scratch directory and compares it with the copy
 * on disk, so a non-reproducible build and a stale output both fail. The
 * scratch directory is always removed.
 *
 * Both variants are checked. The bundled copy is committed, so a stale one
 * would ship inside the image; the public site is built by its host, so a
 * non-reproducible one means two people publishing the same commit get
 * different bytes. The same comparison catches both.
 */
function checkDeterminism(label, onDisk, buildOptions, regenerateCommand) {
  const problems = [];
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'praxis-docs-'));
  const rebuiltDir = path.join(scratch, 'rebuilt');

  try {
    buildDocs({ ...buildOptions, outDir: rebuiltDir, quiet: true });
    const rebuilt = walk(rebuiltDir);

    for (const rel of onDisk.keys()) {
      if (!rebuilt.has(rel)) {
        problems.push(`${label} has "${rel}", which a fresh build does not produce`);
      }
    }
    for (const rel of rebuilt.keys()) {
      if (!onDisk.has(rel)) {
        problems.push(`a fresh build produces "${rel}", which ${label} is missing`);
      }
    }
    for (const [rel, file] of onDisk) {
      if (!rebuilt.has(rel)) continue;
      if (sha256(file) !== sha256(rebuilt.get(rel))) {
        problems.push(`${label} differs from a fresh build at "${rel}"`);
      }
    }

    if (problems.length > 0) {
      problems.push(`Regenerate with: ${regenerateCommand}`);
    }
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }

  return problems;
}

/** Compares which assets each build emitted, collapsing content hashes. */
function checkInventoryParity(publicFiles, bundledFiles) {
  const problems = [];
  const publicInventory = inventory(publicFiles);
  const bundledInventory = inventory(bundledFiles);

  for (const [key, count] of publicInventory) {
    if (PUBLIC_ONLY_FILES.has(key)) continue;
    const other = bundledInventory.get(key) ?? 0;
    if (other !== count) {
      problems.push(
        `"${key}": public site has ${count}, the bundled copy has ${other}`,
      );
    }
  }
  for (const key of bundledInventory.keys()) {
    if (!publicInventory.has(key)) {
      problems.push(`bundled copy has "${key}"; the public site does not`);
    }
  }

  return problems;
}

/** Compares the rendered text of every page both builds produced. */
function checkRenderedText(publicFiles, bundledFiles) {
  const problems = [];
  let comparedPages = 0;

  for (const [rel, file] of publicFiles) {
    if (!rel.endsWith('.html') || !bundledFiles.has(rel)) continue;
    comparedPages += 1;

    const publicHtml = normalise(fs.readFileSync(file, 'utf8'), '');
    const bundledHtml = normalise(fs.readFileSync(bundledFiles.get(rel), 'utf8'), BUNDLED_BASE);

    if (textOf(publicHtml) !== textOf(bundledHtml)) {
      problems.push(`rendered text differs between the two builds at "${rel}"`);
    }
  }

  if (comparedPages === 0) {
    problems.push('no pages were compared; the parity check is not doing anything');
  }

  return { problems, comparedPages };
}

/** Every public page must claim a canonical URL under the public origin. */
function checkPublicCanonicals(publicFiles) {
  const problems = [];
  let canonicals = 0;

  for (const [rel, file] of publicFiles) {
    if (!rel.endsWith('.html') || rel === '404.html') continue;
    const html = fs.readFileSync(file, 'utf8');
    const canonical = /<link rel="canonical" href="([^"]+)"/.exec(html);

    if (!canonical) {
      problems.push(`public page "${rel}" has no canonical URL`);
      continue;
    }
    if (!canonical[1].startsWith(`${PUBLIC_SITE}/`) && canonical[1] !== PUBLIC_SITE) {
      problems.push(`public page "${rel}" has canonical "${canonical[1]}", not under ${PUBLIC_SITE}`);
    }
    canonicals += 1;
  }

  return { problems, canonicals };
}

/** The delivery metadata belongs to the public site and nowhere else. */
function checkPublicOnlyFiles(publicFiles, bundledFiles) {
  const problems = [];

  for (const name of PUBLIC_ONLY_FILES) {
    if (!publicFiles.has(name)) problems.push(`the public site is missing "${name}"`);
    if (bundledFiles.has(name)) problems.push(`the bundled copy must not contain "${name}"`);
  }

  return problems;
}

/** The sitemap must list URLs, all of them under the public origin. */
function checkSitemap(publicFiles) {
  const problems = [];
  const sitemap = publicFiles.has('sitemap-0.xml')
    ? fs.readFileSync(publicFiles.get('sitemap-0.xml'), 'utf8')
    : '';
  const sitemapUrls = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1]);

  if (sitemapUrls.length === 0) {
    problems.push('the public sitemap lists no URLs');
  }
  for (const url of sitemapUrls) {
    if (!url.startsWith(PUBLIC_SITE)) {
      problems.push(`the public sitemap lists "${url}", which is not under ${PUBLIC_SITE}`);
      break;
    }
  }

  return { problems, sitemapUrls };
}

/**
 * The bundled copy is served from an operator's own deployment, offline.
 * Nothing in it may reference the public origin or claim a canonical.
 */
function checkBundledIsSelfContained(bundledFiles) {
  const problems = [];

  for (const [rel, file] of bundledFiles) {
    if (!rel.endsWith('.html')) continue;
    const html = fs.readFileSync(file, 'utf8');
    if (/<link rel="canonical"/.test(html)) {
      problems.push(`bundled page "${rel}" carries a canonical URL`);
    }
    if (html.includes(PUBLIC_SITE)) {
      problems.push(`bundled page "${rel}" references the public origin ${PUBLIC_SITE}`);
    }
  }

  return problems;
}

function main() {
  if (!fs.existsSync(BUNDLED_OUT)) {
    console.error(
      `No bundled documentation at ${path.relative(REPO, BUNDLED_OUT)}. ` +
        'Run: node scripts/build-docs.mjs',
    );
    process.exit(1);
  }

  const committed = walk(BUNDLED_OUT);
  const problems = checkDeterminism(
    'the committed bundle',
    committed,
    { base: BUNDLED_BASE },
    'node scripts/build-docs.mjs --bundled, then commit the result',
  );

  if (!fs.existsSync(PUBLIC_OUT)) {
    problems.push(
      `No public build at ${path.relative(REPO, PUBLIC_OUT)}. Run: node scripts/build-docs.mjs --public`,
    );
  } else {
    const publicFiles = walk(PUBLIC_OUT);
    const bundledFiles = walk(BUNDLED_OUT);

    problems.push(
      ...checkDeterminism(
        'the public site build',
        publicFiles,
        { base: '/', site: PUBLIC_SITE },
        'node scripts/build-docs.mjs --public',
      ),
    );

    problems.push(...checkInventoryParity(publicFiles, bundledFiles));

    const rendered = checkRenderedText(publicFiles, bundledFiles);
    problems.push(...rendered.problems);

    const canonical = checkPublicCanonicals(publicFiles);
    problems.push(...canonical.problems);

    problems.push(...checkPublicOnlyFiles(publicFiles, bundledFiles));

    const sitemap = checkSitemap(publicFiles);
    problems.push(...sitemap.problems);

    problems.push(...checkBundledIsSelfContained(bundledFiles));

    if (problems.length === 0) {
      console.log(
        `Bundled documentation OK: ${committed.size} bundled and ${publicFiles.size} public ` +
          'files reproduce byte for byte, ' +
          `${rendered.comparedPages} pages match the public site, ` +
          `${canonical.canonicals} public canonicals and ${sitemap.sitemapUrls.length} sitemap URLs use ${PUBLIC_SITE}, ` +
          'and the bundled copy carries neither.',
      );
    }
  }

  if (problems.length > 0) {
    console.error(`Bundled documentation check failed (${problems.length} problems):\n`);
    for (const problem of problems.slice(0, 40)) console.error(`  ${problem}`);
    if (problems.length > 40) console.error(`  ... and ${problems.length - 40} more`);
    process.exit(1);
  }
}

main();
