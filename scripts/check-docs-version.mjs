#!/usr/bin/env node
/**
 * Keeps the documentation pinned to one product version.
 *
 * The documentation set describes the current release only. That is a claim
 * with two halves, and this checks both:
 *
 *   marker      every emitted page carries exactly one version marker, and it
 *               is the canonical product version;
 *   pins        every release the documentation tells a reader to check out,
 *               pull, download, or pin is that same version.
 *
 * The canonical version lives in `frontend-next/src/config/version.ts` and is
 * read, never written, by the documentation build. A pin that drifts from it
 * is the failure that matters: an operator who copies an install or upgrade
 * command gets a release the surrounding pages do not describe.
 *
 * Usage:
 *   node scripts/check-docs-version.mjs              check source and builds
 *   node scripts/check-docs-version.mjs --self-test  check the checker
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { DOCS_DIR, listPublishedSlugs } from '../docs-site/src/published.mjs';
import { PRODUCT_VERSION, VERSION_ATTRIBUTE } from '../docs-site/src/version.mjs';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PUBLIC_OUT = path.join(REPO, 'docs-site', 'dist');
const BUNDLED_OUT = path.join(REPO, 'frontend-next', 'public', 'help');

/**
 * Places the documentation names a Praxis release rather than merely
 * mentioning a number. Each pattern captures the version it pins.
 *
 * Third-party versions (OpenBao, an OVAL definition id, an IP address) are
 * deliberately unmatched: they are facts about other software and have
 * nothing to do with which Praxis release these pages describe.
 */
const PIN_PATTERNS = [
  { name: 'PRAXIS_VERSION pin', pattern: /PRAXIS_VERSION\s*=\s*v?(\d+\.\d+\.\d+)/g },
  {
    name: 'release tag',
    pattern: /\b(?:git checkout|gh release (?:download|view|create))\s+v(\d+\.\d+\.\d+)/g,
  },
  {
    name: 'published image tag',
    pattern: /ghcr\.io\/[A-Za-z0-9._/-]*praxis[A-Za-z0-9._-]*:(\d+\.\d+\.\d+)/g,
  },
  { name: 'release artifact name', pattern: /\bsbom-[a-z]+-(\d+\.\d+\.\d+)\.cdx\.json\b/g },
];

/** Every emitted HTML page that makes a documentation claim. */
function* pages(distDir) {
  const walk = function* (dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
      a.name < b.name ? -1 : 1,
    )) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) yield* walk(full);
      else if (entry.name.endsWith('.html')) yield full;
    }
  };

  for (const file of walk(distDir)) {
    // Built from the theme rather than from a document, so it carries no
    // documentation footer.
    if (path.basename(file) === '404.html') continue;
    yield [path.relative(distDir, file), fs.readFileSync(file, 'utf8')];
  }
}

/** Collect every release pin one document states. */
export function findPins(text) {
  const found = [];
  for (const { name, pattern } of PIN_PATTERNS) {
    for (const match of text.matchAll(pattern)) {
      found.push({ name, version: match[1], quote: match[0].trim() });
    }
  }
  return found;
}

function checkSource(problems) {
  let pinsChecked = 0;

  for (const slug of listPublishedSlugs()) {
    const raw = fs.readFileSync(path.join(DOCS_DIR, `${slug}.md`), 'utf8');

    for (const pin of findPins(raw)) {
      pinsChecked += 1;
      if (pin.version !== PRODUCT_VERSION) {
        problems.push(
          `docs/${slug}.md states ${pin.name} "${pin.quote}", ` +
            `but the product version is ${PRODUCT_VERSION}`,
        );
      }
    }
  }

  return pinsChecked;
}

function checkBuild(label, distDir, problems) {
  if (!fs.existsSync(distDir)) {
    problems.push(`no ${label} build at ${path.relative(REPO, distDir)}; run scripts/build-docs.mjs`);
    return 0;
  }

  const marker = new RegExp(`${VERSION_ATTRIBUTE}="([^"]*)"`, 'g');
  let checked = 0;

  for (const [rel, html] of pages(distDir)) {
    const markers = [...html.matchAll(marker)].map((m) => m[1]);

    if (markers.length === 0) {
      problems.push(`${label} page "${rel}" carries no version marker`);
      continue;
    }
    if (markers.length > 1) {
      problems.push(`${label} page "${rel}" carries ${markers.length} version markers; expected one`);
    }
    for (const value of new Set(markers)) {
      if (value !== PRODUCT_VERSION) {
        problems.push(
          `${label} page "${rel}" is marked version "${value}", not ${PRODUCT_VERSION}`,
        );
      }
    }
    // The attribute is what a machine reads; a reader sees the rendered text,
    // so a marker that is present but blank on screen still fails.
    const text = html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
    if (!text.includes(`Version ${PRODUCT_VERSION}`)) {
      problems.push(`${label} page "${rel}" does not render "Version ${PRODUCT_VERSION}" as text`);
    }
    checked += 1;
  }

  if (checked === 0) {
    problems.push(`${label} build produced no pages to check`);
  }

  return checked;
}

/* ------------------------------------------------------------------ */
/* Self-test: the pin matcher has to catch a real drifted pin and      */
/* leave third-party version numbers alone.                            */
/* ------------------------------------------------------------------ */

const SELF_TEST_CASES = [
  { name: 'environment pin', source: 'PRAXIS_VERSION=9.9.9', expect: '9.9.9' },
  { name: 'checkout tag', source: 'git checkout v9.9.9', expect: '9.9.9' },
  { name: 'release download', source: "gh release download v9.9.9 --pattern 'x'", expect: '9.9.9' },
  {
    name: 'image tag',
    source: 'docker pull ghcr.io/cytechlabs/praxis-backend:9.9.9',
    expect: '9.9.9',
  },
  { name: 'sbom artifact', source: 'jq . sbom-backend-9.9.9.cdx.json', expect: '9.9.9' },

  { name: 'loopback address', source: 'Bind to 127.0.0.1 only.', expect: null },
  { name: 'third-party version', source: 'The bundled secrets engine is 2.6.1.', expect: null },
  { name: 'control identifier', source: '| CC7.2.4 | Detection |', expect: null },
  { name: 'digest placeholder', source: 'praxis-backend@sha256:<digest>', expect: null },
  { name: 'image tag by digest', source: 'ghcr.io/cytechlabs/praxis-backend:latest', expect: null },
];

function selfTest() {
  const failures = [];

  for (const testCase of SELF_TEST_CASES) {
    const pins = findPins(testCase.source);
    const versions = pins.map((p) => p.version);

    if (testCase.expect && !versions.includes(testCase.expect)) {
      failures.push(
        `${testCase.name}: expected to pin "${testCase.expect}", found ${versions.length === 0 ? 'nothing' : versions.join(', ')}`,
      );
    }
    if (!testCase.expect && pins.length > 0) {
      failures.push(`${testCase.name}: expected no pin, found ${versions.join(', ')}`);
    }
  }

  if (failures.length > 0) {
    console.error(`Documentation version self-test failed (${failures.length}):\n`);
    for (const failure of failures) console.error(`  ${failure}`);
    process.exit(1);
  }

  const pinned = SELF_TEST_CASES.filter((c) => c.expect).length;
  console.log(
    `Documentation version self-test OK: ${pinned} release pins detected, ` +
      `${SELF_TEST_CASES.length - pinned} unrelated version numbers ignored.`,
  );
}

/* ------------------------------------------------------------------ */

function main() {
  if (process.argv.includes('--self-test')) {
    selfTest();
    return;
  }

  const problems = [];
  const pinsChecked = checkSource(problems);
  const publicPages = checkBuild('public site', PUBLIC_OUT, problems);
  const bundledPages = checkBuild('bundled copy', BUNDLED_OUT, problems);

  if (problems.length > 0) {
    console.error(`Documentation version check failed (${problems.length} problems):\n`);
    for (const problem of problems.slice(0, 40)) console.error(`  ${problem}`);
    if (problems.length > 40) console.error(`  ... and ${problems.length - 40} more`);
    console.error(
      `\nThe canonical version is ${PRODUCT_VERSION}, from frontend-next/src/config/version.ts.`,
    );
    process.exit(1);
  }

  console.log(
    `Documentation version OK: ${publicPages} public and ${bundledPages} bundled pages ` +
      `marked ${PRODUCT_VERSION}, and ${pinsChecked} release pins in source agree.`,
  );
}

main();
