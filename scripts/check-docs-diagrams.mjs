#!/usr/bin/env node
/**
 * Verifies that Mermaid diagrams shipped as pictures rather than as source.
 *
 * A fence in `docs/` is plain Mermaid, which is what GitHub renders. The
 * documentation build replaces it with an SVG. Nothing else in the pipeline
 * fails if that step silently stops working: the page still builds, and the
 * fence just reappears as a highlighted code block, which is the state this
 * check exists to catch.
 *
 * For every fence in the source, the corresponding page must contain a drawn
 * diagram, must not contain the Mermaid source as a code block, must label the
 * diagram for a screen reader, and must reference nothing off the origin. The
 * last one matters because the same output is served from an air-gapped
 * deployment, where a remote reference is a broken image.
 *
 * Usage:
 *   node scripts/check-docs-diagrams.mjs <dist-dir> [--base /help]
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { DOCS_DIR, listPublishedSlugs, routeForSlug } from '../docs-site/src/published.mjs';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** Matches an opening Mermaid fence in a Markdown source file. */
const MERMAID_FENCE = /^```mermaid\s*$/gm;

/** Resolves the command line into the directory to check and its mount point. */
function parseArguments(argv) {
  const [distArg, ...rest] = argv;
  if (!distArg) {
    console.error('usage: check-docs-diagrams.mjs <dist-dir> [--base /help]');
    process.exit(2);
  }

  const baseFlag = rest.indexOf('--base');
  const rawBase = baseFlag === -1 ? '/' : rest[baseFlag + 1];
  const base = !rawBase || rawBase === '/' ? '' : rawBase.replace(/\/$/, '');

  return { dist: path.resolve(distArg), base };
}

/** Published slugs whose source contains at least one Mermaid fence. */
function slugsWithDiagrams() {
  const found = new Map();

  for (const slug of listPublishedSlugs()) {
    const source = fs.readFileSync(path.join(DOCS_DIR, `${slug}.md`), 'utf8');
    const fences = source.match(MERMAID_FENCE)?.length ?? 0;
    if (fences > 0) found.set(slug, fences);
  }

  return found;
}

/**
 * The rendered diagrams on a page, as markup.
 *
 * Sliced from the opening tag Mermaid marks with its role to the matching
 * close, so the content checks below look at the diagram rather than at the
 * page's own icons, which would satisfy them on their own.
 */
function diagramsIn(html) {
  const found = [];
  const opening = /<svg\b[^>]*role="graphics-document document"[^>]*>/g;

  for (const match of html.matchAll(opening)) {
    const start = match.index;
    const end = html.indexOf('</svg>', start);
    if (end !== -1) found.push(html.slice(start, end + '</svg>'.length));
  }

  return found;
}

/** The emitted page for a slug, or null when the build did not produce one. */
function pageFor(dist, base, slug) {
  const route = routeForSlug(slug, base);
  const relative = route === '/' || route === base ? '' : route.slice(base.length + 1);
  const file = path.join(dist, relative, 'index.html');
  return fs.existsSync(file) ? { file, html: fs.readFileSync(file, 'utf8') } : null;
}

function main() {
  const { dist, base } = parseArguments(process.argv.slice(2));
  const problems = [];

  if (!fs.existsSync(dist)) {
    console.error(`No build at ${path.relative(REPO, dist)}. Run: node scripts/build-docs.mjs`);
    process.exit(1);
  }

  const expected = slugsWithDiagrams();
  if (expected.size === 0) {
    console.error(
      'No Mermaid fence found in any published page, so this check proves nothing. ' +
        'Remove it if diagrams are gone for good.',
    );
    process.exit(1);
  }

  let diagrams = 0;

  for (const [slug, fences] of expected) {
    const page = pageFor(dist, base, slug);
    if (!page) {
      problems.push(`${slug}: the build emitted no page`);
      continue;
    }

    const { html } = page;
    const where = `${slug}: `;

    // The rendered diagram. Mermaid gives the root SVG this role, so counting
    // it counts diagrams rather than every inline icon on the page.
    const rendered = diagramsIn(html);
    if (rendered.length !== fences) {
      problems.push(
        `${where}${fences} Mermaid fence(s) in the source, ${rendered.length} rendered`,
      );
    }
    diagrams += rendered.length;

    // The failure this check is for: the renderer did not run, so the code
    // block renderer claimed the fence and shipped the source as text.
    if (/data-language="mermaid"/.test(html) || /class="[^"]*language-mermaid/.test(html)) {
      problems.push(`${where}a Mermaid code block reached the page instead of a diagram`);
    }

    // Scrollable wrapper, so a diagram wider than the column cannot widen the
    // page or be scaled down to an unreadable size.
    const wrapped = [...html.matchAll(/<figure class="diagram"/g)].length;
    if (wrapped !== rendered.length) {
      problems.push(
        `${where}${rendered.length} diagram(s) rendered, ${wrapped} wrapped for scrolling`,
      );
    }

    rendered.forEach((svg, index) => {
      const which = `${where}diagram ${index + 1} `;

      // Something was actually drawn. An empty frame passes every other check.
      const shapes = [...svg.matchAll(/<(?:path|rect|circle|polygon|line)\b/g)].length;
      if (shapes < 10) {
        problems.push(`${which}has ${shapes} shapes, so it is effectively blank`);
      }

      // Labels, and a name a screen reader can read out.
      if (!/<tspan[\s>]/.test(svg)) {
        problems.push(`${which}carries no text`);
      }
      if (!/<title id="chart-title-/.test(svg) || !/<desc id="chart-desc-/.test(svg)) {
        problems.push(`${which}has no accessible title and description`);
      }

      // Geometry, so a diagram that measured to nothing cannot pass as one.
      const viewBox = /viewBox="[-\d.]+ [-\d.]+ ([\d.]+) ([\d.]+)"/.exec(svg);
      if (!viewBox || Number(viewBox[1]) < 100 || Number(viewBox[2]) < 100) {
        problems.push(`${which}has no usable viewBox: ${viewBox?.[0] ?? 'missing'}`);
      }
    });
  }

  // Offline safety, over every page the build emitted rather than only the
  // ones with diagrams: a remote reference anywhere would break the bundled
  // copy the same way.
  for (const [slug] of expected) {
    const page = pageFor(dist, base, slug);
    if (!page) continue;
    const remote = [...page.html.matchAll(/(?:href|src|xlink:href)="(https?:)?\/\/[^"]*"/g)]
      .map((match) => match[0])
      .filter((attribute) => !/^href="/.test(attribute));
    if (remote.length > 0) {
      problems.push(`${slug}: diagram page loads a remote asset: ${remote[0]}`);
    }
  }

  if (problems.length > 0) {
    console.error(`Diagram check failed (${problems.length} problems):\n`);
    for (const problem of problems) console.error(`  ${problem}`);
    process.exit(1);
  }

  console.log(
    `Diagrams OK: ${diagrams} rendered across ${expected.size} page(s) in ` +
      `${path.relative(REPO, dist) || '.'}, none left as a code block.`,
  );
}

main();
