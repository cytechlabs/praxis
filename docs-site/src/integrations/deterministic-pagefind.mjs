import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Imported statically, as Starlight's own integration does. Resolving it
// inside the build:done hook would go through Vite's module runner, which is
// already closed by the time the hook runs.
import * as pagefind from 'pagefind';

/**
 * Builds the Pagefind search index in a reproducible order.
 *
 * Pagefind numbers pages as they are added and encodes those numbers into its
 * index chunks, so the chunk bytes, their content-hashed filenames, the
 * metadata file, and `pagefind-entry.json` all depend on insertion order. The
 * page fragments do not, because each is addressed by its own content.
 *
 * Starlight's built-in integration adds pages with `addDirectory`, which walks
 * the output directory in filesystem order. On ext4 that order comes from a
 * hash seeded per filesystem at creation time, so two machines indexing byte
 * identical pages produce different index chunks. The build is reproducible on
 * any one machine and irreproducible across machines, which is why a bundle
 * generated on a workstation fails a parity check rebuilt on a CI runner.
 *
 * The ordering invariant lives in `writeSearchIndex`, which sorts a copy of
 * whatever it is handed. Enforcing it there rather than in the caller means no
 * caller can index in an unstable order by accident, and the property can be
 * tested by feeding the boundary genuinely different orders.
 */

/** Deterministic everywhere, unlike String.prototype.localeCompare. */
export function byCodeUnit(a, b) {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

/**
 * Every built HTML page, in **filesystem discovery order**.
 *
 * The order is deliberately not normalised here. It is whatever the filesystem
 * yields, which is exactly the unstable input `writeSearchIndex` is
 * responsible for neutralising, and it gives the regression gate a genuinely
 * unsorted order to test with.
 */
export function collectPages(distDir) {
  const pages = [];

  const walk = (dir, prefix) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        // The output directory is where the index is written; never index it.
        if (rel === 'pagefind') continue;
        walk(path.join(dir, entry.name), rel);
      } else if (entry.name.endsWith('.html')) {
        pages.push(rel);
      }
    }
  };

  walk(distDir, '');
  return pages;
}

/**
 * Index the given pages and write the bundle.
 *
 * This is the ordering boundary. The supplied list is copied and sorted before
 * anything is added, so the emitted bundle depends only on which pages exist
 * and what they contain, never on the order they arrived in.
 */
export async function writeSearchIndex({ distDir, pages, outputPath }) {
  const ordered = [...pages].sort(byCodeUnit);

  try {
    const { index, errors } = await pagefind.createIndex();
    if (errors?.length) throw new Error(`Pagefind: ${errors.join(', ')}`);

    for (const page of ordered) {
      const { errors: addErrors } = await index.addHTMLFile({
        // Pagefind derives the indexed URL from this path, so it must stay
        // relative to the output root to match what a reader requests.
        sourcePath: page,
        content: fs.readFileSync(path.join(distDir, page), 'utf8'),
      });
      if (addErrors?.length) throw new Error(`Pagefind (${page}): ${addErrors.join(', ')}`);
    }

    // Replace rather than merge: chunk filenames are content hashes, so a
    // leftover chunk from an earlier run would linger as an orphan.
    fs.rmSync(outputPath, { recursive: true, force: true });

    const { errors: writeErrors } = await index.writeFiles({ outputPath });
    if (writeErrors?.length) throw new Error(`Pagefind: ${writeErrors.join(', ')}`);
  } finally {
    await pagefind.close();
  }

  return ordered.length;
}

export function deterministicPagefind() {
  return {
    name: 'praxis:deterministic-pagefind',
    hooks: {
      'astro:build:done': async ({ dir, logger }) => {
        const distDir = fileURLToPath(dir);
        const outputPath = fileURLToPath(new URL('./pagefind/', dir));

        const count = await writeSearchIndex({
          distDir,
          pages: collectPages(distDir),
          outputPath,
        });
        logger.info(`Indexed ${count} pages for search in reproducible order.`);
      },
    },
  };
}
