import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * The product version the documentation describes.
 *
 * `frontend-next/src/config/version.ts` is the single hand-maintained build
 * identity value for Praxis. The documentation reads it here at build time so
 * the marker shown on every page, the release pinned by the install and
 * upgrade instructions, and the version the application reports are one
 * value. Nothing in the documentation build writes to that file.
 *
 * The documentation set describes the current release only, so there is
 * exactly one version to state and no version selector to maintain.
 */

const HERE = path.dirname(fileURLToPath(import.meta.url));

export const VERSION_FILE = path.resolve(
  HERE,
  '..',
  '..',
  'frontend-next',
  'src',
  'config',
  'version.ts',
);

/** Read the canonical product version from its declaration. */
export function readProductVersion(file = VERSION_FILE) {
  const source = fs.readFileSync(file, 'utf8');
  const declared = /export const PRODUCT_VERSION\s*=\s*['"]([^'"]+)['"]/.exec(source);

  if (!declared) {
    throw new Error(
      `No PRODUCT_VERSION declaration in ${file}. The documentation version ` +
        'marker is derived from that file and has no other source.',
    );
  }

  return declared[1];
}

export const PRODUCT_VERSION = readProductVersion();

/**
 * Attribute carrying the version on the rendered marker. Machine-readable so
 * the release gate can assert the marker on every emitted page rather than
 * matching prose.
 */
export const VERSION_ATTRIBUTE = 'data-praxis-docs-version';
