import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * The rendered form of every Mermaid diagram in the documentation.
 *
 * Rendering Mermaid means running a headless browser. The documentation site's
 * hosting cannot be assumed to provide one: the build image documents no
 * browser and no way to install the system libraries one needs. A deploy that
 * had to launch a browser would be one base-image change away from failing to
 * publish the public site.
 *
 * So the browser runs where it is known to exist, at authoring time and in CI,
 * and its output is committed here. A site build reads these files and needs
 * nothing but Node; nothing in the build's module graph reaches the renderer or
 * Playwright. `scripts/build-docs-diagrams.mjs` regenerates the directory and,
 * with `--check`, proves the committed files are what the current source
 * renders to.
 *
 * A file is named for the hash of the diagram source it came from, so an edited
 * diagram cannot silently keep its old picture: the name stops matching and the
 * build fails until the directory is regenerated.
 */
export const CACHE_DIR = process.env.PRAXIS_DOCS_DIAGRAM_CACHE
  ? path.resolve(process.env.PRAXIS_DOCS_DIAGRAM_CACHE)
  : fileURLToPath(new URL('../diagrams', import.meta.url));

/** The name a diagram source is stored under. */
export function diagramKey(source) {
  return createHash('sha256').update(source, 'utf8').digest('hex').slice(0, 16);
}

/** Where a key is stored, in whichever directory is configured. */
export function diagramPath(key, cacheDir = CACHE_DIR) {
  return path.join(cacheDir, `${key}.svg`);
}

/** The stored SVG for a key, or null when nothing is stored. */
export function readDiagram(key, cacheDir = CACHE_DIR) {
  const file = diagramPath(key, cacheDir);
  return fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : null;
}

/** Stores the SVG for a key, creating the directory on first write. */
export function writeDiagram(key, svg, cacheDir = CACHE_DIR) {
  fs.mkdirSync(cacheDir, { recursive: true });
  fs.writeFileSync(diagramPath(key, cacheDir), svg);
}

/** Every key currently stored, sorted. */
export function storedKeys(cacheDir = CACHE_DIR) {
  if (!fs.existsSync(cacheDir)) return [];
  return fs
    .readdirSync(cacheDir)
    .filter((name) => name.endsWith('.svg'))
    .map((name) => name.slice(0, -'.svg'.length))
    .sort();
}

/**
 * Where a build should record the diagram sources it encountered.
 *
 * Regeneration cannot re-read the fences out of `docs/` on its own without
 * guessing how Markdown turned them into text, and a guess that is subtly wrong
 * stores a diagram under a name the build will never look for. Instead the
 * build itself reports what it saw, and the renderer works from that, so the
 * two agree by construction rather than by reimplementation.
 */
export const MANIFEST = process.env.PRAXIS_DOCS_DIAGRAM_MANIFEST || '';

/** Appends one encountered diagram to the manifest. */
export function recordDiagram(key, source, manifest = MANIFEST) {
  fs.appendFileSync(manifest, `${JSON.stringify({ key, source })}\n`);
}

/** Every distinct diagram a collecting build recorded, in a stable order. */
export function readManifest(manifest) {
  const seen = new Map();

  for (const line of fs.readFileSync(manifest, 'utf8').split('\n')) {
    if (line === '') continue;
    const { key, source } = JSON.parse(line);
    if (!seen.has(key)) seen.set(key, source);
  }

  return [...seen].sort(([a], [b]) => (a < b ? -1 : 1)).map(([key, source]) => ({ key, source }));
}
