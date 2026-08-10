/**
 * Contract coverage for the documentation bundled into the frontend image.
 *
 * `/help` is no longer rendered by the application. It serves a pre-built
 * static site that is generated from `docs/` and committed under
 * `public/help/`. These tests pin the two halves of that contract: the built
 * files are present, and the rewrite rules in `next.config.ts` map an
 * extensionless documentation URL onto them while leaving assets alone.
 *
 * The paths asserted here are the ones the application itself links to, so a
 * documentation page that is renamed without a redirect fails this suite
 * rather than becoming a dead help icon in production.
 */
import fs from 'node:fs';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import nextConfig from '../../../next.config';

const HELP_DIR = path.join(process.cwd(), 'public', 'help');

/** Slugs the application deep-links to from `HelpLink`. */
const CONTEXTUAL_SLUGS = [
  'credentials-and-vault',
  'fleet-and-hosts',
  'getting-started',
  'jobs-and-scheduling',
  'monitoring-and-alerts',
  'packages',
  'settings',
  'ssh-and-security',
];

/** The rest of the guides that were reachable at /help/<slug> before. */
const MIGRATED_SLUGS = [
  'admin',
  'compliance-workflows',
  'mirrors-and-airgap',
  'patch-workflows',
  'reports-and-schedules',
];

async function rewriteRules() {
  const rewrites = await nextConfig.rewrites!();
  if (Array.isArray(rewrites)) {
    throw new Error('expected the object form of rewrites');
  }
  return rewrites;
}

/**
 * Reproduces how Next matches `/help/:slug([^/.]+)`, so the guard that keeps
 * assets out of the page rewrite is tested rather than assumed.
 */
const SLUG_PATTERN = /^\/help\/([^/.]+)$/;

describe('bundled documentation', () => {
  it('ships a built site at public/help', () => {
    expect(fs.existsSync(path.join(HELP_DIR, 'index.html'))).toBe(true);
  });

  it('keeps every /help/<slug> the application links to', () => {
    for (const slug of CONTEXTUAL_SLUGS) {
      const page = path.join(HELP_DIR, slug, 'index.html');
      expect(fs.existsSync(page), `missing help page for /help/${slug}`).toBe(true);
    }
  });

  it('keeps the guides that were previously served at /help/<slug>', () => {
    for (const slug of MIGRATED_SLUGS) {
      const page = path.join(HELP_DIR, slug, 'index.html');
      expect(fs.existsSync(page), `missing help page for /help/${slug}`).toBe(true);
    }
  });

  it('ships an offline search index', () => {
    const entry = path.join(HELP_DIR, 'pagefind', 'pagefind-entry.json');
    expect(fs.existsSync(entry)).toBe(true);
    expect(fs.existsSync(path.join(HELP_DIR, 'pagefind', 'pagefind.js'))).toBe(true);
  });

  it('references only same-origin assets so it works offline', () => {
    const html = fs.readFileSync(path.join(HELP_DIR, 'index.html'), 'utf8');
    const externalAssets = [...html.matchAll(/src="(https?:)?\/\/[^"]+"/g)];
    expect(externalAssets.map((m) => m[0])).toEqual([]);
  });

  it('limits optional outbound links to the reviewed public destinations', () => {
    const html = fs.readFileSync(path.join(HELP_DIR, 'index.html'), 'utf8');
    const externalLinks = [...html.matchAll(/href="(https?:\/\/[^"]+)"/g)].map(
      (match) => match[1],
    );

    expect(new Set(externalLinks)).toEqual(
      new Set(['https://praxisfleet.com', 'https://github.com/cytechlabs/praxis']),
    );
  });

  it('rewrites the documentation root and slugs before the filesystem', async () => {
    const { beforeFiles } = await rewriteRules();
    expect(beforeFiles).toEqual([
      { source: '/help', destination: '/help/index.html' },
      { source: '/help/:slug([^/.]+)', destination: '/help/:slug/index.html' },
    ]);
  });

  it('matches page URLs and not asset URLs', () => {
    for (const slug of [...CONTEXTUAL_SLUGS, ...MIGRATED_SLUGS]) {
      expect(SLUG_PATTERN.test(`/help/${slug}`), `/help/${slug} should rewrite`).toBe(true);
    }

    for (const asset of [
      '/help/_astro/page.js',
      '/help/pagefind/pagefind.js',
      '/help/pagefind/pagefind-entry.json',
      '/help/favicon.svg',
      '/help/404.html',
      '/help/index.html',
    ]) {
      expect(SLUG_PATTERN.test(asset), `${asset} should not rewrite`).toBe(false);
    }
  });

  it('leaves the backend proxy rewrites in place', async () => {
    const { afterFiles } = await rewriteRules();
    const sources = afterFiles!.map((rule) => rule.source);
    expect(sources).toContain('/api/backend/:path*');
    expect(sources).toContain('/openapi.json');
  });
});
