// @ts-check
import { defineConfig, passthroughImageService } from 'astro/config';
import { unified } from '@astrojs/markdown-remark';
import starlight from '@astrojs/starlight';

import { rewriteDocLinks } from './src/plugins/rewrite-doc-links.mjs';
import { sidebar } from './src/sidebar.mjs';

/**
 * The compiled site is served from two mount points:
 *
 *   /       the public documentation site
 *   /help   the copy bundled into the Praxis frontend image
 *
 * Both come from the same content in ../docs and the same build command; the
 * mount point is the only input that changes. PRAXIS_DOCS_BASE selects it.
 *
 * PRAXIS_DOCS_SITE is the public origin, and is set for the public build only.
 * It produces canonical URLs and a sitemap, which the public site needs and
 * the bundled copy must not carry: a canonical pointing at the public origin
 * would be wrong inside an offline deployment, and a sitemap there is dead
 * weight. Delivery metadata is the only thing it changes; rendered content and
 * links stay identical, which is what the parity gate proves.
 */
const rawBase = process.env.PRAXIS_DOCS_BASE || '/';
const site = process.env.PRAXIS_DOCS_SITE || undefined;

if (!rawBase.startsWith('/')) {
  throw new Error(`PRAXIS_DOCS_BASE must start with "/" (got "${rawBase}")`);
}

if (site && rawBase !== '/') {
  throw new Error(
    'PRAXIS_DOCS_SITE is for the public build only; it must not be combined ' +
      `with a mount point (got base "${rawBase}").`,
  );
}

export default defineConfig({
  base: rawBase,
  site,
  outDir: process.env.PRAXIS_DOCS_OUTDIR || './dist',
  // The content collection is persisted in the cache directory between runs.
  // PRAXIS_DOCS_CACHE_DIR redirects it so a build can be forced to rediscover
  // every page from disk, which is what a fresh checkout does and what
  // scripts/check-docs-clean-build.mjs reproduces.
  cacheDir: process.env.PRAXIS_DOCS_CACHE_DIR || undefined,
  trailingSlash: 'never',
  build: {
    // Each route becomes "<route>/index.html" and every emitted link is
    // extensionless with no trailing slash. Static hosts resolve that shape
    // natively, and the frontend needs a single rewrite to do the same, so
    // documentation URLs look identical from both mount points.
    format: 'directory',
  },
  // Screenshots are captured at their final size and are copied verbatim.
  // Skipping the sharp-backed service keeps asset bytes identical on every
  // platform, which is what the determinism check depends on.
  image: {
    service: passthroughImageService(),
  },
  compressHTML: true,
  devToolbar: {
    enabled: false,
  },
  markdown: {
    processor: unified({
      rehypePlugins: [[rewriteDocLinks, { base: rawBase }]],
    }),
  },
  integrations: [
    starlight({
      title: 'Praxis',
      description:
        'Operator documentation for Praxis, a self-hosted Linux fleet lifecycle control plane.',
      logo: {
        src: './src/assets/praxis-mark.svg',
        alt: 'Praxis',
        replacesTitle: false,
      },
      favicon: '/favicon.svg',
      // Pagefind ships with Starlight and is indexed at build time. The index
      // and the UI bundle are emitted under the configured base, so search
      // works offline from the bundled copy with no network access.
      pagefind: true,
      credits: false,
      tableOfContents: {
        minHeadingLevel: 2,
        maxHeadingLevel: 3,
      },
      customCss: ['./src/styles/praxis.css'],
      components: {
        // Starlight's default footer links back to a source repository page
        // per document. The public site and the bundled copy have different
        // notions of "edit this page", so the footer is replaced with a
        // static, mount-independent one.
        Footer: './src/components/Footer.astro',
      },
      sidebar,
    }),
  ],
});
