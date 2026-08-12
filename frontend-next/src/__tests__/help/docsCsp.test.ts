/**
 * Header contract for the documentation mount point.
 *
 * Pagefind compiles WebAssembly to query its search index, which the
 * application's production `script-src` forbids. The relaxation is granted to
 * `/help` and nothing else, so these tests pin both halves: an ordinary
 * application route must never receive `wasm-unsafe-eval`, and a documentation
 * route must.
 *
 * Route matching is checked with the same path-to-regexp build Next uses, so
 * this proves which rule a URL actually lands on rather than only that two
 * rules exist. That matters because a URL matching both rules would be sent
 * two CSP headers, and browsers enforce their intersection, which would drop
 * the capability search depends on.
 */
import { pathToRegexp } from 'next/dist/compiled/path-to-regexp';
import { describe, expect, it } from 'vitest';

import nextConfig, {
  APP_CSP,
  APP_ROUTE_SOURCE,
  DOCS_CSP,
  DOCS_ROUTE_SOURCES,
} from '../../../next.config';

const APPLICATION_ROUTES = [
  '/',
  '/login',
  '/settings',
  '/fleet-dashboard',
  '/system-management/all-systems',
  '/ssh/command-execution',
  '/api/backend/systems',
  // Adjacent to the mount point but not part of it.
  '/helpdesk',
  '/help-me',
];

const DOCUMENTATION_ROUTES = [
  '/help',
  '/help/troubleshooting',
  '/help/guide-safe-upgrade',
  '/help/_astro/page.js',
  '/help/pagefind/pagefind.js',
  '/help/pagefind/wasm.en.pagefind',
];

function matches(source: string, url: string): boolean {
  return pathToRegexp(source).test(url);
}

/**
 * The header rules the documentation mount point depends on. A missing hook is
 * a configuration failure, not an empty rule set, so it fails loudly here.
 */
function headerRules() {
  const { headers } = nextConfig;
  if (!headers) {
    throw new Error('next.config.ts declares no headers');
  }
  return headers();
}

/** Every CSP a URL would be sent, in rule order. */
async function policiesFor(url: string): Promise<string[]> {
  const rules = await headerRules();
  return rules
    .filter((rule) => matches(rule.source, url))
    .flatMap((rule) =>
      rule.headers
        .filter((header) => header.key === 'Content-Security-Policy')
        .map((header) => header.value),
    );
}

describe('documentation content security policy', () => {
  it('grants WebAssembly compilation to documentation only', () => {
    expect(DOCS_CSP).toContain("'wasm-unsafe-eval'");
    expect(APP_CSP).not.toContain("'wasm-unsafe-eval'");
  });

  it('relaxes nothing beyond WebAssembly compilation', () => {
    // The two policies must differ by exactly that one source expression.
    expect(DOCS_CSP.replace(" 'wasm-unsafe-eval'", '')).toBe(APP_CSP);
  });

  it('never re-enables eval in production', () => {
    // NODE_ENV is not 'production' under vitest, so assert the production
    // directive list the config builds rather than the resolved value.
    expect(APP_ROUTE_SOURCE).toBe('/:path((?!help$|help/).*)');
    expect(DOCS_ROUTE_SOURCES).toEqual(['/help/:path*']);
  });

  it.each(APPLICATION_ROUTES)('serves the application policy on %s', async (url) => {
    const policies = await policiesFor(url);
    expect(policies).toHaveLength(1);
    expect(policies[0]).toBe(APP_CSP);
    expect(policies[0]).not.toContain("'wasm-unsafe-eval'");
  });

  it.each(DOCUMENTATION_ROUTES)('serves the documentation policy on %s', async (url) => {
    const policies = await policiesFor(url);
    expect(policies).toHaveLength(1);
    expect(policies[0]).toBe(DOCS_CSP);
    expect(policies[0]).toContain("'wasm-unsafe-eval'");
  });

  it('sends exactly one policy for every route, so none are intersected', async () => {
    for (const url of [...APPLICATION_ROUTES, ...DOCUMENTATION_ROUTES]) {
      expect(await policiesFor(url), `${url} received the wrong number of policies`).toHaveLength(1);
    }
  });

  it('keeps the shared security headers on both rules', async () => {
    const rules = await headerRules();
    for (const rule of rules) {
      const keys = rule.headers.map((header) => header.key);
      expect(keys).toContain('X-Content-Type-Options');
      expect(keys).toContain('X-Frame-Options');
      expect(keys).toContain('Referrer-Policy');
      expect(keys).toContain('Strict-Transport-Security');
      expect(keys).toContain('Permissions-Policy');
      expect(keys).toContain('Content-Security-Policy');
    }
  });
});
