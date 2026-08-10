import type { NextConfig } from "next";

const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// PRA-341: resolve build identity once, at build time. The build date is the
// image/bundle build timestamp (overridable via PRAXIS_BUILD_DATE); environment
// follows NODE_ENV. Exposed to the app as NEXT_PUBLIC_BUILD_* and consumed via
// the canonical contract in src/config/buildInfo.ts. No git/commit — dropped as
// low value (usually 'unknown' for `docker compose build`).
const BUILD_DATE = process.env.PRAXIS_BUILD_DATE || new Date().toISOString();
const BUILD_ENV = process.env.PRAXIS_BUILD_ENV || process.env.NODE_ENV || 'development';

// PRA-226 FRONTEND-02: tighter CSP in production. Dev keeps 'unsafe-eval' and
// wildcard ws/img sources because Next's HMR/React-refresh runtime needs eval
// and the dev overlay opens auxiliary connections. Production drops:
//   - script-src 'unsafe-eval'   (the Next prod runtime does not need eval)
//   - connect-src ws:/wss: wildcards  (the in-app terminal WebSocket is
//     same-origin — wss://<host>/api/backend/... — so 'self' covers it, while
//     the wildcards were an open exfiltration channel to any WS server)
//   - img-src https:             (the app loads no external images)
// 'unsafe-inline' stays on script-src/style-src: Next injects inline bootstrap
// scripts and styles without a nonce pipeline, so removing it would break
// hydration. object-src/base-uri/frame-ancestors/form-action are added as
// defense-in-depth (frame-ancestors also backstops X-Frame-Options).
const PRODUCTION_CSP_DIRECTIVES = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self' data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "frame-ancestors 'none'",
  "form-action 'self'",
];

const DEVELOPMENT_CSP_DIRECTIVES = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: https:",
  "font-src 'self' data:",
  "connect-src 'self' ws: wss:",
];

const CSP_DIRECTIVES = IS_PRODUCTION
  ? PRODUCTION_CSP_DIRECTIVES
  : DEVELOPMENT_CSP_DIRECTIVES;

// The application's policy. Unchanged by the documentation bundle.
export const APP_CSP = CSP_DIRECTIVES.join('; ');

// The bundled documentation at /help searches with Pagefind, which compiles a
// WebAssembly module to query its index. 'wasm-unsafe-eval' permits exactly
// that and nothing else; it does not re-enable eval() or new Function().
//
// It is granted only on the documentation routes. Application routes keep
// APP_CSP verbatim, so serving documentation does not widen the script policy
// anywhere else. The two policies are mutually exclusive by construction: the
// application header rule below excludes /help, because a route matching both
// rules would receive two CSP headers and browsers enforce their intersection,
// which would silently drop the capability search needs.
// Built by extending the single script-src directive in place. Appending a
// second script-src would be silently ignored: where a policy repeats a
// directive, the first occurrence wins.
export const DOCS_CSP = CSP_DIRECTIVES.map((directive) =>
  directive.startsWith('script-src ') ? `${directive} 'wasm-unsafe-eval'` : directive,
).join('; ');

/** Every route except the documentation mount point. */
export const APP_ROUTE_SOURCE = '/:path((?!help$|help/).*)';

/**
 * The documentation mount point and everything under it. The repeating
 * parameter also matches zero segments, so this covers `/help` itself; adding
 * a separate `/help` rule would send that URL two identical CSP headers.
 */
export const DOCS_ROUTE_SOURCES = ['/help/:path*'];

const SHARED_SECURITY_HEADERS = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-XSS-Protection', value: '1; mode=block' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  {
    key: 'Strict-Transport-Security',
    value: 'max-age=31536000; includeSubDomains',
  },
  {
    key: 'Permissions-Policy',
    value: 'geolocation=(), microphone=(), camera=()',
  },
];

const nextConfig: NextConfig = {
  // PRA-27: produces a minimal self-contained server bundle at
  // .next/standalone/ for the production Docker image. No effect on dev.
  output: "standalone",
  // PRA-341: inline the build identity into the client bundle at build time.
  env: {
    NEXT_PUBLIC_BUILD_DATE: BUILD_DATE,
    NEXT_PUBLIC_BUILD_ENV: BUILD_ENV,
  },
  async headers() {
    return [
      {
        source: APP_ROUTE_SOURCE,
        headers: [
          ...SHARED_SECURITY_HEADERS,
          { key: 'Content-Security-Policy', value: APP_CSP },
        ],
      },
      ...DOCS_ROUTE_SOURCES.map((source) => ({
        source,
        headers: [
          ...SHARED_SECURITY_HEADERS,
          { key: 'Content-Security-Policy', value: DOCS_CSP },
        ],
      })),
    ];
  },
  async rewrites() {
    return {
      // The documentation bundled at public/help/ is a pre-built static site.
      // Its pages are emitted as "<slug>/index.html" and it links to them
      // extensionlessly, which is what every static host resolves natively and
      // what Next needs these two rules to reproduce. They run beforeFiles so
      // /help is documentation regardless of what page routes exist.
      //
      // The `[^/.]+` pattern matches a single path segment containing no dot,
      // which is exactly the shape of a documentation slug. Assets are either
      // nested (/help/_astro/..., /help/pagefind/...) or carry an extension
      // (/help/favicon.svg), so both fall through to normal static serving.
      beforeFiles: [
        {
          source: '/help',
          destination: '/help/index.html',
        },
        {
          source: '/help/:slug([^/.]+)',
          destination: '/help/:slug/index.html',
        },
      ],
      afterFiles: [
        {
          source: '/api/backend/:path*',
          destination: 'http://backend:8000/:path*',
        },
        // Proxy Swagger/OpenAPI docs through frontend (access at /backend-docs)
        {
          source: '/backend-docs',
          destination: 'http://backend:8000/docs',
        },
        {
          source: '/backend-redoc',
          destination: 'http://backend:8000/redoc',
        },
        {
          source: '/openapi.json',
          destination: 'http://backend:8000/openapi.json',
        },
      ],
    };
  },
};

export default nextConfig;
