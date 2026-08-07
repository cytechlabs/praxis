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
const CSP = IS_PRODUCTION
  ? [
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
    ].join('; ')
  : "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' ws: wss:";

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
        source: '/(.*)',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-XSS-Protection', value: '1; mode=block' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          {
            key: 'Content-Security-Policy',
            value: CSP,
          },
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=31536000; includeSubDomains',
          },
          {
            key: 'Permissions-Policy',
            value: 'geolocation=(), microphone=(), camera=()',
          },
        ],
      },
    ];
  },
  async rewrites() {
    return [
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
    ];
  },
};

export default nextConfig;
