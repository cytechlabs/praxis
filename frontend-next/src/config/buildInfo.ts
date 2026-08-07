import { PRODUCT_VERSION } from './version';

/**
 * PRA-341: the single canonical build-identity contract.
 *
 * Every surface (the footer badge, the About panel) reads from HERE so identity
 * can't drift. The product `version` is hand-maintained in `version.ts`; the
 * build date + environment are injected at build time by `next.config.ts` as
 * `NEXT_PUBLIC_BUILD_*`, with safe fallbacks so dev / Docker / CI never crash.
 *
 * Deliberately NOT surfaced: commit SHA (dropped — usually `unknown` for
 * `docker compose build` and low value), branch, internal PRA/slice names,
 * secrets, tokens, container IDs, hostnames, internal/DB/Vault URLs.
 */
export interface BuildInfo {
  /** Product version (hand-maintained, one place). */
  version: string;
  /** Full ISO 8601 build timestamp, or 'unknown'. */
  buildDate: string;
  /** Compact UTC build date `YYYYMMDD`, or '' when unavailable. */
  buildDateCompact: string;
  /** Build environment: production / development / test. */
  environment: string;
  /** Deployment mode — all supported 1.0 deploys are Docker. */
  deploymentMode: 'Docker';
}

/** The raw, injected build values (before defaults are applied). */
export interface RawBuildEnv {
  date: string;
  env: string;
}

/** `2026-08-02T12:00:00Z` → `20260802`; empty string when not a valid ISO date. */
export function toCompactDate(iso: string): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(iso);
  return m ? `${m[1]}${m[2]}${m[3]}` : '';
}

/** Pure derivation of the build contract from raw env — with safe fallbacks. */
export function getBuildInfo(raw: RawBuildEnv): BuildInfo {
  return {
    version: PRODUCT_VERSION,
    buildDate: raw.date || 'unknown',
    buildDateCompact: toCompactDate(raw.date),
    environment: raw.env || 'development',
    deploymentMode: 'Docker',
  };
}

// These reads are statically inlined by Next at build time (see next.config.ts).
const RAW: RawBuildEnv = {
  date: process.env.NEXT_PUBLIC_BUILD_DATE || '',
  env: process.env.NEXT_PUBLIC_BUILD_ENV || process.env.NODE_ENV || 'development',
};

export const BUILD_INFO: BuildInfo = getBuildInfo(RAW);
