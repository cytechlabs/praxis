/**
 * PRA-341: the single canonical Praxis product version.
 *
 * This is the ONLY intentionally hand-maintained build-identity value. Bump it
 * here on a release; everything else in the build-info contract
 * (`src/config/buildInfo.ts`) is generated/injected at build time. Do not read
 * the product version from anywhere else (the frontend `package.json` version is
 * a separate, unrelated package version).
 */
export const PRODUCT_VERSION = '1.0.0';
