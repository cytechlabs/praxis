/**
 * Minimal typing for the path-to-regexp build bundled inside Next.
 *
 * The header-contract test compiles route `source` patterns with the exact
 * matcher Next uses at runtime, rather than a separately installed copy that
 * could drift from it. That bundled build ships no declaration file, so only
 * the one function the test calls is declared here.
 */
declare module 'next/dist/compiled/path-to-regexp' {
  export function pathToRegexp(path: string): RegExp;
}
