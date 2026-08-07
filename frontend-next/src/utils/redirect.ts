/**
 * PRA-250: post-login redirect sanitization.
 *
 * `returnUrl` on the login page comes straight from attacker-controllable query
 * data. Passing it to `router.push()` unchecked is an open redirect: a crafted
 * `/login?returnUrl=https://evil.example` (or an encoded/backslash/scheme-relative
 * variant) can bounce an authenticated user to a phishing origin.
 *
 * `safeLoginReturnUrl` reduces the value to a single, normalized, same-origin
 * application path or falls back to "/". It is intentionally strict: it only ever
 * returns "/" or the original input verbatim (so valid query/hash fragments are
 * preserved exactly), and it never returns anything that could leave the app
 * origin.
 */

const FALLBACK = "/";

/**
 * Sanitize a login `returnUrl` down to a safe same-origin path.
 *
 * Accepts only a string that:
 *  - is a string (not an array from repeated query params, not nullish);
 *  - starts with exactly one "/" (not "//" scheme-relative, not "/\" backslash);
 *  - contains no raw control characters (browsers strip tab/newline from URLs,
 *    which can turn "/<TAB>/evil" into scheme-relative "//evil");
 *  - contains no raw or percent-encoded backslash;
 *  - does not decode (or normalize) into a "//host" scheme-relative form;
 *  - stays same-origin when resolved against a dummy origin.
 *
 * Malformed percent-encoding (which would throw in `decodeURIComponent`) and any
 * other unexpected shape fall back to "/". On success the ORIGINAL value is
 * returned unchanged so legitimate query strings and hash fragments survive.
 */
export function safeLoginReturnUrl(
  value: string | string[] | undefined | null,
): string {
  // Arrays (?returnUrl=a&returnUrl=b), undefined, null, or any non-string.
  if (typeof value !== "string" || value.length === 0) {
    return FALLBACK;
  }

  // Must be a rooted internal path: exactly one leading slash. Reject
  // scheme-relative "//host" and backslash-authority "/\host" up front. This
  // also rejects protocol URLs (https:, javascript:, ...) and bare
  // percent-encoded payloads, since none of those begin with "/".
  if (value[0] !== "/" || value[1] === "/" || value[1] === "\\") {
    return FALLBACK;
  }

  // Raw control characters (tab, newline, NUL, DEL, ...) are stripped by
  // browsers when parsing URLs and can smuggle "/<TAB>/evil" -> "//evil".
  // Legitimate paths encode these; a raw one is hostile. Checked by char code
  // to avoid a control-character regex.
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code <= 0x1f || code === 0x7f) {
      return FALLBACK;
    }
  }

  // Any raw backslash: some browsers treat "\" as "/", so "/\evil" or "/foo\bar"
  // could become an authority. Reject before and after decoding.
  if (value.includes("\\")) {
    return FALLBACK;
  }

  // Decode to catch encoded slash/backslash tricks (%2f, %5c). Malformed
  // encoding throws -> reject.
  let decoded: string;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    return FALLBACK;
  }

  // After decoding it must still be a single-slash-rooted path with no
  // backslash: rejects "/%2f%2fevil" -> "///evil" and "/foo%5cbar" -> "/foo\bar".
  if (decoded.startsWith("//") || decoded.includes("\\")) {
    return FALLBACK;
  }

  // Defense in depth: resolve against a dummy origin and require the result to
  // stay on that origin with a rooted path. Anything absolute or scheme-relative
  // resolves to a different origin.
  try {
    const base = "http://localhost";
    const resolved = new URL(value, base);
    if (resolved.origin !== base || resolved.pathname.startsWith("//")) {
      return FALLBACK;
    }
  } catch {
    return FALLBACK;
  }

  return value;
}
