/**
 * PRA-269: shared status/value humanization.
 *
 * One place to turn machine enums (`in_progress`, `NOT_ENROLLED`, `auth-failed`)
 * into operator-readable sentence-case labels, so every table/badge/detail view
 * renders the same string instead of ad-hoc `.replace(/_/g, ' ')` scattered
 * across pages. Sentence case (not Title Case) per the operator-focused UI rules.
 */

// Tokens that should keep a fixed casing rather than being sentence-cased.
// Key is the lowercased token; value is the display form.
const ACRONYMS: Record<string, string> = {
  ssh: 'SSH',
  ssl: 'SSL',
  tls: 'TLS',
  ca: 'CA',
  cpu: 'CPU',
  os: 'OS',
  ip: 'IP',
  id: 'ID',
  url: 'URL',
  api: 'API',
  http: 'HTTP',
  https: 'HTTPS',
  dns: 'DNS',
  sso: 'SSO',
  oidc: 'OIDC',
  mfa: 'MFA',
  totp: 'TOTP',
  json: 'JSON',
  sbom: 'SBOM',
  cve: 'CVE',
  eol: 'EOL',
  vm: 'VM',
  db: 'DB',
  // Package-format initialisms (mirror package_family): render as recognizable
  // tokens rather than an awkward sentence-cased "Deb" / "Rpm".
  deb: 'DEB',
  rpm: 'RPM',
};

// Whole-value overrides for statuses whose humanized form isn't just a
// word-split (e.g. compact/abbreviated enums). Keyed by lowercased raw value.
const STATUS_LABELS: Record<string, string> = {
  not_enrolled: 'Not enrolled',
  in_progress: 'In progress',
  auth_failed: 'Auth failed',
  dead_letter: 'Dead letter',
  n_a: 'N/A',
  na: 'N/A',
  ok: 'OK',
  eol: 'End of life',
  // PRA-271: rollback/state enums whose word-split reads awkwardly.
  rollback_attempted: 'Rollback attempted',
  rollback_attempted_failed: 'Rollback failed',
  rollback_completed: 'Rollback completed',
  not_applicable: 'Not applicable',
  never_checked: 'Never checked',
  not_checked: 'Not checked',
};

function splitWords(raw: string): string[] {
  return raw
    // camelCase / PascalCase -> spaced
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    // separators -> space
    .replace(/[_\-.]+/g, ' ')
    .trim()
    .split(/\s+/)
    .filter(Boolean);
}

/**
 * Turn an arbitrary machine label into a sentence-case, human-readable string.
 * Known acronyms keep their casing; the first word is capitalized, the rest are
 * lowercased (sentence case).
 */
export function humanizeLabel(raw: string | null | undefined): string {
  if (raw === null || raw === undefined) return '';
  const value = String(raw).trim();
  if (!value) return '';

  const words = splitWords(value);
  if (words.length === 0) return '';

  return words
    .map((word, i) => {
      const lower = word.toLowerCase();
      if (ACRONYMS[lower]) return ACRONYMS[lower];
      if (i === 0) return lower.charAt(0).toUpperCase() + lower.slice(1);
      return lower;
    })
    .join(' ');
}

/**
 * Humanize a status/enum value, preferring a shared override when one exists so
 * the same status reads identically everywhere.
 */
export function humanizeStatus(raw: string | null | undefined): string {
  if (raw === null || raw === undefined) return '';
  const value = String(raw).trim();
  if (!value) return '';
  const override = STATUS_LABELS[value.toLowerCase()];
  return override ?? humanizeLabel(value);
}
