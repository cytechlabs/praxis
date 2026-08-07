/**
 * PRA-258: pure timestamp formatting.
 *
 * This module holds NO mutable state and performs NO network I/O — it is a pure
 * formatter. The reactive/loaded preferences live in
 * `context/TimestampPreferencesContext`; call sites subscribe via
 * `useFormatTimestamp()` / `<FormattedTimestamp />`, which pass the current
 * config into `formatTimestamp` here. `formatTimestamp` still works outside
 * React (with the default config) as a low-level utility.
 */

export interface TimestampConfig {
  timezone: string;
  dateFormat: string;
  timeFormat: string;
}

export const DEFAULT_TIMESTAMP_CONFIG: TimestampConfig = {
  timezone: 'UTC',
  dateFormat: 'YYYY-MM-DD',
  timeFormat: '24h',
};

/** Shape of a single app-settings row from `/api/backend/app-settings`. */
export interface AppSettingRow {
  setting_key: string;
  setting_value: string;
}

/**
 * Validate a durable timezone value, returning a usable IANA identifier.
 *
 * Durable settings must store IANA region/city IDs (e.g. `America/New_York`),
 * never display abbreviations like `EDT` — those are seasonal labels derived
 * from `Intl`, not stable zones.
 *
 * Two guards, both falling back deterministically to UTC (the module default):
 *
 *  1. Shape: a durable ID must contain a `/` (region/city), with `UTC` the one
 *     allowed slash-less identifier. This is what rejects abbreviation-like
 *     values — `Intl` in Node happily resolves `EST`/`CST`/`MST`/`PST` to real
 *     zones, so a plain `Intl` probe is too permissive; requiring the IANA shape
 *     keeps the "durable IANA ID only" contract. (`EDT` also fails the next
 *     guard, but the shape check catches the whole abbreviation family.)
 *  2. Resolvability: probe through `Intl.DateTimeFormat`, which throws a
 *     `RangeError` for anything it can't resolve (`garbage`, `Foo/Bar`). Without
 *     this, `toLocaleString({ timeZone })` would throw and crash every render.
 */
export function normalizeTimezone(raw: string | null | undefined): string {
  const fallback = DEFAULT_TIMESTAMP_CONFIG.timezone;
  if (!raw || typeof raw !== 'string') {
    return fallback;
  }
  const value = raw.trim();
  if (value !== 'UTC' && !value.includes('/')) {
    return fallback;
  }
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: value });
    return value;
  } catch {
    return fallback;
  }
}

/**
 * Map raw app-settings rows to a TimestampConfig, falling back to defaults for
 * any missing key. Pure — used by the preferences loader and directly testable.
 * The timezone is normalized here so a bad stored value never reaches (and
 * poisons) the reactive preferences context.
 */
export function parseTimestampConfig(
  settings: AppSettingRow[] | null | undefined,
): TimestampConfig {
  const map: Record<string, string> = {};
  for (const s of settings ?? []) {
    if (s && typeof s.setting_key === 'string') {
      map[s.setting_key] = s.setting_value;
    }
  }
  return {
    timezone: normalizeTimezone(map['timezone'] || DEFAULT_TIMESTAMP_CONFIG.timezone),
    dateFormat: map['date_format'] || DEFAULT_TIMESTAMP_CONFIG.dateFormat,
    timeFormat: map['time_format'] || DEFAULT_TIMESTAMP_CONFIG.timeFormat,
  };
}

function pad(n: number): string {
  return n < 10 ? '0' + n : String(n);
}

function formatDatePart(date: Date, fmt: string): string {
  const y = date.getFullYear();
  const m = date.getMonth() + 1;
  const d = date.getDate();
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

  switch (fmt) {
    case 'MM/DD/YYYY':
      return `${pad(m)}/${pad(d)}/${y}`;
    case 'DD/MM/YYYY':
      return `${pad(d)}/${pad(m)}/${y}`;
    case 'DD.MM.YYYY':
      return `${pad(d)}.${pad(m)}.${y}`;
    case 'MMM DD, YYYY':
      return `${months[date.getMonth()]} ${pad(d)}, ${y}`;
    case 'YYYY-MM-DD':
    default:
      return `${y}-${pad(m)}-${pad(d)}`;
  }
}

function formatTimePart(date: Date, fmt: string): string {
  const h = date.getHours();
  const min = pad(date.getMinutes());
  const sec = pad(date.getSeconds());

  if (fmt === '12h') {
    const period = h >= 12 ? 'PM' : 'AM';
    const h12 = h % 12 || 12;
    return `${h12}:${min}:${sec} ${period}`;
  }
  return `${pad(h)}:${min}:${sec}`;
}

function toTimezone(date: Date, tz: string): Date {
  const str = date.toLocaleString('en-US', { timeZone: tz });
  return new Date(str);
}

function getTzAbbr(date: Date, tz: string): string {
  try {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      timeZoneName: 'short',
    }).formatToParts(date);
    const tzPart = parts.find((p) => p.type === 'timeZoneName');
    return tzPart?.value || tz;
  } catch {
    return tz;
  }
}

export interface FormatTimestampOptions {
  dateOnly?: boolean;
  timeOnly?: boolean;
}

/**
 * Parse an incoming value to a Date, treating a *zoneless* ISO date-time as UTC.
 *
 * PRA-347 defense-in-depth: the API contract is that all timestamps are UTC, but
 * if a route ever serializes a naive datetime with no `Z`/offset (e.g.
 * `2026-08-04T21:24:56`), the JS `Date` constructor parses it as browser-*local*
 * time — so a tz-aware display renders it hours off. The backend is the primary
 * fix (it now appends `Z`); this guard keeps the formatter correct if a bare
 * value slips through. It only applies to strings that carry a time component:
 * a date-only string like `2026-08-04` is already parsed as UTC midnight by JS,
 * and appending `Z` to it would produce an invalid date — so those pass through
 * untouched. Values that already carry a zone (`Z` or `±HH:MM`) are unchanged.
 */
function parseApiDate(value: string): Date {
  const hasTime = /\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/.test(value);
  const hasZone = /(Z|[+-]\d{2}:?\d{2})$/.test(value);
  if (hasTime && !hasZone) {
    return new Date(value + 'Z');
  }
  return new Date(value);
}

/**
 * Format a timestamp using an EXPLICIT config. Pure and synchronous.
 *
 * Config defaults to {@link DEFAULT_TIMESTAMP_CONFIG} so this remains usable
 * from non-React code and during SSR; React consumers pass the loaded config
 * via `useFormatTimestamp()` so displays re-render when preferences change.
 */
export function formatTimestamp(
  value: string | Date | null | undefined,
  options?: FormatTimestampOptions,
  config: TimestampConfig = DEFAULT_TIMESTAMP_CONFIG,
): string {
  if (!value) return '-';

  const date = typeof value === 'string' ? parseApiDate(value) : value;
  if (isNaN(date.getTime())) return '-';

  // Guard here too, not just in parseTimestampConfig: this stays robust when
  // called with a hand-built config (non-React call sites, tests) whose timezone
  // was never validated. Without this a bad `EDT` would throw in toTimezone.
  const tz = normalizeTimezone(config.timezone);
  const converted = toTimezone(date, tz);
  const abbr = getTzAbbr(date, tz);

  if (options?.dateOnly) {
    return formatDatePart(converted, config.dateFormat);
  }

  if (options?.timeOnly) {
    return `${formatTimePart(converted, config.timeFormat)} ${abbr}`;
  }

  return `${formatDatePart(converted, config.dateFormat)} ${formatTimePart(converted, config.timeFormat)} ${abbr}`;
}
