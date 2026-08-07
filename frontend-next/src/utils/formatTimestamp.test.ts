import { describe, it, expect } from 'vitest';

import {
  DEFAULT_TIMESTAMP_CONFIG,
  formatTimestamp,
  normalizeTimezone,
  parseTimestampConfig,
  type TimestampConfig,
} from './formatTimestamp';

// A fixed UTC instant. With a UTC config the wall-clock parts are deterministic
// regardless of the test runner's timezone.
const UTC_INPUT = '2026-03-15T14:30:45Z';
const UTC: TimestampConfig = { timezone: 'UTC', dateFormat: 'YYYY-MM-DD', timeFormat: '24h' };

describe('formatTimestamp — null/invalid', () => {
  it('returns "-" for null/undefined/empty/invalid', () => {
    expect(formatTimestamp(null, undefined, UTC)).toBe('-');
    expect(formatTimestamp(undefined, undefined, UTC)).toBe('-');
    expect(formatTimestamp('', undefined, UTC)).toBe('-');
    expect(formatTimestamp('not-a-date', undefined, UTC)).toBe('-');
  });
});

describe('formatTimestamp — date formats (UTC)', () => {
  const cases: Array<[string, string]> = [
    ['YYYY-MM-DD', '2026-03-15'],
    ['MM/DD/YYYY', '03/15/2026'],
    ['DD/MM/YYYY', '15/03/2026'],
    ['DD.MM.YYYY', '15.03.2026'],
    ['MMM DD, YYYY', 'Mar 15, 2026'],
  ];
  for (const [dateFormat, expected] of cases) {
    it(`${dateFormat} -> ${expected}`, () => {
      const out = formatTimestamp(UTC_INPUT, { dateOnly: true }, { ...UTC, dateFormat });
      expect(out).toBe(expected);
    });
  }
});

describe('formatTimestamp — time formats (UTC)', () => {
  it('24h', () => {
    expect(formatTimestamp(UTC_INPUT, { timeOnly: true }, { ...UTC, timeFormat: '24h' })).toBe(
      '14:30:45 UTC',
    );
  });
  it('12h', () => {
    expect(formatTimestamp(UTC_INPUT, { timeOnly: true }, { ...UTC, timeFormat: '12h' })).toBe(
      '2:30:45 PM UTC',
    );
  });
});

describe('formatTimestamp — combined + timezone label', () => {
  it('full string includes date, time, and tz abbreviation', () => {
    expect(formatTimestamp(UTC_INPUT, undefined, UTC)).toBe('2026-03-15 14:30:45 UTC');
  });
});

describe('formatTimestamp — reactive at the pure level', () => {
  it('produces DIFFERENT output for different configs (drives rerender value)', () => {
    const a = formatTimestamp(UTC_INPUT, undefined, {
      timezone: 'UTC',
      dateFormat: 'YYYY-MM-DD',
      timeFormat: '24h',
    });
    const b = formatTimestamp(UTC_INPUT, undefined, {
      timezone: 'UTC',
      dateFormat: 'MM/DD/YYYY',
      timeFormat: '12h',
    });
    expect(a).not.toBe(b);
  });

  it('defaults to DEFAULT_TIMESTAMP_CONFIG when no config passed', () => {
    const withDefault = formatTimestamp(UTC_INPUT);
    const explicit = formatTimestamp(UTC_INPUT, undefined, DEFAULT_TIMESTAMP_CONFIG);
    expect(withDefault).toBe(explicit);
  });
});

// A summer instant (US DST in effect on 2026-03-15) and a winter instant
// (standard time on 2026-01-15). Same wall-clock UTC time so only the zone/DST
// differs. Runner-TZ independent: formatTimestamp's double-conversion cancels
// the local zone, so these assertions hold no matter where the tests run.
const SUMMER_UTC = '2026-03-15T14:30:45Z';
const WINTER_UTC = '2026-01-15T14:30:45Z';

describe('normalizeTimezone', () => {
  it('passes through valid IANA identifiers unchanged', () => {
    expect(normalizeTimezone('America/New_York')).toBe('America/New_York');
    expect(normalizeTimezone('Europe/Paris')).toBe('Europe/Paris');
    expect(normalizeTimezone('UTC')).toBe('UTC');
  });

  it('keeps UTC (the one allowed slash-less identifier)', () => {
    expect(normalizeTimezone('UTC')).toBe('UTC');
  });

  it('rejects display abbreviations, not just the throwing ones', () => {
    // EDT throws in Intl, but EST/CST/MST/PST resolve to real zones in Node —
    // the IANA-shape guard rejects the whole abbreviation family regardless, so
    // durable settings never confuse a display label with a stored timezone.
    for (const abbr of ['EDT', 'EST', 'CST', 'MST', 'PST', 'GMT', 'PDT']) {
      expect(normalizeTimezone(abbr)).toBe('UTC');
    }
  });

  it('falls back to UTC for junk / empty / nullish input', () => {
    expect(normalizeTimezone('garbage')).toBe('UTC');
    expect(normalizeTimezone('Foo/Bar')).toBe('UTC');
    expect(normalizeTimezone('')).toBe('UTC');
    expect(normalizeTimezone(null)).toBe('UTC');
    expect(normalizeTimezone(undefined)).toBe('UTC');
  });
});

describe('formatTimestamp — IANA timezone + seasonal abbreviation', () => {
  const eastern: TimestampConfig = {
    timezone: 'America/New_York',
    dateFormat: 'YYYY-MM-DD',
    timeFormat: '24h',
  };

  it('renders a summer UTC instant as Eastern Daylight Time (EDT)', () => {
    // 14:30:45Z − 4h = 10:30:45 EDT on the same calendar day.
    expect(formatTimestamp(SUMMER_UTC, undefined, eastern)).toBe('2026-03-15 10:30:45 EDT');
  });

  it('renders a winter UTC instant as Eastern Standard Time (EST)', () => {
    // 14:30:45Z − 5h = 09:30:45 EST on the same calendar day.
    expect(formatTimestamp(WINTER_UTC, undefined, eastern)).toBe('2026-01-15 09:30:45 EST');
  });
});

describe('formatTimestamp — zoneless datetime treated as UTC (defense-in-depth)', () => {
  const eastern: TimestampConfig = {
    timezone: 'America/New_York',
    dateFormat: 'YYYY-MM-DD',
    timeFormat: '24h',
  };

  it('parses a naive datetime (no Z) as UTC, not browser-local', () => {
    // The reopened bug: a bare "2026-08-04T21:24:56" must render as 17:24 EDT,
    // the same as the explicit-UTC "...Z" form — never 21:24 EDT.
    const naive = formatTimestamp('2026-08-04T21:24:56', undefined, eastern);
    const withZ = formatTimestamp('2026-08-04T21:24:56Z', undefined, eastern);
    expect(naive).toBe('2026-08-04 17:24:56 EDT');
    expect(naive).toBe(withZ);
  });

  it('leaves an explicit offset untouched', () => {
    // 17:24:56-04:00 is the same instant as 21:24:56Z → 17:24 EDT.
    expect(formatTimestamp('2026-08-04T17:24:56-04:00', undefined, eastern)).toBe(
      '2026-08-04 17:24:56 EDT',
    );
  });

  it('does not corrupt a date-only string (no bogus Z → no Invalid Date)', () => {
    // "2026-03-15" must stay a valid date; appending Z would make it invalid.
    expect(formatTimestamp('2026-03-15', { dateOnly: true }, UTC)).toBe('2026-03-15');
  });
});

describe('formatTimestamp — bad/legacy timezone does not crash', () => {
  it('falls back to UTC output instead of throwing on EDT', () => {
    const bad: TimestampConfig = {
      timezone: 'EDT',
      dateFormat: 'YYYY-MM-DD',
      timeFormat: '24h',
    };
    // Without the guard, toLocaleString({ timeZone: 'EDT' }) throws a RangeError
    // and crashes every timestamp render. Now it deterministically formats UTC.
    expect(() => formatTimestamp(SUMMER_UTC, undefined, bad)).not.toThrow();
    expect(formatTimestamp(SUMMER_UTC, undefined, bad)).toBe('2026-03-15 14:30:45 UTC');
  });
});

describe('parseTimestampConfig', () => {
  it('maps known keys', () => {
    const cfg = parseTimestampConfig([
      { setting_key: 'timezone', setting_value: 'America/New_York' },
      { setting_key: 'date_format', setting_value: 'MM/DD/YYYY' },
      { setting_key: 'time_format', setting_value: '12h' },
      { setting_key: 'unrelated', setting_value: 'ignored' },
    ]);
    expect(cfg).toEqual({
      timezone: 'America/New_York',
      dateFormat: 'MM/DD/YYYY',
      timeFormat: '12h',
    });
  });

  it('normalizes a bad stored timezone to UTC so context is never poisoned', () => {
    const cfg = parseTimestampConfig([{ setting_key: 'timezone', setting_value: 'EDT' }]);
    expect(cfg.timezone).toBe('UTC');
  });

  it('falls back to defaults for missing keys / null / empty', () => {
    expect(parseTimestampConfig([])).toEqual(DEFAULT_TIMESTAMP_CONFIG);
    expect(parseTimestampConfig(null)).toEqual(DEFAULT_TIMESTAMP_CONFIG);
    expect(parseTimestampConfig(undefined)).toEqual(DEFAULT_TIMESTAMP_CONFIG);
    expect(
      parseTimestampConfig([{ setting_key: 'timezone', setting_value: 'Europe/Paris' }]),
    ).toEqual({
      timezone: 'Europe/Paris',
      dateFormat: DEFAULT_TIMESTAMP_CONFIG.dateFormat,
      timeFormat: DEFAULT_TIMESTAMP_CONFIG.timeFormat,
    });
  });
});
