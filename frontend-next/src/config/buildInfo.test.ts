import { describe, it, expect } from 'vitest';
import { getBuildInfo, toCompactDate, BUILD_INFO } from './buildInfo';
import { PRODUCT_VERSION } from './version';

describe('toCompactDate', () => {
  it('compacts a valid ISO date to YYYYMMDD', () => {
    expect(toCompactDate('2026-08-02T12:34:56Z')).toBe('20260802');
    expect(toCompactDate('2026-08-02')).toBe('20260802');
  });
  it('returns empty string for missing/invalid dates', () => {
    expect(toCompactDate('')).toBe('');
    expect(toCompactDate('not-a-date')).toBe('');
  });
});

describe('getBuildInfo', () => {
  it('derives the contract when values are injected', () => {
    const info = getBuildInfo({ date: '2026-08-02T09:00:00Z', env: 'production' });
    expect(info.version).toBe(PRODUCT_VERSION);
    expect(info.buildDate).toBe('2026-08-02T09:00:00Z');
    expect(info.buildDateCompact).toBe('20260802');
    expect(info.environment).toBe('production');
    expect(info.deploymentMode).toBe('Docker');
  });

  it('falls back safely when nothing is injected', () => {
    const info = getBuildInfo({ date: '', env: '' });
    expect(info.version).toBe(PRODUCT_VERSION);
    expect(info.buildDate).toBe('unknown');
    expect(info.buildDateCompact).toBe('');
    expect(info.environment).toBe('development');
    expect(info.deploymentMode).toBe('Docker');
  });

  it('never carries a commit or branch (dropped fields)', () => {
    const info = getBuildInfo({ date: '2026-08-02T09:00:00Z', env: 'production' });
    expect(info).not.toHaveProperty('commitSha');
    expect(info).not.toHaveProperty('commitShort');
    expect(info).not.toHaveProperty('branch');
  });
});

describe('BUILD_INFO (module export)', () => {
  it('always carries the canonical version and Docker deployment mode', () => {
    expect(BUILD_INFO.version).toBe(PRODUCT_VERSION);
    expect(BUILD_INFO.deploymentMode).toBe('Docker');
  });
});
