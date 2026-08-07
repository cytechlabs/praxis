import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

/**
 * PRA-258 SSR/import safety: importing the timestamp modules must NOT trigger a
 * network fetch, and the loader must return defaults without fetching when there
 * is no window (SSR). This is a node-environment test — `window` is undefined.
 */

describe('timestamp preferences — import & SSR safety', () => {
  const fetchSpy = vi.fn();

  beforeEach(() => {
    fetchSpy.mockReset();
    vi.stubGlobal('fetch', fetchSpy);
    vi.resetModules();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('does not fetch at module import time', async () => {
    await import('../utils/formatTimestamp');
    await import('./TimestampPreferencesContext');
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('fetchTimestampConfig returns defaults WITHOUT fetching under SSR (no window)', async () => {
    expect(typeof window).toBe('undefined'); // node env
    const { fetchTimestampConfig } = await import('./TimestampPreferencesContext');
    const { DEFAULT_TIMESTAMP_CONFIG } = await import('../utils/formatTimestamp');

    const cfg = await fetchTimestampConfig();

    expect(cfg).toEqual(DEFAULT_TIMESTAMP_CONFIG);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
