import { describe, it, expect } from 'vitest';
import { createLatestRequestTracker } from './useLatestRequest';

describe('createLatestRequestTracker', () => {
  it('marks only the newest request current', () => {
    const t = createLatestRequestTracker();
    const first = t.begin();
    const second = t.begin();
    expect(first()).toBe(false); // superseded
    expect(second()).toBe(true); // newest
  });

  it('a stale request resolving AFTER a newer one never becomes current', () => {
    const t = createLatestRequestTracker();
    const stale = t.begin();
    const fresh = t.begin();
    // Newer resolves first and commits.
    expect(fresh()).toBe(true);
    // Older resolves later — still stale, so its success/catch/finally are all skipped.
    expect(stale()).toBe(false);
  });

  it('invalidate() supersedes every in-flight request (unmount)', () => {
    const t = createLatestRequestTracker();
    const inflight = t.begin();
    t.invalidate();
    expect(inflight()).toBe(false);
  });

  it('the current request stays current until explicitly superseded', () => {
    const t = createLatestRequestTracker();
    const only = t.begin();
    expect(only()).toBe(true);
    expect(only()).toBe(true); // idempotent while newest
  });
});

// Simulates the real page bug: two loads race and the OLDER response resolves
// last. Only the newest response may commit data / clear loading / show errors.
describe('out-of-order response handling with the guard', () => {
  type Ctrl = { resolve: (v: string) => void; reject: (e: Error) => void; promise: Promise<string> };
  function deferred(): Ctrl {
    let resolve!: (v: string) => void;
    let reject!: (e: Error) => void;
    const promise = new Promise<string>((res, rej) => {
      resolve = res;
      reject = rej;
    });
    return { resolve, reject, promise };
  }

  it('older success cannot overwrite newer data, nor clear newer loading', async () => {
    const tracker = createLatestRequestTracker();
    let committedData: string | null = null;
    let loading = false;

    const load = async (source: Ctrl) => {
      const isCurrent = tracker.begin();
      loading = true;
      try {
        const data = await source.promise;
        if (!isCurrent()) return;
        committedData = data;
      } finally {
        if (isCurrent()) loading = false;
      }
    };

    const older = deferred();
    const newer = deferred();
    const olderRun = load(older); // request A (selection A)
    const newerRun = load(newer); // request B (selection B) supersedes A

    // B resolves first and commits.
    newer.resolve('B-data');
    await newerRun;
    expect(committedData).toBe('B-data');
    expect(loading).toBe(false);

    // A resolves LATE — must be ignored: data stays B, loading stays false.
    older.resolve('A-data');
    await olderRun;
    expect(committedData).toBe('B-data');
    expect(loading).toBe(false);
  });

  it('older failure cannot clear newer loading state or surface a stale error', async () => {
    const tracker = createLatestRequestTracker();
    let errorShown: string | null = null;
    let loading = false;

    const load = async (source: Ctrl) => {
      const isCurrent = tracker.begin();
      loading = true;
      try {
        await source.promise;
      } catch (e) {
        if (!isCurrent()) return;
        errorShown = (e as Error).message;
      } finally {
        if (isCurrent()) loading = false;
      }
    };

    const older = deferred();
    const newer = deferred();
    const olderRun = load(older);
    const newerRun = load(newer); // newest — still in flight

    // Older request FAILS after being superseded.
    older.reject(new Error('stale error'));
    await olderRun;
    // The stale failure must NOT show an error and must NOT clear the newer
    // request's loading state.
    expect(errorShown).toBeNull();
    expect(loading).toBe(true);

    // Newer finally resolves and clears loading.
    newer.resolve('ok');
    await newerRun;
    expect(errorShown).toBeNull();
    expect(loading).toBe(false);
  });
});
