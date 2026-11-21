// @vitest-environment jsdom
// PRA-259: useUrlState follows router query changes (back/forward, links)
// without replace loops or lost updates between hook instances.
import { act, renderHook } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

type Query = Record<string, string | string[] | undefined>;

const state = vi.hoisted(() => ({
  router: null as unknown as Record<string, unknown>,
  listeners: new Set<() => void>(),
}));

vi.mock('next/router', () => ({ useRouter: () => state.router }));

import { useUrlState } from './useUrlState';

function makeRouter(query: Query, isReady = true) {
  const router = {
    isReady,
    pathname: '/page',
    query,
    replace: vi.fn(() => Promise.resolve(true)),
  };
  state.router = router;
  return router;
}

// Simulates the router publishing a new query (navigation or settled replace).
function navigate(query: Query, isReady = true) {
  state.router = { ...(state.router as object), query, isReady };
}

beforeEach(() => {
  makeRouter({});
});

describe('useUrlState', () => {
  it('reads the initial value from the query and defaults when absent', () => {
    makeRouter({ status: 'active' });
    const withValue = renderHook(() => useUrlState('status', 'all'));
    expect(withValue.result.current[0]).toBe('active');
    makeRouter({});
    const withDefault = renderHook(() => useUrlState('status', 'all'));
    expect(withDefault.result.current[0]).toBe('all');
  });

  it('hydrates once the router becomes ready (bookmark / reload)', () => {
    makeRouter({}, false);
    const { result, rerender } = renderHook(() => useUrlState('status', 'all'));
    expect(result.current[0]).toBe('all');
    act(() => navigate({ status: 'down' }, true));
    rerender();
    expect(result.current[0]).toBe('down');
  });

  it('does not write to the URL before the router is ready', () => {
    const router = makeRouter({}, false);
    const { result } = renderHook(() => useUrlState('status', 'all'));
    act(() => result.current[1]('down'));
    expect(router.replace).not.toHaveBeenCalled();
    expect(result.current[0]).toBe('down');
  });

  it('follows back/forward query changes, including a removed key', () => {
    makeRouter({ status: 'down' });
    const { result, rerender } = renderHook(() => useUrlState('status', 'all'));
    act(() => navigate({ status: 'active' }));
    rerender();
    expect(result.current[0]).toBe('active');
    act(() => navigate({}));
    rerender();
    expect(result.current[0]).toBe('all');
  });

  it('treats empty and array params as the default', () => {
    makeRouter({ status: '' });
    expect(renderHook(() => useUrlState('status', 'all')).result.current[0]).toBe('all');
    makeRouter({ status: ['a', 'b'] });
    expect(renderHook(() => useUrlState('status', 'all')).result.current[0]).toBe('all');
  });

  it('writes a shallow replace preserving unrelated params', () => {
    const router = makeRouter({ keep: ['1', '2'], other: 'x' });
    const { result } = renderHook(() => useUrlState('status', 'all'));
    act(() => result.current[1]('down'));
    expect(router.replace).toHaveBeenCalledTimes(1);
    expect(router.replace).toHaveBeenCalledWith(
      { pathname: '/page', query: { keep: ['1', '2'], other: 'x', status: 'down' } },
      undefined,
      { shallow: true },
    );
    expect(result.current[0]).toBe('down');
  });

  it('removes the param when set to the default or empty', () => {
    const router = makeRouter({ status: 'down', other: 'x' });
    const { result } = renderHook(() => useUrlState('status', 'all'));
    act(() => result.current[1]('all'));
    expect(router.replace).toHaveBeenLastCalledWith(
      { pathname: '/page', query: { other: 'x' } },
      undefined,
      { shallow: true },
    );
  });

  it('does not replace when the URL already matches (no loops)', () => {
    const router = makeRouter({ status: 'down' });
    const { result, rerender } = renderHook(() => useUrlState('status', 'all'));
    act(() => result.current[1]('down'));
    expect(router.replace).not.toHaveBeenCalled();
    // Navigation echoes never trigger writes.
    act(() => navigate({ status: 'active' }));
    rerender();
    rerender();
    expect(router.replace).not.toHaveBeenCalled();
  });

  it('keeps simultaneous updates from several instances (no lost update)', () => {
    const router = makeRouter({ keep: 'z' });
    const { result } = renderHook(() => ({
      status: useUrlState('status', 'all'),
      env: useUrlState('env', 'all'),
    }));
    // Both setters run before the router publishes either change.
    act(() => {
      result.current.status[1]('down');
      result.current.env[1]('prod');
    });
    const calls = router.replace.mock.calls as unknown as Array<[{ query: Query }]>;
    expect(calls).toHaveLength(2);
    expect(calls[1][0].query).toEqual({ keep: 'z', status: 'down', env: 'prod' });
  });

  it('keeps newer local input when the echo of an earlier write arrives', () => {
    makeRouter({});
    const { result, rerender } = renderHook(() => useUrlState('search', ''));
    act(() => result.current[1]('a'));
    act(() => result.current[1]('ab'));
    act(() => navigate({ search: 'a' }));
    rerender();
    expect(result.current[0]).toBe('ab');
    act(() => navigate({ search: 'ab' }));
    rerender();
    expect(result.current[0]).toBe('ab');
  });

  it('adopts an external change to the same key after own writes settle', () => {
    makeRouter({});
    const { result, rerender } = renderHook(() => useUrlState('search', ''));
    act(() => result.current[1]('a'));
    act(() => navigate({ search: 'a' }));
    rerender();
    act(() => navigate({ search: 'zzz' }));
    rerender();
    expect(result.current[0]).toBe('zzz');
  });

  it('re-reads when the key or default changes', () => {
    makeRouter({ b: 'two' });
    const { result, rerender } = renderHook(({ k, d }) => useUrlState(k, d), {
      initialProps: { k: 'a', d: 'x' },
    });
    expect(result.current[0]).toBe('x');
    rerender({ k: 'b', d: 'x' });
    expect(result.current[0]).toBe('two');
    rerender({ k: 'c', d: 'y' });
    expect(result.current[0]).toBe('y');
  });

  function deferred<T>() {
    let resolve!: (v: T) => void;
    let reject!: (e: unknown) => void;
    const promise = new Promise<T>((res, rej) => {
      resolve = res;
      reject = rej;
    });
    return { promise, resolve, reject };
  }

  it('omits a removed filter immediately and from the next pending write', async () => {
    const router = makeRouter({ status: 'down', keep: 'z' });
    const first = deferred<boolean>();
    router.replace.mockImplementationOnce(() => first.promise);
    const { result } = renderHook(() => ({
      status: useUrlState('status', 'all'),
      search: useUrlState('search', ''),
    }));
    act(() => result.current.status[1]('all'));
    const calls = router.replace.mock.calls as unknown as Array<[{ query: Query }]>;
    expect(calls[0][0].query).toStrictEqual({ keep: 'z' });
    act(() => result.current.search[1]('web'));
    expect(calls[1][0].query).toStrictEqual({ keep: 'z', search: 'web' });
    await act(() => {
      first.resolve(true);
      return first.promise.then(() => undefined);
    });
  });
  it('keeps the whole pending query when the first replace resolves false', async () => {
    const router = makeRouter({});
    const first = deferred<boolean>();
    const second = deferred<boolean>();
    const third = deferred<boolean>();
    router.replace
      .mockImplementationOnce(() => first.promise)
      .mockImplementationOnce(() => second.promise)
      .mockImplementationOnce(() => third.promise);
    const { result } = renderHook(() => ({
      status: useUrlState('status', 'all'),
      ca: useUrlState('ca', 'all'),
      search: useUrlState('search', ''),
    }));
    act(() => result.current.status[1]('Active'));
    act(() => result.current.ca[1]('enabled'));
    // Superseded by the second replace; the router never published it.
    await act(() => {
      first.resolve(false);
      return first.promise.then(() => undefined);
    });
    act(() => result.current.search[1]('web'));
    const calls = router.replace.mock.calls as unknown as Array<[{ query: Query }]>;
    expect(calls[2][0].query).toEqual({ status: 'Active', ca: 'enabled', search: 'web' });
    await act(() => {
      second.resolve(true);
      third.resolve(true);
      return Promise.all([second.promise, third.promise]).then(() => undefined);
    });
  });

  it('converges on the actual URL when every replace is cancelled', async () => {
    const router = makeRouter({ keep: 'z' });
    const first = deferred<boolean>();
    const second = deferred<boolean>();
    router.replace.mockImplementationOnce(() => first.promise).mockImplementationOnce(() => second.promise);
    const { result } = renderHook(() => ({
      status: useUrlState('status', 'all'),
      ca: useUrlState('ca', 'all'),
    }));
    act(() => result.current.status[1]('Active'));
    act(() => result.current.ca[1]('enabled'));
    expect(result.current.status[0]).toBe('Active');
    await act(() => {
      first.resolve(false);
      second.resolve(false);
      return Promise.all([first.promise, second.promise]).then(() => undefined);
    });
    expect(result.current.status[0]).toBe('all');
    expect(result.current.ca[0]).toBe('all');
  });

  it('converges on the actual URL when replace rejects', async () => {
    const router = makeRouter({});
    router.replace.mockImplementationOnce(() => Promise.reject(new Error('aborted')));
    const { result } = renderHook(() => useUrlState('status', 'all'));
    await act(() => {
      result.current[1]('Active');
      return Promise.resolve();
    });
    expect(result.current[0]).toBe('all');
  });

  it('does not leak stale pending filters into writes after navigation', async () => {
    const router = makeRouter({});
    const first = deferred<boolean>();
    router.replace.mockImplementationOnce(() => first.promise);
    const { result, rerender } = renderHook(() => ({
      status: useUrlState('status', 'all'),
      ca: useUrlState('ca', 'all'),
    }));
    act(() => result.current.status[1]('Active'));
    // Back navigation lands on a different query while the replace is pending.
    act(() => navigate({ status: 'Inactive' }));
    rerender();
    expect(result.current.status[0]).toBe('Inactive');
    act(() => result.current.ca[1]('off'));
    const calls = router.replace.mock.calls as unknown as Array<[{ query: Query }]>;
    expect(calls[1][0].query).toEqual({ status: 'Inactive', ca: 'off' });
    await act(() => {
      first.resolve(true);
      return first.promise.then(() => undefined);
    });
  });
});
