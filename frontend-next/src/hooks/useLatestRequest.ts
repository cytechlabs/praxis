import { useCallback, useEffect, useRef } from 'react';

/**
 * PRA-256: monotonic request-ID tracker that defends against out-of-order async
 * responses. When a component refetches on selected-system / search / page /
 * filter changes, a slow older request can resolve AFTER a newer one and clobber
 * current state. Each `begin()` supersedes all earlier in-flight requests and
 * returns an `isCurrent()` predicate; every state write for a request — success,
 * error, AND the finally/loading cleanup — must be gated on `isCurrent()` so a
 * superseded response cannot overwrite newer data, clear a newer loading state,
 * or surface a stale error.
 *
 * This factory is intentionally framework-agnostic (no React) so it is trivially
 * unit-testable; `useLatestRequest` is the thin React wrapper.
 */
export function createLatestRequestTracker() {
  let latest = 0;
  return {
    /** Start a new request, superseding any earlier ones. Returns a predicate
     *  that is true only while this is still the newest request. */
    begin(): () => boolean {
      const id = ++latest;
      return () => id === latest;
    },
    /** Supersede every in-flight request so none of them commit (e.g. on
     *  unmount). */
    invalidate(): void {
      latest += 1;
    },
  };
}

export type LatestRequestTracker = ReturnType<typeof createLatestRequestTracker>;

/**
 * React hook exposing a stable `begin` from a per-component
 * {@link createLatestRequestTracker}. Call `begin()` at the start of a fetch and
 * check the returned `isCurrent()` before every state write. In-flight requests
 * are invalidated on unmount so a late response can't set state on an unmounted
 * component.
 *
 * Use ONE tracker per independent request stream. A page that loads two unrelated
 * things (e.g. the updates list and the held-package set) should call
 * `useLatestRequest()` twice so the streams don't invalidate each other.
 */
export function useLatestRequest(): () => (() => boolean) {
  const ref = useRef<LatestRequestTracker | null>(null);
  if (ref.current === null) {
    ref.current = createLatestRequestTracker();
  }
  useEffect(() => {
    const tracker = ref.current;
    return () => tracker?.invalidate();
  }, []);
  return useCallback(() => ref.current!.begin(), []);
}
