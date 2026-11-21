import { useRouter } from 'next/router';
import { useCallback, useEffect, useRef, useState } from 'react';

type QueryValue = string | string[] | undefined;
type Query = Record<string, QueryValue>;

// Writes issued but not yet reflected in `router.query`, keyed by param. A
// null value means the param is being removed. Hook instances on one page
// share this map so that several setters called before the router settles
// build on each other instead of each starting from the same stale query.
const inflight = new Map<string, string | null>();
// Replaces issued and not yet settled, across all instances. A superseded
// (cancelled) replace must not discard keys a later replace still builds on, so
// the map is only cleared once nothing is pending.
let pendingReplaces = 0;
let anyReplaceFailed = false;
// Each mounted instance registers a callback that re-reads its param from the
// router, used when writes were cancelled or failed and the URL never changed.
const resyncs = new Set<() => void>();

function applyInflight(base: Query): Query {
  const next: Query = { ...base };
  inflight.forEach((value, key) => {
    if (value === null) delete next[key];
    else next[key] = value;
  });
  return next;
}

function sameQuery(a: Query, b: Query): boolean {
  const ak = Object.keys(a);
  if (ak.length !== Object.keys(b).length) return false;
  return ak.every((k) => {
    const x = a[k];
    const y = b[k];
    if (Array.isArray(x) || Array.isArray(y)) {
      return Array.isArray(x) && Array.isArray(y) && x.length === y.length && x.every((v, i) => v === y[i]);
    }
    return x === y;
  });
}

function readParam(raw: QueryValue, defaultValue: string): string {
  return typeof raw === 'string' && raw.length > 0 ? raw : defaultValue;
}

/**
 * Sync a piece of state to a URL search param so filters survive reloads,
 * are bookmarkable, and follow browser back/forward navigation.
 *
 * Usage:
 *   const [status, setStatus] = useUrlState('status', 'all');
 *
 * The URL is the source of truth: whenever the param changes for a reason
 * other than this hook's own writes (back/forward, a link, another router
 * call) the state follows it. A missing or empty param reads as
 * `defaultValue`, and writing `defaultValue` removes the param (clean URLs).
 * Other query parameters are preserved, and several instances with different
 * keys on one page do not overwrite each other's updates.
 */
export function useUrlState<T extends string = string>(
  key: string,
  defaultValue: string,
): [T, (next: T) => void] {
  const router = useRouter();
  const urlValue = router.isReady ? readParam(router.query[key], defaultValue) : defaultValue;
  const [value, setValue] = useState<T>(urlValue as T);
  // URL values this hook has written that the router has not reported yet.
  const written = useRef<string[]>([]);
  const lastUrl = useRef<string | null>(router.isReady ? urlValue : null);
  const routerRef = useRef(router);
  routerRef.current = router;
  const defaultRef = useRef(defaultValue);
  defaultRef.current = defaultValue;

  // After cancelled or failed writes, converge on what the URL actually holds.
  useEffect(() => {
    const resync = () => {
      const currentRouter = routerRef.current;
      if (!currentRouter.isReady) return;
      const actual = readParam(currentRouter.query[key], defaultRef.current);
      written.current = [];
      lastUrl.current = actual;
      setValue(actual as T);
    };
    resyncs.add(resync);
    return () => {
      resyncs.delete(resync);
    };
  }, [key]);

  useEffect(() => {
    if (!router.isReady) return;
    if (lastUrl.current === urlValue) return;
    lastUrl.current = urlValue;
    const at = written.current.indexOf(urlValue);
    if (at !== -1) {
      // Echo of our own write; newer local state wins until the last one lands.
      written.current = written.current.slice(at + 1);
      return;
    }
    written.current = [];
    // Navigation supersedes pending local intent; do not leak it into later writes.
    inflight.clear();
    setValue(urlValue as T);
  }, [router.isReady, urlValue]);

  const update = useCallback(
    (next: T) => {
      const remove = (next as string) === defaultValue || next === '' || next === null || next === undefined;
      const normalized = remove ? defaultValue : (next as string);
      setValue(normalized as T);
      const current = routerRef.current;
      if (!current.isReady) return;

      const base = applyInflight(current.query as Query);
      const target: Query = { ...base };
      if (remove) delete target[key];
      else target[key] = next;
      if (sameQuery(target, base) && sameQuery(base, current.query as Query)) return;

      inflight.set(key, remove ? null : (next as string));
      written.current.push(normalized);
      pendingReplaces += 1;
      Promise.resolve(
        current.replace({ pathname: current.pathname, query: target }, undefined, { shallow: true }),
      )
        .then(
          (ok) => {
            if (ok === false) anyReplaceFailed = true;
          },
          () => {
            anyReplaceFailed = true;
          },
        )
        .finally(() => {
          pendingReplaces -= 1;
          if (pendingReplaces > 0) return;
          // Idle: the router's own query is authoritative again.
          inflight.clear();
          if (anyReplaceFailed) {
            anyReplaceFailed = false;
            resyncs.forEach((fn) => fn());
          }
        });
    },
    [key, defaultValue],
  );

  return [value, update];
}
