import { useRouter } from 'next/router';
import { useCallback, useEffect, useState } from 'react';

/**
 * Sync a piece of state to a URL search param so filters survive reloads,
 * are bookmarkable, and play nicely with browser back/forward.
 *
 * Usage:
 *   const [status, setStatus] = useUrlState('status', 'all');
 *
 * When `value === defaultValue` the param is removed from the URL (clean URLs).
 */
export function useUrlState<T extends string = string>(
  key: string,
  defaultValue: string,
): [T, (next: T) => void] {
  const router = useRouter();
  const [value, setValue] = useState<T>(defaultValue as T);
  const [hydrated, setHydrated] = useState(false);

  // Hydrate from URL on first ready
  useEffect(() => {
    if (!router.isReady || hydrated) return;
    const raw = router.query[key];
    if (typeof raw === 'string' && raw.length > 0) {
      setValue(raw as T);
    }
    setHydrated(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [router.isReady]);

  const update = useCallback(
    (next: T) => {
      setValue(next);
      if (!router.isReady) return;
      const nextQuery = { ...router.query };
      if ((next as string) === defaultValue || next === '' || next === null || next === undefined) {
        delete nextQuery[key];
      } else {
        nextQuery[key] = next;
      }
      router.replace({ pathname: router.pathname, query: nextQuery }, undefined, {
        shallow: true,
      });
    },
    [router, key, defaultValue],
  );

  return [value, update];
}
