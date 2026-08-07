import { useEffect, useState } from 'react';

/**
 * PRA-256: return a debounced copy of `value` that only updates after `delayMs`
 * of no changes. Used to keep a text input responsive (bound to the immediate
 * value) while the value that drives fetches settles, so fast typing does not
 * flood the backend with per-keystroke requests.
 */
export function useDebouncedValue<T>(value: T, delayMs = 300): T {
  const [debounced, setDebounced] = useState<T>(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(timer);
  }, [value, delayMs]);
  return debounced;
}
