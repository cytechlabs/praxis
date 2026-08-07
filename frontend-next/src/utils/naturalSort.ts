/**
 * PRA-352: natural, human-friendly ordering for system selectors/lists.
 *
 * Backend list endpoints return systems in insertion/ID order, so selectors read
 * as `praxis-tserver02` before `praxis-tserver01`. These helpers sort by display
 * name using a numeric-aware, case-insensitive collator so numbered hostnames
 * order the way an operator expects (`…01` < `…02` < `…10`).
 *
 * All helpers return a NEW array and never mutate the caller's input.
 */

// One shared collator instance. `numeric: true` compares embedded digit runs by
// value (so `10` sorts after `2`); `sensitivity: 'base'` makes it
// case/accent-insensitive.
const collator = new Intl.Collator(undefined, {
  numeric: true,
  sensitivity: 'base',
});

/** Natural, case-insensitive string comparison suitable for `Array.sort`. */
export function naturalCompare(a: string, b: string): number {
  return collator.compare(a, b);
}

/**
 * Return a new array sorted by the string `key` of each item, naturally and
 * case-insensitively, with a stable numeric-`id` tie-breaker when present so the
 * order is deterministic for equal display names.
 */
export function sortByKey<T extends Record<string, unknown>>(
  items: readonly T[],
  key: keyof T,
): T[] {
  return [...items].sort((a, b) => {
    const av = a[key];
    const bv = b[key];
    const primary = naturalCompare(
      typeof av === 'string' ? av : String(av ?? ''),
      typeof bv === 'string' ? bv : String(bv ?? ''),
    );
    if (primary !== 0) return primary;
    const aid = (a as { id?: unknown }).id;
    const bid = (b as { id?: unknown }).id;
    if (typeof aid === 'number' && typeof bid === 'number') return aid - bid;
    return 0;
  });
}

/**
 * Return a new array of systems sorted naturally by `hostname`. The default
 * ordering for system selectors/lists.
 */
export function sortByHostname<T extends { hostname?: string | null; id?: number }>(
  items: readonly T[],
): T[] {
  return [...items].sort((a, b) => {
    const primary = naturalCompare(a.hostname ?? '', b.hostname ?? '');
    if (primary !== 0) return primary;
    return (a.id ?? 0) - (b.id ?? 0);
  });
}
