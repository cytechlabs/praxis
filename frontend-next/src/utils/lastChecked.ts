/**
 * PRA-348: derive the Available Updates "Last checked" timestamp from the durable
 * backend `last_audited` on loaded systems (not local-only state), so it rehydrates
 * across navigation/reload.
 *
 *  - A specific selected system → that system's `last_audited`.
 *  - "All Systems" → the most recent `last_audited` across loaded systems.
 *  - `null` (renders as "Never") only when nothing in scope has been scanned.
 */
export interface AuditedSystem {
  id: number;
  last_audited?: string | null;
}

export function deriveLastChecked(
  systems: readonly AuditedSystem[],
  selectedSystem: number | 'all',
): string | null {
  const times = (
    selectedSystem === 'all'
      ? systems.map((s) => s.last_audited)
      : [systems.find((s) => s.id === selectedSystem)?.last_audited]
  ).filter((t): t is string => !!t);
  if (times.length === 0) return null;
  return times.reduce((latest, t) => (new Date(t) > new Date(latest) ? t : latest));
}
