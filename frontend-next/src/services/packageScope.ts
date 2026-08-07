/**
 * Package-management cohort scope model.
 *
 * A shared selector for scoping package views/search to the whole fleet, a single
 * system, a static group, or a smart group. The backend owns the authoritative
 * resolution (fleet scope ∩ cohort); the frontend only carries the selection and
 * turns it into the `scope_type`/`scope_id` query params the scoped endpoints
 * accept.
 */

export type PackageScopeType = 'all' | 'system' | 'group' | 'smart_group';

export interface PackageScope {
  type: PackageScopeType;
  /** Target id for system/group/smart_group; null for `all`. */
  id: number | null;
}

export const ALL_SCOPE: PackageScope = { type: 'all', id: null };

export const PACKAGE_SCOPE_TYPES: PackageScopeType[] = [
  'all',
  'system',
  'group',
  'smart_group',
];

export const PACKAGE_SCOPE_LABELS: Record<PackageScopeType, string> = {
  all: 'All systems',
  system: 'Single system',
  group: 'Group',
  smart_group: 'Smart group',
};

/** A scope other than a single system spans multiple hosts (aggregate view). */
export function isAggregateScope(scope: PackageScope): boolean {
  return scope.type !== 'system';
}

/** True once a non-`all` scope has an actual target selected. */
export function isScopeReady(scope: PackageScope): boolean {
  return scope.type === 'all' || scope.id != null;
}

/**
 * The `scope_type`/`scope_id` query params for the scoped aggregate endpoints.
 * `all` sends nothing (the endpoint uses the caller's full fleet scope). A
 * targeted cohort sends both params. An incomplete non-`all` cohort (no target
 * yet) sends `scope_type` WITHOUT `scope_id` on purpose: it must never serialize
 * the same as `all` and silently widen to the whole fleet — the backend rejects
 * the missing target with a 400 instead. Call sites should gate on
 * {@link isScopeReady} and not fetch at all in that state.
 */
export function scopeSearchParams(scope: PackageScope): Record<string, string> {
  if (scope.type === 'all') return {};
  const params: Record<string, string> = { scope_type: scope.type };
  if (scope.id != null) params.scope_id = String(scope.id);
  return params;
}

/** The one package inventory route; every scoped package link points here. */
export const PACKAGE_INVENTORY_PATH = '/package-management/inventory';

/**
 * Deep link to the package inventory scoped to a single system. Serializes the
 * same `scope_type`/`scope_id` contract the inventory page hydrates from, so a
 * link and an in-page selection resolve to the identical cohort.
 */
export function systemPackageInventoryHref(systemId: number): string {
  const query = new URLSearchParams(
    scopeSearchParams({ type: 'system', id: systemId }),
  );
  return `${PACKAGE_INVENTORY_PATH}?${query.toString()}`;
}
