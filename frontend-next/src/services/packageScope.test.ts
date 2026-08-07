import { describe, it, expect } from 'vitest';
import {
  ALL_SCOPE,
  PACKAGE_INVENTORY_PATH,
  isAggregateScope,
  isScopeReady,
  scopeSearchParams,
  systemPackageInventoryHref,
} from './packageScope';

describe('packageScope helpers', () => {
  it('scopeSearchParams omits params for the fleet-wide default', () => {
    expect(scopeSearchParams(ALL_SCOPE)).toEqual({});
    expect(scopeSearchParams({ type: 'all', id: 5 })).toEqual({});
  });

  it('scopeSearchParams emits scope_type/scope_id for a targeted cohort', () => {
    expect(scopeSearchParams({ type: 'group', id: 7 })).toEqual({
      scope_type: 'group',
      scope_id: '7',
    });
    expect(scopeSearchParams({ type: 'smart_group', id: 3 })).toEqual({
      scope_type: 'smart_group',
      scope_id: '3',
    });
    expect(scopeSearchParams({ type: 'system', id: 12 })).toEqual({
      scope_type: 'system',
      scope_id: '12',
    });
  });

  it('an incomplete non-all cohort never serializes the same as All Systems', () => {
    // A group/smart_group with no target must emit scope_type WITHOUT scope_id
    // (so the backend 400s), never {} which would silently widen to the fleet.
    const fleetWide = scopeSearchParams(ALL_SCOPE); // {}
    for (const type of ['group', 'smart_group', 'system'] as const) {
      const params = scopeSearchParams({ type, id: null });
      expect(params).toEqual({ scope_type: type });
      expect(params).not.toEqual(fleetWide);
      expect('scope_id' in params).toBe(false);
    }
  });

  it('isAggregateScope is true for everything except a single system', () => {
    expect(isAggregateScope({ type: 'system', id: 1 })).toBe(false);
    expect(isAggregateScope({ type: 'all', id: null })).toBe(true);
    expect(isAggregateScope({ type: 'group', id: 1 })).toBe(true);
    expect(isAggregateScope({ type: 'smart_group', id: 1 })).toBe(true);
  });

  it('isScopeReady requires a target for non-fleet scopes', () => {
    expect(isScopeReady(ALL_SCOPE)).toBe(true);
    expect(isScopeReady({ type: 'group', id: 4 })).toBe(true);
    expect(isScopeReady({ type: 'group', id: null })).toBe(false);
    expect(isScopeReady({ type: 'system', id: null })).toBe(false);
  });

  it('systemPackageInventoryHref points at the canonical inventory route', () => {
    expect(systemPackageInventoryHref(42)).toBe(
      '/package-management/inventory?scope_type=system&scope_id=42',
    );
  });

  it('systemPackageInventoryHref carries the scope the inventory page hydrates from', () => {
    const href = systemPackageInventoryHref(7);
    const url = new URL(href, 'https://praxis.invalid');
    expect(url.pathname).toBe(PACKAGE_INVENTORY_PATH);
    expect(url.searchParams.get('scope_type')).toBe('system');
    expect(url.searchParams.get('scope_id')).toBe('7');
    expect([...url.searchParams.keys()]).toEqual(['scope_type', 'scope_id']);
  });

  it('systemPackageInventoryHref serializes the same params the scoped fetches send', () => {
    const url = new URL(systemPackageInventoryHref(12), 'https://praxis.invalid');
    expect(Object.fromEntries(url.searchParams)).toEqual(
      scopeSearchParams({ type: 'system', id: 12 }),
    );
  });
});
