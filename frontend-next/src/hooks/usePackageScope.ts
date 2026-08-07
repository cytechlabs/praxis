import { useCallback, useEffect, useState } from 'react';
import { useRouter } from 'next/router';
import { fetchAllSystems, fetchGroups } from '@/services/systemService';
import { listSmartGroups, SmartGroupListItem } from '@/services/smartGroupService';
import {
  ALL_SCOPE,
  PackageScope,
  PackageScopeType,
  PACKAGE_SCOPE_TYPES,
} from '@/services/packageScope';
import {
  ScopeGroupOption,
  ScopeSmartGroupOption,
  ScopeSystemOption,
} from '@/components/packages/PackageScopeControl';

interface UsePackageScope {
  scope: PackageScope;
  setScope: (next: PackageScope) => void;
  systems: ScopeSystemOption[];
  groups: ScopeGroupOption[];
  smartGroups: ScopeSmartGroupOption[];
  ready: boolean;
}

/**
 * Loads the cohort option lists (systems in natural hostname order,
 * static groups, smart groups) and keeps the selected {@link PackageScope} in
 * sync with the `scope_type`/`scope_id` query params so scoped package views are
 * deep-linkable. Lists that fail to load degrade to empty rather than blocking
 * the page.
 */
export function usePackageScope(): UsePackageScope {
  const router = useRouter();
  const [systems, setSystems] = useState<ScopeSystemOption[]>([]);
  const [groups, setGroups] = useState<ScopeGroupOption[]>([]);
  const [smartGroups, setSmartGroups] = useState<ScopeSmartGroupOption[]>([]);
  const [scope, setScopeState] = useState<PackageScope>(ALL_SCOPE);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    Promise.all([
      fetchAllSystems().catch(() => []),
      fetchGroups().catch(() => []),
      listSmartGroups().catch(() => [] as SmartGroupListItem[]),
    ])
      .then(([sys, grps, sgs]) => {
        setSystems(sys.map((s) => ({ id: s.id, hostname: s.hostname })));
        // Real static-group host count, computed from the caller-visible systems
        // (each carries its group_id) — so the scope summary shows the actual
        // included host count, never the number of rows in the current results.
        const groupCounts = new Map<number, number>();
        for (const s of sys) {
          groupCounts.set(s.group_id, (groupCounts.get(s.group_id) ?? 0) + 1);
        }
        setGroups(
          grps.map((g) => ({
            id: g.id,
            name: g.name,
            member_count: groupCounts.get(g.id) ?? 0,
          })),
        );
        setSmartGroups(
          sgs.map((g) => ({ id: g.id, name: g.name, member_count: g.member_count })),
        );
      })
      .finally(() => setReady(true));
  }, []);

  // Hydrate the scope from the URL once (deep-link support). Only accept a valid
  // scope_type; an unknown value falls back to the fleet-wide default.
  useEffect(() => {
    if (!router.isReady) return;
    const rawType = router.query.scope_type;
    const rawId = router.query.scope_id;
    const t = Array.isArray(rawType) ? rawType[0] : rawType;
    const idStr = Array.isArray(rawId) ? rawId[0] : rawId;
    if (t && (PACKAGE_SCOPE_TYPES as string[]).includes(t)) {
      const type = t as PackageScopeType;
      setScopeState({ type, id: type === 'all' ? null : idStr ? Number(idStr) : null });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [router.isReady]);

  const setScope = useCallback(
    (next: PackageScope) => {
      setScopeState(next);
      const query = { ...router.query };
      delete query.scope_type;
      delete query.scope_id;
      if (next.type !== 'all') {
        query.scope_type = next.type;
        if (next.id != null) query.scope_id = String(next.id);
      }
      void router.replace({ pathname: router.pathname, query }, undefined, {
        shallow: true,
      });
    },
    [router],
  );

  return { scope, setScope, systems, groups, smartGroups, ready };
}
