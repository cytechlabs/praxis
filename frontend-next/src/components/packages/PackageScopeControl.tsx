import React from 'react';
import { nativeSelectClass } from '@/components/ui';
import {
  PackageScope,
  PackageScopeType,
  PACKAGE_SCOPE_LABELS,
  PACKAGE_SCOPE_TYPES,
} from '@/services/packageScope';

export interface ScopeSystemOption {
  id: number;
  hostname: string;
}
export interface ScopeGroupOption {
  id: number;
  name: string;
  /** Real included host count (caller-visible members), not a result-row count. */
  member_count: number;
}
export interface ScopeSmartGroupOption {
  id: number;
  name: string;
  member_count: number;
}

/**
 * Shared package-scope selector.
 *
 * A cohort picker used across the package-management views (inventory, available
 * updates, security updates, fleet search, update history): choose the whole
 * fleet, a single system, a static group, or a smart group. Purely presentational
 * - the option lists, selection state, and URL sync are owned by `usePackageScope`
 * - so it is easy to unit test and reuse.
 */
const selectCls = `border border-border rounded-md px-3 py-2 text-sm ${nativeSelectClass}`;

const labelCls = 'block text-xs font-medium text-content-muted mb-1';

const PackageScopeControl: React.FC<{
  value: PackageScope;
  onChange: (scope: PackageScope) => void;
  systems: ScopeSystemOption[];
  groups: ScopeGroupOption[];
  smartGroups: ScopeSmartGroupOption[];
  /** Whether to offer the single-system scope (default true). */
  includeSystem?: boolean;
  className?: string;
}> = ({
  value,
  onChange,
  systems,
  groups,
  smartGroups,
  includeSystem = true,
  className = '',
}) => {
  const types = includeSystem
    ? PACKAGE_SCOPE_TYPES
    : PACKAGE_SCOPE_TYPES.filter((t) => t !== 'system');

  const changeType = (type: PackageScopeType) => {
    if (type === 'all') {
      onChange({ type, id: null });
      return;
    }
    const firstId =
      type === 'system'
        ? systems[0]?.id
        : type === 'group'
          ? groups[0]?.id
          : smartGroups[0]?.id;
    onChange({ type, id: firstId ?? null });
  };

  // The summary shows the cohort's REAL included host count (group/smart-group
  // membership), never the number of rows in the current results.
  const selectedCohort =
    value.type === 'smart_group'
      ? smartGroups.find((g) => g.id === value.id)
      : value.type === 'group'
        ? groups.find((g) => g.id === value.id)
        : null;
  const summaryCount = selectedCohort?.member_count;

  return (
    <div className={`flex flex-wrap items-end gap-3 ${className}`}>
      <div>
        <label htmlFor="pkg-scope-type" className={labelCls}>
          Scope
        </label>
        <select
          id="pkg-scope-type"
          aria-label="Package scope"
          className={selectCls}
          value={value.type}
          onChange={(e) => changeType(e.target.value as PackageScopeType)}
        >
          {types.map((t) => (
            <option key={t} value={t}>
              {PACKAGE_SCOPE_LABELS[t]}
            </option>
          ))}
        </select>
      </div>

      {value.type === 'system' && (
        <div>
          <label htmlFor="pkg-scope-system" className={labelCls}>
            System
          </label>
          <select
            id="pkg-scope-system"
            aria-label="Select system"
            className={selectCls}
            value={value.id ?? ''}
            onChange={(e) =>
              onChange({ type: 'system', id: e.target.value ? Number(e.target.value) : null })
            }
          >
            {systems.length === 0 && <option value="">No systems</option>}
            {systems.map((s) => (
              <option key={s.id} value={s.id}>
                {s.hostname}
              </option>
            ))}
          </select>
        </div>
      )}

      {value.type === 'group' && (
        <div>
          <label htmlFor="pkg-scope-group" className={labelCls}>
            Group
          </label>
          <select
            id="pkg-scope-group"
            aria-label="Select group"
            className={selectCls}
            value={value.id ?? ''}
            onChange={(e) =>
              onChange({ type: 'group', id: e.target.value ? Number(e.target.value) : null })
            }
          >
            {groups.length === 0 && <option value="">No groups</option>}
            {groups.map((g) => (
              <option key={g.id} value={g.id}>
                {g.name}
              </option>
            ))}
          </select>
        </div>
      )}

      {value.type === 'smart_group' && (
        <div>
          <label htmlFor="pkg-scope-smart" className={labelCls}>
            Smart group
          </label>
          <select
            id="pkg-scope-smart"
            aria-label="Select smart group"
            className={selectCls}
            value={value.id ?? ''}
            onChange={(e) =>
              onChange({
                type: 'smart_group',
                id: e.target.value ? Number(e.target.value) : null,
              })
            }
          >
            {smartGroups.length === 0 && <option value="">No smart groups</option>}
            {smartGroups.map((g) => (
              <option key={g.id} value={g.id}>
                {g.name} ({g.member_count})
              </option>
            ))}
          </select>
        </div>
      )}

      {value.type !== 'all' && value.id != null && summaryCount != null && (
        <span className="pb-2 text-xs text-content-subtle">
          {summaryCount} {summaryCount === 1 ? 'system' : 'systems'} in scope
        </span>
      )}
    </div>
  );
};

export default PackageScopeControl;
