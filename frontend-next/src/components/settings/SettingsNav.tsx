import React from 'react';

/**
 * PRA-276: grouped vertical Settings navigation.
 *
 * Replaces the long horizontal Settings tab row, which wrapped into an
 * unusable two-line strip at supported widths. The sections are unchanged -
 * only the shell that lists them - so existing `?tab=<id>` deep links and the
 * permission gating still hold. Each item is a full-width button (a vertical
 * list never wraps horizontally), and switching a section swaps in-page content,
 * so items use `aria-current="page"` inside a labelled `<nav>` rather than tab
 * semantics.
 */

export interface SettingsNavItem {
  id: string;
  label: string;
}

export interface SettingsNavGroup {
  label: string;
  items: SettingsNavItem[];
}

/**
 * Build the grouped section list for the current permissions. Kept pure and
 * exported so the gating is unit-testable without rendering the whole page.
 * Gated sections match the server-side checks (PRA-257): Auth Logs is
 * admin/auditor, Activation Tokens and Support / Diagnostics are admin-only.
 * Empty groups are dropped so a fully-gated group never renders a bare heading.
 */
export function buildSettingsGroups(isAdmin: boolean, isAuditor: boolean): SettingsNavGroup[] {
  const groups: SettingsNavGroup[] = [
    {
      label: 'General',
      items: [
        { id: 'general', label: 'General' },
        { id: 'alert-config', label: 'Alert Configuration' },
        { id: 'connection-settings', label: 'Connection Settings' },
      ],
    },
    {
      label: 'Access & Identity',
      items: [
        { id: 'user-management', label: 'User Management' },
        { id: 'identity-provider', label: 'Identity Provider' },
        ...(isAdmin || isAuditor ? [{ id: 'auth-logs', label: 'Auth Logs' }] : []),
        { id: 'fleet-access', label: 'Fleet Access' },
      ],
    },
    {
      label: 'Agents & Connectivity',
      items: [
        { id: 'ssh-identity', label: 'SSH Identity' },
        ...(isAdmin ? [{ id: 'activation-tokens', label: 'Activation Tokens' }] : []),
      ],
    },
    {
      label: 'Audit & Licensing',
      items: [
        { id: 'audit-export', label: 'Audit Export' },
        { id: 'license', label: 'License' },
        ...(isAdmin ? [{ id: 'diagnostics', label: 'Support / Diagnostics' }] : []),
      ],
    },
  ];
  return groups.filter((g) => g.items.length > 0);
}

const SettingsNav: React.FC<{
  groups: SettingsNavGroup[];
  active: string;
  onSelect: (id: string) => void;
}> = ({ groups, active, onSelect }) => (
  <nav aria-label="Settings sections" className="lg:sticky lg:top-4 lg:w-56 lg:shrink-0">
    <div className="space-y-5">
      {groups.map((group) => (
        <div key={group.label}>
          <div className="px-3 pb-1.5 text-[11px] font-semibold uppercase tracking-wider text-content-subtle">
            {group.label}
          </div>
          <ul className="space-y-0.5">
            {group.items.map((item) => {
              const isActive = item.id === active;
              return (
                <li key={item.id}>
                  <button
                    type="button"
                    aria-current={isActive ? 'page' : undefined}
                    onClick={() => onSelect(item.id)}
                    className={`
                      w-full rounded-md px-3 py-1.5 text-left text-sm transition-colors
                      focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring
                      ${isActive
                        ? 'bg-surface-overlay text-content font-medium'
                        : 'text-content-muted hover:text-content hover:bg-white/5'}
                    `}
                  >
                    {item.label}
                  </button>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </div>
  </nav>
);

export default SettingsNav;
