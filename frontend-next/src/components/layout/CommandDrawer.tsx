import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import type { Workspace, WorkspaceItem } from '@/config/workspaces';

/**
 * PRA-273 / PRA-357 (workspace command drawer):
 *
 * The compact floating panel a workspace tab opens OVER the page (absolutely
 * positioned under the tab), so it never pushes content down and never becomes a
 * sidebar. Exactly three sections: Pages, Actions, Activity. Selecting anything
 * closes it.
 *
 * Accessibility (PRA-357): the drawer is a *navigation* panel, not an ARIA menu.
 * Its children are plain route `<Link>`s, so it exposes list semantics - a
 * labelled group of `<ul>`/`<li>` lists - rather than `role="menu"`, which would
 * demand `role="menuitem"` children plus a roving-focus / arrow-key keyboard
 * model these navigation links neither have nor should have. The keyboard model
 * is therefore the standard link model: Tab moves between links, Enter follows.
 * Esc / outside-click / route-change close the drawer (owned by WorkspaceTabs).
 * Ctrl+K remains the complete expert route-discovery path.
 */

function isItemActive(pathname: string | null, item: WorkspaceItem): boolean {
  if (!pathname) return false;
  const base = item.path.split('?')[0];
  return pathname === base || pathname.startsWith(base + '/');
}

const DrawerItem: React.FC<{ item: WorkspaceItem; onSelect: () => void; active: boolean }> = ({
  item,
  onSelect,
  active,
}) => (
  <Link
    href={item.path}
    onClick={onSelect}
    aria-current={active ? 'page' : undefined}
    className={`
      group flex items-center gap-2 rounded-md px-2 py-1.5 text-sm transition-colors
      focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring
      ${active
        ? 'bg-surface-overlay text-content'
        : 'text-content-muted hover:text-content hover:bg-white/5'}
    `}
  >
    <span className={active ? 'text-brand' : 'text-content-subtle group-hover:text-content-muted'}>
      {item.icon}
    </span>
    <span className="flex-1 truncate">{item.label}</span>
    {item.paid && (
      <span className="shrink-0 rounded border border-amber-400/40 px-1 py-px text-[9px] font-semibold uppercase tracking-wide text-amber-400/90">
        Pro
      </span>
    )}
  </Link>
);

const Section: React.FC<{
  title: string;
  labelId: string;
  items: WorkspaceItem[];
  pathname: string | null;
  onSelect: () => void;
}> = ({ title, labelId, items, pathname, onSelect }) => (
  <div className="min-w-0 flex-1">
    <div
      id={labelId}
      className="px-2 pb-1 text-[10px] font-semibold uppercase tracking-widest text-content-subtle"
    >
      {title}
    </div>
    {items.length === 0 ? (
      <div className="px-2 py-1.5 text-xs text-content-subtle">None</div>
    ) : (
      <ul aria-labelledby={labelId} className="space-y-0.5">
        {items.map((item) => (
          <li key={item.id}>
            <DrawerItem item={item} onSelect={onSelect} active={isItemActive(pathname, item)} />
          </li>
        ))}
      </ul>
    )}
  </div>
);

const CommandDrawer: React.FC<{ workspace: Workspace; onClose: () => void }> = ({
  workspace,
  onClose,
}) => {
  const pathname = usePathname();
  const idBase = `workspace-drawer-${workspace.id}`;

  return (
    <div
      id={idBase}
      role="group"
      aria-label={`${workspace.label} navigation`}
      className="absolute left-0 top-full z-50 mt-1 w-[42rem] max-w-[calc(100vw-2rem)] rounded-lg border border-border/60 bg-surface shadow-2xl"
    >
      <div className="flex gap-4 p-3 max-h-[70vh] overflow-y-auto">
        <Section
          title="Pages"
          labelId={`${idBase}-pages`}
          items={workspace.pages}
          pathname={pathname}
          onSelect={onClose}
        />
        <Section
          title="Actions"
          labelId={`${idBase}-actions`}
          items={workspace.actions}
          pathname={pathname}
          onSelect={onClose}
        />
        <Section
          title="Activity"
          labelId={`${idBase}-activity`}
          items={workspace.activity}
          pathname={pathname}
          onSelect={onClose}
        />
      </div>
    </div>
  );
};

export default CommandDrawer;
