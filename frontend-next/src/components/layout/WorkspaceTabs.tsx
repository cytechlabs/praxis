import React, { useCallback, useEffect, useRef, useState } from 'react';
import { usePathname } from 'next/navigation';
import { WORKSPACES, findActiveWorkspace } from '@/config/workspaces';
import CommandDrawer from './CommandDrawer';

/**
 * PRA-273 (workspace tabs): the six flat workspace tabs that replace the old ten
 * dropdown menus. Clicking a tab opens its floating command drawer over the page;
 * the drawer is dismissed on outside click, Esc, route change, or selection.
 *
 * Tabs keep the restored console top-bar feel: dense, flat, Signal-Red active
 * underline. Ctrl+K remains the complete expert path.
 */
const WorkspaceTabs: React.FC = () => {
  const pathname = usePathname();
  const activeWorkspace = findActiveWorkspace(pathname);
  const [openId, setOpenId] = useState<string | null>(null);
  const navRef = useRef<HTMLElement>(null);

  const close = useCallback(() => setOpenId(null), []);

  // Close on route change.
  useEffect(() => {
    setOpenId(null);
  }, [pathname]);

  // Close on outside click + Esc.
  useEffect(() => {
    if (!openId) return;
    const onDown = (e: MouseEvent) => {
      if (navRef.current && !navRef.current.contains(e.target as Node)) close();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close();
    };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [openId, close]);

  const openWorkspace = openId ? WORKSPACES.find((w) => w.id === openId) : undefined;

  return (
    <nav ref={navRef} aria-label="Workspaces" className="relative flex items-center gap-1">
      {WORKSPACES.map((ws) => {
        const active = ws.id === activeWorkspace?.id;
        const open = ws.id === openId;
        return (
          <button
            key={ws.id}
            type="button"
            onClick={() => setOpenId(open ? null : ws.id)}
            // Disclosure semantics (PRA-357): the tab reveals a labelled
            // navigation panel, not an ARIA menu, so no `aria-haspopup="menu"` -
            // that would promise `menuitem`/roving-focus semantics the drawer's
            // plain route links don't provide. `aria-expanded` + `aria-controls`
            // are the correct disclosure contract for a revealed region.
            aria-expanded={open}
            aria-controls={`workspace-drawer-${ws.id}`}
            className={`
              relative flex items-center px-3 py-1.5 text-sm font-medium rounded-md transition-colors
              focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring
              ${active || open
                ? 'text-brand bg-brand/10'
                : 'text-content-muted hover:text-content hover:bg-white/5'}
            `}
          >
            {ws.label}
            {active && (
              <span
                aria-hidden="true"
                className="absolute -bottom-0.5 left-1/2 h-[2px] w-6 -translate-x-1/2 rounded-full bg-brand"
              />
            )}
          </button>
        );
      })}

      {openWorkspace && <CommandDrawer workspace={openWorkspace} onClose={close} />}
    </nav>
  );
};

export default WorkspaceTabs;
