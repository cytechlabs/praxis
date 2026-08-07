/**
 * PRA-349: a small portal-based action ("•••") menu with viewport collision
 * handling and keyboard/outside-click behavior.
 *
 * Replaces the Groups page's hover-only, card-clipped dropdown. The open menu is
 * rendered into `document.body` (so no parent `overflow`/stacking context can clip
 * it), positioned with {@link computeMenuPosition} (flips above when near the
 * bottom, clamps to the viewport), and closes on outside click, Escape, or after
 * an action. Accessible: the trigger exposes `aria-haspopup`/`aria-expanded`, the
 * menu is `role="menu"`, items are `role="menuitem"`, and focus moves into the
 * menu on open (arrow keys navigate, Escape returns focus to the trigger).
 */
import React, {
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from 'react';
import { createPortal } from 'react-dom';
import { computeMenuPosition, type MenuPosition } from '@/utils/menuPosition';

export interface ActionMenuItem {
  label: string;
  onSelect: () => void;
  /** Signal-Red destructive action styling (e.g. Delete). */
  danger?: boolean;
}

interface ActionMenuProps {
  items: ActionMenuItem[];
  /** Accessible label for the trigger button (e.g. "Actions for Web Servers"). */
  triggerLabel: string;
  /** Horizontal anchoring of the menu relative to the trigger. Default "right". */
  align?: 'left' | 'right';
}

const ActionMenu: React.FC<ActionMenuProps> = ({ items, triggerLabel, align = 'right' }) => {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<MenuPosition | null>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const itemRefs = useRef<Array<HTMLButtonElement | null>>([]);

  const close = useCallback((restoreFocus = false) => {
    setOpen(false);
    setPos(null);
    if (restoreFocus) triggerRef.current?.focus();
  }, []);

  // Position the menu once it is in the DOM and measurable. useLayoutEffect runs
  // before paint, so the menu never flashes at the wrong spot.
  useLayoutEffect(() => {
    if (!open) return;
    const trigger = triggerRef.current;
    const menu = menuRef.current;
    if (!trigger || !menu) return;
    const t = trigger.getBoundingClientRect();
    const m = menu.getBoundingClientRect();
    setPos(
      computeMenuPosition({
        trigger: t,
        menu: { width: m.width, height: m.height },
        viewport: { width: window.innerWidth, height: window.innerHeight },
        align,
      }),
    );
  }, [open, align]);

  // Move focus into the menu on open.
  useEffect(() => {
    if (open && pos) itemRefs.current[0]?.focus();
  }, [open, pos]);

  // Global listeners while open: outside click, Escape, and close on scroll/resize
  // (the trigger's position would otherwise go stale).
  useEffect(() => {
    if (!open) return;
    const onPointerDown = (e: MouseEvent) => {
      const target = e.target as Node;
      if (menuRef.current?.contains(target) || triggerRef.current?.contains(target)) return;
      close();
    };
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        close(true);
      }
    };
    const onReflow = () => close();
    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    window.addEventListener('resize', onReflow);
    // capture so scrolls in any ancestor container also dismiss.
    window.addEventListener('scroll', onReflow, true);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
      window.removeEventListener('resize', onReflow);
      window.removeEventListener('scroll', onReflow, true);
    };
  }, [open, close]);

  const focusItem = (index: number) => {
    const count = items.length;
    if (count === 0) return;
    const next = (index + count) % count;
    itemRefs.current[next]?.focus();
  };

  const onMenuKeyDown = (e: React.KeyboardEvent) => {
    const active = itemRefs.current.findIndex((el) => el === document.activeElement);
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      focusItem(active + 1);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      focusItem(active - 1);
    } else if (e.key === 'Home') {
      e.preventDefault();
      focusItem(0);
    } else if (e.key === 'End') {
      e.preventDefault();
      focusItem(items.length - 1);
    }
  };

  const handleSelect = (item: ActionMenuItem) => {
    close();
    item.onSelect();
  };

  return (
    <>
      <button
        ref={triggerRef}
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={triggerLabel}
        onClick={() => (open ? close() : setOpen(true))}
        className="text-gray-400 hover:text-gray-100 px-2 py-1 rounded focus:outline-none focus:ring-2 focus:ring-danger/40"
      >
        •••
      </button>

      {open &&
        typeof document !== 'undefined' &&
        createPortal(
          <div
            ref={menuRef}
            role="menu"
            aria-label={triggerLabel}
            onKeyDown={onMenuKeyDown}
            style={{
              position: 'fixed',
              top: pos ? pos.top : -9999,
              left: pos ? pos.left : -9999,
              // Hidden until measured/positioned to avoid a first-paint flash.
              visibility: pos ? 'visible' : 'hidden',
            }}
            className="w-48 bg-gray-950 border border-gray-800 rounded-md shadow-lg z-[100] py-1"
          >
            {items.map((item, i) => (
              <button
                key={item.label}
                ref={(el) => {
                  itemRefs.current[i] = el;
                }}
                type="button"
                role="menuitem"
                tabIndex={-1}
                onClick={() => handleSelect(item)}
                className={`block w-full text-left px-4 py-2 text-sm hover:bg-gray-800 focus:bg-gray-800 focus:outline-none ${
                  item.danger ? 'text-danger' : 'text-gray-300'
                }`}
              >
                {item.label}
              </button>
            ))}
          </div>,
          document.body,
        )}
    </>
  );
};

export default ActionMenu;
