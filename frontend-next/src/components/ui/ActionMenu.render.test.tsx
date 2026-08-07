// @vitest-environment jsdom
//
// PRA-349: the portal action menu opens on click, exposes accessible menu
// semantics and the expected items, and closes on selection, Escape, and outside
// click.
import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup } from '@testing-library/react';

import ActionMenu, { type ActionMenuItem } from './ActionMenu';

afterEach(() => cleanup());

function setup(overrides?: Partial<Record<'view' | 'del', () => void>>) {
  const view = overrides?.view ?? vi.fn();
  const del = overrides?.del ?? vi.fn();
  const items: ActionMenuItem[] = [
    { label: 'View Systems', onSelect: view },
    { label: 'Delete Group', onSelect: del, danger: true },
  ];
  render(<ActionMenu items={items} triggerLabel="Actions for Web Servers" />);
  return { view, del };
}

function trigger() {
  return screen.getByRole('button', { name: 'Actions for Web Servers' });
}

describe('ActionMenu', () => {
  it('is closed initially with the correct aria state', () => {
    setup();
    const btn = trigger();
    expect(btn.getAttribute('aria-haspopup')).toBe('menu');
    expect(btn.getAttribute('aria-expanded')).toBe('false');
    expect(screen.queryByRole('menu')).toBeNull();
  });

  it('opens on click and renders the items as a menu', () => {
    setup();
    fireEvent.click(trigger());
    expect(trigger().getAttribute('aria-expanded')).toBe('true');
    const menu = screen.getByRole('menu', { name: 'Actions for Web Servers' });
    expect(menu).toBeTruthy();
    const items = screen.getAllByRole('menuitem');
    expect(items.map((i) => i.textContent)).toEqual(['View Systems', 'Delete Group']);
  });

  it('invokes the action and closes when an item is selected', () => {
    const { view } = setup();
    fireEvent.click(trigger());
    fireEvent.click(screen.getByRole('menuitem', { name: 'View Systems' }));
    expect(view).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole('menu')).toBeNull();
    expect(trigger().getAttribute('aria-expanded')).toBe('false');
  });

  it('closes on Escape', () => {
    setup();
    fireEvent.click(trigger());
    expect(screen.getByRole('menu')).toBeTruthy();
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(screen.queryByRole('menu')).toBeNull();
  });

  it('closes on outside click', () => {
    setup();
    fireEvent.click(trigger());
    expect(screen.getByRole('menu')).toBeTruthy();
    fireEvent.mouseDown(document.body);
    expect(screen.queryByRole('menu')).toBeNull();
  });

  it('does not close when clicking inside the menu (only on selection)', () => {
    setup();
    fireEvent.click(trigger());
    const menu = screen.getByRole('menu');
    fireEvent.mouseDown(menu);
    expect(screen.getByRole('menu')).toBeTruthy();
  });
});
