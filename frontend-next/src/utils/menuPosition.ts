/**
 * PRA-349: pure viewport-collision positioning for a portal menu.
 *
 * The Groups context menu was an absolutely-positioned child clipped by its card
 * (`overflow`/stacking context) with no collision handling, so a menu opened near
 * the bottom edge was cut off. A portal menu escapes the clipping, and this helper
 * decides where to place it: prefer below the trigger, flip above when there isn't
 * room, and clamp inside the viewport so it's always fully visible.
 *
 * Pure and framework-free so the flip/clamp logic is unit-testable without a DOM.
 * Coordinates are viewport-relative, matching `position: fixed` + `getBoundingClientRect()`.
 */

export type MenuPlacement = 'below' | 'above';

export interface RectLike {
  top: number;
  left: number;
  right: number;
  bottom: number;
  width: number;
  height: number;
}

export interface Size {
  width: number;
  height: number;
}

export interface MenuPositionInput {
  /** Trigger button rect in viewport coordinates (getBoundingClientRect). */
  trigger: RectLike;
  /** Measured menu size. */
  menu: Size;
  /** Viewport size (window.innerWidth/innerHeight). */
  viewport: Size;
  /** Gap between trigger and menu. Default 4. */
  gap?: number;
  /** Minimum padding from every viewport edge. Default 8. */
  margin?: number;
  /**
   * Horizontal anchoring: `right` aligns the menu's right edge to the trigger's
   * right edge (the default for a right-side ••• button); `left` aligns left
   * edges. Either way the result is clamped inside the viewport.
   */
  align?: 'left' | 'right';
}

export interface MenuPosition {
  top: number;
  left: number;
  placement: MenuPlacement;
}

function clamp(value: number, min: number, max: number): number {
  // When the element is larger than the available span (max < min), pin to min
  // so it never escapes the leading edge.
  return Math.max(min, Math.min(value, Math.max(min, max)));
}

export function computeMenuPosition(input: MenuPositionInput): MenuPosition {
  const { trigger, menu, viewport } = input;
  const gap = input.gap ?? 4;
  const margin = input.margin ?? 8;
  const align = input.align ?? 'right';

  const spaceBelow = viewport.height - trigger.bottom;
  const spaceAbove = trigger.top;
  const needed = menu.height + gap + margin;

  let placement: MenuPlacement;
  if (spaceBelow >= needed) {
    placement = 'below';
  } else if (spaceAbove >= needed) {
    placement = 'above';
  } else {
    // Neither side fully fits — use the roomier side and let the clamp keep it
    // on screen.
    placement = spaceBelow >= spaceAbove ? 'below' : 'above';
  }

  let top =
    placement === 'below' ? trigger.bottom + gap : trigger.top - gap - menu.height;
  let left = align === 'right' ? trigger.right - menu.width : trigger.left;

  left = clamp(left, margin, viewport.width - menu.width - margin);
  top = clamp(top, margin, viewport.height - menu.height - margin);

  return { top, left, placement };
}
