import { describe, it, expect } from 'vitest';

import { computeMenuPosition, type RectLike } from './menuPosition';

const VIEWPORT = { width: 1000, height: 800 };
const MENU = { width: 192, height: 160 };

function trigger(partial: Partial<RectLike>): RectLike {
  return {
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    width: 0,
    height: 0,
    ...partial,
  };
}

describe('computeMenuPosition — vertical placement', () => {
  it('places below the trigger when there is room', () => {
    const pos = computeMenuPosition({
      trigger: trigger({ top: 100, bottom: 130, left: 900, right: 940, width: 40, height: 30 }),
      menu: MENU,
      viewport: VIEWPORT,
    });
    expect(pos.placement).toBe('below');
    expect(pos.top).toBe(134); // bottom + gap(4)
  });

  it('flips above when there is not enough room below', () => {
    const pos = computeMenuPosition({
      trigger: trigger({ top: 740, bottom: 770, left: 900, right: 940, width: 40, height: 30 }),
      menu: MENU,
      viewport: VIEWPORT,
    });
    expect(pos.placement).toBe('above');
    expect(pos.top).toBe(576); // top(740) - gap(4) - menuHeight(160)
  });

  it('when neither side fully fits, uses the roomier side and clamps on screen', () => {
    // Short viewport: menu (160) fits neither above nor below.
    const shortViewport = { width: 1000, height: 150 };
    const below = computeMenuPosition({
      trigger: trigger({ top: 20, bottom: 50, left: 100, right: 140, width: 40, height: 30 }),
      menu: MENU,
      viewport: shortViewport,
    });
    // more room below (100) than above (20) -> below, clamped to top margin
    expect(below.placement).toBe('below');
    expect(below.top).toBe(8);

    const above = computeMenuPosition({
      trigger: trigger({ top: 70, bottom: 100, left: 100, right: 140, width: 40, height: 30 }),
      menu: MENU,
      viewport: shortViewport,
    });
    // more room above (70) than below (50) -> above, clamped to top margin
    expect(above.placement).toBe('above');
    expect(above.top).toBe(8);
  });
});

describe('computeMenuPosition — horizontal clamp/align', () => {
  it('right-aligns the menu to the trigger by default', () => {
    const pos = computeMenuPosition({
      trigger: trigger({ top: 100, bottom: 130, left: 700, right: 740 }),
      menu: MENU,
      viewport: VIEWPORT,
    });
    expect(pos.left).toBe(548); // right(740) - menuWidth(192)
  });

  it('clamps to the left margin when the trigger is at the left edge', () => {
    const pos = computeMenuPosition({
      trigger: trigger({ top: 100, bottom: 130, left: 5, right: 20 }),
      menu: MENU,
      viewport: VIEWPORT,
    });
    expect(pos.left).toBe(8); // would be 20-192=-172, clamped to margin
  });

  it('clamps to the right margin when a left-aligned menu would overflow', () => {
    const pos = computeMenuPosition({
      trigger: trigger({ top: 100, bottom: 130, left: 950, right: 990 }),
      menu: MENU,
      viewport: VIEWPORT,
      align: 'left',
    });
    // left would be 950; max left is 1000 - 192 - 8 = 800
    expect(pos.left).toBe(800);
  });
});
