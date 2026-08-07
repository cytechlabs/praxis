import { describe, it, expect } from 'vitest';

import { naturalCompare, sortByHostname, sortByKey } from './naturalSort';

describe('naturalCompare', () => {
  it('orders numeric suffixes by value, not lexicographically', () => {
    const out = ['praxis-tserver10', 'praxis-tserver2', 'praxis-tserver1'].sort(naturalCompare);
    expect(out).toEqual(['praxis-tserver1', 'praxis-tserver2', 'praxis-tserver10']);
  });

  it('is case-insensitive', () => {
    expect(naturalCompare('alpha', 'ALPHA')).toBe(0);
    expect(naturalCompare('Beta', 'alpha')).toBeGreaterThan(0);
  });
});

describe('sortByHostname', () => {
  it('sorts systems naturally by hostname (the PRA-352 repro)', () => {
    const systems = [
      { id: 2, hostname: 'praxis-tserver02' },
      { id: 1, hostname: 'praxis-tserver01' },
      { id: 10, hostname: 'praxis-tserver10' },
    ];
    expect(sortByHostname(systems).map((s) => s.hostname)).toEqual([
      'praxis-tserver01',
      'praxis-tserver02',
      'praxis-tserver10',
    ]);
  });

  it('does not mutate the input array', () => {
    const systems = [
      { id: 2, hostname: 'praxis-tserver02' },
      { id: 1, hostname: 'praxis-tserver01' },
    ];
    const before = systems.map((s) => s.hostname);
    const sorted = sortByHostname(systems);
    expect(systems.map((s) => s.hostname)).toEqual(before); // input unchanged
    expect(sorted).not.toBe(systems); // new array
  });

  it('is case-insensitive and deterministic', () => {
    const systems = [
      { id: 1, hostname: 'Zeta' },
      { id: 2, hostname: 'alpha' },
      { id: 3, hostname: 'Beta' },
    ];
    expect(sortByHostname(systems).map((s) => s.hostname)).toEqual(['alpha', 'Beta', 'Zeta']);
  });

  it('breaks ties by id for equal hostnames', () => {
    const systems = [
      { id: 5, hostname: 'dup' },
      { id: 3, hostname: 'dup' },
      { id: 9, hostname: 'dup' },
    ];
    expect(sortByHostname(systems).map((s) => s.id)).toEqual([3, 5, 9]);
  });

  it('tolerates missing hostnames without throwing', () => {
    const systems = [
      { id: 1, hostname: 'praxis-tserver01' },
      { id: 2 } as { id: number; hostname?: string },
    ];
    expect(() => sortByHostname(systems)).not.toThrow();
    // missing hostname ('') sorts before a named host
    expect(sortByHostname(systems).map((s) => s.id)).toEqual([2, 1]);
  });
});

describe('sortByKey', () => {
  it('sorts by an arbitrary string key, non-mutating', () => {
    const items = [{ name: 'b10' }, { name: 'b2' }, { name: 'b1' }];
    const sorted = sortByKey(items, 'name');
    expect(sorted.map((i) => i.name)).toEqual(['b1', 'b2', 'b10']);
    expect(items.map((i) => i.name)).toEqual(['b10', 'b2', 'b1']); // unchanged
  });
});
