import { describe, expect, it } from 'vitest';
import { ALL_DIMENSIONS, GLOBAL_DIMENSIONS, collapseFlows, layoutFlows, valueOf } from './flowLayout';
import { PEOPLE_WINDOW, applyView, emptyView, onlyPeople, setChecked, toggleExclusion, viewCriteria } from './flowView';
import type { Flow } from './types';

function flow(over: Partial<Flow>): Flow { return { actor_id: 'actor-01', actor_name: 'Personne 01', tool: 'chrome', provider: 'chatgpt.com', model: 'gpt-4o', count: 1, blocked: 0, ...over }; }
/** Twelve people, busiest first (120, 110, … 10 requests), alternating browsers. */
const wide: Flow[] = Array.from({ length: 12 }, (_, i) => flow({ actor_id: `actor-${String(i + 1).padStart(2, '0')}`, actor_name: `Personne ${String(i + 1).padStart(2, '0')}`, tool: i % 2 ? 'firefox' : 'chrome', count: 120 - 10 * i, blocked: i === 0 ? 3 : 0 }));

describe('layoutFlows', () => {
  it('merges rows that share a left value, a right value and a vendor into one ribbon', () => {
    const flows = [flow({ model: 'gpt-4o', count: 3 }), flow({ model: 'gpt-4o-mini', count: 2 })];
    const layout = layoutFlows(flows, { width: 960, dimensions: ALL_DIMENSIONS, sensitivity: false });
    expect(layout.columns).toHaveLength(4);
    const first = layout.links.filter(link => link.column === 0);
    expect(first).toHaveLength(1); expect(first[0].count).toBe(5); expect(first[0].flows).toEqual(flows);
    // The model column keeps both models, busiest first, and the vendor hue.
    expect(layout.columns[3].map(node => node.value)).toEqual(['gpt-4o', 'gpt-4o-mini']);
    expect(layout.columns[3][0].color).toBe(layout.columns[2][0].color);
    expect(layout.links.filter(link => link.column === 2)).toHaveLength(2);
  });
  it('stacks the bands of a tile inside it and starts each path at the tile edge', () => {
    const layout = layoutFlows(wide, { width: 1200, dimensions: ALL_DIMENSIONS, sensitivity: false });
    for (const node of layout.columns.flat()) {
      const out = layout.links.filter(link => link.left === node);
      if (!out.length) continue;
      const thickness = out.reduce((sum, link) => sum + link.thickness, 0);
      expect(thickness).toBeLessThanOrEqual(node.height + 0.01);
      for (const link of out) { expect(link.y0).toBeGreaterThanOrEqual(node.y - 0.01); expect(link.path.startsWith(`M${node.x + node.width},`)).toBe(true); }
    }
    // Bands inside the chrome tile follow the rank of the services they reach.
    const chrome = layout.columns[1].find(node => node.value === 'chrome')!;
    const bands = layout.links.filter(link => link.left === chrome).sort((a, b) => a.y0 - b.y0);
    expect(bands.map(link => link.right.index)).toEqual([...bands.map(link => link.right.index)].sort((a, b) => a - b));
  });
  it('declares one gradient per column and vendor, spanning the gap between the columns', () => {
    const flows = [flow({ count: 4 }), flow({ actor_id: 'actor-02', actor_name: 'Personne 02', provider: 'claude.ai', model: 'claude', count: 2 }), flow({ actor_id: 'actor-03', actor_name: 'Personne 03', count: 1 })];
    const layout = layoutFlows(flows, { width: 960, dimensions: ALL_DIMENSIONS, sensitivity: false });
    const firstColumn = layout.gradients.filter(gradient => gradient.id.startsWith('g0-'));
    expect(firstColumn).toHaveLength(2);
    for (const gradient of firstColumn) { expect(gradient.x1).toBe(layout.columnX[0] + layout.tileWidth); expect(gradient.x2).toBe(layout.columnX[1]); }
    expect(new Set(layout.links.map(link => link.gradient)).size).toBe(layout.gradients.length);
  });
  it('lays out three columns in overall-usage mode and collapses people out of the table rows', () => {
    const layout = layoutFlows(wide, { width: 960, dimensions: GLOBAL_DIMENSIONS, sensitivity: false });
    expect(layout.columns).toHaveLength(3); expect(layout.columns[0].map(node => node.value)).toEqual(['chrome', 'firefox']);
    const rows = collapseFlows(wide, GLOBAL_DIMENSIONS);
    expect(rows).toHaveLength(2); expect(rows[0]).toMatchObject({ tool: 'chrome', actor_id: '', count: 420, blocked: 3 });
  });
  it('never produces NaN geometry from hostile numbers and ignores rows without requests', () => {
    const hostile = [flow({ count: Number.NaN }), flow({ actor_id: 'actor-02', count: -5 }), flow({ actor_id: 'actor-03', count: 'many' as unknown as number }), flow({ actor_id: 'actor-04', count: 2, blocked: Number.POSITIVE_INFINITY })];
    const layout = layoutFlows(hostile, { width: Number.NaN, dimensions: ALL_DIMENSIONS, sensitivity: true });
    expect(layout.columns[0].map(node => node.value)).toEqual(['actor-04']);
    expect(Number.isFinite(layout.height) && Number.isFinite(layout.width)).toBe(true);
    for (const link of layout.links) expect(link.path).not.toMatch(/NaN|Infinity/);
    expect(layoutFlows([], { width: 800, dimensions: ALL_DIMENSIONS, sensitivity: false }).links).toEqual([]);
    // Two finite counts whose sum overflows a double: every height, offset and path must stay finite.
    const overflow = layoutFlows([flow({ count: 1e308 }), flow({ actor_id: 'actor-02', count: 1e308 }), flow({ actor_id: 'actor-03', count: 5 })], { width: 960, dimensions: ALL_DIMENSIONS, sensitivity: false });
    expect(Number.isFinite(overflow.height) && Number.isFinite(overflow.total)).toBe(true);
    for (const node of overflow.columns.flat()) expect(Number.isFinite(node.height) && Number.isFinite(node.y) && Number.isFinite(node.share)).toBe(true);
    for (const link of overflow.links) { expect(Number.isFinite(link.thickness)).toBe(true); expect(link.path).not.toMatch(/NaN|Infinity/); }
  });
});

describe('applyView', () => {
  it('shows the ten busiest people and lets the next one in when one is unchecked', () => {
    const initial = applyView(wide, emptyView());
    expect(initial.displayedPeople).toHaveLength(PEOPLE_WINDOW);
    expect(initial.displayedPeople).not.toContain('actor-11'); expect(initial.truncated).toBe(true);
    expect(initial.people[10]).toMatchObject({ rank: 11, checked: true, displayed: false });
    const next = applyView(wide, toggleExclusion(emptyView(), 'actor_id', 'actor-03'));
    expect(next.displayedPeople).toHaveLength(PEOPLE_WINDOW);
    expect(next.displayedPeople).toContain('actor-11'); expect(next.displayedPeople).not.toContain('actor-03');
    expect(next.people.find(person => person.value === 'actor-12')).toMatchObject({ rank: 12, displayed: false });
    expect(next.restriction.actor_id).toEqual(next.displayedPeople);
    expect(next.visible.every(item => valueOf(item, 'actor_id') !== 'actor-03')).toBe(true);
  });
  it('draws every checked person when people are hidden and keeps the same flow objects', () => {
    const view = { ...toggleExclusion(emptyView(), 'actor_id', 'actor-12'), peopleHidden: true };
    const result = applyView(wide, view);
    expect(result.visible).toHaveLength(11); expect(result.truncated).toBe(false);
    expect(result.visible.every(item => wide.includes(item))).toBe(true);
    expect(result.restriction.actor_id).toHaveLength(11);
    expect(applyView(wide, { ...emptyView(), peopleHidden: true }).restriction.actor_id).toBeUndefined();
  });
  it('recounts people against the other panels and names the kept values for the journal', () => {
    const result = applyView(wide, toggleExclusion(emptyView(), 'tool', 'firefox'));
    expect(result.people.find(person => person.value === 'actor-02')!.count).toBe(0);
    expect(result.displayedPeople).toEqual(['actor-01', 'actor-03', 'actor-05', 'actor-07', 'actor-09', 'actor-11']);
    expect(result.restriction.tool).toEqual(['chrome']); expect(result.restriction.actor_id).toBeUndefined();
    expect(result.facets.tool.map(option => [option.value, option.checked])).toEqual([['chrome', true], ['firefox', false]]);
    expect(result.visible.every(item => item.tool === 'chrome')).toBe(true);
  });
  it('keeps exactly the chosen people and toggles a searched subset', () => {
    const all = wide.map(item => item.actor_id);
    const only = onlyPeople(emptyView(), all, ['actor-05', 'actor-07']);
    expect(only.excluded.actor_id).toHaveLength(10); expect(applyView(wide, only).displayedPeople).toEqual(['actor-05', 'actor-07']);
    const unchecked = setChecked(emptyView(), 'actor_id', ['actor-01', 'actor-02'], false);
    expect(applyView(wide, unchecked).displayedPeople[0]).toBe('actor-03');
    expect(setChecked(unchecked, 'actor_id', ['actor-01'], true).excluded.actor_id).toEqual(['actor-02']);
  });
  it('lets an explicit selection override the panel restriction of its dimension only', () => {
    const result = applyView(wide, toggleExclusion(emptyView(), 'tool', 'firefox'));
    const criteria = viewCriteria({ from: 'a', to: 'b' }, [{ dimension: 'actor_id', value: 'actor-01', label: 'Personne 01' }], result);
    expect(criteria).toEqual({ from: 'a', to: 'b', actor_id: ['actor-01'], tool: ['chrome'] });
  });
});
