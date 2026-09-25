/** Client-side view over the flows the server already returned: which values are
 * unchecked in the side panels, whether people are hidden altogether, and the
 * ten-people window. Nothing here widens the data — the server stays the
 * authority on what the period contains — it only decides what is drawn. */
import { ALL_DIMENSIONS, labelOf, safe, valueOf } from './flowLayout';
import type { Dimension, Selection } from './flowLayout';
import type { Cartography, CaptureHealth, Criteria, Flow } from './types';

export type View = { peopleHidden: boolean; excluded: Record<Dimension, string[]> };
export type FacetDimension = 'tool' | 'provider' | 'model';
export const FACET_DIMENSIONS: readonly FacetDimension[] = ['tool', 'provider', 'model'];
/** How many people the ribbon shows at once; unchecking one lets the next ranked person in. */
export const PEOPLE_WINDOW = 10;
export function emptyView(): View { return { peopleHidden: false, excluded: { actor_id: [], tool: [], provider: [], model: [] } }; }

export type FacetOption = { dimension: Dimension; value: string; label: string; count: number; blocked: number; checked: boolean };
export type RankedPerson = FacetOption & { rank: number; displayed: boolean };
export type ViewResult = {
  /** The flows to draw — the same objects as the input, never copies. */
  visible: Flow[];
  /** Every person of the period, busiest first, counted against the other three panels. */
  people: RankedPerson[];
  displayedPeople: string[];
  facets: Record<FacetDimension, FacetOption[]>;
  /** Values to hand to the conversations page so it shows exactly what is drawn; absent when a dimension is not narrowed. */
  restriction: Partial<Record<Dimension, string[]>>;
  /** More checked people than the window holds: some are waiting their turn. */
  truncated: boolean;
};

function options(flows: Flow[], base: Flow[], dimension: Dimension, excluded: Set<string>): FacetOption[] {
  const map = new Map<string, FacetOption>();
  for (const flow of flows) { const value = valueOf(flow, dimension); if (!map.has(value)) map.set(value, { dimension, value, label: labelOf(flow, dimension), count: 0, blocked: 0, checked: !excluded.has(value) }); }
  for (const flow of base) { const option = map.get(valueOf(flow, dimension))!; option.count += safe(flow.count); option.blocked += safe(flow.blocked); }
  return [...map.values()].sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
}

export function applyView(flows: Flow[], view: View): ViewResult {
  const excluded = Object.fromEntries(ALL_DIMENSIONS.map(dimension => [dimension, new Set(view.excluded[dimension] ?? [])])) as Record<Dimension, Set<string>>;
  const passes = (flow: Flow, skip?: Dimension) => ALL_DIMENSIONS.every(dimension => dimension === skip || !excluded[dimension].has(valueOf(flow, dimension)));
  // People are counted against the other panels, so unchecking a browser lowers the
  // people who only used it — and can push them out of the window.
  const people = options(flows, flows.filter(flow => passes(flow, 'actor_id')), 'actor_id', excluded.actor_id) as RankedPerson[];
  let shown = 0;
  people.forEach((person, index) => { person.rank = index + 1; person.displayed = person.checked && person.count > 0 && (view.peopleHidden || shown++ < PEOPLE_WINDOW); });
  const displayedPeople = people.filter(person => person.displayed).map(person => person.value);
  const shownSet = new Set(displayedPeople);
  const eligible = people.filter(person => person.checked && person.count > 0).length;
  const truncated = !view.peopleHidden && eligible > PEOPLE_WINDOW;
  const visible = flows.filter(flow => passes(flow) && shownSet.has(valueOf(flow, 'actor_id')));
  // Each panel is counted against the others and the people actually drawn: the
  // number next to a value is what checking or unchecking it would change.
  const facets = Object.fromEntries(FACET_DIMENSIONS.map(dimension => [dimension, options(flows, flows.filter(flow => passes(flow, dimension) && shownSet.has(valueOf(flow, 'actor_id'))), dimension, excluded[dimension])])) as Record<FacetDimension, FacetOption[]>;
  const restriction: Partial<Record<Dimension, string[]>> = {};
  if (view.peopleHidden) { if (excluded.actor_id.size) restriction.actor_id = people.filter(person => person.checked).map(person => person.value); }
  else if (excluded.actor_id.size || truncated) restriction.actor_id = displayedPeople;
  for (const dimension of FACET_DIMENSIONS) if (excluded[dimension].size) restriction[dimension] = facets[dimension].filter(option => option.checked).map(option => option.value);
  return { visible, people, displayedPeople, facets, restriction, truncated };
}

export function toggleExclusion(view: View, dimension: Dimension, value: string): View {
  const list = view.excluded[dimension];
  return { ...view, excluded: { ...view.excluded, [dimension]: list.includes(value) ? list.filter(item => item !== value) : [...list, value] } };
}
/** Checks (`checked` true) or unchecks every listed value, leaving the others as they are. */
export function setChecked(view: View, dimension: Dimension, values: string[], checked: boolean): View {
  const set = new Set(values); const list = view.excluded[dimension];
  return { ...view, excluded: { ...view.excluded, [dimension]: checked ? list.filter(item => !set.has(item)) : [...new Set([...list, ...values])] } };
}
/** Keeps exactly `chosen` among `all` people: the top-bar picker's "only these people". */
export function onlyPeople(view: View, all: string[], chosen: string[]): View {
  const keep = new Set(chosen);
  return { ...view, excluded: { ...view.excluded, actor_id: all.filter(value => !keep.has(value)) } };
}
export function hasRestriction(view: View) { return ALL_DIMENSIONS.some(dimension => view.excluded[dimension].length > 0); }
/** Server criteria for the conversations page: an explicit selection wins over the panel restriction of the same dimension. */
export function viewCriteria(criteria: Criteria, selected: Selection[], result: ViewResult): Criteria {
  const next = { ...criteria };
  for (const dimension of ALL_DIMENSIONS) {
    const chosen = selected.filter(item => item.dimension === dimension).map(item => item.value);
    const values = chosen.length ? chosen : result.restriction[dimension];
    if (values?.length) next[dimension] = values;
  }
  return next;
}

function list<T>(value: unknown): T[] { return Array.isArray(value) ? value.filter(item => item && typeof item === 'object') as T[] : []; }
/** A forged or truncated payload (null totals, a `flows` that is not a list, a row without numbers)
 * degrades to zeros and empty lists instead of blanking the page. Numbers go through `safe()`.
 * Shared by the map and the printed report, which read the same payload and must be hardened alike. */
export function normalise(data: Cartography | undefined): Cartography | undefined {
  if (!data || typeof data !== 'object') return undefined;
  const totals = (data.totals && typeof data.totals === 'object' ? data.totals : {}) as Partial<Cartography['totals']>;
  return {
    flows: list<Flow>(data.flows),
    capture: list<CaptureHealth>(data.capture).map(row => ({ provider: typeof row.provider === 'string' ? row.provider : '', navigations: safe(row.navigations), requests: safe(row.requests), devices_seen: safe(row.devices_seen), devices_reporting: safe(row.devices_reporting) })),
    totals: { requests: safe(totals.requests), responses: safe(totals.responses), navigations: safe(totals.navigations), conversations: safe(totals.conversations), actors: safe(totals.actors), tools: safe(totals.tools), providers: safe(totals.providers), models: safe(totals.models), blocked: safe(totals.blocked), ...(totals.sensitive !== undefined ? { sensitive: safe(totals.sensitive) } : {}) },
    series: list(data.series), unattributed: safe(data.unattributed),
  };
}
