/** Pure layout for the cartography ribbon: no React, no i18n, no DOM.
 * Flows keep their identity all the way through (`Link.flows` holds the very
 * objects passed in), which is what lets the diagram light up a whole path when
 * one ribbon or one tile is hovered. Every number coming from the server is
 * coerced through `safe()` so a hostile or degenerate payload can never turn
 * into NaN geometry or a negative thickness. */
import { brand } from './brands';
import type { BrandDimension } from './brands';
import type { Flow } from './types';

export type Dimension = BrandDimension;
export const ALL_DIMENSIONS: readonly Dimension[] = ['actor_id', 'tool', 'provider', 'model'];
export const GLOBAL_DIMENSIONS: readonly Dimension[] = ['tool', 'provider', 'model'];
/** One highlighted value; combining several across dimensions narrows the view (AND between dimensions, OR inside one). */
export type Selection = { dimension: Dimension; value: string; label: string };
export type Node = { dimension: Dimension; value: string; label: string; count: number; blocked: number; sensitive: number; share: number; column: number; index: number; x: number; y: number; width: number; height: number; color: string };
export type Link = { key: string; column: number; left: Node; right: Node; provider: string; count: number; blocked: number; sensitive: number; flows: Flow[]; x0: number; x1: number; y0: number; y1: number; thickness: number; path: string; color: string; gradient: string };
export type Gradient = { id: string; color: string; x1: number; x2: number };
export type Layout = { width: number; height: number; tileWidth: number; columnX: number[]; columns: Node[][]; links: Link[]; gradients: Gradient[]; scale: number; total: number };
export type LayoutOptions = { width: number; dimensions: readonly Dimension[]; sensitivity: boolean };

const PAD_X = 12, HEAD = 40, PAD_BOTTOM = 20, GAP = 10, MIN_NODE = 30, MIN_LINK = 1.5, MIN_WIDTH = 640, MIN_HEIGHT = 380, MAX_TARGET = 920, ROW = 56;
/** Width used before the container has been measured (and under jsdom, which never measures). */
export const FALLBACK_WIDTH = 960;

/** A finite, non-negative number or zero: the server never sends anything else, a forged payload might.
 * Capped at 2^53 - 1 so that summing many of them can never overflow to Infinity and turn into NaN geometry. */
export function safe(value: unknown): number { return typeof value === 'number' && Number.isFinite(value) && value > 0 ? Math.min(value, Number.MAX_SAFE_INTEGER) : 0; }
export function valueOf(flow: Flow, dimension: Dimension): string { const value = flow[dimension]; return typeof value === 'string' && value ? value : 'unknown'; }
/** Raw display label: the person's name when known, otherwise the value itself. 'unknown' is translated by the caller. */
export function labelOf(flow: Flow, dimension: Dimension): string { const value = valueOf(flow, dimension); return dimension === 'actor_id' && value !== 'unknown' && typeof flow.actor_name === 'string' && flow.actor_name ? flow.actor_name : value; }
export function nodeKey(node: Pick<Node, 'dimension' | 'value'>) { return `${node.dimension}:${node.value}`; }
function clamp(value: number, low: number, high: number) { return Math.min(high, Math.max(low, value)); }
function compare(a: { count: number; label: string }, b: { count: number; label: string }) { return b.count - a.count || a.label.localeCompare(b.label); }

/** Closed ribbon between two vertical edges; both control points sit at mid-span, the classic horizontal Sankey link. */
export function ribbonPath(x0: number, y0: number, x1: number, y1: number, thickness: number) {
  const cx = (x0 + x1) / 2;
  return `M${x0},${y0}C${cx},${y0} ${cx},${y1} ${x1},${y1}L${x1},${y1 + thickness}C${cx},${y1 + thickness} ${cx},${y0 + thickness} ${x0},${y0 + thickness}Z`;
}

function buildColumns(flows: Flow[], dimensions: readonly Dimension[], columnX: number[], tileWidth: number, total: number, sensitive: (flow: Flow) => number): Node[][] {
  const columns = dimensions.map((dimension, column) => {
    const grouped = new Map<string, Node>(); const vendors = new Map<string, Map<string, number>>();
    for (const flow of flows) {
      const value = valueOf(flow, dimension);
      let node = grouped.get(value);
      if (!node) { node = { dimension, value, label: labelOf(flow, dimension), count: 0, blocked: 0, sensitive: 0, share: 0, column, index: 0, x: columnX[column], y: 0, width: tileWidth, height: 0, color: '' }; grouped.set(value, node); }
      node.count += safe(flow.count); node.blocked += safe(flow.blocked); node.sensitive += sensitive(flow);
      if (dimension === 'model') { const provider = valueOf(flow, 'provider'); const tally = vendors.get(value) ?? new Map<string, number>(); tally.set(provider, (tally.get(provider) ?? 0) + safe(flow.count)); vendors.set(value, tally); }
    }
    const nodes = [...grouped.values()].sort(compare);
    nodes.forEach((node, index) => {
      node.index = index; node.share = node.count / total;
      if (dimension === 'model') { let dominant = 'unknown', best = -1; for (const [provider, count] of vendors.get(node.value) ?? []) { if (count > best) { dominant = provider; best = count; } } node.color = brand('provider', dominant).color; }
      else node.color = brand(dimension, node.value).color;
    });
    return nodes;
  });

  return columns;
}

function buildLinks(flows: Flow[], dimensions: readonly Dimension[], columns: Node[][], tileWidth: number, scale: number, sensitive: (flow: Flow) => number): { links: Link[]; gradients: Gradient[] } {
  const links: Link[] = []; const gradients = new Map<string, Gradient>();
  for (let column = 0; column < dimensions.length - 1; column++) {
    const left = new Map(columns[column].map(node => [node.value, node])); const right = new Map(columns[column + 1].map(node => [node.value, node]));
    const pairs = new Map<string, Link>();
    for (const flow of flows) {
      const source = left.get(valueOf(flow, dimensions[column]))!; const target = right.get(valueOf(flow, dimensions[column + 1]))!; const provider = valueOf(flow, 'provider');
      const key = `${column}|${source.value}|${target.value}|${provider}`;
      let link = pairs.get(key);
      if (!link) { link = { key, column, left: source, right: target, provider, count: 0, blocked: 0, sensitive: 0, flows: [], x0: source.x + tileWidth, x1: target.x, y0: 0, y1: 0, thickness: 0, path: '', color: brand('provider', provider).color, gradient: '' }; pairs.set(key, link); }
      link.count += safe(flow.count); link.blocked += safe(flow.blocked); link.sensitive += sensitive(flow); link.flows.push(flow);
    }
    const list = [...pairs.values()];
    for (const link of list) link.thickness = Math.max(MIN_LINK, link.count * scale);
    const place = (side: 'left' | 'right') => {
      const byNode = new Map<Node, Link[]>();
      for (const link of list) { const node = link[side]; byNode.set(node, [...(byNode.get(node) ?? []), link]); }
      for (const [node, bands] of byNode) {
        const other = side === 'left' ? 'right' : 'left';
        bands.sort((a, b) => a[other].index - b[other].index || a.provider.localeCompare(b.provider));
        let y = node.y + (node.height - bands.reduce((sum, band) => sum + band.thickness, 0)) / 2;
        for (const band of bands) { if (side === 'left') { band.y0 = y; } else { band.y1 = y; } y += band.thickness; }
      }
    };
    place('left'); place('right');
    for (const link of list) {
      link.path = ribbonPath(link.x0, link.y0, link.x1, link.y1, link.thickness);
      link.gradient = `g${column}-${link.color.replace(/[^0-9a-z]/gi, '')}`;
      if (!gradients.has(link.gradient)) gradients.set(link.gradient, { id: link.gradient, color: link.color, x1: link.x0, x2: link.x1 });
    }
    list.sort((a, b) => b.count - a.count);
    links.push(...list);
  }
  return { links, gradients: [...gradients.values()] };
}

export function layoutFlows(input: Flow[], options: LayoutOptions): Layout {
  const flows = input.filter(flow => safe(flow.count) > 0);
  const dimensions = options.dimensions;
  const width = Math.max(MIN_WIDTH, Math.floor(safe(options.width)));
  // Narrow tiles leave the ribbons room to curve: names are cut with an ellipsis and
  // read in full in the tooltip and the side panels.
  const tileWidth = clamp(Math.round(width * 0.15), 120, 172);
  const step = dimensions.length > 1 ? (width - 2 * PAD_X - tileWidth) / (dimensions.length - 1) : 0;
  const columnX = dimensions.map((_, column) => Math.round(PAD_X + column * step));
  const sensitive = (flow: Flow) => options.sensitivity ? safe(flow.sensitive) : 0;
  const total = Math.max(1, flows.reduce((sum, flow) => sum + safe(flow.count), 0));

  // 1. One node per distinct value and column, busiest first. A model takes the hue
  //    of the vendor that served it most, so a column of models reads like its services.
  const columns = buildColumns(flows, dimensions, columnX, tileWidth, total, sensitive);

  // 2. Vertical scale from the tallest column; a tile never drops under MIN_NODE, so
  //    the canvas grows when many small values would otherwise overflow it.
  const maxNodes = Math.max(1, ...columns.map(column => column.length));
  const target = clamp(HEAD + PAD_BOTTOM + maxNodes * ROW, MIN_HEIGHT, MAX_TARGET);
  const scale = Math.max(0, target - HEAD - PAD_BOTTOM - (maxNodes - 1) * GAP) / total;
  // Heights and offsets stay unrounded: the bands stacked inside a tile must sum to
  // exactly its height, and a rounded tile next to exact bands would leak a pixel.
  for (const column of columns) { for (const node of column) { node.height = Math.max(MIN_NODE, node.count * scale); } }
  const used = (column: Node[]) => column.reduce((sum, node) => sum + node.height, 0) + Math.max(0, column.length - 1) * GAP;
  const height = Math.ceil(Math.max(target, HEAD + PAD_BOTTOM + Math.max(0, ...columns.map(used))));
  for (const column of columns) { let y = HEAD + (height - HEAD - PAD_BOTTOM - used(column)) / 2; for (const node of column) { node.y = y; y += node.height + GAP; } }

  // 3. Ribbons between adjacent columns, one per (left value, right value, vendor):
  //    the vendor hue survives every column and duplicate rows collapse into one band.
  //    Inside a tile, bands are ordered by the opposite tile's rank so they do not cross.
  const { links, gradients } = buildLinks(flows, dimensions, columns, tileWidth, scale, sensitive);
  return { width, height, tileWidth, columnX, columns, links, gradients, scale, total };
}

/** Merges flows that only differ on dimensions absent from `dimensions` (the table in
 * overall-usage mode). Produces fresh objects: never feed the result back into a layout. */
function newCollapsedFlow(flow: Flow, dimensions: readonly Dimension[]): Flow {
  return { actor_id: dimensions.includes('actor_id') ? flow.actor_id : '', actor_name: dimensions.includes('actor_id') ? flow.actor_name : '', tool: dimensions.includes('tool') ? flow.tool : '', provider: dimensions.includes('provider') ? flow.provider : '', model: dimensions.includes('model') ? flow.model : '', count: safe(flow.count), blocked: safe(flow.blocked), ...(flow.sensitive !== undefined ? { sensitive: safe(flow.sensitive) } : {}) };
}

function mergeCollapsedFlow(previous: Flow, flow: Flow): void {
  previous.count += safe(flow.count);
  previous.blocked += safe(flow.blocked);
  if (previous.sensitive !== undefined || flow.sensitive !== undefined) previous.sensitive = safe(previous.sensitive) + safe(flow.sensitive);
}

export function collapseFlows(flows: Flow[], dimensions: readonly Dimension[]): Flow[] {
  const merged = new Map<string, Flow>();
  for (const flow of flows) {
    const key = dimensions.map(dimension => valueOf(flow, dimension)).join(' ');
    const previous = merged.get(key);
    if (previous) mergeCollapsedFlow(previous, flow);
    else merged.set(key, newCollapsedFlow(flow, dimensions));
  }
  return [...merged.values()].sort((a, b) => b.count - a.count);
}
