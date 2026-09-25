import { Fragment, useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { CSSProperties } from 'react';
import { Icon, useText } from '../ui';
import { brand } from './brands';
import { ALL_DIMENSIONS, FALLBACK_WIDTH, collapseFlows, labelOf, layoutFlows, nodeKey, ribbonPath, safe, valueOf } from './flowLayout';
import type { Dimension, Link, Node, Selection } from './flowLayout';
import type { Flow } from './types';
import './flow.css';
export type { Selection } from './flowLayout';

type Hover = { kind: 'node'; node: Node } | { kind: 'link'; link: Link } | null;
const TIP_WIDTH = 260, TIP_HEIGHT = 176;

function initials(text: string) {
  const words = text.trim().split(/\s+/).filter(Boolean);
  return words.length ? words.slice(0, 2).map(word => word[0]!.toUpperCase()).join('') : '?';
}

/** Width of the scroll container, re-measured on resize. jsdom neither lays out nor
 * observes, so it keeps the fallback and the layout stays deterministic in tests. */
function useMeasuredWidth() {
  const ref = useRef<HTMLDivElement>(null); const [width, setWidth] = useState(FALLBACK_WIDTH);
  useLayoutEffect(() => {
    const element = ref.current; if (!element) return;
    const apply = (value: number) => { if (value > 0) setWidth(current => Math.abs(current - value) < 1 ? current : Math.round(value)); };
    apply(element.clientWidth);
    if (typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver(entries => { for (const entry of entries) apply(entry.contentRect.width); });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);
  return [ref, width] as const;
}

export function TileLogo({ dimension, value, label, size }: Readonly<{ dimension: Dimension; value: string; label: string; size: number }>) {
  const [failed, setFailed] = useState(false);
  if (value === 'unknown') return <span className="fd-logo soft" style={{ width: size, height: size }}>?</span>;
  if (dimension === 'actor_id') return <span className="fd-logo soft" style={{ width: size, height: size }}>{initials(label)}</span>;
  const info = brand(dimension, value);
  if (info.logo && !failed) return <img className="fd-logo" style={{ width: size, height: size }} src={info.logo} alt="" onError={() => setFailed(true)} />;
  return <span className="fd-logo" style={{ width: size, height: size, background: info.color }}>{info.monogram}</span>;
}

export function FlowDiagram({ flows, dimensions = ALL_DIMENSIONS, selected, select, drill, sensitivity, totals, tableToggle = true, actorLabels }: Readonly<{
  flows: Flow[]; dimensions?: readonly Dimension[]; selected: Selection[]; select: (node: Selection) => void; sensitivity: boolean;
  /** Opens the journal for one path. Omitted where the reader has no individual view to
   * open -- a weekly aggregate report -- and the detail column then disappears rather
   * than offering a button the server would refuse. */
  drill?: (flow: Flow) => void;
  /** Values existing in the period per dimension, so a column head can read "10 / 47". */
  totals?: Partial<Record<Dimension, number>>;
  /** The toolbar's own "show table" switch. Callers that already offer a table/flows
   * choice of their own turn it off, so one screen never holds two different tables.
   * The narrow-viewport fallback is untouched: it is CSS, not this button. */
  tableToggle?: boolean;
  /** Renames the first column when it does not carry people: a report draws teams or
   * device groups there, and the heading, the tooltip and the canvas label must say so. */
  actorLabels?: { plural: string; singular: string; map: string };
}>) {
  const t = useText(); const id = useId().replaceAll(':', ''); const [table, setTable] = useState(false); const [hover, setHover] = useState<Hover>(null);
  const [scrollRef, width] = useMeasuredWidth(); const canvasRef = useRef<HTMLFieldSetElement>(null); const tipRef = useRef<HTMLDivElement>(null); const rectRef = useRef<DOMRect | null>(null); const tipAt = useRef({ x: 0, y: 0 });
  const layout = useMemo(() => layoutFlows(flows, { width, dimensions, sensitivity }), [flows, width, dimensions, sensitivity]);
  // Entrance runs once per data change as a CSS transition driven by three phases:
  // `pre` (the first paint of new data, tiles hidden), `entering` (staggered fade-in),
  // `done`. A transition cannot replay on its own, unlike a CSS animation, which the
  // engine restarted on every viewport change (observed on a full-page capture).
  const revision = useRef(0);
  const dataKey = useMemo(() => ++revision.current, [flows, dimensions]);
  const [enteredKey, setEnteredKey] = useState(0); const [settledKey, setSettledKey] = useState(0);
  let phase = 'done';
  if (settledKey !== dataKey) phase = 'entering';
  if (enteredKey !== dataKey) phase = 'pre';
  useEffect(() => {
    setHover(null);
    const schedule = typeof requestAnimationFrame === 'function' ? requestAnimationFrame : (callback: () => void) => window.setTimeout(callback, 16);
    const cancel = typeof cancelAnimationFrame === 'function' ? cancelAnimationFrame : window.clearTimeout;
    const frame = schedule(() => setEnteredKey(dataKey)); const timer = window.setTimeout(() => setSettledKey(dataKey), 700);
    return () => { cancel(frame); window.clearTimeout(timer); };
  }, [dataKey]);
  function columnTitle(dimension: Dimension) {
    if (dimension === 'actor_id') return actorLabels?.plural ?? t('people');
    if (dimension === 'tool') return t('browsersApplications');
    if (dimension === 'provider') return t('services');
    return t('models');
  }
  function singular(dimension: Dimension) {
    if (dimension === 'actor_id') return actorLabels?.singular ?? t('person');
    if (dimension === 'tool') return t('browserApplication');
    if (dimension === 'provider') return t('service');
    return t('model');
  }
  const label = (node: Pick<Node, 'value' | 'label'>) => node.value === 'unknown' ? t('unattributed') : node.label;
  const percent = (share: number) => share.toLocaleString(undefined, { style: 'percent', maximumFractionDigits: 1 });

  // Selection: OR inside a dimension, AND across dimensions. A ribbon carries a solid
  // sub-band as wide as the share of its flows that match.
  const matcher = useMemo(() => {
    const by = new Map<Dimension, Set<string>>();
    for (const item of selected) { const set = by.get(item.dimension) ?? new Set<string>(); set.add(item.value); by.set(item.dimension, set); }
    return (flow: Flow) => [...by].every(([dimension, set]) => set.has(valueOf(flow, dimension)));
  }, [selected]);
  const matchShare = useMemo(() => selected.length ? new Map(layout.links.map(link => [link.key, link.flows.reduce((sum, flow) => matcher(flow) ? sum + safe(flow.count) : sum, 0) / link.count])) : null, [layout, matcher, selected.length]);
  // Hover lights the whole path of the hovered tile or ribbon: every ribbon sharing
  // one of its flows, and both ends of each of them.
  const hot = useMemo(() => {
    if (!hover) return null;
    const seed = hover.kind === 'link' ? new Set(hover.link.flows) : null; const node = hover.kind === 'node' ? hover.node : null;
    const links = new Set<string>(); const nodes = new Set<string>();
    if (node) nodes.add(nodeKey(node));
    for (const link of layout.links) { if (link.flows.some(flow => seed ? seed.has(flow) : node !== null && valueOf(flow, node.dimension) === node.value)) { links.add(link.key); nodes.add(nodeKey(link.left)); nodes.add(nodeKey(link.right)); } }
    return { links, nodes };
  }, [hover, layout]);
  const vendors = useMemo(() => {
    const seen = new Map<string, { name: string; color: string }>();
    for (const link of layout.links) {
      const info = brand('provider', link.provider);
      let name = info.name;
      if (!name && link.provider !== 'unknown') name = link.provider;
      seen.set(String(info.color) + '|' + String(name), { name, color: info.color });
    }
    return [...seen.values()];
  }, [layout]);
  const rows = useMemo(() => dimensions.includes('actor_id') ? flows : collapseFlows(flows, dimensions), [flows, dimensions]);

  function placeTooltip(x: number, y: number) {
    const tip = tipRef.current;
    if (!tip) { return; }
    tipAt.current = { x, y };
    // The tooltip is as tall as its content: measure it rather than trust the nominal
    // height, so a long label never pushes it past the bottom of the canvas.
    const tipHeight = tip.offsetHeight || TIP_HEIGHT;
    const tx = x + 16 + TIP_WIDTH > layout.width ? Math.max(0, x - TIP_WIDTH - 12) : x + 16;
    const ty = Math.max(0, Math.min(y + 16, layout.height - tipHeight));
    tip.style.transform = `translate(${Math.round(tx)}px, ${Math.round(ty)}px)`;
  }
  // The content, hence the height, changes with the hovered element: re-clamp once it has rendered.
  useLayoutEffect(() => { if (hover) placeTooltip(tipAt.current.x, tipAt.current.y); }, [hover]); // eslint-disable-line react-hooks/exhaustive-deps
  function ribbonClass(link: Link) {
    let className = 'fd-ribbon';
    if (matchShare) className += matchShare.get(link.key)! > 0 ? ' match' : ' fade';
    if (hot) className += hot.links.has(link.key) ? ' hot' : ' dim';
    return className;
  }
  type Tooltip = { title: string; rows: [string, string][] };
  function nodeTooltip(node: Node): Tooltip {
    const info = node.dimension === 'provider' || node.dimension === 'model' ? brand(node.dimension, node.value) : null;
    const rows: [string, string][] = [
      [singular(node.dimension), label(node)],
      ...(info?.name && info.name !== node.value ? [[t('vendor'), info.name] as [string, string]] : []),
      [t('requests'), node.count.toLocaleString()],
      [t('share'), percent(node.share)],
      ...(node.blocked > 0 ? [[t('blocked'), node.blocked.toLocaleString()] as [string, string]] : []),
      ...(sensitivity && node.sensitive > 0 ? [[t('sensitive3'), node.sensitive.toLocaleString()] as [string, string]] : []),
    ];
    return { title: label(node), rows };
  }
  function linkTooltip(link: Link): Tooltip {
    const info = brand('provider', link.provider);
    let provider = info.name;
    if (!provider) provider = link.provider === 'unknown' ? t('unattributed') : link.provider;
    const rows: [string, string][] = [
      [singular(link.left.dimension), label(link.left)],
      [singular(link.right.dimension), label(link.right)],
      [t('vendor'), provider],
      [t('requests'), link.count.toLocaleString()],
      [t('share'), percent(link.count / layout.total)],
      ...(link.blocked > 0 ? [[t('blocked'), link.blocked.toLocaleString()] as [string, string]] : []),
      ...(sensitivity && link.sensitive > 0 ? [[t('sensitive3'), link.sensitive.toLocaleString()] as [string, string]] : []),
    ];
    return { title: `${label(link.left)} → ${label(link.right)}`, rows };
  }
  function tooltip(): Tooltip | null {
    if (!hover) return null;
    if (hover.kind === 'node') return nodeTooltip(hover.node);
    return linkTooltip(hover.link);
  }
  const tip = tooltip();

  return <div className="fd-visual">
    <div className="fd-toolbar"><p>{t('selectMultipleElementsToCombineDimensions')}</p>{tableToggle && <button className="button small secondary" aria-pressed={table} onClick={() => setTable(!table)}>{table ? t('showFlows') : t('showTable')}</button>}</div>
    <div ref={scrollRef} className={`fd-scroll${table ? ' fd-hidden' : ''}`}>
      <fieldset ref={canvasRef} className={`fd-canvas fd-${phase}`} aria-label={dimensions.includes('actor_id') ? actorLabels?.map ?? t('requestMapPersonToolServiceModel') : t('requestMapToolServiceModel')} style={{ width: layout.width, height: layout.height }}
        onMouseEnter={() => { rectRef.current = canvasRef.current?.getBoundingClientRect() ?? null; }}
        onMouseMove={event => { const rect = rectRef.current ?? (rectRef.current = canvasRef.current?.getBoundingClientRect() ?? null); if (rect) placeTooltip(event.clientX - rect.left, event.clientY - rect.top); }}
        onMouseLeave={() => setHover(null)}>
        <svg aria-hidden="true" width={layout.width} height={layout.height} viewBox={`0 0 ${layout.width} ${layout.height}`}>
          <defs>
            <pattern id={`${id}-hatch`} width="7" height="7" patternUnits="userSpaceOnUse"><path d="M-1 1 1-1M0 7 7 0M6 8 8 6" stroke="var(--warning)" strokeWidth="1" /></pattern>
            {layout.gradients.map(gradient => <linearGradient key={gradient.id} id={`${id}-${gradient.id}`} gradientUnits="userSpaceOnUse" x1={gradient.x1} y1="0" x2={gradient.x2} y2="0"><stop offset="0" stopColor={gradient.color} stopOpacity=".55" /><stop offset="1" stopColor={gradient.color} stopOpacity=".95" /></linearGradient>)}
          </defs>
          <g key={dataKey} className="fd-ribbons">
            {layout.links.map(link => {
              const share = matchShare?.get(link.key) ?? 0; const sensitiveShare = sensitivity && link.sensitive > 0 ? Math.min(1, link.sensitive / link.count) : 0; const dim = hot && !hot.links.has(link.key) ? ' dim' : '';
              return <Fragment key={link.key}>
                <path d={link.path} className={ribbonClass(link)} fill={`url(#${id}-${link.gradient})`} onMouseEnter={() => setHover({ kind: 'link', link })} onMouseLeave={() => setHover(null)} />
                {share > 0 && <path d={ribbonPath(link.x0, link.y0 + link.thickness * (1 - share), link.x1, link.y1 + link.thickness * (1 - share), Math.max(1, link.thickness * share))} className={`fd-highlight${dim}`} fill={link.color} pointerEvents="none" />}
                {sensitiveShare > 0 && <path d={ribbonPath(link.x0, link.y0, link.x1, link.y1, Math.max(1, link.thickness * sensitiveShare))} className={`fd-hatch${matchShare && share === 0 ? ' fade' : ''}${dim}`} fill={`url(#${id}-hatch)`} pointerEvents="none" />}
              </Fragment>;
            })}
          </g>
        </svg>
        {dimensions.map((dimension, column) => { const shown = layout.columns[column].length; const total = totals?.[dimension]; return <div key={dimension} className="fd-head" style={{ left: layout.columnX[column], width: layout.tileWidth }}><span>{columnTitle(dimension)}</span><span className="fd-head-count num">{shown}{total !== undefined && total !== shown ? ` / ${total}` : ''}</span></div>; })}
        <div key={dataKey} className="fd-tiles">
          {layout.columns.flat().map(node => {
            const key = nodeKey(node); const active = selected.some(item => item.dimension === node.dimension && item.value === node.value); const compact = node.height < 46; const name = label(node);
            let state = '';
            if (active) state += ' selected';
            if (node.value === 'unknown') state += ' unknown';
            if (compact) state += ' compact';
            if (hot) state += hot.nodes.has(key) ? ' hot' : ' dim';
            const style = { left: node.x, top: node.y, width: node.width, height: node.height, '--i': node.column * 12 + node.index } as CSSProperties;
            const focus = () => { setHover({ kind: 'node', node }); placeTooltip(node.x + node.width, node.y); };
            return <button key={key} type="button" aria-pressed={active} aria-label={`${name} · ${node.count} ${t('requests2')}`} data-dimension={node.dimension} className={`fd-tile${state}`} style={style}
              onClick={() => select(node)}
              onMouseEnter={() => setHover({ kind: 'node', node })} onMouseLeave={() => setHover(null)} onFocus={focus} onBlur={() => setHover(null)}>
              <TileLogo dimension={node.dimension} value={node.value} label={name} size={compact ? 20 : 24} />
              <span className="fd-text">
                <span className="fd-name">{name}</span>
                {!compact && <span className="fd-sub"><span className="fd-count"><span className="num">{node.count.toLocaleString()}</span> {t('requests2')}</span>{node.blocked > 0 && <span className="fd-blocked num" title={t('blocked')}>{node.blocked.toLocaleString()}</span>}{sensitivity && node.sensitive > 0 && <span className="fd-sensitive num" title={t('sensitive3')}><Icon name="alert" size={12} />{node.sensitive.toLocaleString()}</span>}</span>}
              </span>
              <span className="fd-share" aria-hidden="true"><i style={{ width: `${Math.min(100, node.share * 100)}%`, background: node.color }} /></span>
            </button>;
          })}
        </div>
        <div ref={tipRef} className={`fd-tooltip${tip ? ' visible' : ''}`} aria-hidden="true">{tip && <><strong className="fd-tooltip-title">{tip.title}</strong><dl>{tip.rows.map(([term, value]) => <Fragment key={term}><dt>{term}</dt><dd>{value}</dd></Fragment>)}</dl></>}</div>
      </fieldset>
    </div>
    {!table && vendors.length > 0 && <ul className="fd-vendors">{vendors.map(vendor => <li key={`${vendor.color}|${vendor.name}`}><i style={{ background: vendor.color }} />{vendor.name || t('unattributed')}</li>)}</ul>}
    <div className={`fd-table${table ? ' fd-visible' : ''}`}>
      <div className="table-scroll" tabIndex={0} aria-label={t('observedPathsTable')}>
        <table>
          <thead><tr>{dimensions.map(dimension => <th key={dimension}>{columnTitle(dimension)}</th>)}<th>{t('requests')}</th>{sensitivity && <th>{t('sensitive3')}</th>}{drill && <th>{t('detail')}</th>}</tr></thead>
          <tbody>{rows.map(flow => <tr key={dimensions.map(dimension => valueOf(flow, dimension)).join('\u0000')}>
            {dimensions.map(dimension => { const value = valueOf(flow, dimension); const text = value === 'unknown' ? t('unattributed') : labelOf(flow, dimension); return <td key={dimension}><button className="fd-select" aria-pressed={selected.some(item => item.dimension === dimension && item.value === value)} onClick={() => select({ dimension, value, label: text })}>{text}</button></td>; })}
            <td className="num">{safe(flow.count).toLocaleString()}</td>
            {sensitivity && <td className="num">{safe(flow.sensitive).toLocaleString()}</td>}
            {drill && <td><button className="button small secondary" onClick={() => drill(flow)}>{t('journal')}</button></td>}
          </tr>)}</tbody>
        </table>
      </div>
    </div>
  </div>;
}
