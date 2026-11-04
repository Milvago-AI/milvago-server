import { useContext, useMemo, useState } from 'react';
import { Context, Icon, useText } from '../ui';
import { TileLogo } from './FlowDiagram';
import { ALL_DIMENSIONS, collapseFlows, labelOf, safe, valueOf } from './flowLayout';
import type { Dimension, Selection } from './flowLayout';
import type { Flow } from './types';

type Group = { value: string; label: string; count: number; blocked: number; flows: Flow[] };
function groupBy(flows: Flow[], dimension: Dimension): Group[] {
  const groups = new Map<string, Group>();
  for (const flow of flows) {
    const value = valueOf(flow, dimension);
    let group = groups.get(value);
    if (!group) { group = { value, label: labelOf(flow, dimension), count: 0, blocked: 0, flows: [] }; groups.set(value, group); }
    group.count += safe(flow.count); group.blocked += safe(flow.blocked); group.flows.push(flow);
  }
  return [...groups.values()].sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
}
function matches(flow: Flow, selected: Selection[], skip?: Dimension) {
  return ALL_DIMENSIONS.every(dimension => {
    const values = selected.filter(item => item.dimension === dimension);
    return dimension === skip || !values.length || values.some(item => item.value === valueOf(flow, dimension));
  });
}

/** Service first: no crossing ribbons or hidden hover dependency in the default view. */
export function FlowExplorer({ flows, selected, focus, clear, drill, peopleHidden, sensitivity }: Readonly<{
  flows: Flow[]; selected: Selection[]; focus: (item: Selection) => void; clear: () => void;
  drill: (flow: Flow) => void; peopleHidden: boolean; sensitivity: boolean;
}>) {
  const t = useText(); const { language } = useContext(Context);
  const services = useMemo(() => groupBy(flows, 'provider'), [flows]);
  const active = selected.find(item => item.dimension === 'provider');
  const visible = useMemo(() => flows.filter(flow => matches(flow, selected)), [flows, selected]);
  const number = (value: number) => value.toLocaleString(language);
  const name = (group: Group) => group.value === 'unknown' ? t('unattributed') : group.label;
  const total = flows.reduce((sum, flow) => sum + safe(flow.count), 0);
  if (!active) return <section className="flow-explorer" aria-label={t('mapGuidedView')}>
    <header className="flow-explorer-heading"><div><p className="workspace-eyebrow">{t('mapChooseService')}</p><h2>{t('mapOverviewTitle')}</h2><p>{t('mapOverviewHelp')}</p></div><span className="flow-scope">{t('services')}<strong>{number(services.length)}</strong></span></header>
    <div className="flow-service-grid">{services.map(service => {
      const actors = new Set(service.flows.map(flow => valueOf(flow, 'actor_id')).filter(value => value !== 'unknown')).size;
      const tools = new Set(service.flows.map(flow => valueOf(flow, 'tool'))).size;
      const models = new Set(service.flows.map(flow => valueOf(flow, 'model')).filter(value => value !== 'unknown')).size;
      return <button type="button" className="flow-service-card" key={service.value} onClick={() => focus({ dimension: 'provider', value: service.value, label: name(service) })}>
        <span className="flow-service-title"><TileLogo dimension="provider" value={service.value} label={name(service)} size={36}/><strong>{name(service)}</strong><Icon name="arrow" size={16}/></span>
        <span className="flow-service-volume"><strong>{number(service.count)}</strong><span>{t('requests2')}</span></span>
        <span className="flow-service-meter" aria-hidden="true"><i style={{ width: (total ? service.count / total * 100 : 0) + '%' }}/></span>
        <span className="flow-service-facts">{!peopleHidden && <span><Icon name="users" size={14}/>{number(actors)} {t(actors === 1 ? 'person' : 'people')}</span>}<span><Icon name="device" size={14}/>{number(tools)} {t(tools === 1 ? 'application' : 'mapApplications')}</span><span><Icon name="activity" size={14}/>{number(models)} {t(models === 1 ? 'model' : 'models')}</span></span>
        <span className="flow-service-bottom"><span className={service.blocked ? 'is-blocked' : ''}>{number(service.blocked)} {t('blocked2')}</span><span>{t('mapExploreService')}<Icon name="chevron-right" size={13}/></span></span>
      </button>;
    })}</div>
  </section>;
  const count = visible.reduce((sum, flow) => sum + safe(flow.count), 0);
  const blocked = visible.reduce((sum, flow) => sum + safe(flow.blocked), 0);
  return <section className="flow-explorer" aria-label={t('mapGuidedView')}>
    <nav className="flow-breadcrumb" aria-label={t('selection')}><button type="button" onClick={clear}><Icon name="arrow" size={14}/>{t('mapAllServices')}</button><Icon name="chevron-right" size={14}/><strong>{active.label}</strong></nav>
    <header className="flow-focus-heading"><div><TileLogo dimension="provider" value={active.value} label={active.label} size={40}/><div><h2>{active.label}</h2><p>{t('mapFocusedHelp')}</p></div></div><div className="flow-focus-count"><strong>{number(count)}</strong><span>{t('requests2')}</span>{blocked > 0 && <small className="is-blocked">{number(blocked)} {t('blocked2')}</small>}</div></header>
    <div className={'flow-reading' + (peopleHidden ? ' people-hidden' : '')}>
      {!peopleHidden && <FlowColumn dimension="actor_id" title={t('people')} flows={flows} selected={selected} focus={focus}/>}
      <FlowColumn dimension="tool" title={t('browsersApplications')} flows={flows} selected={selected} focus={focus}/>
      <section className="flow-destination"><p className="workspace-eyebrow">{t('service')}</p><TileLogo dimension="provider" value={active.value} label={active.label} size={44}/><strong>{active.label}</strong><span>{number(count)} {t('requests2')}</span><Icon name="arrow" size={18}/></section>
      <FlowColumn dimension="model" title={t('models')} flows={flows} selected={selected} focus={focus}/>
    </div>
    <details className="flow-paths"><summary>{t('mapPaths', [collapseFlows(visible, peopleHidden ? ALL_DIMENSIONS.filter(dimension => dimension !== 'actor_id') : ALL_DIMENSIONS).length])}<Icon name="chevron" size={14}/></summary>
      <FlowPaths key={JSON.stringify([selected, peopleHidden])} flows={visible} peopleHidden={peopleHidden} sensitivity={sensitivity} drill={drill}/>
    </details>
  </section>;
}

function FlowColumn({ dimension, title, flows, selected, focus }: Readonly<{ dimension: Dimension; title: string; flows: Flow[]; selected: Selection[]; focus: (item: Selection) => void }>) {
  const t = useText(); const { language } = useContext(Context); const [shown, setShown] = useState(6); const [query, setQuery] = useState('');
  // A selected value stays in its own column so the same button can clear it.
  const groups = useMemo(() => groupBy(flows.filter(flow => matches(flow, selected, dimension)), dimension), [flows, selected, dimension]);
  const filtered = groups.filter(group => (group.value === 'unknown' ? t('unattributed') : group.label).toLocaleLowerCase().includes(query.trim().toLocaleLowerCase()));
  const largest = Math.max(1, ...groups.map(group => group.count));
  return <section className="flow-column" aria-label={title}>
    <header><h3>{title}</h3><span>{groups.length}</span></header>
    {groups.length > 6 && <input className="flow-column-search" type="search" aria-label={t('search') + ' · ' + title} placeholder={t('search')} maxLength={100} value={query} onChange={event => { setQuery(event.target.value); setShown(6); }}/>}
    {filtered.length === 0 ? <p className="muted">{t('noMatchingEntry')}</p> : <ul>{filtered.slice(0, shown).map(group => {
      const label = group.value === 'unknown' ? t('unattributed') : group.label;
      const active = selected.some(item => item.dimension === dimension && item.value === group.value);
      return <li key={group.value}><button type="button" aria-pressed={active} onClick={() => focus({ dimension, value: group.value, label })}>
        <TileLogo dimension={dimension} value={group.value} label={label} size={26}/><span><strong>{label}</strong><small>{group.count.toLocaleString(language)} {t('requests2')}{dimension === 'actor_id' && group.value.startsWith('os:') && <> · {t('osUser')}</>}</small></span>{active && <Icon name="check" size={14}/>}
        <i className="flow-column-meter" aria-hidden="true"><i style={{ width: group.count / largest * 100 + '%' }}/></i>
      </button></li>;
    })}</ul>}
    {filtered.length > shown && <button type="button" className="flow-show-more" onClick={() => setShown(shown + 6)}>{t('mapShowMore', [filtered.length - shown])}</button>}{shown > 6 && <button type="button" className="flow-show-more" onClick={() => setShown(6)}>{t('mapShowLess')}</button>}
  </section>;
}

function FlowPaths({ flows, peopleHidden, sensitivity, drill }: Readonly<{ flows: Flow[]; peopleHidden: boolean; sensitivity: boolean; drill: (flow: Flow) => void }>) {
  const t = useText(); const { language } = useContext(Context); const [page, setPage] = useState(0);
  const dimensions = peopleHidden ? ALL_DIMENSIONS.filter(dimension => dimension !== 'actor_id') : ALL_DIMENSIONS;
  const rows = useMemo(() => collapseFlows(flows, dimensions), [flows, peopleHidden]); // dimensions follow peopleHidden only.
  const pages = Math.max(1, Math.ceil(rows.length / 10));
  const current = Math.min(page, pages - 1);
  return <><div className="table-scroll"><table><thead><tr>{!peopleHidden && <th>{t('people')}</th>}<th>{t('browsersApplications')}</th><th>{t('service')}</th><th>{t('models')}</th><th>{t('requests')}</th><th>{t('blocked')}</th>{sensitivity && <th>{t('sensitive3')}</th>}<th>{t('detail')}</th></tr></thead><tbody>{rows.slice(current * 10, current * 10 + 10).map(row => <tr key={dimensions.map(dimension => valueOf(row, dimension)).join('\u0000')}>
    {dimensions.map(dimension => <td key={dimension}>{valueOf(row, dimension) === 'unknown' ? t('unattributed') : labelOf(row, dimension)}</td>)}<td className="num">{safe(row.count).toLocaleString(language)}</td><td className={safe(row.blocked) ? 'num is-blocked' : 'num'}>{safe(row.blocked).toLocaleString(language)}</td>{sensitivity && <td className="num">{safe(row.sensitive).toLocaleString(language)}</td>}<td><button type="button" className="button secondary small" onClick={() => drill(row)}>{t('journal')}</button></td>
  </tr>)}</tbody></table></div><div className="flow-path-pagination"><button type="button" className="button secondary small" disabled={current === 0} onClick={() => setPage(current - 1)}>{t('previous')}</button><span>{current + 1} / {pages}</span><button type="button" className="button secondary small" disabled={current + 1 === pages} onClick={() => setPage(current + 1)}>{t('next')}</button></div></>;
}
