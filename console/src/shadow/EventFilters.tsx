import { useContext, useEffect, useId, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Context, Icon, useText } from '../ui';
import type { Translate } from '../ui';
import { periodCriteria, serializeCriteria, valueOf } from './filters';
import { FilterPopover } from './FilterPopover';
import type { Criteria } from './types';
import { criterionValues, formatEventQuery, parseEventQuery, regexFields, splitRegexSelections, usesRegex } from './eventQuery';
import type { EventQueryError, QueryOperators } from './eventQuery';

export type SearchField = { key: string; label: string; options?: [string, string][]; technical?: boolean };
function fields(t: Translate, commercial: boolean): SearchField[] {
  return [
    { key: 'provider', label: t('service') }, { key: 'actor_id', label: t('actorIdentifier') },
    { key: 'device_name', label: t('device') }, { key: 'device_id', label: t('deviceIdentifier'), technical: true }, { key: 'tool', label: t('browserApplication') },
    { key: 'model', label: t('model') },
    { key: 'action', label: t('action'), options: [['observed', t('observed2')], ['blocked', t('blocked3')], ['redirected', t('redirected')]] },
    { key: 'kind', label: t('kind'), options: [['prompt', t('request')], ['response', t('response')], ['navigation', t('navigation')]] },
    { key: 'attachment', label: t('attachedFiles'), options: [['yes', t('withAttachment')], ['no', t('withoutAttachment')]] },
    ...(commercial ? [{ key: 'sensitivity', label: t('sensitivity'), options: [['sensitive', t('sensitive')], ['normal', t('normal')], ['unknown', t('unknown')]] } as SearchField] : []),
    { key: 'dlp_rule', label: t('dlpRuleIdentifier'), technical: true },
    { key: 'dlp_mode', label: t('dlpMode'), technical: true, options: [['active', t('dlpActive')], ['simulation', t('dlpSimulation')]] },
    { key: 'dlp_consequence', label: t('dlpConsequence'), technical: true, options: [['observe', t('dlpObserve')], ['warn', t('dlpWarn')], ['block', t('dlpBlock')], ['mask', t('dlpMask')], ['replace', t('dlpReplace')]] },
    { key: 'dlp_outcome', label: t('dlpOutcome'), technical: true, options: [['matched', t('dlpMatched')], ['blocked', t('dlpBlocked')], ['prepared', t('dlpPrepared')], ['simulated', t('dlpSimulated')], ['unavailable', t('dlpUnavailable')], ['observed', t('dlpObserved')], ['overridden', t('dlpOverridden')], ['final_blocked', t('dlpFinalBlocked')], ['cancelled', t('dlpCancelled')], ['observed_after_send', t('dlpObservedAfterSend')]] },
  ];
}
const values = (criteria: Criteria, key: string): string[] => {
  const value = criteria[key]; return (Array.isArray(value) ? value : value ? [value] : []).filter(Boolean);
};
function localTime(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '' : new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}

export function EventFilters({ criteria, change, views, children, extraCount = 0, configuration }: Readonly<{
  configuration?: { fields: SearchField[]; operators: QueryOperators; placeholder: string; help: string; example: string; label: string; period?: boolean };
  criteria: Criteria; change: (next: Criteria) => void; views?: ReactNode | ((apply: (next: Criteria) => void) => ReactNode); children?: ReactNode; extraCount?: number;
}>) {
  const t = useText(); const { session, language } = useContext(Context);
  const available = configuration?.fields ?? fields(t, session.edition === 'commercial');
  const operators = configuration?.operators;
  const searchRegexFields = configuration ? new Set(Object.values(configuration.operators)) : regexFields;
  const showPeriod = configuration?.period ?? true;
  const searchLabel = configuration?.label ?? t('eventMetadataSearch');
  const format = (next: Criteria) => formatEventQuery(next, operators);
  const parse = (input: string, base: Criteria, allowed?: ReadonlySet<string>) => parseEventQuery(input, base, allowed, operators);
  // Display inherited filters too, including an edition-specific criterion we cannot offer anew.
  const visible = criteria.sensitivity && !available.some(field => field.key === 'sensitivity')
    ? [...available, { key: 'sensitivity', label: t('sensitivity') }] : available;
  const appliedQuery = format(criteria);
  const appliedScope = configuration ? JSON.stringify(criteria) : serializeCriteria(criteria);
  const [query, setQuery] = useState(appliedQuery);
  const [queryError, setQueryError] = useState<EventQueryError | null>(null);
  const queryId = useId();
  const search = useRef<HTMLInputElement>(null);
  const [editing, setEditing] = useState<string | null>(null);
  const [editRequest, setEditRequest] = useState(0);
  const [value, setValue] = useState('');
  const [from, setFrom] = useState(''), [to, setTo] = useState(''), [dateError, setDateError] = useState(false);
  // A hash synchronization can repeat the same scope after the user starts typing.
  useEffect(() => { setQuery(appliedQuery); setQueryError(null); }, [appliedQuery]);
  useEffect(() => { setEditing(null); }, [appliedScope]);
  const field = visible.find(item => item.key === editing);
  const activeCount = visible.reduce((sum, item) => sum + values(criteria, item.key).length, extraCount);
  const hours = (Date.parse(valueOf(criteria, 'to')) - Date.parse(valueOf(criteria, 'from'))) / 3600000;
  const shortPeriod = hours === 24 ? t('period24h') : hours === 168 ? t('period7d') : hours === 720 ? t('period30d') : t('custom');
  const fullPeriod = ['from', 'to'].map(key => {
    const date = new Date(valueOf(criteria, key));
    return Number.isNaN(date.getTime()) ? '—' : new Intl.DateTimeFormat(language, { dateStyle: 'medium', timeStyle: 'short' }).format(date);
  }).join(' – ');
  function invalid(error: EventQueryError) { setQueryError(error); search.current?.focus(); return false; }
  function readDraft(): Criteria | null {
    if (query === appliedQuery) return { ...criteria };
    const result = parse(query, criteria, new Set(['query', ...available.map(item => item.key)]));
    if (!result.ok) { invalid(result.error); return null; }
    return result.criteria;
  }
  function commit(next: Criteria): boolean {
    const parsed = parse(format(next), next, new Set(['query', ...available.map(item => item.key)]));
    if (!parsed.ok) return invalid(parsed.error);
    next = parsed.criteria;
    for (const [key, entries] of Object.entries(next)) {
      if (!visible.some(item => item.key === key) && key !== 'query') continue;
      const items = Array.isArray(entries) ? entries : [entries];
      const field = visible.find(item => item.key === key);
      if (items.length > 20) return invalid({ kind: 'limit', value: field?.label });
      for (const entry of items) {
        if (criterionValues(criteria, key).includes(entry)) continue;
        if (new TextEncoder().encode(entry).length > (key === 'query' || key.startsWith('dlp_') ? 100 : 200) || entry.includes('\r') || entry.includes('\n') || entry.includes('\0')) return invalid({ kind: 'limit', value: field?.label });
        const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
        if ((!usesRegex(next, key) && ((key === 'device_id' && !uuid.test(entry)) || (key === 'actor_id' && entry !== 'unknown' && !uuid.test(entry) && !/^os:[0-9a-f]{64}$/.test(entry)))) || (!usesRegex(next, key) && field?.options && !field.options.some(([value]) => value === entry))) return invalid({ kind: 'invalid', value: field?.label });
      }
    }
    if ((configuration ? new URLSearchParams(Object.entries(next).flatMap(([key, value]) => (Array.isArray(value) ? value : [value]).map(entry => [key, entry]))).toString() : serializeCriteria(next)).length > 6200) return invalid({ kind: 'limit' });
    setQuery(format(next)); setQueryError(null); change(next); return true;
  }
  function edit(item: SearchField) { const next = readDraft(); if (next) { setEditing(item.key); setValue(valueOf(next, item.key)); } }
  function remove(key: string, index: number) {
    const next = readDraft(); if (!next) return;
    const removed = values(criteria, key)[index]; const remaining = values(next, key).filter(entry => entry !== removed);
    if (remaining.length) next[key] = remaining.length === 1 ? remaining[0] : remaining; else delete next[key];
    if (commit(next)) search.current?.focus();
  }
  return <section className="event-filters" aria-label={t('eventSearchFilters')}>
    <div className="event-filter-toolbar">
      <form className="event-search" role="search" aria-label={searchLabel} onSubmit={event => {
        event.preventDefault(); const next = readDraft(); if (next) commit(next);
      }}>
        <label><span className="sr-only">{searchLabel}</span><Icon name="search" size={16}/><input ref={search} type="search" value={query} maxLength={2048} spellCheck={false} autoComplete="off" aria-invalid={Boolean(queryError)} aria-describedby={queryId}
          placeholder={configuration?.placeholder ?? t('eventSearchPlaceholder')} onChange={event => {
            const value = event.target.value; setQuery(value); setQueryError(null);
            if (!value) { const cleared = parse('', criteria); if (cleared.ok) commit(cleared.criteria); }
          }}/></label>
        <button className="button secondary" type="submit" aria-label={t('search2')}><Icon name="arrow" size={16}/></button>
      </form>
      {showPeriod && <FilterPopover label={t('eventPeriod', [shortPeriod])} onOpen={() => { setFrom(localTime(valueOf(criteria, 'from'))); setTo(localTime(valueOf(criteria, 'to'))); setDateError(false); }}>
        {close => <><p className="event-period-range">{fullPeriod}</p><div className="event-period-presets">
          {([[24, 'period24h'], [168, 'period7d'], [720, 'period30d']] as const).map(([duration, key]) => <button type="button" key={duration} className="button secondary" aria-pressed={hours === duration}
            onClick={() => { change({ ...criteria, ...periodCriteria(duration) }); close(); }}>{t(key)}</button>)}
        </div><details className="event-custom-period" open={![24, 168, 720].includes(hours) || undefined}><summary>{t('custom')}</summary>
          <form onSubmit={event => {
            event.preventDefault(); const start = new Date(from), end = new Date(to);
            if (!Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime()) || start >= end || end.getTime() - start.getTime() > 366 * 86400000) { setDateError(true); return; }
            change({ ...criteria, from: start.toISOString(), to: end.toISOString() }); close();
          }}><label>{t('from')}<input type="datetime-local" required value={from} onChange={event => { setFrom(event.target.value); setDateError(false); }}/></label>
          <label>{t('to')}<input type="datetime-local" required min={from} value={to} onChange={event => { setTo(event.target.value); setDateError(false); }}/></label>
          {dateError && <p role="alert">{t('eventDateError')}</p>}<button type="submit" className="button primary">{t('apply')}</button></form>
        </details></>}
      </FilterPopover>}
      <FilterPopover label={activeCount ? t('eventAddFilterCount', [activeCount]) : t('eventAddFilter')} align="end" onOpen={() => setEditing(null)} requestOpen={editRequest}>
        {close => field ? <form className="event-filter-editor" onSubmit={event => {
          event.preventDefault(); const parsed = readDraft(); if (!parsed) return; const next = { ...parsed };
          if (value !== valueOf(parsed, field.key)) {
            const selected = searchRegexFields.has(field.key) ? splitRegexSelections(value) : value.split(',').map(part => part.trim()).filter(Boolean);
            if (selected.length) next[field.key] = selected.length === 1 ? selected[0] : selected; else delete next[field.key];
            if (searchRegexFields.has(field.key)) next.regex = [...searchRegexFields].filter(key => (key === field.key && selected.length > 0) || (key !== field.key && usesRegex(next, key)));
          }
          if (commit(next)) close();
        }}><button type="button" className="event-filter-back" onClick={() => setEditing(null)}><Icon name="chevron-right" size={14}/>{t('eventChooseFilter')}</button>
          <label>{field.label}<input autoFocus value={value} maxLength={200} list={field.options ? queryId + '-values' : undefined} onChange={event => setValue(event.target.value)}/></label>
          {field.options && <datalist id={queryId + '-values'}>{field.options.map(([key, label]) => <option key={key} value={key}>{label}</option>)}</datalist>}
          <p className="event-filter-hint">{t('eventRegexValues')}</p>
          <div className="event-filter-actions"><button type="button" className="button secondary" onClick={close}>{t('cancel')}</button><button type="submit" className="button primary">{t('apply')}</button></div>
        </form> : <><div className="event-filter-choices">{available.filter(item => !item.technical).map(item => <button type="button" key={item.key} onClick={() => edit(item)}>{item.label}{values(criteria, item.key).length > 0 && <Icon name="check" size={14}/>}</button>)}</div>
          {available.some(item => item.technical) && <details className="event-technical-filters"><summary>{t('eventTechnicalFilters')}</summary><div className="event-filter-choices">{available.filter(item => item.technical).map(item => <button type="button" key={item.key} onClick={() => edit(item)}>{item.label}{values(criteria, item.key).length > 0 && <Icon name="check" size={14}/>}</button>)}</div></details>}</>}
      </FilterPopover>
      {typeof views === 'function' ? views(next => { commit(next); }) : views}
    </div>
    <div className="event-query-assistance">
      <details><summary>{t('eventQueryHelp')}</summary><p id={queryId}>{configuration?.help ?? t('eventQueryHelpBody')}</p><code>{configuration?.example ?? 'service:(chatgpt|claude) model:^gpt-5 app:chrome'}</code></details>
      {query !== appliedQuery && !queryError && <span>{t('eventQueryDraft')}</span>}
    </div>
    {queryError && <p className="event-query-error" role="alert">{({
      syntax: t('eventQuerySyntax'), operator: t('eventQueryUnknown', [queryError.value ?? '']), quote: t('eventQueryQuote'),
      value: t('eventQueryValue', [queryError.value ?? '']), limit: t('eventQueryLimit'), single: t('eventQuerySingle', [queryError.value ?? '']),
      boolean: t('eventQueryBoolean'), unavailable: t('eventQueryUnavailable', [queryError.value ?? '']), invalid: t('eventQueryInvalid', [queryError.value ?? '']),
      regex: t('eventQueryRegex'),
    })[queryError.kind]}</p>}
    {(activeCount > 0 || criteria.query || children || queryError) && <div className="event-filter-summary" aria-label={t('eventActiveFilters')}>
      {criteria.query && <div className="event-filter-chip"><span>{t('eventCriterion', [t('search2'), valueOf(criteria, 'query')])}</span><button type="button" aria-label={t('eventRemoveFilter', [t('search2'), valueOf(criteria, 'query')])} onClick={() => { const next = readDraft(); if (!next) return; delete next.query; if (commit(next)) search.current?.focus(); }}><Icon name="close" size={12}/></button></div>}
      {visible.flatMap(item => values(criteria, item.key).map((entry, index) => {
        const label = item.options?.find(([key]) => key === entry)?.[1] ?? entry;
        return <div className="event-filter-chip" key={item.key + ':' + index}>
          <button type="button" className="event-chip-value" onClick={() => { edit(item); setEditRequest(current => current + 1); }}>{t('eventCriterion', [item.label, label])}</button><button type="button" aria-label={t('eventRemoveFilter', [item.label, label])} onClick={() => remove(item.key, index)}><Icon name="close" size={12}/></button>
        </div>;
      }))}
      {children}
      {(activeCount > 0 || criteria.query || queryError) && <button type="button" className="event-filter-reset" onClick={() => { const next = { ...criteria, ...(showPeriod ? periodCriteria(24) : {}) }; for (const key of [...searchRegexFields, 'regex']) delete next[key]; commit(next); search.current?.focus(); }}>{t('reset')}</button>}
    </div>}
  </section>;
}
