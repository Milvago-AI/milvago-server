import { useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { Dialog, Icon, useText } from '../ui';
import type { IconName } from '../ui';
import { brand } from './brands';
import type { Dimension } from './flowLayout';
import { onlyPeople, setChecked, toggleExclusion } from './flowView';
import type { FacetOption, RankedPerson, View } from './flowView';

/** A person named by the OS account of their records rather than by a verified
 * association: the name is informational, and the list says so instead of
 * letting it pass for a verified identity. */
const osAccount = (option: FacetOption) => option.dimension === 'actor_id' && option.value.startsWith('os:');

export function BrandDot({ dimension, value, label }: Readonly<{ dimension: Dimension; value: string; label: string }>) {
  if (value === 'unknown') return <i className="fd-dot soft" aria-hidden="true">?</i>;
  if (dimension === 'actor_id') return <i className="fd-dot soft" aria-hidden="true">{label.trim().charAt(0).toUpperCase() || '?'}</i>;
  return <i className="fd-dot" aria-hidden="true" style={{ background: brand(dimension, value).color }} />;
}

/** Searchable checkbox list shared by the rails and the top-bar picker. Check all /
 * uncheck all act on what the search currently shows, which is everything when empty. */
function OptionList({ dimension, options, checked, toggle, setAll, waiting, className }: Readonly<{
  dimension: Dimension; options: FacetOption[]; checked: (option: FacetOption) => boolean; toggle: (value: string) => void; setAll: (values: string[], checked: boolean) => void;
  /** Rank of a person who is checked but waiting outside the ten-people window, null otherwise. */
  waiting?: (option: FacetOption) => number | null; className?: string;
}>) {
  const t = useText(); const [query, setQuery] = useState('');
  const listClass = 'fd-facet-list' + (className ? ' ' + className : '');
  const label = (option: FacetOption) => option.value === 'unknown' ? t('unattributed') : option.label;
  const filtered = useMemo(() => { const needle = query.trim().toLocaleLowerCase(); return needle ? options.filter(option => label(option).toLocaleLowerCase().includes(needle)) : options; }, [options, query, t]); // eslint-disable-line react-hooks/exhaustive-deps
  return <>
    <div className="fd-facet-tools">
      <input type="search" aria-label={t('search')} placeholder={t('search')} value={query} onChange={event => setQuery(event.target.value)} maxLength={100} />
      <button type="button" className="button ghost small" onClick={() => setAll(filtered.map(option => option.value), true)}>{t('checkAll')}</button>
      <button type="button" className="button ghost small" onClick={() => setAll(filtered.map(option => option.value), false)}>{t('uncheckAll')}</button>
    </div>
    <ul className={listClass}>{filtered.map(option => {
      const rank = waiting?.(option) ?? null;
      return <li key={option.value} className={rank !== null ? 'waiting' : undefined}><label className="fd-option">
        <input type="checkbox" checked={checked(option)} aria-label={`${label(option)} · ${option.count} ${t('requests2')}`} onChange={() => toggle(option.value)} />
        <BrandDot dimension={dimension} value={option.value} label={label(option)} />
        <span className="fd-option-name" title={label(option)}>{label(option)}</span>
        {osAccount(option) && <span className="fd-option-tag">{t('osUser')}</span>}
        <span className="fd-option-count num">{option.count.toLocaleString()}</span>
        {rank !== null && <span className="fd-waiting">{t('waitingRank0', [rank])}</span>}
      </label></li>;
    })}</ul>
    {filtered.length === 0 && <p className="fd-facet-empty muted">{t('noMatchingEntry')}</p>}
  </>;
}

export function Facet({ dimension, title, options, view, change, window }: Readonly<{
  dimension: Dimension; title: string; options: FacetOption[]; view: View; change: (view: View) => void;
  /** People only: how many are drawn out of how many exist; absent in overall-usage mode. */
  window?: { shown: number; total: number };
}>) {
  const t = useText(); const checkedCount = options.filter(option => option.checked).length;
  return <fieldset className="fd-facet">
    <legend><span>{title}</span><span className="fd-facet-count num">{window ? t('n0ShownOfN1', [window.shown, window.total]) : `${checkedCount} / ${options.length}`}</span></legend>
    <OptionList dimension={dimension} options={options} checked={option => option.checked}
      toggle={value => change(toggleExclusion(view, dimension, value))} setAll={(values, checked) => change(setChecked(view, dimension, values, checked))}
      waiting={window ? option => { const person = option as RankedPerson; return person.checked && !person.displayed && person.count > 0 ? person.rank : null; } : undefined} />
  </fieldset>;
}

/** A side panel that folds into a 36 px strip so the ribbon can take the whole width. */
export function FacetRail({ side, icons, children }: Readonly<{ side: 'left' | 'right'; icons: IconName[]; children: ReactNode }>) {
  const t = useText(); const [collapsed, setCollapsed] = useState(false);
  return <aside className={`fd-rail ${side}${collapsed ? ' collapsed' : ''}`}>
    <button type="button" className="icon-button fd-rail-toggle" aria-expanded={!collapsed} aria-label={collapsed ? t('expandPanel') : t('collapsePanel')} onClick={() => setCollapsed(!collapsed)}><Icon name="chevron-right" /></button>
    <div className="fd-rail-icons" aria-hidden="true">{icons.map(name => <Icon key={name} name={name} />)}</div>
    <div className="fd-rail-body">{children}</div>
  </aside>;
}

/** Top-bar control: "only these people". Applying keeps exactly the chosen people checked. */
export function PeoplePicker({ people, view, apply }: Readonly<{ people: RankedPerson[]; view: View; apply: (view: View) => void }>) {
  const t = useText(); const [open, setOpen] = useState(false); const [draft, setDraft] = useState<Set<string>>(() => new Set());
  const checkedCount = people.filter(person => person.checked).length; const restricted = view.excluded.actor_id.length > 0;
  let summary = t('n0People', [checkedCount]);
  if (!restricted) summary = t('peopleAll');
  else if (checkedCount === 1) summary = t('onePerson');
  return <>
    <button type="button" className="button secondary" aria-haspopup="dialog" aria-expanded={open} disabled={people.length === 0} onClick={() => { setDraft(new Set(people.filter(person => person.checked).map(person => person.value))); setOpen(true); }}><Icon name="users" />{summary}</button>
    {open && <Dialog title={t('onlyThesePeople')} close={() => setOpen(false)}>
      <OptionList dimension="actor_id" options={people} className="fd-picker-list" checked={option => draft.has(option.value)}
        toggle={value => setDraft(current => { const next = new Set(current); if (next.has(value)) { next.delete(value); } else { next.add(value); } return next; })}
        setAll={(values, checked) => setDraft(current => { const next = new Set(current); for (const value of values) { if (checked) { next.add(value); } else { next.delete(value); } } return next; })} />
      <div className="dialog-actions">
        <button type="button" className="button secondary" onClick={() => setOpen(false)}>{t('cancel')}</button>
        <button type="button" className="button primary" disabled={draft.size === 0} onClick={() => { apply(onlyPeople(view, people.map(person => person.value), [...draft])); setOpen(false); }}>{t('apply')}</button>
      </div>
    </Dialog>}
  </>;
}
