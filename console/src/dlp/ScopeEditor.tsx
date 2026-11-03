import { useText } from '../ui';
import type { DlpExpr, DlpScopeOptions } from './types';

type Selection = { web: boolean; local: boolean; browsers?: string[]; services?: string[]; applications?: string[] };
const defaults: DlpScopeOptions = { browsers: [{ id: 'chrome', label: 'Chrome' }, { id: 'edge', label: 'Edge' }, { id: 'firefox', label: 'Firefox' }], services: [{ id: 'chatgpt', label: 'ChatGPT' }, { id: 'claude', label: 'Claude' }], applications: [] };
const leafValues = (value: DlpExpr, field: string): string[] | undefined => value.op === 'eq' && value.field === field ? [value.value] : value.op === 'in' && value.field === field ? value.values : undefined;

/** Only lossless, recognized scopes use the simple editor. Advanced ASTs stay intact. */
function readScope(value: DlpExpr, native: boolean): Selection | null {
  if (value.op === 'true') return { web: true, local: native, browsers: undefined, services: undefined, applications: undefined };
  const result: Selection = { web: false, local: false, browsers: undefined, services: undefined, applications: undefined };
  const branches = value.op === 'any' ? value.children : [value];
  for (const branch of branches) {
    const clauses = branch.op === 'all' ? branch.children : [branch];
    const channels = clauses.map(c => leafValues(c, 'channel')).filter((v): v is string[] => !!v);
    if (channels.length !== 1 || channels[0].length !== 1) return null;
    const channel = channels[0][0];
    if (!['browser', 'native'].includes(channel) || channel === 'native' && !native || channel === 'browser' && result.web || channel === 'native' && result.local) return null;
    const seen = new Set<string>();
    for (const clause of clauses) {
      if (clause.op !== 'eq' && clause.op !== 'in' || seen.has(clause.field)) return null;
      seen.add(clause.field);
      const values = clause.op === 'eq' ? [clause.value] : clause.values;
      if (clause.field === 'channel') continue;
      if (channel === 'browser' && clause.field === 'provider') result.services = values;
      else if (clause.field === 'tool') { if (channel === 'browser') result.browsers = values; else result.applications = values; }
      else return null;
    }
    if (channel === 'browser') result.web = true; else result.local = true;
  }
  return result.web || result.local ? result : null;
}

function writeScope(value: Selection): DlpExpr {
  const group = (channel: string, fields: [string, string[] | undefined][]): DlpExpr => {
    const children: DlpExpr[] = [{ op: 'eq', field: 'channel', value: channel }];
    for (const [field, values] of fields) if (values !== undefined) children.push({ op: 'in', field, values });
    return children.length === 1 ? children[0] : { op: 'all', children };
  };
  const children: DlpExpr[] = [];
  if (value.web) children.push(group('browser', [['tool', value.browsers], ['provider', value.services]]));
  if (value.local) children.push(group('native', [['tool', value.applications]]));
  return children.length === 1 ? children[0] : { op: 'any', children };
}

export function ScopeEditor({ value, change, options, advanced }: Readonly<{ value: DlpExpr; change: (value: DlpExpr) => void; options?: DlpScopeOptions; advanced: () => void }>) {
  const t = useText(); const choices = options || defaults; const native = choices.applications.length > 0;
  const selected = readScope(value, native);
  if (!selected) return <div className="dlp-scope-advanced"><p>{t('dlpScopeAdvanced')}</p><button className="button secondary small" type="button" onClick={advanced}>{t('dlpLanguage')}</button><button className="button ghost small" type="button" onClick={() => change({ op: 'eq', field: 'channel', value: 'browser' })}>{t('dlpDefineSimpleScope')}</button></div>;
  const set = (next: Selection) => { if (next.web || next.local) change(writeScope(next)); };
  const toggle = (field: 'browsers' | 'services' | 'applications', id: string) => set({ ...selected, [field]: (selected[field] || []).includes(id) ? (selected[field] || []).filter(v => v !== id) : [...(selected[field] || []), id] });
  function picker(field: 'browsers' | 'services' | 'applications', title: string, all: string, items: { id: string; label: string }[]) {
    const values = selected![field];
    return <fieldset className="dlp-scope-choices"><legend>{title}</legend><label className="dlp-scope-all"><input type="checkbox" checked={values === undefined} onChange={event => set({ ...selected!, [field]: event.target.checked ? undefined : [] })} />{all}</label><div className="dlp-scope-chips">{items.map(item => <label key={item.id} className={(values || []).includes(item.id) ? 'selected' : ''}><input type="checkbox" checked={(values || []).includes(item.id)} onChange={() => toggle(field, item.id)} />{item.label}</label>)}{(values || []).filter(id => !items.some(item => item.id === id)).map(id => <label key={id} className="selected"><input type="checkbox" checked onChange={() => toggle(field, id)} />{t('dlpCustomScopeValue', [id])}</label>)}</div>{values?.length === 0 && <p className="field-help" role="alert">{t('dlpSelectAtLeastOne')}</p>}</fieldset>;
  }
  return <div className="dlp-friendly-scope"><p className="field-help">{t('dlpScopeUsageHint')}</p>
    <section className={`dlp-scope-surface${selected.web ? ' selected' : ''}`}><label className="dlp-scope-surface-title"><input type="checkbox" checked={selected.web} disabled={selected.web && !selected.local} onChange={e => set({ ...selected, web: e.target.checked })} /><strong>{t('dlpWebSurface')}</strong></label><p>{t('dlpWebSurfaceHint')}</p>{selected.web && <>{picker('services', t('dlpAiServices'), t('dlpAllAiServices'), choices.services)}{picker('browsers', t('dlpWebBrowsers'), t('dlpAllWebBrowsers'), choices.browsers)}</>}</section>
    {native && <section className={`dlp-scope-surface${selected.local ? ' selected' : ''}`}><label className="dlp-scope-surface-title"><input type="checkbox" checked={selected.local} disabled={selected.local && !selected.web} onChange={e => set({ ...selected, local: e.target.checked })} /><strong>{t('dlpLocalSurface')}</strong></label><p>{t('dlpLocalSurfaceHint')}</p>{selected.local && <>{picker('applications', t('dlpLocalApps'), t('dlpAllLocalApps'), choices.applications)}<p className="field-help">{t('dlpNativeScopeLimit')}</p></>}</section>}
  </div>;
}
