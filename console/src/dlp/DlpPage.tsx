import {ConsequenceEditor} from './ConsequenceEditor';
import { TargetPicker, targetIds } from './TargetPicker';
import { ScopeEditor } from './ScopeEditor';
import { useContext, useEffect, useMemo, useRef, useState } from 'react';
import { Badge, Context, Dialog, ErrorNotice, Icon, Notice, PageBar, ResourceView, can, readOnly, useMutation, useResource, useText } from '../ui';
import { ObjectDrawer, ObjectDrawerClose } from '../ObjectDrawer';
import { createDlpEngine } from './engine';
import { ExpressionEditor } from './ExpressionEditor';
import { SourceEditor } from './SourceEditor';
import { DlpDecisionList } from './DlpDecisions';
import { newRule } from './types';
import type { DlpApplication, DlpScopeOptions, DlpDefinition, DlpDetector, DlpInput, DlpPolicy, DlpResult, DlpRule, DlpSettings } from './types';
import './dlp.css';
import { dlpAction, dlpStatus, dlpDetector, detectorName, ruleName } from './labels';

type Engine = ReturnType<typeof createDlpEngine>;
type Tab = 'rules' | 'detectors' | 'dictionaries' | 'lab' | 'deployment';
const lines = (value: string) => value.split('\n').map(v => v.trim()).filter(Boolean);
const clone = <T,>(value: T): T => structuredClone(value);

export function DlpPage() {
  const t = useText(); const { session } = useContext(Context);
  const query = new URLSearchParams(window.location.hash.split('?')[1] || '');
  const device = query.get('device') || ''; const group = query.get('group') || '';
  const path = !device && !group ? '/api/dlp/settings' : `/api/${group ? 'groups' : 'devices'}/${encodeURIComponent(group || device)}/dlp`;
  const resource = useResource<DlpSettings>(path);
  if (!can(session, 'policy.manage')) return <Notice>{t('accessRestricted')}</Notice>;
  return <><PageBar title={t('dlpTitle')} info={t('dlpIntro')} /><section className="dlp-page"><ResourceView resource={resource}>{settings => <PolicyWorkspace key={`${path}:${settings.revision}`} initial={settings} path={path} engineScope={group ? `group:${group}` : device ? `device:${device}` : ''} />}</ResourceView></section></>;
}

function usesDetector(value:import('./types').DlpExpr,id:string):boolean {
 if(value.op==='matches') return value.detector===id;
 if('children' in value) return value.children.some(child=>usesDetector(child,id));
 if(value.op==='not') return usesDetector(value.child,id);
 return false;
}

function PolicyWorkspace({ initial, path, engineScope }: Readonly<{ initial: DlpSettings; path: string; engineScope: string }>) {
  const t = useText(); const { session } = useContext(Context); const frozen = readOnly(session);
  const [defaultIDs,setDefaultIDs]=useState(initial.default_rule_ids||[]);
  const [selected,setSelected]=useState<string[]>([]);
  const [confirmDeletion,setConfirmDeletion]=useState(false);
  const [deleting,setDeleting]=useState(false);const deleteFlight=useRef(false);
  const [policy, setPolicy] = useState(initial.policy); const [inherited, setInherited] = useState(initial.inherited);
  const [baseline, setBaseline] = useState({ policy: initial.policy, inherited: initial.inherited }); const [revision, setRevision] = useState(initial.revision);
  const requested = new URLSearchParams(window.location.hash.split('?')[1] || '').get('rule');
  const [tab, setTab] = useState<Tab>('rules'); const [search, setSearch] = useState(''); const [page, setPage] = useState(1);
  const [ruleDraft, setRuleDraft] = useState<DlpRule | null>(() => initial.policy.rules.find(r => r.id === requested) || null);
  const [detectorDraft, setDetectorDraft] = useState<DlpDetector | null>(null);
  const [original, setOriginal] = useState(() => {const rule=initial.policy.rules.find(r=>r.id===requested);return rule?JSON.stringify(rule):'';}); const [sources, setSources] = useState<Record<string, string>>({}); const [diagnostics, setDiagnostics] = useState<Record<string, string>>({});
  const [validation, setValidation] = useState(''); const [saved, setSaved] = useState(false); const mutation = useMutation();
  const engine = useMemo(() => createDlpEngine(), []);
  useEffect(() => () => engine.close(), [engine]);
  const drawerDraft = ruleDraft || detectorDraft;
  const drawerDirty = !!drawerDraft && (JSON.stringify(drawerDraft) !== original || !!(ruleDraft && diagnostics[ruleDraft.id]));
  const dirty = JSON.stringify({ policy, inherited }) !== JSON.stringify(baseline) || drawerDirty;
  useEffect(() => { const warn = (e: BeforeUnloadEvent) => e.preventDefault(); if (dirty) window.addEventListener('beforeunload', warn); return () => window.removeEventListener('beforeunload', warn); }, [dirty]);
  function selectTab(next:Tab) { setTab(next); setSearch(''); setPage(1); }
  function update(next: DlpPolicy) { setPolicy(next); setSaved(false); setValidation(''); }
  function openRule(rule?: DlpRule) { const draft = clone(rule || newRule('endpoint', t('dlpNewRule'))); setOriginal(JSON.stringify(draft)); setRuleDraft(draft); setValidation(''); }
  function openDetector(detector?: DlpDetector, dictionary = false) {
    const draft = clone(detector || { id: crypto.randomUUID(), name: t(dictionary ? 'dlpNewDictionary' : 'dlpNewDetector'), definition: dictionary ? { kind: 'dictionary', values: [], exceptions: [] } : { kind: 'literal', value: '', ignore_case: true, whole_word: false, unicode: true } } as DlpDetector);
    setOriginal(JSON.stringify(draft)); setDetectorDraft(draft); setValidation('');
  }
  function closeDrawer() { setRuleDraft(null); setDetectorDraft(null); setValidation(''); setDiagnostics({}); setSources({}); }
  async function save(next = policy, close = false) {
    try {
      setValidation(''); await engine.call({ op: 'validate', policy: next });
      const response = await mutation.run<DlpSettings>(path, 'PUT', { revision, policy: next, inherited });
      if (response) { setDefaultIDs(response.default_rule_ids||[]); setPolicy(response.policy); setInherited(response.inherited); setBaseline({ policy: response.policy, inherited: response.inherited }); setRevision(response.revision); setSaved(true); if (close) closeDrawer(); return true; }
    } catch (error) { if (error instanceof Error) setValidation(error.message); }
  }
  async function deleteSelected(){
    if(deleteFlight.current||frozen||inherited||!selected.length)return;
    const ids=new Set(selected.filter(id=>!defaultIDs.includes(id)));
    if(!ids.size)return;
    deleteFlight.current=true;setDeleting(true);
    try{if(await save({...policy,rules:policy.rules.filter(rule=>!ids.has(rule.id))})){setSelected([]);setConfirmDeletion(false);}}
    finally{deleteFlight.current=false;setDeleting(false);}
  }
  function saveObject() {
    if (ruleDraft) {
      if (diagnostics[ruleDraft.id]) return;
      const rules = policy.rules.some(r => r.id === ruleDraft.id) ? policy.rules.map(r => r.id === ruleDraft.id ? ruleDraft : r) : [...policy.rules, ruleDraft];
      void save({ ...policy, rules }, true);
    } else if (detectorDraft) {
      const detectors = policy.detectors.some(d => d.id === detectorDraft.id) ? policy.detectors.map(d => d.id === detectorDraft.id ? detectorDraft : d) : [...policy.detectors, detectorDraft];
      void save({ ...policy, detectors }, true);
    }
  }
  function deleteObject() {
    if (ruleDraft) { if(defaultIDs.includes(ruleDraft.id)){setValidation(t('dlpDefaultRuleProtected'));return;} void save({ ...policy, rules: policy.rules.filter(r => r.id !== ruleDraft.id) }, true); return; }
    if (!detectorDraft) return;
    const id = detectorDraft.id;
    const used = policy.rules.some(rule => usesDetector(rule.condition,id) || rule.consequence.action==='mask' && rule.consequence.detector===id) || policy.detectors.some(d => (d.definition.kind === 'keyword_tier' || d.definition.kind === 'dictionary_context') && d.definition.dictionary === id);
    if (used) { setValidation(t('dlpObjectUsed')); return; }
    void save({ ...policy, detectors: policy.detectors.filter(d => d.id !== id) }, true);
  }
  const q = search.trim().toLocaleLowerCase(); const editingDisabled = frozen || inherited;
  useEffect(()=>{setSelected(ids=>ids.filter(id=>!editingDisabled&&!defaultIDs.includes(id)&&policy.rules.some(rule=>rule.id===id)));},[policy.rules,defaultIDs,editingDisabled]);
  const rules = policy.rules.filter(r => [r.name,ruleName(t,r,policy), r.id, r.mode, r.consequence.action, dlpAction(t,r.consequence.action),t(({disabled:'dlpDisabled',simulation:'dlpSimulation',active:'dlpActive'} as const)[r.mode]), r.application?.kind || 'organization'].some(v => v.toLocaleLowerCase().includes(q)));
  const objects = policy.detectors.filter(d => (tab === 'dictionaries') === (d.definition.kind === 'dictionary')).filter(d => [d.name, d.id, d.definition.kind, detectorName(t,d)].some(v => v.toLocaleLowerCase().includes(q)));
  const count = tab === 'rules' ? rules.length : objects.length; const pages = Math.max(1, Math.ceil(count / 20)); const current = Math.min(page, pages);
  const pageRules=rules.slice((current-1)*20,current*20);
  const selectable=pageRules.filter(rule=>!defaultIDs.includes(rule.id));
  const allSelected=selectable.length>0&&selectable.every(rule=>selected.includes(rule.id));
  const someSelected=selectable.some(rule=>selected.includes(rule.id));
  const selectedRules=policy.rules.filter(rule=>selected.includes(rule.id)&&!defaultIDs.includes(rule.id));
  const objectExists = ruleDraft ? policy.rules.some(r => r.id === ruleDraft.id) : detectorDraft ? policy.detectors.some(d => d.id === detectorDraft.id) : false;
  return <div className="dlp-workspace">
    <header className="dlp-hero"><div className="dlp-hero-symbol"><Icon name="scan" size={30} /></div><div><span className="dlp-eyebrow">{t('dlpPolicyStudio')}</span><h2>{t('dlpTitle')}</h2><p>{t('dlpWorkspaceIntro')}</p></div><Badge>{dirty ? t('dlpDraft') : t('dlpSaved')}</Badge></header>
    <nav className="dlp-tabs" aria-label={t('dlpSections')}>{(['rules', 'detectors', 'dictionaries', 'lab', 'deployment'] as const).map(name => <button type="button" key={name} aria-current={tab === name ? 'page' : undefined} onClick={() => selectTab(name)}><Icon name={({ rules: 'filter', detectors: 'search', dictionaries: 'book', lab: 'map', deployment: 'activity' } as const)[name]} />{t(({ rules: 'dlpRules', detectors: 'dlpDetectors', dictionaries: 'dlpDictionaries', lab: 'dlpLaboratory', deployment: 'dlpDeployment' } as const)[name])}</button>)}</nav>
    {tab !== 'deployment' && <fieldset className="dlp-policy-controls" disabled={frozen || mutation.pending}><label className="dlp-checkbox"><input type="checkbox" checked={policy.inspection} disabled={inherited} onChange={event => update({ ...policy, inspection: event.target.checked })} />{t('dlpInspection')}</label>{initial.capabilities.native && <label className="dlp-checkbox"><input type="checkbox" checked={policy.native_inspection} disabled={inherited} onChange={event => update({ ...policy, native_inspection: event.target.checked })} />{t('dlpNativeInspection')}</label>}<label className="dlp-checkbox"><input type="checkbox" checked={policy.journal} disabled={inherited} onChange={event => update({ ...policy, journal: event.target.checked })} />{t('dlpJournal')}</label>{(engineScope || initial.inherited_from) && <label className="dlp-checkbox"><input type="checkbox" checked={inherited} onChange={event => { setInherited(event.target.checked); setSaved(false); }} />{t('dlpInherit')}</label>}<small>{t('dlpNoRetention')}</small></fieldset>}
    {initial.inherited_from && <p className="field-help">{t('dlpInheritedFrom')} · <code>{initial.inherited_from}</code></p>}
    {!policy.inspection && tab !== 'deployment' && <Notice>{t('dlpInspectionOff')}</Notice>}
    {requested && !policy.rules.some(rule => rule.id === requested) && <Notice>{t('dlpHistoricalRuleMissing')}</Notice>}
    {['rules', 'detectors', 'dictionaries'].includes(tab) && <section className="dlp-object-list">
      <div className="dlp-list-toolbar"><label className="dlp-list-search"><Icon name="search" /><span className="sr-only">{t(tab === 'rules' ? 'dlpRuleSearch' : tab === 'detectors' ? 'dlpDetectorSearch' : 'dlpDictionarySearch')}</span><input type="search" placeholder={t(tab === 'rules' ? 'dlpRuleSearch' : tab === 'detectors' ? 'dlpDetectorSearch' : 'dlpDictionarySearch')} value={search} onChange={e => { setSearch(e.target.value); setPage(1); }} /></label><button className="button primary" type="button" disabled={editingDisabled || (tab === 'rules' ? policy.rules.length >= 128 : policy.detectors.length >= 256)} onClick={() => tab === 'rules' ? openRule() : openDetector(undefined, tab === 'dictionaries')}><Icon name="plus" />{t(tab === 'rules' ? 'dlpAddRule' : tab === 'detectors' ? 'dlpAddDetector' : 'dlpAddDictionary')}</button></div>
      {tab === 'rules' ? <>
      {selectedRules.length>0&&<div className="dlp-bulk-actions"><strong role="status">{t(selectedRules.length===1?'dlpSelectedRule':'dlpSelectedRules',[selectedRules.length])}</strong><button className="button secondary small" type="button" disabled={mutation.pending||deleting} onClick={()=>setSelected([])}>{t('dlpClearRuleSelection')}</button><button className="button danger small" type="button" disabled={editingDisabled||mutation.pending||deleting} onClick={()=>setConfirmDeletion(true)}><Icon name="trash"/>{t('dlpDeleteSelection')}</button></div>}
      <p className="field-help">{t('dlpPriorityHint')}</p><div className="table-scroll"><table className="dlp-object-table"><thead><tr><th className="dlp-select-cell"><input type="checkbox" aria-label={t('dlpSelectPageRules')} disabled={editingDisabled||mutation.pending||!selectable.length} checked={allSelected} ref={input=>{if(input)input.indeterminate=someSelected&&!allSelected;}} onChange={event=>{const checked=event.target.checked;const ids=selectable.map(rule=>rule.id);setSelected(previous=>checked?[...new Set([...previous,...ids])]:previous.filter(id=>!ids.includes(id)));}}/></th><th>{t('dlpRuleName')}</th><th>{t('dlpApplicationScope')}</th><th>{t('dlpMode')}</th><th>{t('dlpConsequence')}</th><th>{t('dlpPriority')}</th><th>{t('dlpRuleActivation')}</th></tr></thead><tbody>{pageRules.map(rule => <tr key={rule.id} onClick={() => openRule(rule)}><td className="dlp-select-cell" onClick={event=>event.stopPropagation()}><input type="checkbox" aria-label={t('dlpSelectRuleNamed',[ruleName(t,rule,policy)])} title={defaultIDs.includes(rule.id)?t('dlpDefaultRuleProtected'):undefined} disabled={editingDisabled||mutation.pending||defaultIDs.includes(rule.id)} checked={selected.includes(rule.id)} onChange={()=>setSelected(previous=>previous.includes(rule.id)?previous.filter(id=>id!==rule.id):[...previous,rule.id])}/></td><td><button className="dlp-row-name" type="button" onClick={e => { e.stopPropagation(); openRule(rule); }}>{ruleName(t,rule,policy)}</button>{defaultIDs.includes(rule.id)&&<span className="dlp-default-badge"><Icon name="lock" size={12}/>{t('dlpDefaultRule')}</span>}</td><td><ApplicationLabel application={rule.application} policyScope={engineScope} /></td><td><Badge>{t(({ disabled: 'dlpDisabled', simulation: 'dlpSimulation', active: 'dlpActive' } as const)[rule.mode])}</Badge></td><td>{dlpAction(t, rule.consequence.action)}</td><td>{rule.priority}</td><td onClick={event=>event.stopPropagation()}><button className="button secondary small" type="button" disabled={editingDisabled||mutation.pending} aria-label={t(rule.mode==='disabled'?'dlpResumeRuleNamed':'dlpDisableRuleNamed',[ruleName(t,rule,policy)])} onClick={()=>{void save({...policy,rules:policy.rules.map(item=>item.id===rule.id?{...item,mode:rule.mode==='disabled'?'active':'disabled'}:item)});}}>{t(rule.mode==='disabled'?'dlpResumeRule':'dlpDisableRule')}</button></td></tr>)}</tbody></table></div></> : <div className="table-scroll"><table className="dlp-object-table"><thead><tr><th>{t(tab === 'dictionaries' ? 'dlpDictionaryName' : 'dlpDetectorName')}</th><th>{t('dlpDetectorType')}</th><th>{t('dlpDefinitionSummary')}</th></tr></thead><tbody>{objects.slice((current - 1) * 20, current * 20).map(detector => <tr key={detector.id} onClick={() => openDetector(detector)}><td><button type="button" className="dlp-row-name" onClick={e => { e.stopPropagation(); openDetector(detector); }}>{detectorName(t,detector)}</button></td><td>{dlpDetector(t, detector.definition.kind)}</td><td>{detector.definition.kind === 'dictionary' ? t('dlpWordCount', [detector.definition.values.length]) : detector.definition.kind === 'keyword_tier' ? policy.detectors.find(d => d.id === ('dictionary' in detector.definition ? detector.definition.dictionary : ''))?.name || detector.definition.dictionary : detector.definition.kind === 'dictionary_context' ? t('dlpDictionaryContextSummary',[detectorName(t,policy.detectors.find(d=>d.id===('dictionary' in detector.definition?detector.definition.dictionary:''))||detector),detector.definition.minimum]) : detector.definition.kind === 'builtin' ? t('dlpPredefined') : t('dlpCustom')}</td></tr>)}</tbody></table></div>}
      {count === 0 && <div className="dlp-empty"><Icon name={tab === 'rules' ? 'filter' : tab === 'dictionaries' ? 'book' : 'scan'} size={36} /><p>{t(search ? 'dlpNoSearchResults' : tab === 'rules' ? 'dlpNoRules' : 'dlpNoObjects')}</p></div>}
      <div className="dlp-list-pager"><span>{t('dlpObjectCount', [count])}</span><button className="button secondary small" type="button" disabled={current === 1} onClick={() => setPage(current - 1)}>{t('previous')}</button><span>{current} / {pages}</span><button className="button secondary small" type="button" disabled={current === pages} onClick={() => setPage(current + 1)}>{t('next')}</button></div>
    </section>}
    {tab === 'lab' && <Laboratory policy={policy} engine={engine} native={initial.capabilities.native} scopeOptions={initial.scope_options} />}
    {tab === 'deployment' && <Deployment scope={engineScope} />}
    {!drawerDraft && <><ErrorNotice error={mutation.error} />{validation && <Notice tone="danger">{validation}</Notice>}{saved && <Notice tone="success">{t('dlpSaveSuccess')}</Notice>}</>}
    {!frozen && JSON.stringify({ policy, inherited }) !== JSON.stringify(baseline) && <footer className="dlp-savebar is-dirty"><button className="button secondary" type="button" onClick={() => { setPolicy(baseline.policy); setInherited(baseline.inherited); }}>{t('dlpDiscard')}</button><button className="button primary" disabled={mutation.pending} type="button" onClick={() => void save()}>{t('dlpSave')}</button></footer>}
    {drawerDraft && <ObjectDrawer title={ruleDraft ? t(objectExists ? 'dlpEditRule' : 'dlpNewRule') : t(detectorDraft?.definition.kind === 'dictionary' ? objectExists ? 'dlpEditDictionary' : 'dlpNewDictionary' : objectExists ? 'dlpEditDetector' : 'dlpNewDetector')} dirty={drawerDirty} close={closeDrawer}>
      <div className="dlp-drawer-body">{ruleDraft&&defaultIDs.includes(ruleDraft.id)&&<Notice>{t('dlpDefaultRuleProtected')}</Notice>}{ruleDraft ? <RuleEditor rule={ruleDraft} change={setRuleDraft} policy={policy} scopeOptions={initial.scope_options} policyScope={engineScope} frozen={editingDisabled || mutation.pending} engine={engine} source={sources[ruleDraft.id]} sourceChanged={source => setSources(previous => ({ ...previous, [ruleDraft.id]: source }))} diagnostic={diagnostics[ruleDraft.id] || ''} diagnosticChanged={error => setDiagnostics(previous => ({ ...previous, [ruleDraft.id]: error }))} /> : detectorDraft && <DetectorEditor detector={detectorDraft} change={setDetectorDraft} policy={policy} frozen={editingDisabled || mutation.pending} builtins={initial.capabilities.builtins} />}
      <ErrorNotice error={mutation.error} />{validation && <Notice tone="danger">{validation}</Notice>}</div>
      <footer className="object-drawer-actions">{objectExists && !(ruleDraft&&defaultIDs.includes(ruleDraft.id)) && detectorDraft?.definition.kind!=='builtin' && <button className="button danger" type="button" disabled={editingDisabled || mutation.pending} onClick={deleteObject}>{t(ruleDraft ? 'dlpDeleteRule' : detectorDraft?.definition.kind === 'dictionary' ? 'dlpDeleteDictionary' : 'dlpDeleteDetector')}</button>}<ObjectDrawerClose /><button className="button primary" type="button" disabled={editingDisabled || mutation.pending || !!(ruleDraft && diagnostics[ruleDraft.id])} onClick={saveObject}>{t('dlpObjectSave')}</button></footer>
    </ObjectDrawer>}
    {confirmDeletion&&<Dialog title={t('dlpDeleteSelectionTitle')} close={()=>{if(!deleteFlight.current)setConfirmDeletion(false);}}><div className="dialog-body"><p>{t('dlpDeleteSelectionHint')}</p><ul>{selectedRules.map(rule=><li key={rule.id}>{ruleName(t,rule,policy)}</li>)}</ul>{validation&&<Notice tone="danger">{validation}</Notice>}<div className="dialog-actions"><button type="button" className="button secondary" disabled={deleting} onClick={()=>setConfirmDeletion(false)}>{t('cancel')}</button><button type="button" className="button danger" disabled={deleting||mutation.pending||editingDisabled||!selectedRules.length} onClick={()=>void deleteSelected()}>{deleting?t('saving'):t('dlpDeleteSelection')}</button></div></div></Dialog>}
  </div>;
}

function ApplicationLabel({ application,policyScope='' }: Readonly<{ application?: DlpApplication;policyScope?:string }>) {
  const t = useText(); const { session } = useContext(Context);
  if ((!application || application.kind === 'organization') && policyScope) {const [kind,id]=policyScope.split(':');return <span>{t(kind==='group'?'dlpGroupScope':'dlpDeviceScope')} · <TargetName application={{kind:kind==='group'?'group':'device',id}} /></span>;}
  if (!application || application.kind === 'organization') return <span>{t('dlpOrganizationScope')} · {session.organization.name}</span>;
  const ids=targetIds(application);const kind=application.kind==='group'||application.kind==='groups'?'group':'device';
  return <span className="dlp-target-summary">{t(kind==='group'?'dlpGroupScope':'dlpDeviceScope')} · {ids.slice(0,2).map((id,index)=><span key={id}>{index>0?', ':''}<TargetName application={{kind,id}}/></span>)}{ids.length>2&&<span> +{ids.length-2}</span>}</span>;
}
function TargetName({ application }: Readonly<{ application: Extract<DlpApplication, {id:string}> }>) {
  const { session } = useContext(Context);
  if (!can(session, 'devices.read') || session.privacy?.aggregate_only) return <code>{application.id.slice(0, 8)}</code>;
  return <TargetNameResource application={application} />;
}
function TargetNameResource({ application }: Readonly<{ application: Extract<DlpApplication, {id:string}> }>) {
  const resource = useResource<{ items: { id: string; name?: string; hostname?: string }[] }>(application.kind === 'group' ? '/api/groups' : `/api/devices?device_id=${encodeURIComponent(application.id)}`);
  const item = resource.data?.items.find(v => v.id === application.id);
  return <span>{item?.name || item?.hostname || application.id.slice(0, 8)}</span>;
}

function ApplicationPicker({ value, change,policyScope }: Readonly<{ value?: DlpApplication; change: (value: DlpApplication) => void;policyScope?:string }>) {
  const t = useText(); const { session } = useContext(Context); const kind = value?.kind || 'organization';
  if(policyScope)return <section className="dlp-application-picker"><strong>{t('dlpApplicationScope')}</strong><ApplicationLabel application={value} policyScope={policyScope}/></section>;
  const selectionKind=kind==='group'||kind==='groups'?'groups':kind==='device'||kind==='devices'?'devices':'organization';
  return <section className="dlp-application-picker"><label>{t('dlpApplicationScope')}<select value={selectionKind} onChange={e => change(e.target.value === 'organization' ? { kind: 'organization' } : { kind: e.target.value as 'groups' | 'devices', ids: [] })}><option value="organization">{t('dlpOrganizationScope')} · {session.organization.name}</option><option value="groups">{t('dlpChooseGroups')}</option><option value="devices">{t('dlpChooseDevices')}</option></select></label>{value&&value.kind!=='organization'&&<TargetPicker key={selectionKind} value={value} change={change}/>}</section>;
}

function DetectorEditor({ detector, change, policy, frozen, builtins }: Readonly<{ detector: DlpDetector; change: (value: DlpDetector) => void; policy: DlpPolicy; scopeOptions?:DlpScopeOptions; policyScope?:string; frozen: boolean; builtins: boolean }>) {
  const t = useText(); const dictionary = detector.definition.kind === 'dictionary'; const system = detector.definition.kind === 'builtin';
  const definition = (kind: string): DlpDefinition => kind === 'regex' ? { kind, pattern: '', ignore_case: true } : kind === 'dictionary_context' ? {kind,dictionary:policy.detectors.find(d=>d.definition.kind==='dictionary')?.id||'',minimum:2} : kind === 'keyword_tier' ? { kind, dictionary: policy.detectors.find(d => d.definition.kind === 'dictionary')?.id || '', tier: 'exact' } : { kind: 'literal', value: '', ignore_case: true, whole_word: false, unicode: true };
  return <fieldset className="dlp-detector-form" disabled={frozen}><label>{t(dictionary ? 'dlpDictionaryName' : 'dlpDetectorName')}<input disabled={system} value={detectorName(t,detector)} maxLength={100} onChange={e => change({ ...detector, name: e.target.value })} /></label>{!dictionary && <label>{t('dlpDetectorType')}<select value={detector.definition.kind} onChange={e => change({ ...detector, definition: definition(e.target.value) })} disabled={system}>{['literal', 'regex', 'keyword_tier', 'dictionary_context', ...(system && builtins ? ['builtin'] : []), ...(detector.definition.kind === 'keyword' ? ['keyword'] : [])].map(kind => <option key={kind} value={kind}>{dlpDetector(t, kind)}</option>)}</select></label>}{system ? <p className="field-help">{t('dlpBuiltinReadOnly')}</p> : <DetectorFields value={detector.definition} change={definition => change({ ...detector, definition })} detectors={policy.detectors} />}<small className="mono">{detector.id}</small></fieldset>;
}

function RuleEditor({ rule, change, policy, scopeOptions, policyScope, frozen, engine, source, sourceChanged, diagnostic, diagnosticChanged }: Readonly<{ rule: DlpRule; change: (rule: DlpRule) => void; policy: DlpPolicy; scopeOptions?:DlpScopeOptions; policyScope?:string; frozen: boolean; engine: Engine; source?: string; sourceChanged: (source: string) => void; diagnostic: string; diagnosticChanged: (error: string) => void }>) {
  const t = useText(); const [view, setView] = useState<'visual' | 'language' | 'split'>('split'); const requestId = useRef(0); const parseTimer = useRef<number | undefined>(undefined); const ruleRef=useRef(rule); ruleRef.current=rule; const textarea = useRef<HTMLTextAreaElement>(null); const [caret,setCaret]=useState(0);
  const changeRef = useRef(change); changeRef.current = change; const sourceRef = useRef(sourceChanged); sourceRef.current = sourceChanged; const diagnosticRef = useRef(diagnosticChanged); diagnosticRef.current = diagnosticChanged;
  useEffect(() => { let active = true; if (source === undefined) engine.call({ op: 'format', rule }).then(value => { if (active) sourceRef.current(String(value.source)); }).catch(error => { if (active) diagnosticRef.current(error.message); }); return () => { active = false; }; }, [source, engine, rule]);
  useEffect(()=>()=>{requestId.current++;window.clearTimeout(parseTimer.current);},[]);
  function visual(next: DlpRule) { window.clearTimeout(parseTimer.current); change(next); const sequence = ++requestId.current; engine.call({ op: 'format', rule: next }).then(value => { if (sequence === requestId.current) { sourceRef.current(String(value.source)); diagnosticRef.current(''); } }).catch(error => diagnosticRef.current(error.message)); }
  function textual(value: string) {
    sourceChanged(value); const sequence = ++requestId.current;
    window.clearTimeout(parseTimer.current); diagnosticRef.current(t('dlpChecking'));
    parseTimer.current=window.setTimeout(()=>{
      engine.call({ op: 'parse', source: value }).then(response => { if (sequence !== requestId.current) return; const parsed = response.rule as DlpRule; changeRef.current({ ...ruleRef.current, condition: parsed.condition, scope: parsed.scope, consequence: parsed.consequence, review: parsed.review, message: parsed.message }); diagnosticRef.current(''); }).catch(error => { if (sequence === requestId.current) diagnosticRef.current(error.message); });
    },250);
  }
  function criteria(next: DlpRule) { visual({ ...next, consequence: { action: 'block' }, review: false, message: '' }); }
  function insert(token: string) { const area = textarea.current; const start = area?.selectionStart ?? (source?.length || 0); const end = area?.selectionEnd ?? start; textual((source || '').slice(0, start) + token + (source || '').slice(end)); area?.focus(); }
  const before=(source||'').slice(0,caret);
  const section=before.lastIndexOf('THEN')>before.lastIndexOf('SCOPE')?'effect':before.lastIndexOf('SCOPE')>before.lastIndexOf('WHEN')?'scope':'condition';
  const completionTokens=section==='effect'?['OBSERVE','WARN MESSAGE ""','BLOCK','REPLACE "Tomate" WITH "Carotte"',...policy.detectors.map(d=>`MASK detector(${JSON.stringify(d.id)}) AS "REDACTED"`),' REVIEW',' MESSAGE ""']:section==='scope'?[`channel = "${'browser'}"`,'provider = "chatgpt"','tool = ""','AND ','OR ','XOR ','NOT ','TRUE']:[`${'prompt'} CONTAINS ""`,...policy.detectors.map(d=>`${'prompt'} MATCHES detector(${JSON.stringify(d.id)})`),'WHEN ','SCOPE ','THEN ','AND ','OR ','XOR ','NOT ','UPLOAD'];
  return <fieldset className="dlp-rule-form" disabled={frozen}><div className="dlp-rule-meta"><label>{t('dlpRuleName')}<input value={ruleName(t,rule,policy)} maxLength={100} onChange={event => change({ ...rule, name: event.target.value })} /></label><label>{t('dlpMode')}<select value={rule.mode} onChange={event => change({ ...rule, mode: event.target.value as DlpRule['mode'] })}><option value="simulation">{t('dlpSimulation')}</option><option value="active">{t('dlpActive')}</option><option value="disabled">{t('dlpDisabled')}</option></select></label><label>{t('dlpPriority')}<input type="number" min={0} max={65535} value={rule.priority} onChange={event => change({ ...rule, priority: Number(event.target.value) })} /></label></div>
    <ApplicationPicker policyScope={policyScope} value={rule.application} change={application => criteria({ ...rule, application })} /><p className="field-help">{t('dlpPriorityHint')}</p><div className="dlp-view-switch" role="group" aria-label={t('dlpEditorView')}>{(['visual', 'language', 'split'] as const).map(value => <button key={value} type="button" aria-label={t(({ visual: 'dlpVisual', language: 'dlpLanguage', split: 'dlpSplit' } as const)[value])} title={t(({ visual: 'dlpVisual', language: 'dlpLanguage', split: 'dlpSplit' } as const)[value])} aria-pressed={view === value} onClick={() => setView(value)}><Icon name={({visual:'workflow',language:'code',split:'split'} as const)[value]} size={17} /></button>)}</div>
    <div className={`dlp-composer view-${view}`}>{view !== 'language' && <div className="dlp-visual"><section className="dlp-stage"><header><span>01</span><h3>{t('dlpCondition')}</h3></header><ExpressionEditor value={rule.condition} change={condition => criteria({ ...rule, condition })} scope={false} detectors={policy.detectors} field={'prompt'} /></section><div className="dlp-connector" aria-hidden="true">↓</div><section className="dlp-stage"><header><span>02</span><h3>{t('dlpScope')}</h3></header><ScopeEditor value={rule.scope} change={scope => criteria({ ...rule, scope })} options={scopeOptions} advanced={()=>setView('language')} /></section><div className="dlp-connector" aria-hidden="true">↓</div><section className="dlp-stage"><header><span>03</span><h3>{t('dlpConsequence')}</h3></header><ConsequenceEditor rule={rule} policy={policy} engine={engine} change={visual}/></section></div>}
      {view !== 'visual' && <section className="dlp-language"><header><strong>{t('dlpLanguage')}</strong><Badge>{t('dlpLocalEngine')}</Badge></header><SourceEditor inputRef={textarea} value={source||''} change={textual} label={t('dlpRuleSource')} diagnostic={diagnostic} caretChanged={()=>setCaret(textarea.current?.selectionStart||0)} /><div className="dlp-completions" aria-label={t('dlpCompletion')}>{completionTokens.map(token => <button type="button" key={token} onClick={() => insert(token)}>{token.trim()}</button>)}</div>{diagnostic && <p role="alert" className="dlp-diagnostic">{diagnostic}</p>}<p className="field-help">{t('dlpLanguageHint')}</p></section>}
    </div><div className="dlp-rule-bottom"><small className="mono">{rule.id} · {t('dlpRuleRevision', [rule.revision])}</small></div></fieldset>;
}

function DetectorFields({ value, change, detectors }: Readonly<{ value: DlpDefinition; change: (value: DlpDefinition) => void; detectors: DlpDetector[] }>) {
  const t = useText();
  if (value.kind === 'dictionary') return <><label>{t('dlpDictionaryValues')}<textarea rows={5} value={value.values.join('\n')} onChange={event => change({ ...value, values: lines(event.target.value) })} /></label></>;
  if (value.kind === 'dictionary_context') return <><label>{t('dlpDictionary')}<select value={value.dictionary} onChange={event=>change({...value,dictionary:event.target.value})}><option value="">{t('dlpChooseDictionary')}</option>{detectors.filter(d=>d.definition.kind==='dictionary').map(d=><option key={d.id} value={d.id}>{detectorName(t,d)}</option>)}</select></label><label>{t('dlpDistinctMinimum')}<input type="number" min={1} max={200} step={1} value={value.minimum} onChange={event=>change({...value,minimum:Number(event.target.value)})}/></label><p className="field-help">{t('dlpDictionaryContextHint')}</p></>;
  if (value.kind === 'keyword_tier') return <><select aria-label={t('dlpDictionary')} value={value.dictionary} onChange={event => change({ ...value, dictionary: event.target.value })}><option value="">{t('dlpChooseDictionary')}</option>{detectors.filter(d => d.definition.kind === 'dictionary').map(d => <option key={d.id} value={d.id}>{detectorName(t,d)}</option>)}</select><select aria-label={t('dlpMatchTier')} value={value.tier} onChange={event => change({ ...value, tier: event.target.value })}>{['exact', 'unicode', 'fuzzy'].map(tier => <option key={tier} value={tier}>{t(({exact:'dlpExactMatch',unicode:'dlpUnicodeMatch',fuzzy:'dlpFuzzyMatch'} as const)[tier as 'exact'])}</option>)}</select></>;
  if (value.kind === 'builtin') return null;
  if (value.kind === 'keyword') return <input aria-label={t('dlpExpression')} value={value.value} onChange={event => change({ ...value, value: event.target.value })} />;
  return <><label>{t(value.kind === 'regex' ? 'dlpRegularExpression' : 'dlpExpression')}<input className="mono" maxLength={value.kind === 'regex' ? 200 : 512} value={value.kind === 'regex' ? value.pattern : value.value} onChange={event => change(value.kind === 'regex' ? { ...value, pattern: event.target.value } : { ...value, value: event.target.value })} /></label><label className="dlp-checkbox"><input type="checkbox" checked={value.ignore_case} onChange={event => change({ ...value, ignore_case: event.target.checked })} />{t('dlpIgnoreCase')}</label>{value.kind === 'literal' && <><label className="dlp-checkbox"><input type="checkbox" checked={value.whole_word} onChange={event => change({ ...value, whole_word: event.target.checked })} />{t('dlpWholeWord')}</label><label className="dlp-checkbox"><input type="checkbox" checked={value.unicode} onChange={event => change({ ...value, unicode: event.target.checked })} />{t('dlpUnicode')}</label></>}</>;
}

function Laboratory({ policy, engine, native,scopeOptions }: Readonly<{ policy: DlpPolicy; engine: Engine; native: boolean;scopeOptions?:DlpScopeOptions }>) {
  const t = useText(); const [sample, setSample] = useState(''); const [channel, setChannel] = useState('browser');
  const [provider, setProvider] = useState(''); const [tool, setTool] = useState(''); const [upload, setUpload] = useState('false');
  const [contextFacts,setContextFacts]=useState<Record<string,string>>({});
  const [preview, setPreview] = useState<DlpResult>(); const [actual, setActual] = useState<DlpResult>(); const [error, setError] = useState(''); const [running, setRunning] = useState(false); const runId = useRef(0);
  useEffect(() => () => { runId.current++; }, []);
  useEffect(() => { setPreview(undefined); setActual(undefined); setError(''); setRunning(false); runId.current++; }, [policy, sample, channel, provider, tool, upload,contextFacts]);
  async function simulate() {
    const id = ++runId.current; setRunning(true); setError('');
    const facts: Record<string, string> = { channel,...Object.fromEntries(Object.entries(contextFacts).filter(([,value])=>value)) }; if (provider) facts.provider = provider; if (tool) facts.tool = tool;
    const input: DlpInput = { policy, texts: { ['prompt']: [sample] }, facts, upload: upload === 'unknown' ? null : upload === 'true' };
    try {
      const [real, projected] = await Promise.all([engine.call({ op: 'evaluate', input }), engine.call({ op: 'evaluate', input: { ...input, policy: { ...input.policy, inspection:true,native_inspection:true,rules: input.policy.rules.map(rule => rule.mode === 'simulation' ? { ...rule, mode: 'active' } : rule) } } })]);
      if (id === runId.current) { setActual(real.result as DlpResult); setPreview(projected.result as DlpResult); }
    } catch (e) { if (id === runId.current) setError(e instanceof Error ? e.message : t('dlpUnavailable')); }
    finally { if (id === runId.current) setRunning(false); }
  }
  return <section className="dlp-laboratory"><div className="dlp-section-heading"><div><h3>{t('dlpLaboratory')}</h3><p>{t('dlpLabHint')}</p></div><Badge>{t('dlpLocalEngine')}</Badge></div><div className="dlp-lab-context"><label>{t('dlpFieldChannel')}<select value={channel} onChange={event => {setChannel(event.target.value);setTool('');setProvider('');}}>{(['browser', ...(native ? ['native'] : [])]).map(value => <option key={value} value={value}>{t(value==='browser'?'dlpWebSurface':'dlpLocalSurface')}</option>)}</select></label><label>{t('dlpProvider')}<select aria-label={t('dlpProvider')} value={provider} onChange={event=>setProvider(event.target.value)}><option value="">{t('dlpUnknown')}</option>{(scopeOptions?.services||[{id:'chatgpt',label:'ChatGPT'},{id:'claude',label:'Claude'}]).map(item=><option key={item.id} value={item.id}>{item.label}</option>)}</select></label><label>{t('dlpApplication')}<select aria-label={t('dlpApplication')} value={tool} onChange={event=>setTool(event.target.value)}><option value="">{t('dlpUnknown')}</option>{(channel==='native'?scopeOptions?.applications||[]:scopeOptions?.browsers||[{id:'chrome',label:'Chrome'},{id:'firefox',label:'Firefox'}]).map(item=><option key={item.id} value={item.id}>{item.label}</option>)}</select></label>{(['device_id','group_id','organization_id',...(native?['model']:[])]).map(field=><label key={field}>{t(({device_id:'dlpFieldDevice',group_id:'dlpFieldGroup',organization_id:'dlpFieldOrganization',model:'dlpFieldModel'} as const)[field as 'device_id'])}<input value={contextFacts[field]||''} maxLength={256} onChange={event=>setContextFacts(previous=>({...previous,[field]:event.target.value}))}/></label>)}<label>{t('dlpUpload')}<select value={upload} onChange={event => setUpload(event.target.value)}><option value="false">{t('dlpNo')}</option><option value="true">{t('dlpYes')}</option><option value="unknown">{t('dlpUnknown')}</option></select></label></div><div className="dlp-lab-diff"><label>{t('dlpBefore')}<textarea rows={10} maxLength={32768} value={sample} onChange={event => setSample(event.target.value)} /></label><div><strong>{t('dlpAfter')}</strong><pre>{preview ? Object.values(preview.texts).flat().join('\n') : t('dlpLabEmpty')}</pre></div></div><button type="button" className="button primary" disabled={running} onClick={() => void simulate()}><Icon name="search" />{t('dlpRunSimulation')}</button>{error && <Notice tone="danger">{error}</Notice>}{actual && <><p className="dlp-result"><strong>{t('dlpActualDecision')} : {dlpAction(t,actual.action)}</strong> · {t('dlpPreviewDecision')} : {preview?dlpAction(t,preview.action):t('dlpUnknown')}</p><DlpDecisionList decisions={actual.decisions} manage /></>}<p className="field-help">{t('dlpLabPrivacy')}</p></section>;
}

function Deployment({ scope }: Readonly<{ scope: string }>) {
  const t=useText();const [cursors,setCursors]=useState<string[]>(['']);const cursor=cursors[cursors.length-1];
  const resource=useResource<{fingerprint?:string;next_cursor?:string;items:{device_id:string;hostname?:string;channel:string;tool?:string;mechanism?:string;status:string;expected_fingerprint:string;applied_fingerprint:string}[];counts:Record<string,number>}>(`/api/dlp/status?${scope?`${scope.startsWith('device:')?'device_id':'group_id'}=${encodeURIComponent(scope.slice(scope.indexOf(':')+1))}`:''}${cursor?`&after=${encodeURIComponent(cursor)}`:''}`);
  return <section className="dlp-deployment"><h3>{t('dlpDeployment')}</h3><p>{t('dlpDeploymentHint')}</p><p className="field-help">{t('dlpCoveragePage')}</p><ResourceView resource={resource}>{data=><>
    <div className="dlp-status-counts">{Object.entries(data.counts).map(([status,count])=><div key={status}><strong>{count}</strong><span>{dlpStatus(t,status)}</span></div>)}</div>
    {data.fingerprint&&<p className="mono">{data.fingerprint}</p>}
    {!!data.items.length&&<div className="table-scroll"><table><thead><tr>{[t('dlpDevice'),t('dlpChannel'),t('dlpApplication'),t('dlpComponent'),t('dlpStatus'),t('dlpExpected'),t('dlpApplied')].map(label=><th key={label}>{label}</th>)}</tr></thead><tbody>{data.items.map(item=><tr key={`${item.device_id}:${item.channel}:${item.tool}:${item.mechanism}`}><td>{item.hostname || item.device_id}</td><td>{item.channel==='browser'?t('browser'):t('localApplication')}</td><td>{item.tool||'—'}</td><td>{item.mechanism==='browser-engine'?t('dlpLocalEngine'):item.mechanism==='browser-request'?t('dlpNetworkControl'):item.mechanism||'—'}</td><td>{dlpStatus(t,item.status)}</td><td className="mono">{item.expected_fingerprint.slice(0,12)}</td><td className="mono">{item.applied_fingerprint.slice(0,12)||'—'}</td></tr>)}</tbody></table></div>}
    <div className="dlp-rule-bottom"><button className="button secondary" type="button" disabled={cursors.length===1} onClick={()=>setCursors(previous=>previous.slice(0,-1))}>{t('previous')}</button><span>{cursors.length}</span><button className="button secondary" type="button" disabled={!data.next_cursor} onClick={()=>setCursors(previous=>[...previous,data.next_cursor!])}>{t('next')}</button></div>
  </>}</ResourceView></section>;
}
