import './AIGovernance.css';
import './dlp/dlp.css';
import { useContext, useEffect, useId, useRef, useState } from 'react';
import { can, Context, DateValue, ErrorNotice, Notice, ResourceView, readOnly, useMutation, useResource, useText } from './ui';
import type { Translate } from './ui';
import type { TranslationKey } from './locales/en';
import { TargetPicker, targetIds } from './dlp/TargetPicker';
import { AIDeclaredSystems } from './AIDeclaredSystems';

type Rule={id:string;application_id:string;activity:'presence'|'execution';scope:'organization'|'group'|'device';target_id:string;decision:'allow'|'deny';mandatory:boolean;allow_exceptions:boolean;owner:string;purpose:string;review_due:string;valid_until?:string};
type Document={version:number;rules:Rule[]};
type Policy={revision:number;document:Document;ancestors?:{organization_id:string;revision:number;document:Document}[]};
type Assessment={status:string;decision?:string;rule_id?:string;revision?:number;scope?:string;exception_id?:string;review_overdue?:boolean;enforcement?:string};
type Governance={presence:Assessment;execution:Assessment;evaluated_at:string};
const statusKeys:Record<string,TranslationKey>={allowed:'aiGovAllowed',deviation:'aiGovDeviation',no_rule:'aiGovNoRule',insufficient_evidence:'aiGovInsufficient',review_due:'aiGovReviewDue'};
const localDate=(value:string)=>value?new Date(value).toISOString().slice(0,10):'';
const isoDate=(value:string)=>value?new Date(`${value}T23:59:59Z`).toISOString():'';
function assessmentText(t:Translate,status:unknown){const text=String(status??'');return Object.hasOwn(statusKeys,text)?t(statusKeys[text]):t('unknown');}

// Recheck time-bound decisions while visible and immediately when returning to
// the page. Leaving a view releases its timer and listeners with the resource.
export function useGovernanceRefresh(data:unknown,reload:()=>void,enabled=true){
 const current=useRef({data,reload});current.current={data,reload};
 // Keep return-to-page listeners installed across loading/render transitions.
 // A completed answer must not leave a gap before its refresh listener exists.
 useEffect(()=>{
  if(!enabled)return;
  const refresh=()=>{if(document.visibilityState==='visible'&&current.current.data!==undefined)current.current.reload();};
  window.addEventListener('focus',refresh);document.addEventListener('visibilitychange',refresh);
  return()=>{window.removeEventListener('focus',refresh);document.removeEventListener('visibilitychange',refresh);};
 },[enabled]);
 useEffect(()=>{
  if(!enabled||data===undefined)return;
  const timer=window.setTimeout(()=>{if(document.visibilityState==='visible')current.current.reload();},30000);
  return()=>window.clearTimeout(timer);
 },[data,enabled]);
}

export function GovernanceLocation({value}:Readonly<{value:unknown}>){
 const t=useText();if(!value||typeof value!=='object'||Array.isArray(value))return <span>{t('unknown')}</span>;
 const g=value as Partial<Governance>;
 return <div>{(['presence','execution'] as const).map(activity=><p key={activity}>{t(activity==='presence'?'aiGovPresence':'aiGovExecution')}: {assessmentText(t,g[activity]?.status)}{g[activity]?.exception_id&&<> · {t('aiGovException')}</>}</p>)}</div>;
}

export function AIGovernancePanel(){
 const resource=useResource<Policy>('/api/ai-governance/policy');const t=useText();const [registryRevision,setRegistryRevision]=useState(0);
 return <section className="panel shadow-config ai-governance-panel"><h2>{t('aiGovTitle')}</h2><p>{t('aiGovDescription')}</p><Notice>{t('aiGovDetectionOnly')}</Notice><ResourceView resource={resource}>{data=><PolicyEditor key={data.revision} initial={data} reload={resource.reload}/>}</ResourceView><AIDeclaredSystems changed={()=>setRegistryRevision(value=>value+1)}/><FrameworkProfile/><GovernanceHistory key={`${resource.data?.revision??0}:${registryRevision}`}/></section>;
}
function PolicyEditor({initial,reload}:Readonly<{initial:Policy;reload:()=>void}>){
 const t=useText();const {session}=useContext(Context);const mutation=useMutation();const [document,setDocument]=useState(initial.document);const [reason,setReason]=useState('');const [source,setSource]=useState('');const [imported,setImported]=useState<Document>();
 const dirty=JSON.stringify(document)!==JSON.stringify(initial.document);const frozen=readOnly(session);const applicationList=useId();
 useEffect(()=>{if(!dirty)return;const warn=(event:BeforeUnloadEvent)=>event.preventDefault();window.addEventListener('beforeunload',warn);return()=>window.removeEventListener('beforeunload',warn);},[dirty]);
 const update=(index:number,next:Rule)=>setDocument(current=>({...current,rules:current.rules.map((r,n)=>n===index?next:r)}));
 const add=()=>setDocument(current=>({...current,rules:[...current.rules,{id:crypto.randomUUID(),application_id:'',activity:'execution',scope:'organization',target_id:'',decision:'deny',mandatory:false,allow_exceptions:false,owner:'',purpose:'',review_due:new Date(Date.now()+90*86400000).toISOString()}]}));
 return <><form className="ai-governance-policy" onSubmit={event=>{event.preventDefault();void mutation.run('/api/ai-governance/policy','PUT',{revision:initial.revision,document,reason}).then(reload).catch(()=>undefined);}}><p>{t('revision')} {initial.revision} · {t('aiGovFreshMFA')}</p><p>{t('aiGovPublicationExceptions')}</p><fieldset disabled={mutation.pending||frozen}>
 {initial.ancestors?.some(layer=>layer.document.rules.length>0)&&<Notice>{t('aiGovAncestorRules')}</Notice>}
 {can(session,'discovery.read')&&<KnownApplicationOptions id={applicationList}/>}
 {document.rules.map((rule,index)=><fieldset className="ai-governance-rule" key={rule.id}><legend>{t('aiGovRule')} {index+1}</legend><RuleEditor value={rule} applicationList={applicationList} change={next=>update(index,next)}/><button type="button" className="button secondary" onClick={()=>setDocument(current=>({...current,rules:current.rules.filter((_,n)=>n!==index)}))}>{t('delete')}</button></fieldset>)}
 <button type="button" className="button secondary" disabled={document.rules.length>=256} onClick={add}>{t('aiGovAddRule')}</button>
 <label>{t('discoveryReason')}<textarea required minLength={8} maxLength={1000} value={reason} onChange={event=>setReason(event.target.value)}/></label><ErrorNotice error={mutation.error}/><button className="button primary" type="submit" disabled={!dirty||reason.trim().length<8||mutation.pending}>{t('aiGovPublish')}</button>
 </fieldset></form><details><summary>{t('aiGovImport')}</summary><label>YAML / JSON<textarea disabled={mutation.pending||frozen} maxLength={131072} value={source} onChange={event=>{setSource(event.target.value);setImported(undefined);}}/></label><button type="button" className="button secondary" disabled={!source||mutation.pending||frozen} onClick={()=>{void mutation.run<{document:Document}>('/api/ai-governance/validate','POST',{source}).then(result=>{if(result)setImported(result.document);}).catch(()=>undefined);}}>{t('aiGovValidate')}</button>{imported&&<><p>{t('aiGovRuleCount',[imported.rules.length])}</p><button type="button" className="button secondary" disabled={frozen} onClick={()=>{setDocument(imported);setImported(undefined);}}>{t('aiGovUseDraft')}</button></>}</details></>;
}
function KnownApplicationOptions({id}:Readonly<{id:string}>){
 const resource=useResource<{items?:{id:string;name?:string}[]}>('/api/discovery/applications?limit=100');
 const items=Array.isArray(resource.data?.items)?resource.data.items.slice(0,100):[];
 return <datalist id={id}>{items.filter(item=>item&&typeof item.id==='string').map(item=><option key={item.id} value={item.id}>{item.name??item.id}</option>)}</datalist>;
}
function RuleEditor({value,change,applicationList}:Readonly<{value:Rule;change:(next:Rule)=>void;applicationList:string}>){
 const t=useText();const purposeHelp=useId();const set=<K extends keyof Rule>(key:K,next:Rule[K])=>change({...value,[key]:next});
 return <><label>{t('application')}<input required list={applicationList} maxLength={160} placeholder="ollama" value={value.application_id} onChange={event=>set('application_id',event.target.value)}/><small>{t('aiGovApplicationHelp')}</small></label>
 <label>{t('aiGovActivity')}<select value={value.activity} onChange={event=>set('activity',event.target.value as Rule['activity'])}><option value="presence">{t('aiGovPresence')}</option><option value="execution">{t('aiGovExecution')}</option></select></label>
 <label>{t('aiGovScope')}<select value={value.scope} onChange={event=>change({...value,scope:event.target.value as Rule['scope'],target_id:''})}><option value="organization">{t('organization')}</option><option value="group">{t('deviceGroups')}</option><option value="device">{t('device')}</option></select></label>
 {value.scope!=='organization'&&<TargetPicker value={{kind:value.scope==='group'?'groups':'devices',ids:value.target_id?[value.target_id]:[]}} change={selection=>set('target_id',targetIds(selection).at(-1)??'')}/>}
 <label>{t('aiGovDecision')}<select value={value.decision} onChange={event=>change({...value,decision:event.target.value as Rule['decision'],mandatory:false,allow_exceptions:false})}><option value="allow">{t('aiGovPermit')}</option><option value="deny">{t('aiGovProhibit')}</option></select></label>
 {value.decision==='deny'&&<><label className="ai-governance-checkbox"><input type="checkbox" checked={value.mandatory} onChange={event=>set('mandatory',event.target.checked)}/>{t('aiGovMandatory')}</label><label className="ai-governance-checkbox"><input type="checkbox" checked={value.allow_exceptions} onChange={event=>set('allow_exceptions',event.target.checked)}/>{t('aiGovAllowExceptions')}</label></>}
 <label>{t('aiGovOwner')}<input required maxLength={200} value={value.owner} onChange={event=>set('owner',event.target.value)}/></label><label>{t('aiGovPurpose')}<textarea aria-describedby={purposeHelp} required minLength={8} maxLength={1000} value={value.purpose} onChange={event=>set('purpose',event.target.value)}/></label>
 <p id={purposeHelp} className="muted ai-governance-help">{t('aiGovPurposeHelp')}</p>
 <label>{t('aiGovReviewDate')}<input type="date" required value={localDate(value.review_due)} onChange={event=>set('review_due',isoDate(event.target.value))}/></label><label>{t('aiGovValidUntil')}<input type="date" value={value.valid_until?localDate(value.valid_until):''} onChange={event=>change({...value,valid_until:event.target.value?isoDate(event.target.value):undefined})}/></label></>;
}
function FrameworkProfile(){
 const t=useText();const resource=useResource<{framework:string;controls:{id:string;capability:string;coverage:string}[]}>('/api/ai-governance/framework');
 const coverage:Record<string,TranslationKey>={partial:'aiGovCoveragePartial',manual:'aiGovCoverageManual',not_covered:'aiGovCoverageNone'};
 return <ResourceView resource={resource}>{data=><details><summary>{t('aiGovCoverage')}</summary><p>{data.framework}</p><p>{t('aiGovFrameworkLimit')}</p><ul>{data.controls.map(control=><li key={control.id}><strong>{control.id}</strong> · {t(Object.hasOwn(coverage,control.coverage)?coverage[control.coverage]:'unknown')}</li>)}</ul><a href="https://airc.nist.gov/airmf-resources/airmf/5-sec-core/" target="_blank" rel="noreferrer">NIST AI RMF</a></details>}</ResourceView>;
}

function GovernanceHistory(){
 const t=useText();const [cursors,setCursors]=useState<string[]>(['']);const cursor=cursors.at(-1);
 const resource=useResource<{items:{id:string;action:string;created_at:string;details:{reason?:string;revision?:number}}[];next_cursor:string}>(`/api/ai-governance/history?limit=50${cursor?`&cursor=${encodeURIComponent(cursor)}`:''}`);
 const actions:Record<string,TranslationKey>={'ai.governance.publish':'aiGovPublish','ai.governance.exception.approve':'aiGovApprove','ai.governance.exception.revoke':'aiGovRevoke','ai.governance.systems.update':'aiSystemsSave'};
 return <details><summary>{t('aiGovHistory')}</summary><p>{t('aiGovHistoryHelp')}</p><ResourceView resource={resource}>{data=><><ul>{data.items.map(item=><li key={item.id}>{t(Object.hasOwn(actions,item.action)?actions[item.action]:'unknown')} · <DateValue value={item.created_at}/>{typeof item.details.reason==='string'&&<p>{item.details.reason}</p>}{typeof item.details.revision==='number'&&<p>{t('revision')} {item.details.revision}</p>}</li>)}</ul><nav className="discovery-pagination" aria-label={t('pagination')}><button type="button" className="button secondary" disabled={cursors.length===1} onClick={()=>setCursors(value=>value.slice(0,-1))}>{t('previous')}</button><button type="button" className="button secondary" disabled={!data.next_cursor||cursors.length>=256} onClick={()=>setCursors(value=>[...value,data.next_cursor])}>{t('next')}</button></nav></>}</ResourceView></details>;
}

export function AIGovernanceDevice({device,application}:Readonly<{device:string;application:string}>){
 const t=useText();const {session}=useContext(Context);const resource=useResource<{governance:Governance}>(`/api/ai-governance/effective?device_id=${encodeURIComponent(device)}&application_id=${encodeURIComponent(application)}`);
 useGovernanceRefresh(resource.data,resource.reload);
 return <section><h3>{t('aiGovTitle')}</h3><Notice>{t('aiGovDetectionOnly')}</Notice><ResourceView resource={resource}>{data=><><GovernanceLocation value={data.governance}/><DateValue value={data.governance.evaluated_at}/>{(['presence','execution'] as const).map(activity=>{const a=data.governance[activity];return a.rule_id?<p key={activity}>{t(activity==='presence'?'aiGovPresence':'aiGovExecution')} · {t('aiGovRule')}: {a.rule_id} · {t('revision')} {a.revision}</p>:null;})}</>}</ResourceView>{can(session,'policy.manage')&&<a className="button secondary" href="#shadow?area=governance">{t('aiGovManage')}</a>}{!readOnly(session)&&can(session,'ai.governance.approve')&&<DeviceExceptions device={device} application={application} reload={resource.reload}/>}</section>;
}
function DeviceExceptions({device,application,reload}:Readonly<{device:string;application:string;reload:()=>void}>){
 const t=useText();const policy=useResource<{revision:number;rules:Rule[]}>(`/api/ai-governance/approval-options?device_id=${encodeURIComponent(device)}&application_id=${encodeURIComponent(application)}`);const existing=useResource<{items:{id:string;rule_id:string;expires_at:string;policy_revision:number}[]}>(`/api/ai-governance/exceptions?device_id=${encodeURIComponent(device)}`);const mutation=useMutation();const [rule,setRule]=useState('');const [reason,setReason]=useState('');const [until,setUntil]=useState('');
 return <details><summary>{t('aiGovExceptions')}</summary><p>{t('aiGovExceptionHelp')}</p><ResourceView resource={policy}>{data=><form onSubmit={event=>{event.preventDefault();void mutation.run('/api/ai-governance/exceptions','POST',{device_id:device,rule_id:rule,revision:data.revision,reason,expires_at:isoDate(until)}).then(()=>{existing.reload();reload();setReason('');}).catch(()=>undefined);}}><label>{t('aiGovRule')}<select required value={rule} onChange={event=>setRule(event.target.value)}><option value="">{t('aiGovSelectRule')}</option>{data.rules.map(r=><option key={r.id} value={r.id}>{r.application_id} · {t(r.activity==='presence'?'aiGovPresence':'aiGovExecution')} · {r.id}</option>)}</select></label><label>{t('discoveryReason')}<textarea required minLength={8} maxLength={1000} value={reason} onChange={event=>setReason(event.target.value)}/></label><label>{t('aiGovValidUntil')}<input type="date" required value={until} onChange={event=>setUntil(event.target.value)}/></label><button type="submit" className="button secondary" disabled={mutation.pending}>{t('aiGovApprove')}</button></form>}</ResourceView><ResourceView resource={existing}>{data=><ul>{data.items.map(e=><li key={e.id}>{e.rule_id} · <DateValue value={e.expires_at}/><button type="button" className="button secondary" disabled={mutation.pending||reason.trim().length<8} onClick={()=>{void mutation.run(`/api/ai-governance/exceptions/${encodeURIComponent(e.id)}/revoke`,'POST',{reason}).then(()=>{existing.reload();reload();}).catch(()=>undefined);}}>{t('aiGovRevoke')}</button></li>)}</ul>}</ResourceView><ErrorNotice error={mutation.error}/></details>;
}
