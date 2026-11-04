import { useContext, useEffect, useState } from 'react';
import { ObjectDrawer, ObjectDrawerClose } from './ObjectDrawer';
import { can, Context, DateValue, Dialog, ErrorNotice, Notice, ResourceView, readOnly, useMutation, useResource, useText } from './ui';
import type { TranslationKey } from './locales/en';
import { TargetPicker, targetIds } from './dlp/TargetPicker';

type System={id:string;name:string;owner:string;purpose:string;scope:'organization'|'group'|'device';target_id:string;application_ids:string[];providers:string[];models:string[];data_categories:string[];risk_level:'unassessed'|'low'|'moderate'|'high';risk_summary:string;safeguards:string;status:'planned'|'review'|'active'|'retired';review_due:string};
type Registry={revision:number;document:{version:number;systems:System[]}};
const risks:Record<string,TranslationKey>={unassessed:'aiSystemsUnassessed',low:'aiSystemsLow',moderate:'aiSystemsModerate',high:'aiSystemsHigh'};
const statuses:Record<string,TranslationKey>={planned:'aiSystemsPlanned',review:'aiSystemsReview',active:'aiSystemsActive',retired:'aiSystemsRetired'};
const categories:Record<string,TranslationKey>={public:'aiSystemsPublic',internal:'aiSystemsInternal',confidential:'aiSystemsConfidential',personal:'aiSystemsPersonal',sensitive_personal:'aiSystemsSensitive'};
const split=(value:string)=>value.split(',').map(part=>part.trim()).filter(Boolean);
const date=(value:string)=>{const parsed=new Date(value);return Number.isFinite(parsed.getTime())?parsed.toISOString().slice(0,10):'';};
const isoDate=(value:string)=>{
 if(!/^\d{4}-\d{2}-\d{2}$/.test(value))return '';
 const parsed=new Date(`${value}T23:59:59Z`);
 return Number.isFinite(parsed.getTime())&&parsed.toISOString().slice(0,10)===value?parsed.toISOString():'';
};
const fresh=():System=>({id:crypto.randomUUID(),name:'',owner:'',purpose:'',scope:'organization',target_id:'',application_ids:[],providers:[],models:[],data_categories:[],risk_level:'unassessed',risk_summary:'',safeguards:'',status:'review',review_due:new Date(Date.now()+90*86400000).toISOString()});

export function AIDeclaredSystems({changed}:Readonly<{changed?:()=>void}>){
 const t=useText();const resource=useResource<Registry>('/api/ai-governance/systems');
 return <section className="ai-systems"><h3>{t('aiSystemsTitle')}</h3><Notice>{t('aiSystemsHelp')}</Notice><ResourceView resource={resource}>{data=><RegistryList key={data.revision} initial={data} reload={resource.reload} changed={changed}/>}</ResourceView></section>;
}

function RegistryList({initial,reload,changed}:Readonly<{initial:Registry;reload:()=>void;changed?:()=>void}>){
 const t=useText();const {session}=useContext(Context);const frozen=readOnly(session)||!can(session,'policy.manage');
 const [search,setSearch]=useState('');const [selected,setSelected]=useState<System>();
 const systems=Array.isArray(initial.document.systems)?initial.document.systems:[];
 const filtered=systems.filter(system=>`${system.name} ${system.owner} ${system.purpose} ${system.application_ids.join(' ')}`.toLocaleLowerCase().includes(search.toLocaleLowerCase()));
 return <><div className="ai-systems-toolbar"><label>{t('aiSystemsSearch')}<input type="search" maxLength={160} value={search} onChange={event=>setSearch(event.target.value)}/></label><button type="button" className="button secondary" disabled={frozen||systems.length>=128} onClick={()=>setSelected(fresh())}>{t('aiSystemsAdd')}</button></div>
 {systems.length===0?<p>{t('aiSystemsEmpty')}</p>:<div className="ai-systems-table"><table><thead><tr><th>{t('aiSystemsName')}</th><th>{t('aiGovOwner')}</th><th>{t('aiSystemsStatus')}</th><th>{t('aiSystemsRisk')}</th><th>{t('aiGovReviewDate')}</th></tr></thead><tbody>{filtered.map(system=><tr key={system.id}><td><button type="button" className="button secondary" onClick={()=>setSelected(system)}>{system.name}</button></td><td>{system.owner}</td><td>{t(Object.hasOwn(statuses,system.status)?statuses[system.status]:'unknown')}</td><td>{t(Object.hasOwn(risks,system.risk_level)?risks[system.risk_level]:'unknown')}</td><td><DateValue value={system.review_due}/>{new Date(system.review_due).getTime()<Date.now()&&<span> · {t('aiSystemsOverdue')}</span>}</td></tr>)}</tbody></table>{filtered.length===0&&<p>{t('aiSystemsNoMatch')}</p>}</div>}
 {selected&&<SystemDrawer key={selected.id} original={selected} initial={{...initial,document:{version:initial.document.version,systems}}} close={()=>setSelected(undefined)} reload={reload} changed={changed} frozen={frozen}/>}
 </>;
}

function SystemDrawer({original,initial,close,reload,changed,frozen}:Readonly<{original:System;initial:Registry;close:()=>void;reload:()=>void;changed?:()=>void;frozen:boolean}>){
 const t=useText();const mutation=useMutation();const [value,setValue]=useState(original);const [reason,setReason]=useState('');const [deleting,setDeleting]=useState(false);
 const start={applications:original.application_ids.join(', '),providers:original.providers.join(', '),models:original.models.join(', ')};
 const [lists,setLists]=useState(start);const existing=initial.document.systems.some(system=>system.id===original.id);
 const dirty=JSON.stringify(value)!==JSON.stringify(original)||JSON.stringify(lists)!==JSON.stringify(start)||reason!=='';
 const set=<K extends keyof System>(key:K,next:System[K])=>setValue(current=>({...current,[key]:next}));
 useEffect(()=>{if(!dirty)return;const warn=(event:BeforeUnloadEvent)=>event.preventDefault();window.addEventListener('beforeunload',warn);return()=>window.removeEventListener('beforeunload',warn);},[dirty]);
 const save=(remove=false)=>{
  if(frozen||mutation.pending||reason.trim().length<8)return;
  const record={...value,application_ids:split(lists.applications),providers:split(lists.providers),models:split(lists.models)};
  const systems=remove?initial.document.systems.filter(system=>system.id!==value.id):existing?initial.document.systems.map(system=>system.id===value.id?record:system):[...initial.document.systems,record];
  void mutation.run('/api/ai-governance/systems','PUT',{revision:initial.revision,document:{version:1,systems},reason}).then(()=>{close();reload();changed?.();}).catch(()=>undefined);
 };
 return <><ObjectDrawer title={existing?original.name:t('aiSystemsAdd')} dirty={dirty} close={close}><form className="ai-systems-form" onSubmit={event=>{event.preventDefault();save();}}><fieldset disabled={frozen||mutation.pending}>
 <p>{t('aiSystemsManual')}</p><p>{t('aiSystemsFreshMFA')}</p>
 <label>{t('aiSystemsName')}<input required maxLength={160} value={value.name} onChange={event=>set('name',event.target.value)}/></label>
 <label>{t('aiGovOwner')}<input required maxLength={200} value={value.owner} onChange={event=>set('owner',event.target.value)}/></label>
 <label>{t('aiSystemsPurpose')}<textarea required minLength={8} maxLength={1000} value={value.purpose} onChange={event=>set('purpose',event.target.value)}/></label>
 <label>{t('aiGovScope')}<select value={value.scope} onChange={event=>setValue(current=>({...current,scope:event.target.value as System['scope'],target_id:''}))}><option value="organization">{t('organization')}</option><option value="group">{t('deviceGroups')}</option><option value="device">{t('device')}</option></select></label>
 {value.scope!=='organization'&&<TargetPicker value={{kind:value.scope==='group'?'groups':'devices',ids:value.target_id?[value.target_id]:[]}} change={selection=>set('target_id',targetIds(selection).at(-1)??'')}/>}
 <label>{t('aiSystemsApplications')}<input maxLength={2700} value={lists.applications} onChange={event=>setLists(current=>({...current,applications:event.target.value}))}/><small>{t('aiSystemsListHelp')}</small></label>
 <label>{t('aiSystemsProviders')}<input maxLength={2700} value={lists.providers} onChange={event=>setLists(current=>({...current,providers:event.target.value}))}/></label>
 <label>{t('aiSystemsModels')}<input maxLength={2700} value={lists.models} onChange={event=>setLists(current=>({...current,models:event.target.value}))}/></label>
 <fieldset><legend>{t('aiSystemsData')}</legend><p>{t('aiSystemsDataHelp')}</p>{Object.entries(categories).map(([category,key])=><label className="ai-governance-checkbox" key={category}><input type="checkbox" checked={value.data_categories.includes(category)} onChange={event=>set('data_categories',event.target.checked?[...value.data_categories,category]:value.data_categories.filter(item=>item!==category))}/>{t(key)}</label>)}</fieldset>
 <label>{t('aiSystemsRisk')}<select value={value.risk_level} onChange={event=>set('risk_level',event.target.value as System['risk_level'])}>{Object.entries(risks).map(([risk,key])=><option value={risk} key={risk}>{t(key)}</option>)}</select></label>
 <label>{t('aiSystemsRiskSummary')}<textarea maxLength={2000} value={value.risk_summary} onChange={event=>set('risk_summary',event.target.value)}/></label>
 <label>{t('aiSystemsSafeguards')}<textarea maxLength={2000} value={value.safeguards} onChange={event=>set('safeguards',event.target.value)}/></label>
 <label>{t('aiSystemsStatus')}<select value={value.status} onChange={event=>set('status',event.target.value as System['status'])}>{Object.entries(statuses).map(([status,key])=><option value={status} key={status}>{t(key)}</option>)}</select></label>
 <label>{t('aiGovReviewDate')}<input required type="date" value={date(value.review_due)} onChange={event=>set('review_due',isoDate(event.target.value))}/></label>
 <label>{t('discoveryReason')}<textarea required minLength={8} maxLength={1000} value={reason} onChange={event=>setReason(event.target.value)}/></label>
 <ErrorNotice error={mutation.error}/><div className="ai-systems-actions"><button type="submit" className="button primary" disabled={mutation.pending||reason.trim().length<8||value.scope!=='organization'&&!value.target_id}>{t('aiSystemsSave')}</button>{existing&&<button type="button" className="button danger" disabled={reason.trim().length<8||mutation.pending} onClick={()=>setDeleting(true)}>{t('delete')}</button>}</div>
 </fieldset><div className="ai-systems-actions"><ObjectDrawerClose/></div></form></ObjectDrawer>{deleting&&<Dialog title={t('aiSystemsRemove')} close={()=>setDeleting(false)}><div className="dialog-body"><p>{t('aiSystemsRemoveHelp')}</p><ErrorNotice error={mutation.error}/><div className="dialog-actions"><button className="button secondary" type="button" onClick={()=>setDeleting(false)}>{t('cancel')}</button><button className="button danger" type="button" disabled={mutation.pending} onClick={()=>save(true)}>{t('delete')}</button></div></div></Dialog>}</>;
}
