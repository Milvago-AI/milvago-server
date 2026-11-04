import { useState } from 'react';
import { ObjectDrawer, ObjectDrawerClose } from './ObjectDrawer';
import { DateValue, Icon, useText } from './ui';
import type { Translate } from './ui';
import type { TranslationKey } from './locales/en';

type ObjectValue = Record<string, unknown>;
function object(value: unknown): ObjectValue | undefined { return value && typeof value === 'object' && !Array.isArray(value) ? value as ObjectValue : undefined; }
const relationSourceKeys: Record<string, TranslationKey> = {'guest-channel-http-connection':'discoveryGuestHttpOrigin','socket-map':'discoverySocketInventory','container-api-publication':'discoveryDeclaredPublication','docker-procfs':'discoveryKernelProcessProof','containerd-procfs':'discoveryKernelProcessProof','container-top':'discoveryRuntimeProcessProof'};
const sourceKeys: Record<string, TranslationKey> = { installation: 'discoveryInstalled', host_process: 'discoveryHostProcess', guest_process: 'discoveryGuestProcess', container_process: 'discoveryContainerProcess', container_metadata: 'discoveryContainerMetadata', http: 'discoveryInterface', host_flow: 'discoveryHostFlow', host_dns_query: 'discoveryHostDnsQuery', vm_flow: 'discoveryVmFlow', runtime_flow: 'discoveryRuntimeFlow', container_flow: 'discoveryContainerFlow' };
const evidenceSourceKeys: Record<string,TranslationKey> = {...sourceKeys,inventory_observation:'discoveryInventoryObservation'};
const fieldKeys: Record<string, TranslationKey> = { executable: 'discoveryExecutable', argument_token: 'discoveryEntryPoint', package: 'discoveryPackage', image_repository: 'discoveryImage', image_digest: 'discoveryImageDigest', container_name: 'discoveryContainerName', container_state: 'status', label: 'discoveryContainerLabel', http_status: 'discoveryHttpStatus', http_body: 'discoveryHttpResponse', http_path: 'discoveryHttpPath', http_content_type: 'discoveryHttpContentType', remote_host: 'discoveryRemoteHost', remote_port: 'discoveryRemotePort' };
const recognitionKeys: Record<string,TranslationKey> = {process:'kindProcess',executable:'kindExecutable',installed:'kindInstalled',extension:'kindExtension',port:'kindPort'};
const stateKeys: Record<string, TranslationKey> = { indication:'discoveryIndication',installed:'discoveryInstalled',executed:'discoveryExecuted',interface_recognized:'discoveryInterface' };
function named(t: Translate, map: Record<string, TranslationKey>, value: unknown) { const key = String(value ?? ''); return Object.hasOwn(map,key) ? t(map[key]) : key; }
function observationDate(value:unknown) {if(typeof value!=='number')return typeof value==='string'?value:'';const date=new Date(value*1000);return Number.isFinite(date.getTime())?date.toISOString():'';}

export function DiscoveryEvidence({ value }: Readonly<{ value: unknown }>) {
  const t=useText(); const values=(Array.isArray(value)?value:[value]).map(object).filter((row):row is ObjectValue=>!!row).map(row=>typeof row.provider==='string'&&object(row.evidence)?{...object(row.evidence),provider:row.provider}:row);
  if (!values.length) return <p>{t('discoveryNoEvidence')}</p>;
  return <>{values.some(row=>row.source==='inventory_observation')&&<p>{t('discoveryInventoryObservationHelp')}</p>}{values.some(row=>row.source==='host_dns_query')&&<p>{t('discoveryDomainQueryHelp')}</p>}<ul className="discovery-evidence">{values.slice(0,80).map((row,index)=><li key={`${String(row.fact_id??row.from??index)}:${index}`}>
    {row.from!==undefined&&row.to!==undefined ? <><strong>{t('discoveryRelation')}</strong><dl><dt>{t('discoveryLocation')}</dt><dd className="discovery-identifier">{String(row.from)} → {String(row.to)}</dd><dt>{t('discoverySource')}</dt><dd>{named(t,relationSourceKeys,row.source)}</dd></dl></> : <>
      <strong>{named(t,evidenceSourceKeys,row.source)}</strong><dl>
        {typeof row.recognition_kind==='string'&&<><dt>{t('discoveryRecognitionMethod')}</dt><dd>{named(t,recognitionKeys,row.recognition_kind)}</dd></>}
        {typeof row.provider==='string'&&<><dt>{t('discoveryProviderName')}</dt><dd>{row.provider}</dd></>}
        {row.observed_at!==undefined&&<><dt>{t('lastObservation')}</dt><dd><DateValue value={observationDate(row.observed_at)} /></dd></>}
        {Array.isArray(row.fields)&&<><dt>{t('discoveryMatchedFields')}</dt><dd>{row.fields.map(field=>named(t,fieldKeys,field)).join(', ')}</dd></>}
        {row.fact_id!==undefined&&<><dt>{t('discoveryProofReference')}</dt><dd className="discovery-identifier">{String(row.fact_id)}</dd></>}
      </dl>
    </>}
  </li>)}</ul></>;
}

export function DiscoverySimulation({ value }: Readonly<{value:unknown}>) {
  const t=useText(); const result=object(value); const rows=Array.isArray(result?.identifications)?result.identifications:[];const flows=Array.isArray(result?.communications)?result.communications:[];const queries=Array.isArray(result?.queries)?result.queries:[];
  return <div role="status"><p>{t('discoverySimulationMatches')}: {rows.length}</p>{result?.saturated===true&&<p>{t('discoverySimulationLimited')}</p>}{rows.map((value,index)=>{const row=object(value);return row?<section key={index}><h4>{String(row.application_id)} · {named(t,stateKeys,row.state)}</h4><p className="discovery-identifier">{String(row.entity_id)}</p><DiscoveryEvidence value={row.evidence} /></section>:null;})}{flows.map((value,index)=>{const row=object(value);return row?<section key={index}><h4>{t('discoveryProviderContacted')} · {String(row.provider)}</h4><p className="discovery-identifier">{String(row.entity_id)}</p><DiscoveryEvidence value={row.evidence}/></section>:null;})}{queries.map((value,index)=>{const row=object(value);return row?<section key={`query:${index}`}><h4>{t('discoveryProviderDomainQueried')} · {String(row.provider)}</h4><p className="discovery-identifier">{String(row.entity_id)}</p><DiscoveryEvidence value={row.evidence}/></section>:null;})}</div>;
}

const operators=['eq','in','token','contains','regex','all','any','not'];
const operatorKeys:Record<string,TranslationKey>={eq:'discoveryEquals',in:'discoveryOneOf',token:'discoveryToken',contains:'discoveryContains',regex:'discoveryRegex',all:'discoveryAll',any:'discoveryAny',not:'discoveryNot',all_http_responses:'discoveryAllHttpResponses'};
function httpResponse(path:string):ObjectValue {return {op:'all',args:[{op:'eq',field:'http_path',value:path},{op:'eq',field:'http_status',value:'200'},{op:'contains',field:'http_body',value:''}]};}
function initialCondition(op:string):ObjectValue {if(op==='all_http_responses')return {op,args:[httpResponse('/'),httpResponse('/health')]};return op==='all'||op==='any'?{op,args:[{op:'eq',field:'executable',value:''}]}:op==='not'?{op,arg:{op:'eq',field:'executable',value:''}}:op==='in'?{op,field:'executable',values:['']}:{op,field:'executable',value:''};}

export function DiscoveryCondition({ value, change, depth=0 }:Readonly<{value:unknown;change:(value:ObjectValue)=>void;depth?:number}>) {
  const t=useText(); const condition=object(value);if(!condition||depth>12)return <p>{t('discoveryValidateFirst')}</p>; const op=String(condition.op); const args=Array.isArray(condition.args)?condition.args:[];
  return <fieldset className="discovery-condition"><legend>{t('discoveryCondition')}</legend>
    <label>{t('discoveryOperator')}<select value={op} onChange={event=>change(initialCondition(event.target.value))}>{(depth===0?[...operators,'all_http_responses']:operators).map(operator=><option key={operator} value={operator}>{t(operatorKeys[operator])}</option>)}</select></label>
    {op==='all_http_responses'&&<p>{t('discoveryAllHttpResponsesHelp')}</p>}
    {op==='all'||op==='any'||op==='all_http_responses'?<>{args.map((child,index)=><div key={index}>{op==='all_http_responses'&&<h4>{t('discoveryHttpResponse')} {index+1}</h4>}<DiscoveryCondition value={child} depth={depth+1} change={next=>change({...condition,args:args.map((item,position)=>position===index?next:item)})}/><button className="button secondary" type="button" disabled={args.length<=(op==='all_http_responses'?2:1)} onClick={()=>change({...condition,args:args.filter((_,position)=>position!==index)})}>{t('delete')}</button></div>)}<button className="button secondary" type="button" disabled={depth>=11||args.length>=(op==='all_http_responses'?8:16)} onClick={()=>change({...condition,args:[...args,op==='all_http_responses'?httpResponse('/change-me'):initialCondition('eq')]})}><Icon name="plus"/>{t('discoveryAddCondition')}</button></>:op==='not'?<DiscoveryCondition value={condition.arg} depth={depth+1} change={arg=>change({...condition,arg})}/>:<>
      <label>{t('discoveryField')}<select value={String(condition.field)} onChange={event=>change({...condition,field:event.target.value})}>{Object.keys(fieldKeys).map(field=><option key={field} value={field}>{t(fieldKeys[field])}</option>)}</select></label>
      {op==='in'?<label>{t('discoveryValues')}<textarea maxLength={16384} value={Array.isArray(condition.values)?condition.values.join('\n'):''} onChange={event=>change({...condition,values:event.target.value.split('\n')})}/></label>:<label>{t('discoveryValue')}<input maxLength={4096} value={String(condition.value??'')} onChange={event=>change({...condition,value:event.target.value})}/></label>}
    </>}
  </fieldset>;
}

export function DiscoverySignature({ initial,save,remove,close }:Readonly<{initial:ObjectValue;save:(value:ObjectValue)=>void;remove:()=>void;close:()=>void}>) {
  const t=useText();const [draft,setDraft]=useState(initial);const dirty=JSON.stringify(draft)!==JSON.stringify(initial);
  const sources=Array.isArray(draft.sources)?draft.sources.map(String):[];
  return <ObjectDrawer title={String(draft.name||t('discoveryNewSignature'))} dirty={dirty} close={close}><form className="dialog-body discovery-drawer-body" onSubmit={event=>{event.preventDefault();save({...draft,revision:Number(initial.revision??0)+1});}}>
    <label>{t('discoverySignatureId')}<input required pattern="[A-Za-z0-9_.:/-]+" maxLength={160} value={String(draft.id??'')} onChange={event=>setDraft({...draft,id:event.target.value})}/></label>
    <label>{t('name')}<input required maxLength={120} value={String(draft.name??'')} onChange={event=>setDraft({...draft,name:event.target.value})}/></label>
    <label>{t('application')}<input required pattern="[A-Za-z0-9_.:/-]+" maxLength={160} value={String(draft.application_id??'')} onChange={event=>setDraft({...draft,application_id:event.target.value})}/></label>
    <label>{t('discoveryEvidence')}<select value={String(draft.state)} onChange={event=>setDraft({...draft,state:event.target.value})}>{Object.keys(stateKeys).map(state=><option key={state} value={state}>{t(stateKeys[state])}</option>)}</select></label>
    <fieldset><legend>{t('discoverySource')}</legend>{Object.keys(sourceKeys).filter(source=>!source.endsWith('_flow')&&source!=='host_dns_query').map(source=><label key={source} className="discovery-checkbox"><input type="checkbox" checked={sources.includes(source)} onChange={event=>setDraft({...draft,sources:event.target.checked?[...sources,source]:sources.filter(value=>value!==source)})}/>{t(sourceKeys[source])}</label>)}</fieldset>
    <DiscoveryCondition value={draft.condition} change={condition=>setDraft({...draft,condition})}/>
    <label>{t('discoveryProvenance')}<textarea required maxLength={256} value={String(draft.provenance??'')} onChange={event=>setDraft({...draft,provenance:event.target.value})}/></label>
    <div className="dialog-actions"><button className="button" type="submit" disabled={!sources.length||Number(initial.revision)>=4294967295}>{t('save')}</button><button className="button danger" type="button" onClick={remove}>{t('delete')}</button><ObjectDrawerClose/></div>
  </form></ObjectDrawer>;
}

export function discoveryCatalogDiff(published: ObjectValue[],draft: ObjectValue[]) {
  const old=new Map(published.map(row=>[String(row.id),row])); const next=new Map(draft.map(row=>[String(row.id),row]));
  const canonical=(value:unknown):unknown=>Array.isArray(value)?value.map(canonical):object(value)?Object.fromEntries(Object.entries(value as ObjectValue).sort(([a],[b])=>a.localeCompare(b)).map(([key,item])=>[key,canonical(item)])):value;
  return {added:draft.filter(row=>!old.has(String(row.id))),removed:published.filter(row=>!next.has(String(row.id))),changed:draft.filter(row=>old.has(String(row.id))&&JSON.stringify(canonical(old.get(String(row.id))))!==JSON.stringify(canonical(row)))};
}
