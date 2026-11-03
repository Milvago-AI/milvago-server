import { GovernanceLocation, AIGovernanceDevice, useGovernanceRefresh } from './AIGovernance';
import { useContext, useEffect, useId, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { ApiError, request } from './api';
import { InventorySearch } from './InventorySearch';
import { ObjectDrawer, ObjectDrawerClose } from './ObjectDrawer';
import { DiscoveryEvidence, DiscoverySimulation, DiscoverySignature, discoveryCatalogDiff } from './DiscoveryEditors';
import { Context, can, Card, DateValue, Empty, ErrorNotice, Icon, PageBar, ResourceView, Tabs, useMutation, useResource, useText } from './ui';
import type { Translate } from './ui';
import type { TranslationKey } from './locales/en';
import './DiscoveryHub.css';

type Row = Record<string, unknown>;
type Page = { items: Row[]; next_cursor: string };
function validPage(data:Page) {return !!data&&typeof data==='object'&&Array.isArray(data.items)&&data.items.length<=100&&data.items.every(row=>!!row&&typeof row==='object'&&!Array.isArray(row))&&typeof data.next_cursor==='string'&&data.next_cursor.length<=1024;}
function InvalidPage({retry}:Readonly<{retry:()=>void}>){return <ErrorNotice error={new Error('Invalid discovery response')} retry={retry}/>;}
type Selection = { type: 'application' | 'environment' | 'evidence'; id: string; device?: string; scope?:string; name?:string; event?: Row };
type Configuration = { host: boolean; containers: boolean; virtual_machines: boolean; guest_read: boolean; guest_execute: boolean; http: boolean; network: boolean; interval_seconds: number };
type Settings = { revision: number; configuration: Configuration };
const labels: Record<string, TranslationKey> = {
  'agent-capability':'discoveryAgentCapability', 'report-reception':'discoveryReportReception', agent_capability_missing:'discoveryAgentCapabilityMissing', source_coverage_missing:'discoverySourceCoverageMissing',
  pending:'discoveryRunPending', running:'discoveryRunRunning', completed:'discoveryRunCompleted', cancelled:'discoveryRunCancelled', expired:'discoveryRunExpired',
  indication: 'discoveryIndication', installed: 'discoveryInstalled', executed: 'discoveryExecuted', interface_recognized: 'discoveryInterface',
  review: 'discoveryReview', authorized: 'discoveryAuthorized', unauthorized: 'discoveryUnauthorized', false_positive: 'discoveryFalsePositive',
  host: 'device', vm: 'discoveryVm', wsl: 'discoveryWsl', runtime: 'discoveryRuntime', container: 'discoveryContainer', endpoint: 'discoveryEndpoint', process: 'discoveryProcess',
  available: 'discoveryAvailable', partial: 'discoveryPartial', denied: 'discoveryDenied', unavailable: 'discoveryUnavailable', timeout: 'discoveryTimeout', saturated: 'discoverySaturated', disabled: 'discoveryDisabled',
  identified: 'discoveryIdentified', provider_contacted: 'discoveryProviderContacted', provider_domain_queried: 'discoveryProviderDomainQueried',
};
const adapterLabels: Record<string, TranslationKey> = {
  host: 'discoveryAdapterHost', 'installed-packages': 'discoveryAdapterPackages',
  'windows-interpreter-entries': 'discoveryAdapterWindowsEntries',
  'runtime-channels': 'discoveryAdapterRuntimeChannels', containers: 'discoverySourceContainers', docker: 'discoveryAdapterDocker', podman: 'discoveryAdapterPodman', containerd: 'discoveryAdapterContainerd',
  'hyper-v': 'discoveryAdapterHyperV', libvirt: 'discoveryAdapterLibvirt', vmware: 'discoveryAdapterVMware', virtualbox: 'discoveryAdapterVirtualBox', wsl: 'discoveryAdapterWsl',
  'hyper-v-guest': 'discoveryAdapterHyperVGuest', 'libvirt-guest': 'discoveryAdapterLibvirtGuest',
  'vmware-guest': 'discoveryAdapterVMwareGuest', 'virtualbox-guest': 'discoveryAdapterVirtualBoxGuest',
  'virtualbox-user-session': 'discoveryAdapterVirtualBoxSession', 'vmware-user-session': 'discoveryAdapterVMwareSession',
  'guest-http': 'discoveryAdapterGuestHttp', 'guest-tools': 'discoveryAdapterGuestTools', http: 'discoveryAdapterHttp', network: 'discoveryAdapterNetwork', 'windows-dns': 'discoveryAdapterWindowsDns',
  'vm-network-attribution': 'discoveryAdapterVmNetwork', 'system-collector': 'discoveryAdapterSystemCollector',
};
function label(t: Translate, value: unknown) { const text = String(value ?? ''); return Object.hasOwn(labels, text) ? t(labels[text]) : text; }
function adapterLabel(t: Translate, value: unknown) {const text=String(value??'');return Object.hasOwn(adapterLabels,text)?t(adapterLabels[text]):label(t,value);}
function display(row: Row): Row { const value=row.display; return value&&typeof value==='object'&&!Array.isArray(value)?value as Row:{}; }
function entityTitle(row: Row) { const details=display(row);return String(details.name??details.address??row.id??row.entity_id??''); }
function EntityDescription({row}:{readonly row:Row}) {const t=useText();const details=display(row);return <><strong>{entityTitle(row)}</strong>{typeof details.address==='string'&&<p className="discovery-identifier">{details.address}</p>}{typeof details.image==='string'&&<p>{t('discoveryImage')}: <code>{details.image}</code></p>}<details><summary>{t('discoveryProofReference')}</summary><code className="discovery-identifier">{String(row.id??row.entity_id??'')}</code></details></>;}

export function DiscoveryHub({ legacy, nativeDetail }: Readonly<{ legacy?: ReactNode; nativeDetail?: (id: string, close: () => void) => ReactNode }>) {
  const { session } = useContext(Context); const t = useText();
  const read = can(session, 'discovery.read');
  void legacy;
  const [tab, setTab] = useState('applications');
  const [selected, setSelected] = useState<Selection>();
  const [editor, setEditor] = useState<'settings' | 'catalog'>();
  useEffect(() => { const clear = () => { setSelected(undefined); setEditor(undefined); }; window.addEventListener('milvago:privacy-changed', clear); return () => window.removeEventListener('milvago:privacy-changed', clear); }, []);
  useEffect(() => { if (location.hash.split('?')[0] === '#discovery') { const query = new URLSearchParams(location.hash.split('?')[1]);query.set('type','web');history.replaceState(null,'',`#applications?${query}`);window.dispatchEvent(new HashChangeEvent('hashchange')); } }, []);
  if (session.privacy?.aggregate_only) return <Empty title={t('discoveryAggregateOnly')} />;
  const details = read && can(session, 'devices.read');
  return <div className="discovery-hub">
    <PageBar title={t('aiInventory')} info={t('discoveryHubDescription')} actions={<div className="discovery-actions">
      {can(session, 'discovery.catalog.manage') && <button className="button secondary" onClick={() => setEditor('catalog')}>{t('discoveryCatalog')}</button>}
      {can(session, 'discovery.manage') && <button className="button secondary" onClick={() => setEditor('settings')}>{t('discoverySources')}</button>}
    </div>} />
    <Tabs label={t('aiInventory')} selected={tab} onSelect={id => { setTab(id); setSelected(undefined); }} items={[
      { id: 'applications', name: t('discoverySoftwareServices') },
      ...(details ? [{ id: 'environments', name: t('discoveryEnvironments') }, { id: 'activity', name: t('discoveryActivity') }, { id: 'coverage', name: t('discoveryCoverage') }] : []),
    ]} />
    {tab === 'applications' && <InventorySearch select={setSelected} nativeDetail={nativeDetail} />}
    {tab === 'environments' && details && <DiscoveryList path="/api/discovery/environments" columns={['entity_label', 'kind', 'device_id', 'last_seen']} select={row => setSelected({ type: 'environment', id: String(row.id), name:entityTitle(row), device: String(row.device_id),scope:String(row.scope) })} />}
    {tab === 'activity' && details && <><p className="muted">{t('discoveryActivityDescription')}</p><DiscoveryList path="/api/discovery/events" columns={['kind', 'application_id', 'device_id', 'occurred_at']} select={row => setSelected({ type: 'evidence', id: String(row.id), event: {kind:row.kind,device_id:row.device_id,device_name:row.device_name,entity_id:row.entity_id,application_id:row.application_id,occurred_at:row.occurred_at} })} /></>}
    {tab === 'coverage' && details && <><p className="muted">{t('discoveryCoverageDescription')}</p><DiscoveryList path="/api/discovery/coverage" columns={['device_id', 'adapter', 'status', 'reason', 'checked_at']} /><Card title={t('discoveryRuns')} description={t('discoveryRunsDescription')}><DiscoveryRuns /></Card></>}
    {selected && <ObjectDrawer title={selected.name??(selected.type === 'application' ? selected.id : t('discoveryDetails'))} dirty={false} close={() => setSelected(undefined)}><DiscoveryDetail key={JSON.stringify([selected.type,selected.id,selected.device,selected.scope])} selection={selected} /></ObjectDrawer>}
    {editor === 'settings' && <SourceDrawer close={() => setEditor(undefined)} />}
    {editor === 'catalog' && <CatalogDrawer close={() => setEditor(undefined)} />}
  </div>;
}

const columnLabels: Record<string, TranslationKey> = { first_seen:'firstObservation',observations:'discoveryObservationCount',governance:'aiGovTitle',reason:'discoveryCoverageReason',created_at:'date', expires_at:'discoveryRunExpires', entity_label:'discoveryLocation',id: 'application', kind: 'type', states: 'discoveryEvidence', devices: 'devices', review: 'aiGovTechnicalReview', last_seen: 'lastObservation', device_id: 'device', application_id: 'application', occurred_at: 'date', adapter: 'discoverySource', status: 'status', checked_at: 'discoveryLastCheck', state: 'status', entity_id: 'discoveryLocation' };
function DiscoveryList({ path, columns, select, names, actions }: Readonly<{ path: string; columns: string[]; select?: (row: Row) => void; names?: Map<string, string>; actions?: (row:Row)=>ReactNode }>) {
  const t = useText(); const [cursors, setCursors] = useState<string[]>(['']);
  const cursor = cursors[cursors.length - 1];
  const resource = useResource<Page>(`${path}${path.includes('?') ? '&' : '?'}limit=50${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`);
  useGovernanceRefresh(resource.data,resource.reload,path.split('?')[0].endsWith('/locations'));
  return <ResourceView resource={resource}>{data => !validPage(data)?<InvalidPage retry={resource.reload}/>:<>
    {data.items.length === 0 ? <Empty title={t('discoveryNoObservation')}>{t('discoveryNoObservationDescription')}</Empty> : <div className="table-scroll discovery-table"><table><thead><tr>{columns.map(column => <th key={column}>{t(columnLabels[column] ?? 'discoveryDetails')}</th>)}{actions&&<th>{t('actions')}</th>}</tr></thead><tbody>{data.items.map((row, index) => <tr key={`${String(row.id ?? row.entity_id)}:${String(row.scope)}:${String(row.device_id)}:${String(row.adapter ?? index)}`}>
      {columns.map((column, cell) => <td key={column}>{cell === 0 && select ? <button className="text-link" onClick={() => select(row)}>{column==='device_id'?String(row.device_name??row.device_id):column==='entity_label'?entityTitle(row):names?.get(String(row[column])) ?? (column==='id'&&typeof row.name==='string'?row.name:label(t, row[column]))}</button> : column==='governance' ? <GovernanceLocation value={row.governance}/> : column==='adapter' ? adapterLabel(t,row[column]) : column.endsWith('_at') || column.endsWith('_seen') ? <DateValue value={String(row[column] ?? '')} /> : Array.isArray(row[column]) ? (row[column] as unknown[]).map(value => label(t, value)).join(', ') : column === 'device_id' ? <a className="text-link" href={`#devices?id=${encodeURIComponent(String(row[column]))}`}>{String(row.device_name??row[column])}</a> : names?.get(String(row[column])) ?? (column==='id'&&typeof row.name==='string'?row.name:label(t, row[column]))}</td>)}{actions&&<td>{actions(row)}</td>}
    </tr>)}</tbody></table></div>}
    <nav className="discovery-pagination" aria-label={t('pagination')}><button type="button" className="button secondary" disabled={cursors.length === 1} onClick={() => setCursors(value => value.slice(0, -1))}>{t('discoveryPrevious')}</button><button type="button" className="button secondary" disabled={!data.next_cursor || cursors.length >= 256} onClick={() => setCursors(value => [...value, data.next_cursor])}>{t('discoveryNext')}</button></nav>
  </>}</ResourceView>;
}

function DiscoveryRuns() {
  const t=useText();const {session}=useContext(Context);const mutation=useMutation();const [revision,setRevision]=useState(0);
  return <><DiscoveryList key={revision} path="/api/discovery/runs" columns={['device_id','status','created_at','expires_at']} actions={can(session,'discovery.run')?row=>['pending','running'].includes(String(row.status))?<button className="button secondary" disabled={mutation.pending} onClick={()=>{void mutation.run(`/api/discovery/runs/${encodeURIComponent(String(row.id))}/cancel`,'POST',{}).then(()=>setRevision(value=>value+1)).catch(()=>undefined);}}>{t('discoveryCancelRun')}</button>:null:undefined}/><ErrorNotice error={mutation.error}/></>;
}

function DiscoveryDetail({ selection }: Readonly<{ selection: Selection }>) {
  const t = useText(); const { session } = useContext(Context); const mutation = useMutation();
  const path = selection.type === 'application' ? `/api/discovery/applications/${encodeURIComponent(selection.id)}` : selection.type === 'environment' ? `/api/discovery/environments/${encodeURIComponent(selection.id)}?device_id=${encodeURIComponent(selection.device ?? '')}&scope=${encodeURIComponent(selection.scope??'')}` : `/api/discovery/evidence/${encodeURIComponent(selection.id)}`;
  const resource = useResource<Row>(path);
  const [tab, setTab] = useState(selection.type === 'evidence' ? 'evidence' : 'summary');
  const [location,setLocation]=useState<{device:string;name:string}>();
  return <div className="dialog-body discovery-drawer-body"><Tabs label={t('discoveryDetails')} selected={tab} onSelect={setTab} items={selection.type === 'evidence' ? [{ id: 'evidence', name: t('discoveryEvidence') }] : [{ id: 'summary', name: t('discoverySummary') }, { id: 'locations', name: t('discoveryLocations') }, { id: 'evidence', name: t('discoveryEvidence') }, { id: 'history', name: t('discoveryHistory') }, ...(selection.type==='environment'&&selection.device?[{id:'coverage',name:t('discoveryDeviceCoverage')}]:[])]} />
    <ResourceView resource={resource}>{data => <>
      {selection.type==='environment'&&selection.device&&['vm','wsl','runtime','container'].includes(String(data.kind))&&tab!=='coverage'&&<Card title={t('discoveryEnvironmentVisibility')} description={t('discoveryEnvironmentVisibilityHelp')}><button type="button" className="button secondary" onClick={()=>setTab('coverage')}>{t('discoveryCheckDeviceCoverage')}</button></Card>}
      {tab==='coverage'&&selection.type==='environment'&&selection.device&&<><p className="muted">{t('discoveryDeviceCoverageHelp')}</p><DiscoveryList path={'/api/discovery/coverage?device_id='+encodeURIComponent(selection.device)} columns={['device_id','adapter','status','reason','checked_at']}/></>}
      {tab === 'summary' && <><p>{t('discoveryEvidenceDescription')}</p>{selection.type==='application'&&<p className="muted">{t('aiGovOldReviewHelp')}</p>}<EntityDescription row={{...data,id:selection.id}} /><InventoryMetadata value={data.inventory_metadata}/>{typeof data.first_seen==='string'&&<dl><dt>{t('firstObservation')}</dt><dd><DateValue value={data.first_seen}/></dd></dl>}<dl>{data.review !== undefined && <><dt>{t('aiGovTechnicalReview')}</dt><dd>{label(t, data.review)}</dd></>}</dl>
        {selection.type === 'application' && can(session, 'discovery.manage') && <label>{t('aiGovTechnicalReview')}<select value={String(data.review ?? 'review')} disabled={mutation.pending} onChange={event => { void mutation.run(`${path}/review`, 'PUT', { status: event.target.value }).then(() => {resource.reload();window.dispatchEvent(new Event('milvago:inventory-changed'));}).catch(() => undefined); }}>{['review', 'authorized', 'unauthorized', 'false_positive'].map(value => <option key={value} value={value}>{label(t, value)}</option>)}</select></label>}
        {selection.device && can(session, 'discovery.run') && <button className="button secondary" disabled={mutation.pending} onClick={() => { void mutation.run('/api/discovery/runs', 'POST', { device_id: selection.device }).catch(() => undefined); }}>{t('discoveryCollectNow')}</button>}
        {selection.type==='environment' && selection.device && data.kind==='host' && (data.device_platform==='linux'||data.device_platform==='windows') && can(session,'discovery.manage') && can(session,'devices.read') && <SystemBinding device={selection.device} platform={data.device_platform}/>}
      </>}
      {tab === 'locations' && selection.type === 'application' && <><p className="muted">{t('discoveryLocationsDescription')}</p><DiscoveryList path={`/api/discovery/applications/${encodeURIComponent(selection.id)}/locations`} columns={['device_id','states','governance','observations','first_seen','last_seen']} select={row=>{setLocation({device:String(row.device_id),name:String(row.device_name??row.device_id)});setTab('evidence');}}/></>}
      {tab === 'evidence' && selection.type === 'application' && <>{location&&<AIGovernanceDevice device={location.device} application={selection.id}/>} {location&&<p>{t('device')}: {location.name} <button className="text-link" onClick={()=>setLocation(undefined)}>{t('discoveryAllLocationProofs')}</button></p>}<ApplicationEvidence key={location?.device??''} id={selection.id} device={location?.device}/></>}
      {tab === 'evidence' && selection.type === 'evidence' && <><EventContext value={selection.event} /><Evidence value={data.evidence} /></>}
      {tab === 'locations' && selection.type === 'environment' && <EnvironmentRelations path={path} />}
      {tab === 'evidence' && selection.type === 'environment' && <EnvironmentEvidence selection={selection} />}
      {tab === 'history' && selection.type === 'environment' && <DiscoveryHistory path={'/api/discovery/events?device_id='+encodeURIComponent(selection.device??'')+'&scope='+encodeURIComponent(selection.scope??'')+'&entity_id='+encodeURIComponent(selection.id)} />}
      {tab === 'history' && selection.type === 'application' && <DiscoveryHistory path={`/api/discovery/events?application_id=${encodeURIComponent(selection.id)}`} />}
    </>}</ResourceView><ErrorNotice error={mutation.error} /><ObjectDrawerClose /></div>;
}
function InventoryMetadata({value}:Readonly<{value:unknown}>) {
  const t=useText();if(!value||typeof value!=='object'||Array.isArray(value))return null;
  const row=value as Row;const risk=row.risk==='high'?'high':row.risk==='medium'?'medium':row.risk==='low'?'low':'unknown';
  return <dl>{typeof row.vendor==='string'&&<><dt>{t('vendor')}</dt><dd>{row.vendor}</dd></>}<dt>{t('discoveryCatalogRisk')}</dt><dd>{t(risk)}</dd></dl>;
}
function EventContext({value}:Readonly<{value:Row|undefined}>) {
  const t=useText();if(!value)return null;
  const text=(field:string)=>typeof value[field]==='string'?value[field] as string:'';
  const device=text('device_id');
  return <dl>
    <dt>{t('type')}</dt><dd>{label(t,text('kind'))}</dd>
    {device&&<><dt>{t('device')}</dt><dd><a href={`#devices?id=${encodeURIComponent(device)}`}>{text('device_name')||device}</a></dd></>}
    {text('entity_id')&&<><dt>{t('discoveryLocation')}</dt><dd className="discovery-identifier">{text('entity_id')}</dd></>}
    {text('application_id')&&<><dt>{t('application')}</dt><dd>{text('application_id')}</dd></>}
    {text('occurred_at')&&<><dt>{t('date')}</dt><dd><DateValue value={text('occurred_at')}/></dd></>}
  </dl>;
}
function SystemBinding({device,platform}:Readonly<{device:string;platform:'linux'|'windows'}>) {
  const t=useText();const [pending,setPending]=useState(false);const [error,setError]=useState<unknown>();const active=useRef<AbortController|null>(null);
  const invalid=t(platform==='windows'?'discoveryWindowsBindingInvalid':'discoveryLinuxBindingInvalid');
  useEffect(()=>()=>active.current?.abort(),[device,platform]);
  const download=async()=>{
    const controller=new AbortController();active.current=controller;setPending(true);setError(undefined);
    try {
      const value=await request<unknown>(`/api/discovery/devices/${encodeURIComponent(device)}/system-binding`,{signal:controller.signal});
      if(controller.signal.aborted)return;
      if(!value||typeof value!=='object'||Array.isArray(value))throw new ApiError(502,'invalid_system_binding',invalid);
      const row=value as Row;
      if(Object.keys(row).length!==4||row.version!==1||row.device_id!==device||typeof row.server_url!=='string'||row.server_url.length>2048||typeof row.public_key!=='string'||!/^[A-Za-z0-9+/]{43}=$/.test(row.public_key))throw new ApiError(502,'invalid_system_binding',invalid);
      const url=URL.createObjectURL(new Blob([JSON.stringify(value,null,2)+'\n'],{type:'application/json'}));
      try {const link=document.createElement('a');link.href=url;link.download=platform==='windows'?'milvago-windows-binding.json':'milvago-linux-binding.json';link.click();}
      finally {setTimeout(()=>URL.revokeObjectURL(url),0);}
    } catch(failure) {if(!controller.signal.aborted)setError(failure);}
    finally {if(!controller.signal.aborted)setPending(false);}
  };
  return <div><p className="muted">{t(platform==='windows'?'discoveryWindowsBindingDescription':'discoveryLinuxBindingDescription')}</p><button className="button secondary" disabled={pending} onClick={()=>{void download();}}>{t(platform==='windows'?'discoveryWindowsBinding':'discoveryLinuxBinding')}</button><ErrorNotice error={error}/></div>;
}
function Evidence({ value }: Readonly<{ value: unknown }>) {
  const t = useText();
  if (!value || Array.isArray(value) && !value.length) return <p>{t('discoveryNoEvidence')}</p>;
  return <DiscoveryEvidence value={value} />;
}
function DiscoveryHistory({path}:Readonly<{path:string}>) {
  const t=useText();const [cursors,setCursors]=useState<string[]>(['']);const cursor=cursors[cursors.length-1];
  const resource=useResource<Page>(path+(path.includes('?')?'&':'?')+'limit=50'+(cursor?'&cursor='+encodeURIComponent(cursor):''));
  return <ResourceView resource={resource}>{data=>!validPage(data)?<InvalidPage retry={resource.reload}/>:<>
    {data.items.length===0?<Empty title={t('discoveryNoObservation')}>{t('discoveryNoObservationDescription')}</Empty>:<ol className="observation-timeline">{data.items.map(row=><li key={String(row.id)}>
      <span className="observation-marker"><Icon name="activity" size={14}/></span>
      <div className="observation-entry"><header><h3>{label(t,row.kind)}</h3><time dateTime={String(row.occurred_at??'')}><DateValue value={String(row.occurred_at??'')}/></time></header>
        {typeof row.application_id==='string'&&row.application_id&&<p>{row.application_id}</p>}
        <HistoryProof id={String(row.id)}/>
      </div>
    </li>)}</ol>}
    <nav className="discovery-pagination" aria-label={t('pagination')}><button className="button secondary" disabled={cursors.length===1} onClick={()=>setCursors(value=>value.slice(0,-1))}>{t('discoveryPrevious')}</button><button className="button secondary" disabled={!data.next_cursor||cursors.length>=256} onClick={()=>setCursors(value=>[...value,data.next_cursor])}>{t('discoveryNext')}</button></nav>
  </>}</ResourceView>;
}
function HistoryProof({id}:Readonly<{id:string}>) {
  const t=useText();const [open,setOpen]=useState(false);
  return <details className="history-proof" onToggle={event=>setOpen(event.currentTarget.open)}><summary>{t('discoveryEvidence')}</summary>{open&&<HistoricalEvidence id={id}/>}</details>;
}
function HistoricalEvidence({id}:Readonly<{id:string}>) {
  const resource=useResource<Row>('/api/discovery/evidence/'+encodeURIComponent(id));
  return <ResourceView resource={resource}>{data=><Evidence value={data.evidence}/>}</ResourceView>;
}
function EnvironmentEvidence({selection}:Readonly<{selection:Selection}>) {
  const t=useText();const [cursors,setCursors]=useState<string[]>(['']);const cursor=cursors[cursors.length-1];
  const resource=useResource<Page>('/api/discovery/environments/'+encodeURIComponent(selection.id)+'/evidence?device_id='+encodeURIComponent(selection.device??'')+'&scope='+encodeURIComponent(selection.scope??'')+'&limit=50'+(cursor?'&cursor='+encodeURIComponent(cursor):''));
  return <ResourceView resource={resource}>{data=>!validPage(data)?<InvalidPage retry={resource.reload}/>:<>
    {data.items.length===0?<Empty title={t('discoveryNoEvidence')}/>:data.items.map(row=><section className="evidence-card" key={String(row.kind)+':'+String(row.id)}>
      <h3>{row.kind==='communication'?t('discoveryProviderContacted'):label(t,row.state)}</h3>
      {typeof row.application_id==='string'&&row.application_id&&<p>{t('application')} · {row.application_id}</p>}
      {typeof row.provider==='string'&&row.provider&&<p>{row.provider}</p>}
      {typeof row.last_seen==='string'&&<p><DateValue value={row.last_seen}/></p>}
      <Evidence value={row.evidence}/>
    </section>)}
    <nav className="discovery-pagination" aria-label={t('pagination')}><button className="button secondary" disabled={cursors.length===1} onClick={()=>setCursors(value=>value.slice(0,-1))}>{t('discoveryPrevious')}</button><button className="button secondary" disabled={!data.next_cursor||cursors.length>=256} onClick={()=>setCursors(value=>[...value,data.next_cursor])}>{t('discoveryNext')}</button></nav>
  </>}</ResourceView>;
}
function EnvironmentRelations({path}:Readonly<{path:string}>) {
  const t=useText();const [cursors,setCursors]=useState<string[]>(['']);const cursor=cursors[cursors.length-1];
  const resource=useResource<{relations:unknown[];relations_next_cursor:string}>(`${path}&limit=50${cursor?`&cursor=${encodeURIComponent(cursor)}`:''}`);
  return <ResourceView resource={resource}>{data=><><Evidence value={data.relations}/><nav className="discovery-pagination" aria-label={t('pagination')}><button className="button secondary" disabled={cursors.length===1} onClick={()=>setCursors(value=>value.slice(0,-1))}>{t('discoveryPrevious')}</button><button className="button secondary" disabled={!data.relations_next_cursor||cursors.length>=256} onClick={()=>setCursors(value=>[...value,data.relations_next_cursor])}>{t('discoveryNext')}</button></nav></>}</ResourceView>;
}
function ApplicationEvidence({ id,device }: Readonly<{ id: string;device?:string }>) {
  const [cursors,setCursors]=useState<string[]>(['']);const cursor=cursors[cursors.length-1];
  const resource = useResource<Page>(`/api/discovery/applications/${encodeURIComponent(id)}/instances?limit=50${device?`&device_id=${encodeURIComponent(device)}`:''}${cursor?`&cursor=${encodeURIComponent(cursor)}`:''}`);
  const t = useText();
  return <ResourceView resource={resource}>{data => !validPage(data)?<InvalidPage retry={resource.reload}/>:<>{data.items.map(row => <section key={`${String(row.scope)}:${String(row.entity_id)}:${String(row.signature_id)}`}><h3>{label(t, row.state)}</h3><EntityDescription row={row}/><a href={`#devices?id=${encodeURIComponent(String(row.device_id))}`}>{t('device')} · {String(row.device_name??row.device_id)}</a><Evidence value={row.evidence} /></section>)}<nav className="discovery-pagination" aria-label={t('pagination')}><button className="button secondary" disabled={cursors.length===1} onClick={()=>setCursors(value=>value.slice(0,-1))}>{t('discoveryPrevious')}</button><button className="button secondary" disabled={!data.next_cursor||cursors.length>=256} onClick={()=>setCursors(value=>[...value,data.next_cursor])}>{t('discoveryNext')}</button></nav></>}</ResourceView>;
}

function SourceDrawer({ close }: Readonly<{ close: () => void }>) {
  const resource = useResource<Settings>('/api/discovery/settings'); const t = useText();
  return <ResourceView resource={resource}>{data => <SourceForm key={data.revision} settings={data} close={close} title={t('discoverySources')} />}</ResourceView>;
}
function SourceForm({ settings, close, title }: Readonly<{ settings: Settings; close: () => void; title: string }>) {
  const t = useText(); const mutation = useMutation(); const [configuration, setConfiguration] = useState(settings.configuration); const [reason, setReason] = useState('');
  const dirty = JSON.stringify(configuration) !== JSON.stringify(settings.configuration);
  const toggle = (source: Exclude<keyof Configuration,'interval_seconds'>, checked: boolean) => setConfiguration(current => {
    const next={...current,[source]:checked};
    if (!next.virtual_machines) {next.guest_read=false;next.guest_execute=false;}
    if (!next.guest_read) next.guest_execute=false;
    if (!next.host&&!next.containers&&!next.virtual_machines) next.http=false;
    return next;
  });
  const sourceLabels: Record<Exclude<keyof Configuration, 'interval_seconds'>, TranslationKey> = { host: 'discoverySourceHost', containers: 'discoverySourceContainers', virtual_machines: 'discoverySourceVm', guest_read: 'discoverySourceGuestRead', guest_execute: 'discoverySourceGuestExecute', http: 'discoverySourceHttp', network: 'discoverySourceNetwork' };
  return <ObjectDrawer title={title} dirty={dirty} close={close}><form className="dialog-body discovery-drawer-body" onSubmit={event => { event.preventDefault(); void mutation.run('/api/discovery/settings', 'PUT', { revision: settings.revision, configuration, reason }).then(close).catch(() => undefined); }}><p>{t('discoverySourceDescription')}</p>
    {(Object.keys(sourceLabels) as (keyof typeof sourceLabels)[]).map(source => <label className="discovery-checkbox" key={source}><input type="checkbox" checked={configuration[source]} disabled={source==='guest_read'&&!configuration.virtual_machines||source==='guest_execute'&&!configuration.guest_read||source==='http'&&!configuration.host&&!configuration.containers&&!configuration.virtual_machines} onChange={event => toggle(source,event.target.checked)} />{t(sourceLabels[source])}</label>)}
    <label>{t('discoveryInterval')}<input type="number" min={60} max={3600} required value={configuration.interval_seconds} onChange={event => setConfiguration(current => ({ ...current, interval_seconds: Number(event.target.value) }))} /></label>
    <label>{t('discoveryReason')}<textarea minLength={8} maxLength={1000} required value={reason} onChange={event => setReason(event.target.value)} /></label><ErrorNotice error={mutation.error} /><div className="dialog-actions"><button type="submit" className="button" disabled={mutation.pending || !dirty}>{t('save')}</button><ObjectDrawerClose /></div>
  </form></ObjectDrawer>;
}

type Definition = { version: number; revision: number; signatures: Record<string, unknown>[]; providers?:Record<string,unknown>[];http_ports?:number[];http_paths?:string[] };
function CatalogDrawer({ close }: Readonly<{ close: () => void }>) {
  const resource = useResource<{ source: string; revision: number; published?: Definition }>('/api/discovery/catalog/draft');
  return <ResourceView resource={resource}>{data => <CatalogEditor initial={data} close={close} />}</ResourceView>;
}
function CatalogEditor({ initial, close }: Readonly<{ initial: { source: string; revision: number; published?: Definition }; close: () => void }>) {
  const t = useText(); const { session } = useContext(Context); const mutation = useMutation();
  const [source, setSource] = useState(initial.source); const [saved, setSaved] = useState(initial.source); const [revision, setRevision] = useState(initial.revision);
  const [mode, setMode] = useState('both'); const [definition, setDefinition] = useState<Definition>(); const [error, setError] = useState<unknown>();
  const [validatedSource,setValidatedSource]=useState('');const [visualUsable,setVisualUsable]=useState(false);
  const [sample, setSample] = useState(''); const [result, setResult] = useState<unknown>(); const [reason, setReason] = useState('');
  const resultEpoch=useRef(0);const pathHelpId=useId();
  const [signature,setSignature]=useState<{index:number;value:Record<string,unknown>}>();
  const [signatureQuery,setSignatureQuery]=useState('');
  const changeDefinition=(next:Definition)=>{resultEpoch.current++;setDefinition(next);setSource(JSON.stringify(next,null,2));setResult(undefined);};
  const diff=definition&&initial.published?discoveryCatalogDiff(initial.published.signatures,definition.signatures):undefined;
  const providerDiff=definition&&initial.published?discoveryCatalogDiff(initial.published.providers??[],definition.providers??[]):undefined;
  const oldPorts=[...(initial.published?.http_ports??[11434,18789])].sort((a,b)=>a-b);const nextPorts=[...(definition?.http_ports??[11434,18789])].sort((a,b)=>a-b);const portsChanged=JSON.stringify(oldPorts)!==JSON.stringify(nextPorts);
  const oldPaths=initial.published?.http_paths??['/'];const nextPaths=definition?.http_paths??['/'];const pathsChanged=JSON.stringify(oldPaths)!==JSON.stringify(nextPaths);
  useEffect(() => {
    const controller = new AbortController();setError(undefined);setResult(undefined);
    const timer = window.setTimeout(() => { void request<{ catalog: Definition }>('/api/discovery/catalog/compile', { method: 'POST', body: { source }, csrf: session.csrf_token, signal: controller.signal }).then(value => { if (!controller.signal.aborted) {setDefinition(value.catalog);setValidatedSource(source);setVisualUsable(true);} }).catch(value => { if (!controller.signal.aborted) setError(value); }); }, 300);
    return () => { resultEpoch.current++;clearTimeout(timer); controller.abort(); };
  }, [source, session.csrf_token]);
  return <ObjectDrawer title={t('discoveryCatalog')} dirty={source !== saved} close={close}><div className="dialog-body discovery-drawer-body"><p>{t('discoveryCatalogDescription')}</p><fieldset className="discovery-editor-controls" disabled={mutation.pending}>
    <div className="discovery-mode" role="group" aria-label={t('discoveryEditorMode')}>{([{id:'visual',name:t('discoveryVisual'),icon:'workflow'},{id:'yaml',name:'YAML',icon:'code'},{id:'both',name:t('discoverySideBySide'),icon:'split'}] as const).map(item=><button type="button" className="icon-button" key={item.id} title={item.name} aria-label={item.name} aria-pressed={mode===item.id} onClick={()=>setMode(item.id)}><Icon name={item.icon}/></button>)}</div>
    <div className={`discovery-editor discovery-editor-${mode}`}>
      {mode !== 'yaml' && <div><div className="discovery-search"><label><Icon name="search"/><input aria-label={t('discoverySignatureSearch')} maxLength={120} value={signatureQuery} onChange={event=>setSignatureQuery(event.target.value)}/></label><button className="button secondary" disabled={!definition||!visualUsable||definition.signatures.length>=1024} onClick={()=>setSignature({index:-1,value:{id:'',application_id:'',name:'',revision:0,sources:['host_process'],state:'executed',condition:{op:'eq',field:'executable',value:''},provenance:''}})}><Icon name="plus"/>{t('discoveryNewSignature')}</button></div>{definition ? <ul className="discovery-signatures">{definition.signatures.map((item,index)=>({item,index})).filter(({item})=>`${item.id} ${item.name} ${item.application_id}`.toLocaleLowerCase().includes(signatureQuery.toLocaleLowerCase())).map(({item,index})=><li key={String(item.id)}><button className="text-link" disabled={!visualUsable} onClick={()=>setSignature({index,value:item})}>{String(item.name)}<small>{String(item.id)}</small></button></li>)}</ul> : <p>{t('discoveryValidateFirst')}</p>}</div>}
      {mode !== 'visual' && <label>YAML<textarea className="discovery-source" spellCheck={false} maxLength={98304} value={source} onChange={event => {resultEpoch.current++;setVisualUsable(false);setSource(event.target.value);}} /></label>}
    </div>{definition&&mode!=='yaml'&&<div><label>{t('discoveryHttpProbePaths')}<textarea aria-describedby={pathHelpId} disabled={!visualUsable} maxLength={8223} value={nextPaths.join('\n')} onChange={event=>changeDefinition({...definition,http_paths:event.target.value.split('\n')})}/></label><small id={pathHelpId}>{t('discoveryHttpProbePathsHelp')}</small></div>}<ErrorNotice error={error} /><ErrorNotice error={mutation.error} />
    <div className="dialog-actions"><button className="button secondary" disabled={!definition || validatedSource !== source || mutation.pending} onClick={() => { void mutation.run<{ revision: number }>('/api/discovery/catalog/draft', 'PUT', { source, revision }).then(value => { if (value) { setSaved(source); setRevision(value.revision); } }).catch(() => undefined); }}>{t('discoverySaveDraft')}</button><ObjectDrawerClose /></div>
    <fieldset><legend>{t('discoverySimulation')}</legend><label>{t('discoverySample')}<textarea className="discovery-source" value={sample} maxLength={24576} onChange={event => {resultEpoch.current++;setSample(event.target.value);setResult(undefined);}} /></label><button className="button secondary" disabled={!definition || validatedSource !== source || mutation.pending || !sample} onClick={() => { let snapshot: unknown; try { snapshot = JSON.parse(sample); } catch { setError(new Error(t('discoveryInvalidSample'))); return; } const epoch=resultEpoch.current;void mutation.run('/api/discovery/catalog/evaluate', 'POST', { source, snapshot }).then(value=>{if(epoch===resultEpoch.current)setResult(value);}).catch(() => undefined); }}>{t('discoverySimulate')}</button>{result !== undefined && <DiscoverySimulation value={result} />}</fieldset>
    {diff&&<section aria-label={t('discoveryChangePreview')}><h3>{t('discoveryChangePreview')}</h3>{(['added','changed','removed'] as const).map((kind,index)=><div key={kind}><h4>{t((['discoveryAdded','discoveryChanged','discoveryRemoved'] as const)[index])}: {diff[kind].length}</h4><ul>{diff[kind].map(item=><li key={String(item.id)}>{String(item.name)} · {String(item.id)}</li>)}</ul></div>)}</section>}
    {providerDiff&&<section aria-label={t('discoveryProviderChanges')}><h3>{t('discoveryProviderChanges')}</h3>{(['added','changed','removed'] as const).map((kind,index)=><div key={kind}><h4>{t((['discoveryProvidersAdded','discoveryProvidersChanged','discoveryProvidersRemoved'] as const)[index])}: {providerDiff[kind].length}</h4><ul>{providerDiff[kind].map(item=><li key={String(item.id)}>{String(item.id)} · {Array.isArray(item.hosts)?item.hosts.map(String).join(', '):''}</li>)}</ul></div>)}</section>}
    {definition&&initial.published&&portsChanged&&<section aria-label={t('discoveryHttpCandidatePorts')}><h3>{t('discoveryHttpCandidatePorts')}</h3><p>{oldPorts.join(', ')} → {nextPorts.join(', ')}</p></section>}
    {definition&&initial.published&&pathsChanged&&<section aria-label={t('discoveryHttpProbePaths')}><h3>{t('discoveryHttpProbePaths')}</h3><p>{oldPaths.join(', ')} → {nextPaths.join(', ')}</p></section>}
    <fieldset><legend>{t('discoveryPublish')}</legend><p>{t('discoveryPublishDescription')}</p><label>{t('discoveryReason')}<textarea minLength={8} maxLength={1000} value={reason} onChange={event => setReason(event.target.value)} /></label><button className="button" disabled={source !== saved || validatedSource !== source || revision === 0 || reason.trim().length < 8 || mutation.pending} onClick={() => { void mutation.run('/api/discovery/catalog/publish', 'POST', { revision, reason }).then(close).catch(() => undefined); }}>{t('discoveryPublish')}</button></fieldset>
    </fieldset>{signature&&definition&&<DiscoverySignature key={signature.index} initial={signature.value} close={()=>setSignature(undefined)} save={value=>{changeDefinition({...definition,signatures:signature.index<0?[...definition.signatures,value]:definition.signatures.map((item,index)=>index===signature.index?value:item)});setSignature(undefined);}} remove={()=>{if(signature.index>=0)changeDefinition({...definition,signatures:definition.signatures.filter((_,index)=>index!==signature.index)});setSignature(undefined);}}/>}
  </div></ObjectDrawer>;
}
