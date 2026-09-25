import { PrivacyForm, PublisherSharingForm, ReportsPanel, csvDocument } from './PrivacyDetectionPage';
import { ObservabilityPage } from './ObservabilityPage';
import { App } from './App';
import { PublisherPanel } from './PublisherPanel';
import { DetectionCatalog } from './DetectionCatalog';
import { translate } from './ui';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';
import type { Session } from './api';
import { AliasRotation } from './AliasRotation';
import { IdentityReveal } from './IdentityReveal';
import { Context, ResourceView, useResource } from './ui';
import { ExportMenu } from './shadow/FilterBar';

beforeEach(() => {
 Object.defineProperty(HTMLDialogElement.prototype, 'showModal', { configurable: true, value() { this.setAttribute('open', ''); } });
 Object.defineProperty(HTMLDialogElement.prototype, 'close', { configurable: true, value() { this.removeAttribute('open'); } });
});

const session: Session = { user:{id:'synthetic-user',email:'operator@example.invalid',display_name:'Test operator'},organization:{id:'synthetic-org',name:'Test organization',role:'owner'},organizations:[],permissions:['identity.erase','identity.reveal'],csrf_token:'test-csrf',edition:'community' };
function wrap(children:ReactNode, permissions=session.permissions){return <Context.Provider value={{session:{...session,permissions},language:'en',refreshSession:async()=>{}}}>{children}</Context.Provider>}
function response(value:unknown){return new Response(JSON.stringify(value),{headers:{'Content-Type':'application/json'}})}
afterEach(()=>{vi.useRealTimers();vi.restoreAllMocks()});

it('requires a reason and sends a counted alias rotation with the session CSRF token',async()=>{
 const fetcher=vi.spyOn(globalThis,'fetch').mockResolvedValue(response({subjects:4,revision:8})), done=vi.fn();
 render(wrap(<AliasRotation done={done}/>));
 expect(screen.getByRole('button',{name:'Confirm rotation'})).toBeDisabled();
 fireEvent.change(screen.getByRole('textbox'),{target:{value:'Synthetic investigation'}});
 fireEvent.click(screen.getByRole('button',{name:'Confirm rotation'}));
 expect(await screen.findByText('Aliases recalculated: 4. Active reveals revoked.')).toBeInTheDocument();
 expect(fetcher).toHaveBeenCalledTimes(1);expect(fetcher).toHaveBeenCalledWith('/api/privacy/alias-key/rotate',expect.objectContaining({method:'POST',body:JSON.stringify({reason:'Synthetic investigation'}),headers:expect.objectContaining({'X-CSRF-Token':'test-csrf'})}));
 expect(done).toHaveBeenCalledTimes(1);
});

it('reveals only an authorized subject with an explicit reason and invalidates projections',async()=>{
 const fetcher=vi.spyOn(globalThis,'fetch').mockResolvedValue(response({expires_at:'2099-01-01T00:00:00Z'})),changed=vi.fn();
 window.addEventListener('milvago:privacy-changed',changed);
 const view=render(wrap(<IdentityReveal subject="subject-1"/>,[]));
 expect(screen.queryByRole('button')).not.toBeInTheDocument();
 view.rerender(wrap(<IdentityReveal subject="subject-1"/>));
 fireEvent.change(screen.getByRole('textbox'),{target:{value:'Synthetic incident'}});
 fireEvent.click(screen.getByRole('button',{name:'Reveal identity for 15 minutes'}));
 await waitFor(()=>expect(changed).toHaveBeenCalledTimes(1));
 expect(fetcher).toHaveBeenCalledWith('/api/subjects/subject-1/reveal',expect.objectContaining({method:'POST',body:JSON.stringify({reason:'Synthetic incident'})}));
 window.removeEventListener('milvago:privacy-changed',changed);
});

function Projection(){const r=useResource<{name:string;identity_expires_at?:string}>('/api/test');return <ResourceView resource={r}>{v=><p>{v.name}</p>}</ResourceView>}
it('removes a proven revealed projection at expiry before a slow replacement arrives',async()=>{
 const deadline=Date.now()+1000;
 const fetcher=vi.spyOn(globalThis,'fetch').mockResolvedValueOnce(response({name:'Synthetic revealed identity',identity_expires_at:new Date(deadline).toISOString()})).mockImplementation(()=>new Promise(()=>{}));
 render(wrap(<Projection/>));
 expect(await screen.findByText('Synthetic revealed identity')).toBeInTheDocument();
 await waitFor(()=>expect(screen.queryByText('Synthetic revealed identity')).not.toBeInTheDocument(),{timeout:2000});
 expect(fetcher).toHaveBeenCalledTimes(2);
});

it('discards revealed projections on revocation notification before refetch completion',async()=>{
 const fetcher=vi.spyOn(globalThis,'fetch').mockResolvedValueOnce(response({name:'Synthetic revealed identity',identity_expires_at:'2099-01-01T00:00:00Z'})).mockImplementation(()=>new Promise(()=>{}));
 render(wrap(<Projection/>));expect(await screen.findByText('Synthetic revealed identity')).toBeInTheDocument();
 act(()=>window.dispatchEvent(new Event('milvago:privacy-changed')));
 expect(screen.queryByText('Synthetic revealed identity')).not.toBeInTheDocument();
 await waitFor(()=>expect(fetcher).toHaveBeenCalledTimes(2));
});

it('defaults export to aliases and requires explicit selection of revealed identities',()=>{
 render(wrap(<ExportMenu criteria={{}}/>));
 expect(screen.getByRole('combobox',{name:'Export identity'})).toHaveValue('aliases');
 fireEvent.change(screen.getByRole('combobox',{name:'Export identity'}),{target:{value:'revealed'}});
 expect(screen.getByRole('combobox',{name:'Export identity'})).toHaveValue('revealed');
});

const provider={id:'synthetic',label:'Synthetic provider',domains:['ai.example.invalid'],aliases:[],conversation_path:'',conversation_segment:0,qualified_at:'2026-09-01T00:00:00Z',dom:{editor:'textarea',send:'button',response:'.response'},network:[]};
const catalog={revision:7,can_publish:true,content:{providers:[provider],native_tools:[],heuristics:{keys:[],mime_types:[]}}};

it('previews a signed envelope without publication and binds publication to those exact bytes',async()=>{
 const fetcher=vi.spyOn(globalThis,'fetch').mockImplementation(async(input,init)=>{
  if(String(input)==='/api/detection/catalog')return response(catalog);
  const body=JSON.parse(String(init?.body));return response({...catalog,published:body.publish,revision:body.publish?8:7});
 });
 render(wrap(<DetectionCatalog/>));
 expect(await screen.findByText('Detection catalogue')).toBeInTheDocument();
 fireEvent.click(screen.getByRole('button',{name:'Import signed catalogue'}));
 fireEvent.change(screen.getByRole('textbox',{name:'Signed envelope (JSON)'}),{target:{value:JSON.stringify({payload:'payload-test',signature:'signature-test'})}});
 fireEvent.click(screen.getByRole('button',{name:'Verify signature and preview'}));
 const publish=await screen.findByRole('button',{name:'Publish catalogue'});
 // Publication used to be observed through an onPublished prop, which existed only to
 // feed the candidates table; the confirmation the operator actually sees says the same.
 expect(screen.queryByText('Catalogue published.')).not.toBeInTheDocument();
 expect(fetcher).toHaveBeenCalledWith('/api/detection/catalog/import',expect.objectContaining({body:JSON.stringify({expected_revision:7,envelope:{payload:'payload-test',signature:'signature-test'},publish:false})}));
 fireEvent.click(publish);await screen.findByText('Catalogue published.');
 expect(fetcher).toHaveBeenCalledWith('/api/detection/catalog/import',expect.objectContaining({body:JSON.stringify({expected_revision:7,envelope:{payload:'payload-test',signature:'signature-test'},publish:true})}));
});

it('cannot publish a stale preview after its signed envelope is changed',async()=>{
 vi.spyOn(globalThis,'fetch').mockImplementation(async input=>response(String(input)==='/api/detection/catalog'?catalog:{...catalog,published:false}));
 render(wrap(<DetectionCatalog/>));await screen.findByText('Detection catalogue');
 fireEvent.click(screen.getByRole('button',{name:'Import signed catalogue'}));
 const field=screen.getByRole('textbox',{name:'Signed envelope (JSON)'});
 fireEvent.change(field,{target:{value:JSON.stringify({payload:'first',signature:'signature'})}});
 fireEvent.click(screen.getByRole('button',{name:'Verify signature and preview'}));await screen.findByRole('button',{name:'Publish catalogue'});
 fireEvent.change(field,{target:{value:JSON.stringify({payload:'changed',signature:'signature'})}});
 expect(screen.queryByRole('button',{name:'Publish catalogue'})).not.toBeInTheDocument();
});

it('edits a provider declaratively and previews its exact changes before publishing',async()=>{
 const fetcher=vi.spyOn(globalThis,'fetch').mockResolvedValue(response(catalog));
 render(wrap(<DetectionCatalog/>));await screen.findByText('Detection catalogue');
 fireEvent.click(screen.getByRole('button',{name:'Synthetic provider'}));
 fireEvent.change(screen.getByRole('textbox',{name:'Name'}),{target:{value:'Updated synthetic provider'}});
 fireEvent.click(screen.getByRole('button',{name:'Save changes'}));
 expect(screen.queryByRole('button',{name:'Publish catalogue'})).not.toBeInTheDocument();
 fireEvent.click(screen.getByRole('button',{name:'Preview changes'}));
 expect(screen.getByText('Added or modified: synthetic')).toBeInTheDocument();
 fireEvent.click(screen.getByRole('button',{name:'Publish catalogue'}));
 await waitFor(()=>expect(fetcher).toHaveBeenCalledWith('/api/detection/catalog',expect.objectContaining({method:'PUT',body:JSON.stringify({revision:7,content:{...catalog.content,providers:[{...provider,label:'Updated synthetic provider'}]}})})));
});

it('edits native tools and heuristics declaratively before publishing',async()=>{
 const fetcher=vi.spyOn(globalThis,'fetch').mockResolvedValue(response(catalog));
 render(<Context.Provider value={{session:{...session,edition:'commercial'},language:'en',refreshSession:async()=>{}}}><DetectionCatalog/></Context.Provider>);await screen.findByText('Detection catalogue');
 fireEvent.click(screen.getByRole('button',{name:/Native tools/}));
 fireEvent.click(screen.getByRole('button',{name:'Add native tool'}));
 fireEvent.change(screen.getByRole('combobox',{name:'Identifier'}),{target:{value:'codex'}});
 fireEvent.change(screen.getByRole('combobox',{name:'Platform'}),{target:{value:'windows'}});
 fireEvent.change(screen.getByRole('combobox',{name:'Compiled parser'}),{target:{value:'otlp-v1'}});
 const user=userEvent.setup();
 await user.type(screen.getByRole('textbox',{name:'Qualified versions (one per line)'}),'0.5.8\n0.5.9');
 await user.tab();
 fireEvent.click(screen.getByRole('button',{name:'Save changes'}));
 fireEvent.click(screen.getByRole('button',{name:'Heuristics'}));
 await user.type(screen.getByRole('textbox',{name:'Heuristic keys (one per line)'}),'messages');
 await user.tab();
 await user.type(screen.getByRole('textbox',{name:'MIME types (one per line)'}),'application/json');
 fireEvent.click(screen.getByRole('button',{name:'Save changes'}));
 await user.tab();
 fireEvent.click(screen.getByRole('button',{name:'Preview changes'}));
 expect(screen.getByText('Native tools changed')).toBeInTheDocument();
 expect(screen.getByText('Heuristics changed')).toBeInTheDocument();
 fireEvent.click(screen.getByRole('button',{name:'Publish catalogue'}));
 await waitFor(()=>expect(fetcher).toHaveBeenCalledWith('/api/detection/catalog',expect.objectContaining({method:'PUT',body:JSON.stringify({revision:7,content:{providers:[provider],native_tools:[{id:'codex',platform:'windows',qualified_versions:['0.5.8','0.5.9'],parser:'otlp-v1',telemetry_text_qualified_versions:[]}],heuristics:{keys:['messages'],mime_types:['application/json']}}})})));
});

it.each([{permissions:['overview.read','reports.aggregate'],aggregate:false},{permissions:['overview.read','devices.read','events.read','reports.aggregate'],aggregate:true}])('keeps reporter and aggregate-only navigation on reports (%j)',async ({permissions,aggregate})=>{
 window.location.hash='#overview';
 const fetcher=vi.spyOn(globalThis,'fetch').mockImplementation(async input=>{
  const url=String(input);
  if(url==='/api/session')return response({...session,user:{...session.user,language:'en'},permissions,privacy:{aggregate_only:aggregate}});
  if(url==='/api/bootstrap')return response({edition:'community',default_language:'en'});
  if(url==='/api/shadow/aggregate')return response({items:[]});
  return new Response(JSON.stringify({error:'unexpected_request',message:url}),{status:404});
 });
 render(<App/>);
 expect(await screen.findByRole('heading',{level:1,name:'Reports'})).toBeInTheDocument();
 expect(screen.getByRole('link',{name:'Reports'})).toBeInTheDocument();
 expect(screen.queryByRole('link',{name:'Devices'})).not.toBeInTheDocument();
 expect(screen.queryByRole('link',{name:'Journal'})).not.toBeInTheDocument();
 expect(fetcher.mock.calls.map(c=>String(c[0]))).not.toContain('/api/devices');
 expect(fetcher.mock.calls.map(c=>String(c[0])).filter(x=>x.startsWith('/api/shadow/events'))).toHaveLength(0);
});

it('shows the publisher preview without a remote modification action',async()=>{
 const preview={configured:true,auto_catalog:false,instance_id:'synthetic',telemetry:{provider_health:[{provider:'synthetic',ratio:0.5}]},last_error:'',last_success:null,queue:{state:'held',attempts:3}};
 const fetcher=vi.spyOn(globalThis,'fetch').mockResolvedValue(response(preview));
 render(wrap(<PublisherPanel/>));
 expect(await screen.findByText('Held: configuration or consent changed')).toBeInTheDocument();
 expect(screen.getByText(/"ratio": 0.5/)).toBeInTheDocument();
 expect(screen.queryByRole('button')).not.toBeInTheDocument();
 expect(fetcher).toHaveBeenCalledTimes(1);
});

it('renders held and failed sensitive audit counts from the server',async()=>{
 vi.spyOn(globalThis,'fetch').mockResolvedValue(response({revision:1,grafana_url:'',destinations:[],status:[],privacy_outbox:{pending:2,held:3,failed:4}}));
 render(wrap(<ObservabilityPage/>));
 const heading=await screen.findByText('Sensitive audit delivery queue');const section=heading.closest('section')!;
 expect(section.textContent).toContain('Pending2');expect(section.textContent).toContain('Held3');expect(section.textContent).toContain('Failed4');
});

it('shows a missing machine name separately from its identifier and native collector health',async()=>{
 window.location.hash='#devices?id=10000000-0000-4000-8000-000000000001';
 vi.spyOn(globalThis,'fetch').mockImplementation(async input=>{
  const url=String(input);
  if(url==='/api/session')return response({...session,edition:'commercial',user:{...session.user,language:'en'},permissions:['devices.read']});
  if(url==='/api/bootstrap')return response({edition:'commercial',default_language:'en'});
  if(url==='/api/devices?device_id=10000000-0000-4000-8000-000000000001')return response({items:[{id:'10000000-0000-4000-8000-000000000001',hostname:'',platform:'windows',version:'0.5.7',status:'approved',last_seen:null,os_user:'',collector_health:[{tool:'synthetic-collector',state:'metadata_only',version:'1.0',skipped_trees:2,managed_config_tampered:3}]}]});
  return new Response(JSON.stringify({error:'unexpected_request',message:url}),{status:404});
 });
 render(<App/>);
 expect(await screen.findByRole('heading',{level:1,name:'Machine name unavailable'})).toBeInTheDocument();
 expect(screen.getByText('10000000-0000-4000-8000-000000000001')).toBeInTheDocument();
 expect(screen.getByText('synthetic-collector')).toBeInTheDocument();
 expect(screen.getByText(/Skipped storage trees: 2/)).toBeInTheDocument();
 expect(screen.getByText(/Managed configuration changes: 3/)).toBeInTheDocument();
});

it('does not report rotation success when the server omits the count',async()=>{
 vi.spyOn(globalThis,'fetch').mockResolvedValue(response({revision:8}));const done=vi.fn();render(wrap(<AliasRotation done={done}/>));
 fireEvent.change(screen.getByRole('textbox'),{target:{value:'Synthetic incident'}});
 fireEvent.click(screen.getByRole('button',{name:'Confirm rotation'}));
 expect(await screen.findByText('The server did not confirm the operation.')).toBeInTheDocument();
 expect(done).not.toHaveBeenCalled();
});

it.each(['fr','es','pt-BR'] as const)('translates the privacy page vocabulary in %s instead of copying English',language=>{
 for(const key of ['privacy','pseudonymous','aggregateOnly','kAnonymity','identityLinkDays','shareHealth','shareFleet','reports','suppressed','coverage','candidateDomains','freshMfaRequired','configurationLocked','unableToSave'] as const)expect(translate(language,key)).not.toEqual(translate('en',key));
});

it('offers alias rotation to an identity.erase role without fetching settings',async()=>{
 window.location.hash='#privacy';
 const fetcher=vi.spyOn(globalThis,'fetch').mockImplementation(async input=>String(input)==='/api/session'?response({...session,user:{...session.user,language:'en'},permissions:['identity.erase']}):response({edition:'community',default_language:'en'}));
 render(<App/>);
 expect(await screen.findByRole('button',{name:'Confirm rotation'})).toBeDisabled();
 expect(screen.getByRole('link',{name:'Privacy'})).toBeInTheDocument();
 expect(fetcher.mock.calls.map(c=>String(c[0]))).not.toContain('/api/privacy');
});

it('ignores a signed preview resolved after its envelope was edited, including editing back',async()=>{
 let resolvePreview!:(value:Response)=>void;
 const pending=new Promise<Response>(resolve=>{resolvePreview=resolve});
 const fetcher=vi.spyOn(globalThis,'fetch').mockImplementation(async input=>String(input)==='/api/detection/catalog'?response(catalog):pending);
 render(wrap(<DetectionCatalog/>));await screen.findByText('Detection catalogue');
 fireEvent.click(screen.getByRole('button',{name:'Import signed catalogue'}));
 const field=screen.getByRole('textbox',{name:'Signed envelope (JSON)'});
 const a=JSON.stringify({payload:'synthetic-A',signature:'signature-A'}),b=JSON.stringify({payload:'synthetic-B',signature:'signature-B'});
 fireEvent.change(field,{target:{value:a}});
 fireEvent.click(screen.getByRole('button',{name:'Verify signature and preview'}));
 await waitFor(()=>expect(fetcher).toHaveBeenCalledTimes(2));
 fireEvent.change(field,{target:{value:b}});fireEvent.change(field,{target:{value:a}});
 await act(async()=>resolvePreview(response({...catalog,published:false})));
 expect(field).toHaveValue(a);
 expect(screen.queryByRole('button',{name:'Publish catalogue'})).not.toBeInTheDocument();
 expect(fetcher).toHaveBeenCalledTimes(2);
});

it('saves publisher choices in their own section while preserving existing privacy settings',async()=>{
 const fetcher=vi.spyOn(globalThis,'fetch').mockResolvedValue(response({revision:2}));
 const config={pseudonymous:true,aggregate_only:false,k_anonymity:5,identity_link_days:90,lock_descendants:false,retention_justification:'',team_claim:'',discovery_enabled:false,ignored_domains:['example.invalid'],auto_catalog:false,share_health:false,share_fleet:false};
 const reload=vi.fn();
 render(wrap(<><PrivacyForm value={{revision:1,config}} reload={reload}/><PublisherSharingForm value={{revision:1,config}} reload={reload}/></>));
 const privacy=screen.getByRole('heading',{name:'Privacy'}).closest('section')!;
 const publisher=screen.getByRole('heading',{name:'Publisher sharing'}).closest('section')!;
 expect(privacy).not.toHaveTextContent('Ignored domains');
 expect(privacy).not.toHaveTextContent('Share detector health');
 expect(publisher).toHaveTextContent('Automatically import the publisher catalogue');
 fireEvent.click(screen.getByRole('checkbox',{name:'Share detector health'}));
 fireEvent.change(publisher.querySelector('textarea')!,{target:{value:'Synthetic consent change'}});
 fireEvent.click(publisher.querySelector('button[type=submit]')!);
 await waitFor(()=>expect(fetcher).toHaveBeenCalledTimes(1));
 const request=JSON.parse((fetcher.mock.calls[0][1] as RequestInit).body as string);
 expect(request.config).toMatchObject({share_health:true,share_fleet:false,auto_catalog:false,ignored_domains:['example.invalid'],pseudonymous:true});
 expect(request.reason).toBe('Synthetic consent change');
});

it('shows local publisher consents but no ineffective catalogue switch for a child organization',()=>{
 const child={...session,edition:'commercial' as const,organizations:[{id:'synthetic-org',name:'Test organization',role:'owner',parent_id:'synthetic-parent'}]};
 const config={pseudonymous:true,aggregate_only:false,k_anonymity:5,identity_link_days:90,lock_descendants:false,retention_justification:'',team_claim:'',discovery_enabled:false,ignored_domains:[],auto_catalog:false,share_health:false,share_fleet:false};
 render(<Context.Provider value={{session:child,language:'en',refreshSession:async()=>{}}}><PublisherSharingForm value={{revision:1,config}} reload={()=>{}}/></Context.Provider>);
 expect(screen.queryByRole('checkbox',{name:'Automatically import the publisher catalogue'})).not.toBeInTheDocument();
 expect(screen.getByRole('checkbox',{name:'Share detector health'})).toBeInTheDocument();
 expect(screen.getByRole('checkbox',{name:'Share fleet counts'})).toBeInTheDocument();
});

it('clears revealed data before refreshing aggregate-only session navigation after privacy save',async()=>{
 let finishSession!:()=>void;
 const refreshSession=vi.fn(()=>new Promise<void>(resolve=>{finishSession=resolve})),reload=vi.fn(),changed=vi.fn();
 window.addEventListener('milvago:privacy-changed',changed);
 vi.spyOn(globalThis,'fetch').mockResolvedValue(response({revision:2}));
 const config={pseudonymous:true,aggregate_only:false,k_anonymity:5,identity_link_days:90,lock_descendants:false,retention_justification:'',team_claim:'',discovery_enabled:false,ignored_domains:[],auto_catalog:false,share_health:false,share_fleet:false};
 render(<Context.Provider value={{session,language:'en',refreshSession}}><PrivacyForm value={{revision:1,config}} reload={reload}/></Context.Provider>);
 const aggregate=screen.getByRole('checkbox',{name:translate('en','aggregateOnly')});fireEvent.click(aggregate);
 fireEvent.change(screen.getByRole('textbox',{name:translate('en','privacyChangeReason')}),{target:{value:'Synthetic privacy update'}});
 fireEvent.click(screen.getByRole('button',{name:'Save'}));
 await waitFor(()=>expect(refreshSession).toHaveBeenCalledTimes(1));
 expect(changed).toHaveBeenCalledTimes(1);expect(reload).not.toHaveBeenCalled();
 await act(async()=>finishSession());expect(reload).toHaveBeenCalledTimes(1);
 window.removeEventListener('milvago:privacy-changed',changed);
});

// The weekly report reads either by team (the OIDC claim) or by device group. The group
// name below opens on "=" on purpose: it is the spreadsheet-formula case of the export.
const cell={tool:'chrome',provider:'chatgpt.com',prompts:12,responses:11,subjects:6};
function aggregate(extra:Record<string,unknown>={},week:Record<string,unknown>={}){
 return {items:[{week_start:'2026-09-07',k:5,report:{suppressed:false,cells:[{...cell,team:'Finance',model:'model-x'}],group_cells:[{...cell,group:'=Sales',model:''}],group_suppressed:false,...week}}],k:5,coverage:'complete',teams_available:true,groups_available:true,...extra};
}
function serveAggregate(body:unknown){return vi.spyOn(globalThis,'fetch').mockImplementation(async input=>String(input)==='/api/shadow/aggregate'?response(body):new Response('{}',{status:404}))}

it('hides the teams breakdown when the OIDC claim is unconfigured or never served',async()=>{
 serveAggregate(aggregate({teams_available:false}));
 render(wrap(<ReportsPanel/>));
 expect(await screen.findByRole('columnheader',{name:'Group'})).toBeInTheDocument();
 expect(screen.queryByRole('button',{name:'Teams'})).toBeNull();
 // A single available breakdown needs no tab bar to choose between one thing.
 expect(screen.queryByRole('group',{name:'Report breakdowns'})).toBeNull();
 expect(screen.getByRole('cell',{name:'=Sales'})).toBeInTheDocument();
});

it('offers both breakdowns and switches the table between them',async()=>{
 serveAggregate(aggregate());
 render(wrap(<ReportsPanel/>));
 expect(await screen.findByRole('columnheader',{name:'Team'})).toBeInTheDocument();
 expect(screen.getByRole('cell',{name:'Finance'})).toBeInTheDocument();
 fireEvent.click(screen.getByRole('button',{name:'Groups'}));
 expect(screen.getByRole('columnheader',{name:'Group'})).toBeInTheDocument();
 expect(screen.getByRole('cell',{name:'=Sales'})).toBeInTheDocument();
 expect(screen.queryByRole('cell',{name:'Finance'})).toBeNull();
});

it('draws the report as a map naming the active breakdown, with no journal to open',async()=>{
 serveAggregate(aggregate());
 render(wrap(<ReportsPanel/>));
 await screen.findByRole('columnheader',{name:'Team'});
 fireEvent.click(screen.getByRole('button',{name:'Cartography'}));
 expect(screen.getByRole('group',{name:'Request map: team, tool, service, model'})).toBeInTheDocument();
 // An aggregate report has no individual view to open, and its own table switch already
 // exists outside the diagram: neither of the diagram's own affordances may show up.
 expect(screen.queryByRole('button',{name:'Journal'})).toBeNull();
 expect(screen.queryByRole('button',{name:'Show table'})).toBeNull();
 fireEvent.click(screen.getByRole('button',{name:'Groups'}));
 expect(screen.getByRole('group',{name:'Request map: group, tool, service, model'})).toBeInTheDocument();
});

it('says a week predating the group breakdown has none, instead of showing it empty',async()=>{
 serveAggregate(aggregate({},{group_cells:undefined,group_suppressed:undefined}));
 render(wrap(<ReportsPanel/>));
 await screen.findByRole('columnheader',{name:'Team'});
 fireEvent.click(screen.getByRole('button',{name:'Groups'}));
 expect(screen.getByText(/never recomputed/)).toBeInTheDocument();
 expect(screen.queryByRole('table')).toBeNull();
});

it('explains withheld rows once, lets the reader close it, and keeps the per-week badge',async()=>{
 localStorage.removeItem('milvago.reports.withheldHelp');
 serveAggregate(aggregate({},{suppressed:true}));
 const {unmount}=render(wrap(<ReportsPanel/>));
 await screen.findByRole('columnheader',{name:'Team'});
 expect(screen.getByText('Why some rows are withheld')).toBeInTheDocument();
 // The threshold named in the text is the one the week was published with.
 expect(screen.getByText(/at least 5 distinct people/)).toBeInTheDocument();
 expect(screen.getByText('Rows withheld')).toBeInTheDocument();
 fireEvent.click(screen.getByRole('button',{name:'Hide the explanation'}));
 expect(screen.queryByText('Why some rows are withheld')).toBeNull();
 expect(screen.getByText('Rows withheld')).toBeInTheDocument();
 // Closed stays closed on the next visit, and can be reopened.
 unmount();
 render(wrap(<ReportsPanel/>));
 await screen.findByRole('columnheader',{name:'Team'});
 expect(screen.queryByText('Why some rows are withheld')).toBeNull();
 fireEvent.click(screen.getByRole('button',{name:'Why are rows withheld?'}));
 expect(screen.getByText('Why some rows are withheld')).toBeInTheDocument();
 localStorage.removeItem('milvago.reports.withheldHelp');
});

it('shows no withheld explanation when every row of every week is published',async()=>{
 serveAggregate(aggregate());
 render(wrap(<ReportsPanel/>));
 await screen.findByRole('columnheader',{name:'Team'});
 expect(screen.queryByText('Why some rows are withheld')).toBeNull();
 expect(screen.queryByText('Rows withheld')).toBeNull();
 expect(screen.queryByRole('button',{name:'Why are rows withheld?'})).toBeNull();
});

it('exports the displayed cells as a spreadsheet-safe CSV',async()=>{
 serveAggregate(aggregate());
 const blobs:Blob[]=[];
 Object.defineProperty(URL,'createObjectURL',{configurable:true,value:(blob:Blob)=>{blobs.push(blob);return 'blob:synthetic'}});
 Object.defineProperty(URL,'revokeObjectURL',{configurable:true,value:()=>{}});
 const click=vi.spyOn(HTMLAnchorElement.prototype,'click').mockImplementation(()=>{});
 render(wrap(<ReportsPanel/>));
 await screen.findByRole('columnheader',{name:'Team'});
 fireEvent.click(screen.getByRole('button',{name:'Groups'}));
 fireEvent.click(screen.getByRole('button',{name:'Export'}));
 expect(click).toHaveBeenCalledTimes(1);
 // jsdom's Blob has no text(): read it the way a browser without that method would.
 // readAsText decodes UTF-8 and eats the byte-order mark, so the mark itself is proved
 // on the document the blob is built from, not on the decoded string.
 const text=await new Promise<string>(resolve=>{const reader=new FileReader();reader.onload=()=>resolve(String(reader.result));reader.readAsText(blobs[0])});
 expect(csvDocument(['Week'],[['2026-09-07']])).toBe('﻿sep=;\r\nWeek\r\n2026-09-07\r\n');
 expect(text).toContain('Week;Group;Tool;Service;Model;Requests;Responses;Distinct subjects\r\n');
 // The group name opens on "=", so the spreadsheet must read it as text, not a formula.
 expect(text).toContain("2026-09-07;'=Sales;chrome;chatgpt.com;Unknown;12;11;6");
});
