import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DiscoveryHub } from './DiscoveryHub';
import { Context } from './ui';
import type { Session } from './api';

const session: Session={user:{id:'fixture-user',email:'reviewer@example.test',display_name:'Reviewer'},organization:{id:'fixture-org',name:'Fixture',role:'admin'},organizations:[],permissions:['discovery.read','devices.read','discovery.manage','discovery.catalog.manage','discovery.run'],csrf_token:'fixture-csrf',edition:'community'};
function response(value:unknown,status=200){return new Response(JSON.stringify(value),{status,headers:{'Content-Type':'application/json'}});}
function serve(overrides:(path:string,init?:RequestInit)=>Response|Promise<Response>|undefined=()=>undefined){return vi.spyOn(globalThis,'fetch').mockImplementation(async(input,init)=>{
  const path=String(input);const replaced=overrides(path,init);if(replaced!==undefined)return replaced;
  if(path==='/api/discovery/catalog')return response({revision:1,signatures:[{id:'openclaw.process',application_id:'openclaw',name:'OpenClaw'}]});
  if(path.startsWith('/api/discovery/inventory?'))return response({total:1,items:[{family:'application',observations:1,name:'OpenClaw',vendor:'',type:'software',status:'review',id:'openclaw',states:['executed'],devices:1,review:'review',last_seen:'2026-10-26T00:00:00Z'}],next_cursor:''});
  if(path==='/api/discovery/applications/openclaw')return response({id:'openclaw',review:'review',observations:1});
  if(path.startsWith('/api/ai-governance/effective?'))return response({governance:{presence:{status:'no_rule'},execution:{status:'no_rule'},evaluated_at:'2026-10-28T00:00:00Z'}});
  if(path.includes('/instances?')||path.includes('/locations?'))return response({items:[],next_cursor:''});
  if(path.startsWith('/api/discovery/runs')||path.startsWith('/api/discovery/environments')||path.startsWith('/api/discovery/coverage')||path.startsWith('/api/discovery/events'))return response({items:[],next_cursor:''});
  return response({error:'fixture_missing',message:path},404);
});}
function show(value:Session=session){return render(<Context.Provider value={{session:value,language:'fr',refreshSession:async()=>undefined}}><DiscoveryHub /></Context.Provider>);}
beforeEach(()=>{location.hash='#applications';Object.defineProperty(HTMLDialogElement.prototype,'showModal',{configurable:true,value(){this.setAttribute('open','');}});Object.defineProperty(HTMLDialogElement.prototype,'close',{configurable:true,value(){this.removeAttribute('open');}});});
afterEach(()=>{cleanup();vi.restoreAllMocks();});

describe('Unified discovery hub',()=>{
  it('opens a DNS activity row directly on its proof and explanation',async()=>{
    serve(path=>path.startsWith('/api/discovery/events?')?response({items:[{id:'event-dns',device_id:'device-fixture',device_name:'<img src=x onerror=alert(1)>',entity_id:'vm/fixture',kind:'provider_domain_queried',occurred_at:'2026-10-27T00:00:00Z'}],next_cursor:''}):path==='/api/discovery/evidence/event-dns'?response({id:'event-dns',evidence:{provider:'openai',evidence:{source:'host_dns_query',observed_at:100,fields:['remote_host'],fact_id:'fact/dns'}}}):undefined);
    show();fireEvent.click(screen.getByRole('button',{name:'Activité'}));
    fireEvent.click(await screen.findByRole('button',{name:'Domaine fournisseur recherché'}));
    const dialog=await screen.findByRole('dialog');
    expect(await within(dialog).findByText('Requête DNS du poste')).toBeInTheDocument();
    expect(within(dialog).getByRole('link',{name:'<img src=x onerror=alert(1)>'})).toHaveAttribute('href','#devices?id=device-fixture');
    expect(within(dialog).getByText('vm/fixture')).toBeInTheDocument();
    expect(within(dialog).getByText('Domaine fournisseur recherché')).toBeInTheDocument();
    expect(dialog.querySelector('img')).toBeNull();
    expect(screen.getByRole('button',{name:'Domaine fournisseur recherché'})).toBeInTheDocument();
    expect(within(dialog).getByText(/Elle ne prouve ni une connexion HTTPS/)).toBeInTheDocument();
    expect(within(dialog).queryByRole('button',{name:'Emplacements'})).not.toBeInTheDocument();
    expect(within(dialog).queryByRole('button',{name:'Historique'})).not.toBeInTheDocument();
  });
  it('edits HTTP probe paths visually, previews them and preserves the rest of the catalogue',async()=>{
    const catalog={version:1,revision:1,signatures:[],providers:[],http_ports:[32145],http_paths:['/']};
    let saved:Record<string,unknown>|undefined;
    serve((path,init)=>{
      if(path==='/api/discovery/catalog/draft'&&init?.method==='PUT') {saved=JSON.parse(String(init.body));return response({revision:2});}
      if(path==='/api/discovery/catalog/draft')return response({revision:1,source:JSON.stringify(catalog),published:catalog});
      if(path==='/api/discovery/catalog/compile')return response({catalog:JSON.parse(JSON.parse(String(init?.body)).source)});
      return undefined;
    });
    show();fireEvent.click(screen.getByRole('button',{name:'Catalogue de reconnaissance'}));
    const dialog=await screen.findByRole('dialog');
    const paths=await within(dialog).findByRole('textbox',{name:'Chemins de sondage HTTP'});
    fireEvent.change(paths,{target:{value:'/health\n/v1/health'}});
    expect(await within(dialog).findByText('/ → /health, /v1/health')).toBeInTheDocument();
    const save=within(dialog).getByRole('button',{name:'Enregistrer le brouillon'});
    await waitFor(()=>expect(save).toBeEnabled());fireEvent.click(save);
    await waitFor(()=>expect(saved).toBeDefined());
    expect(JSON.parse(String(saved!.source))).toEqual({...catalog,http_paths:['/health','/v1/health']});
  });
  it('names guest visibility sources without interpreting inherited object properties',async()=>{
    serve(path=>path.startsWith('/api/discovery/coverage?')?response({items:[
      {device_id:'device-fixture',adapter:'vmware-guest',status:'partial'},
      {device_id:'device-fixture',adapter:'runtime-channels',status:'available'},
      {device_id:'device-fixture',adapter:'virtualbox-guest',status:'denied'},
      {device_id:'device-fixture',adapter:'virtualbox-user-session',status:'partial'},
      {device_id:'device-fixture',adapter:'vmware-user-session',status:'unavailable'},
      {device_id:'device-fixture',adapter:'guest-http',status:'partial'},
      {device_id:'device-fixture',adapter:'__proto__',status:'constructor'},
    ],next_cursor:''}):undefined);
    show();fireEvent.click(screen.getByRole('button',{name:'Visibilité'}));
    expect(await screen.findByText('Processus invités VMware')).toBeInTheDocument();
    expect(screen.getByText('Canaux de moteurs configurés')).toBeInTheDocument();
    expect(screen.getByText('Processus invités VirtualBox')).toBeInTheDocument();
    expect(screen.getByText('VirtualBox : sessions utilisateur')).toBeInTheDocument();
    expect(screen.getByText('VMware : sessions utilisateur')).toBeInTheDocument();
    expect(screen.getByText('Services HTTP dans la VM')).toBeInTheDocument();
    expect(screen.getByText('__proto__')).toBeInTheDocument();
    expect(screen.getByText('constructor')).toBeInTheDocument();
  });
  it('keeps inventory presence in the unified list without rendering a second inventory',async()=>{
    const first='2026-10-24T00:00:00Z';
    serve(path=>{
      if(path.startsWith('/api/discovery/inventory?'))return response({total:1,items:[{family:'application',observations:1,vendor:'',type:'software',status:'',last_seen:'2026-10-26T00:00:00Z',id:'fixture-tool',name:'Fixture runtime',states:['indication'],devices:2,review:'review'}],next_cursor:''});
      if(path==='/api/discovery/applications/fixture-tool')return response({id:'fixture-tool',display:{name:'Fixture runtime'},first_seen:first,review:'review',inventory_metadata:{vendor:'Fixture vendor',risk:'medium'}});
      if(path.startsWith('/api/discovery/applications/fixture-tool/instances?'))return response({items:[{entity_id:'inventory/fixture',scope:'inventory',device_id:'fixture-device',state:'indication',evidence:[{source:'inventory_observation',recognition_kind:'process',observed_at:100,fields:[]}]}],next_cursor:''});
      return undefined;
    });
    render(<Context.Provider value={{session,language:'fr',refreshSession:async()=>undefined}}><DiscoveryHub legacy={<p>Separate inventory</p>}/></Context.Provider>);
    fireEvent.click(await screen.findByRole('button',{name:'Fixture runtime'}));
    expect(screen.queryByText('Separate inventory')).not.toBeInTheDocument();
    const drawer=await screen.findByRole('dialog');
    expect(await within(drawer).findByText('Fixture vendor')).toBeInTheDocument();
    expect(within(drawer).getByTitle(first)).toBeInTheDocument();
    fireEvent.click(within(drawer).getByRole('button',{name:'Preuves'}));
    expect(await within(drawer).findByText('Relevé d’inventaire du poste')).toBeInTheDocument();
    expect(within(drawer).getByText(/Sa méthode de reconnaissance ne prouve ni une exécution actuelle/)).toBeInTheDocument();
    expect(within(drawer).queryByText('Exécution observée')).not.toBeInTheDocument();
  });
  it('keeps an independently authorized inventory visible without granting discovery rights',async()=>{
    const fetcher=serve();const value={...session,permissions:['events.read']};
    render(<Context.Provider value={{session:value,language:'fr',refreshSession:async()=>undefined}}><DiscoveryHub legacy={<p>Authorized existing inventory</p>}/></Context.Provider>);
    expect(await screen.findByText('OpenClaw')).toBeInTheDocument();
    expect(screen.queryByText('Authorized existing inventory')).not.toBeInTheDocument();
    await waitFor(()=>expect(fetcher.mock.calls.some(([path])=>String(path).startsWith('/api/discovery/inventory?'))).toBe(true));
    expect(screen.queryByRole('button',{name:'Environnements'})).not.toBeInTheDocument();
  });
  it('offers local discovery in Community and distinguishes observed execution from governance',async()=>{
    serve();show();expect(await screen.findByRole('button',{name:'OpenClaw'})).toBeInTheDocument();
    expect(screen.getByText('Exécution observée')).toBeInTheDocument();expect(screen.getByText('À examiner')).toBeInTheDocument();
    expect(screen.queryByText('Faible')).not.toBeInTheDocument();
    expect(screen.getByRole('button',{name:'Environnements'})).toBeInTheDocument();expect(screen.getByRole('button',{name:'Visibilité'})).toBeInTheDocument();
  });
  it('groups locations separately and opens only the selected device proofs',async()=>{
    const fetcher=serve(path=>path.includes('/locations?')?response({items:[{device_id:'fixture-device',device_name:'<img src=x onerror=alert(1)>',states:['executed'],observations:60}],next_cursor:''}):path.includes('/instances?')?response({items:[{device_id:'fixture-device',entity_id:'process/1',state:'executed',evidence:[]}],next_cursor:''}):undefined);
    show();fireEvent.click(await screen.findByRole('button',{name:'OpenClaw'}));const dialog=await screen.findByRole('dialog');
    fireEvent.click(await within(dialog).findByRole('button',{name:'Emplacements'}));
    expect(await within(dialog).findByText('60')).toBeInTheDocument();
    expect(fetcher.mock.calls.some(([path])=>String(path).includes('/instances?'))).toBe(false);
    fireEvent.click(within(dialog).getByRole('button',{name:'<img src=x onerror=alert(1)>'}));
    expect(await within(dialog).findByText('process/1',{selector:'strong'})).toBeInTheDocument();
    expect(fetcher.mock.calls.some(([path])=>String(path).includes('/instances?limit=50&device_id=fixture-device'))).toBe(true);
    expect(dialog.querySelector('img')).toBeNull();
    fireEvent.click(within(dialog).getByRole('button',{name:'Voir les preuves de tous les postes'}));
    await waitFor(()=>expect(fetcher.mock.calls.filter(([path])=>String(path).endsWith('/instances?limit=50')).length).toBe(1));
  });
  it('does not request device locations without the existing device permission',async()=>{
    const fetcher=serve();show({...session,permissions:['discovery.read']});
    expect(await screen.findByText('OpenClaw')).toBeInTheDocument();expect(screen.queryByRole('button',{name:'Environnements'})).not.toBeInTheDocument();
    expect(screen.queryByRole('button',{name:'OpenClaw'})).not.toBeInTheDocument();expect(fetcher.mock.calls.some(([input])=>String(input).includes('/instances'))).toBe(false);
  });
  it('keeps a VM provider connection distinct from an application identification',async()=>{
    serve(path=>path.startsWith('/api/discovery/inventory?')?response({items:[],total:0,next_cursor:''}):path.startsWith('/api/discovery/events')?response({items:[{id:'event-1',kind:'provider_contacted',application_id:'',device_id:'device-1',occurred_at:'2026-10-26T00:00:00Z'}],next_cursor:''}):undefined);
    show();expect(await screen.findByText('Aucune observation correspondante')).toBeInTheDocument();fireEvent.click(screen.getByRole('button',{name:'Activité'}));
    expect(await screen.findByRole('button',{name:'Connexion à un fournisseur observée'})).toBeInTheDocument();expect(screen.queryByText('OpenClaw')).not.toBeInTheDocument();
  });
  it('requests each page from the server instead of retaining a growing row inventory',async()=>{
    const fetcher=serve(path=>path.startsWith('/api/discovery/inventory?')?response({total:2,items:[{family:'application',observations:1,name:path.includes('cursor=')?'hermes':'OpenClaw',vendor:'',type:'software',status:'',last_seen:'2026-10-26T00:00:00Z',id:path.includes('cursor=')?'hermes':'openclaw',states:['indication'],devices:1,review:'review'}],next_cursor:path.includes('cursor=')?'':'fixture-cursor'}):undefined);
    show();expect(await screen.findByRole('button',{name:'OpenClaw'})).toBeInTheDocument();fireEvent.click(screen.getByRole('button',{name:'Suivant'}));
    expect(await screen.findByRole('button',{name:'hermes'})).toBeInTheDocument();expect(screen.queryByRole('button',{name:'OpenClaw'})).not.toBeInTheDocument();expect(fetcher.mock.calls.some(([input])=>String(input).includes('cursor=fixture-cursor'))).toBe(true);
  });
  it('closes detail views when privacy changes',async()=>{
    serve();show();fireEvent.click(await screen.findByRole('button',{name:'OpenClaw'}));await screen.findByRole('dialog');
    window.dispatchEvent(new Event('milvago:privacy-changed'));await waitFor(()=>expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });
  it('requires VM activation before guest read and guest read before execution',async()=>{
    serve(path=>path==='/api/discovery/settings'?response({revision:0,configuration:{host:false,containers:false,virtual_machines:false,guest_read:false,guest_execute:false,http:false,network:false,interval_seconds:300}}):undefined);
    show();fireEvent.click(screen.getByRole('button',{name:'Sources de découverte'}));const dialog=await screen.findByRole('dialog');
    const read=await within(dialog).findByRole('checkbox',{name:'Lecture par les outils invités existants et autorisés'});const execute=within(dialog).getByRole('checkbox',{name:'Autoriser l’exécution d’un collecteur prédéfini dans un invité'});
    expect(read).toBeDisabled();expect(execute).toBeDisabled();fireEvent.click(within(dialog).getByRole('checkbox',{name:'Machines virtuelles et WSL'}));expect(read).toBeEnabled();fireEvent.click(read);expect(execute).toBeEnabled();fireEvent.click(execute);fireEvent.click(within(dialog).getByRole('checkbox',{name:'Machines virtuelles et WSL'}));expect(read).not.toBeChecked();expect(execute).not.toBeChecked();
  });
  it('releases pending fetches when the hub unmounts',async()=>{
    const signals: AbortSignal[] = [];
    vi.spyOn(globalThis, 'fetch').mockImplementation((_input, init) => new Promise((_resolve, reject) => {
      const signal = init?.signal; if (!signal) return;
      signals.push(signal);
      signal.addEventListener('abort', () => reject(signal.reason), { once: true });
    }));
    const view=show(); await waitFor(()=>expect(signals.length).toBeGreaterThan(0));
    view.unmount(); expect(signals.every(signal=>signal.aborted)).toBe(true);
  });
  it('shows environment names and endpoints as text and pages relationships within the selected scope',async()=>{
    const fetcher=serve(path=>{
      if(path.startsWith('/api/discovery/environments?'))return response({items:[{id:'endpoint/fixture',scope:'vm/scope',kind:'endpoint',device_id:'device-1',display:{name:'<img src=x onerror=alert(1)>',address:'127.0.0.1:32145'}}],next_cursor:''});
      if(path.startsWith('/api/discovery/environments/endpoint%2Ffixture?'))return response({id:'endpoint/fixture',display:{name:'Local inference',address:'127.0.0.1:32145'},relations:[{from:'vm/fixture',to:path.includes('cursor=')?'endpoint/next':'endpoint/first',source:'fixture',kind:'owns_endpoint'}],relations_next_cursor:path.includes('cursor=')?'':'next-relation'});
      return undefined;
    });
    show();fireEvent.click(screen.getByRole('button',{name:'Environnements'}));
    fireEvent.click(await screen.findByRole('button',{name:'<img src=x onerror=alert(1)>'}));
    const dialog=await screen.findByRole('dialog');expect(await within(dialog).findByText('Local inference')).toBeInTheDocument();
    expect(within(dialog).getByText('127.0.0.1:32145')).toBeInTheDocument();expect(document.querySelector('img[src="x"]')).toBeNull();
    fireEvent.click(await within(dialog).findByRole('button',{name:'Emplacements'}));
    expect(await within(dialog).findByText('vm/fixture → endpoint/first')).toBeInTheDocument();fireEvent.click(within(dialog).getByRole('button',{name:'Suivant'}));
    expect(await within(dialog).findByText('vm/fixture → endpoint/next')).toBeInTheDocument();
    expect(fetcher.mock.calls.some(([input])=>String(input).includes('scope=vm%2Fscope&limit=50&cursor=next-relation'))).toBe(true);
  });
});

describe('Discovery response validation',()=>{
  it.each([{items:{image:'data:image/png'},next_cursor:''},{items:[null],next_cursor:''},{items:[],next_cursor:{image:'data:image/png'}}])('contains malformed list responses without crashing the hub: %j',async malformed=>{
    serve(path=>path.startsWith('/api/discovery/inventory?')?response(malformed):undefined);
    show();expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.getByRole('button',{name:'Environnements'})).toBeInTheDocument();
  });
  it('contains malformed instance responses in the open drawer',async()=>{
    serve(path=>path.includes('/instances?')?response({items:{image:'data:image/png'},next_cursor:''}):undefined);
    show();fireEvent.click(await screen.findByRole('button',{name:'OpenClaw'}));
    const dialog=await screen.findByRole('dialog');
    fireEvent.click(await within(dialog).findByRole('button',{name:'Preuves'}));
    expect(await within(dialog).findByRole('alert')).toBeInTheDocument();
  });
});

describe('Discovery collection requests',()=>{
  it('explains devices whose agent does not advertise discovery without implying an empty AI inventory',async()=>{
    serve(path=>path.startsWith('/api/discovery/coverage?')?response({items:[{device_id:'device-fixture',device_name:'Poste synthétique',adapter:'agent-capability',status:'unavailable',complete:false,server_assessed:true,reason:'agent_capability_missing'}],next_cursor:''}):undefined);
    show();fireEvent.click(screen.getByRole('button',{name:'Visibilité'}));
    expect(await screen.findByText('Ce poste n’annonce pas la découverte locale. Vérifiez la présence d’un agent de poste compatible.')).toBeInTheDocument();
    expect(screen.getByText('Poste synthétique')).toBeInTheDocument();
    expect(screen.getByText('Indisponible')).toBeInTheDocument();
  });
  it('shows run states and cancels only an active request with the run permission',async()=>{
    let cancelled=false;
    const fetcher=serve((path,init)=>{
      if(path==='/api/discovery/runs/run-fixture/cancel'&&init?.method==='POST'){cancelled=true;return response({ok:true});}
      if(path.startsWith('/api/discovery/runs?'))return response({items:[{id:'run-fixture',device_id:'device-fixture',status:cancelled?'cancelled':'pending',created_at:'2026-10-26T00:00:00Z',expires_at:'2026-10-26T00:30:00Z'}],next_cursor:''});
      return undefined;
    });
    show();fireEvent.click(screen.getByRole('button',{name:'Visibilité'}));
    expect(await screen.findByText('En attente du poste')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button',{name:'Annuler la collecte'}));
    expect(await screen.findByText('Annulée')).toBeInTheDocument();
    expect(screen.queryByRole('button',{name:'Annuler la collecte'})).not.toBeInTheDocument();
    expect(fetcher.mock.calls.some(([input,init])=>String(input).endsWith('/run-fixture/cancel')&&init?.method==='POST')).toBe(true);
  });
  it('keeps request status readable without offering cancellation to a read-only user',async()=>{
    serve(path=>path.startsWith('/api/discovery/runs?')?response({items:[{id:'run-fixture',device_id:'device-fixture',status:'running'}],next_cursor:''}):undefined);
    show({...session,permissions:['discovery.read','devices.read']});
    fireEvent.click(screen.getByRole('button',{name:'Visibilité'}));
    expect(await screen.findByText('Collecte en cours')).toBeInTheDocument();
    expect(screen.queryByRole('button',{name:'Annuler la collecte'})).not.toBeInTheDocument();
  });
});

describe('System collector association',()=>{
  const device='11111111-1111-4111-8111-111111111111';
  function host(path:string,platform='linux') {
    if(path.startsWith('/api/discovery/environments?'))return response({items:[{id:'host/fixture',scope:'endpoint',kind:'host',device_id:device,display:{name:'Synthetic Linux host'}}],next_cursor:''});
    if(path.startsWith('/api/discovery/environments/host%2Ffixture?'))return response({id:'host/fixture',kind:'host',device_platform:platform,display:{name:'Synthetic Linux host'}});
    return undefined;
  }
  async function openHost(){fireEvent.click(screen.getByRole('button',{name:'Environnements'}));fireEvent.click(await screen.findByRole('button',{name:'Synthetic Linux host'}));return screen.findByRole('dialog');}
  it.each(['linux','windows'])('downloads only public %s binding material and releases the object URL',async(platform)=>{
    const create=vi.fn(()=> 'blob:binding');const revoke=vi.fn();
    Object.defineProperty(URL,'createObjectURL',{configurable:true,value:create});Object.defineProperty(URL,'revokeObjectURL',{configurable:true,value:revoke});
    const click=vi.spyOn(HTMLAnchorElement.prototype,'click').mockImplementation(function(this:HTMLAnchorElement){expect(this.download).toBe(`milvago-${platform}-binding.json`);});
    serve(path=>host(path,platform)??(path.endsWith('/system-binding')?response({version:1,device_id:device,server_url:'https://server.example.test',public_key:'A'.repeat(43)+'='}):undefined));
    show();const dialog=await openHost();fireEvent.click(await within(dialog).findByRole('button',{name:platform==='windows'?'Télécharger l’association du collecteur Windows':'Télécharger l’association du collecteur Linux'}));
    await waitFor(()=>expect(click).toHaveBeenCalledOnce());expect(create).toHaveBeenCalledOnce();await waitFor(()=>expect(revoke).toHaveBeenCalledWith('blob:binding'));
  });
  it.each(['linux','windows'])('keeps %s association unavailable to a reader without source management permission',async(platform)=>{
    const fetcher=serve(path=>host(path,platform));show({...session,permissions:['discovery.read','devices.read']});
    const dialog=await openHost();await within(dialog).findByText('Synthetic Linux host');
    expect(within(dialog).queryByRole('button',{name:platform==='windows'?'Télécharger l’association du collecteur Windows':'Télécharger l’association du collecteur Linux'})).not.toBeInTheDocument();
    expect(fetcher.mock.calls.some(([path])=>String(path).endsWith('/system-binding'))).toBe(false);
  });
  it.each(['linux','windows'])('rejects unexpected private fields instead of exporting %s binding',async(platform)=>{
    const create=vi.fn();Object.defineProperty(URL,'createObjectURL',{configurable:true,value:create});
    serve(path=>host(path,platform)??(path.endsWith('/system-binding')?response({version:1,device_id:device,server_url:'https://server.example.test',public_key:'A'.repeat(43)+'=',credential:'must-not-export'}):undefined));
    show();const dialog=await openHost();fireEvent.click(await within(dialog).findByRole('button',{name:platform==='windows'?'Télécharger l’association du collecteur Windows':'Télécharger l’association du collecteur Linux'}));
    expect(await within(dialog).findByRole('alert')).toHaveTextContent(platform==='windows'?'Association du collecteur Windows invalide':'Association du collecteur Linux invalide');expect(create).not.toHaveBeenCalled();
  });
});

describe('Environment evidence and history',()=>{
  const selected={id:'container/fixture',scope:'runtime/fixture',kind:'container',device_id:'device-fixture',display:{name:'Synthetic container'}};
  async function openEnvironment(){
    show();fireEvent.click(screen.getByRole('button',{name:'Environnements'}));
    fireEvent.click(await screen.findByRole('button',{name:'Synthetic container'}));
    const dialog=await screen.findByRole('dialog');
    await within(dialog).findByRole('button',{name:'Preuves'});
    return dialog;
  }
  function environment(path:string){
    if(path.startsWith('/api/discovery/environments?'))return response({items:[selected],next_cursor:''});
    if(path.startsWith('/api/discovery/environments/container%2Ffixture?'))return response(selected);
    return undefined;
  }
  it('loads selected device visibility on demand and preserves its filter across pages',async()=>{
    const fetcher=serve(path=>{
      if(path.startsWith('/api/discovery/coverage?'))return response({items:[{device_id:'device-fixture',adapter:path.includes('cursor=')?'network':'guest-tools',status:'unavailable'}],next_cursor:path.includes('cursor=')?'':'next-coverage'});
      return environment(path);
    });
    const dialog=await openEnvironment();
    expect(await within(dialog).findByText('Visibilité dans cet environnement')).toBeInTheDocument();
    expect(fetcher.mock.calls.some(([input])=>String(input).includes('/api/discovery/coverage'))).toBe(false);
    fireEvent.click(within(dialog).getByRole('button',{name:'Vérifier la visibilité du poste'}));
    expect(await within(dialog).findByText('Accès aux invités')).toBeInTheDocument();
    expect(within(dialog).getByText(/Ils ne certifient pas une visibilité complète/)).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button',{name:'Suivant'}));
    await waitFor(()=>expect(fetcher.mock.calls.some(([input])=>String(input)==='/api/discovery/coverage?device_id=device-fixture&limit=50&cursor=next-coverage')).toBe(true));
    expect(fetcher.mock.calls.filter(([input])=>String(input).includes('/api/discovery/coverage')).every(([input])=>String(input).includes('device_id=device-fixture&limit=50'))).toBe(true);
  });
  it('loads and pages actual proofs within the environment device and source',async()=>{
    const fetcher=serve(path=>{
      if(path.startsWith('/api/discovery/environments/container%2Ffixture/evidence?'))return response({items:[{kind:'identification',id:path.includes('cursor=')?'second':'first',application_id:path.includes('cursor=')?'next-application':'<img src=x onerror=alert(1)>',state:'indication',evidence:[{source:'container_metadata',observed_at:100,fields:['image_repository'],fact_id:'proof/fixture'}]}],next_cursor:path.includes('cursor=')?'':'next-proof'});
      return environment(path);
    });
    const dialog=await openEnvironment();
    fireEvent.click(within(dialog).getByRole('button',{name:'Preuves'}));
    expect(await within(dialog).findByText('Application · <img src=x onerror=alert(1)>')).toBeInTheDocument();
    expect(dialog.querySelector('img')).toBeNull();
    fireEvent.click(within(dialog).getByRole('button',{name:'Suivant'}));
    expect(await within(dialog).findByText('Application · next-application')).toBeInTheDocument();
    expect(fetcher.mock.calls.some(([input])=>String(input).includes('device_id=device-fixture&scope=runtime%2Ffixture&limit=50&cursor=next-proof'))).toBe(true);
  });
  it('loads environment history with all three filters and preserves them across pages',async()=>{
    const fetcher=serve(path=>{
      if(path.startsWith('/api/discovery/events?'))return response({items:[{id:path.includes('cursor=')?'second':'first',kind:path.includes('cursor=')?'provider_contacted':'identified',application_id:'fixture-application',occurred_at:'2026-10-27T00:00:00Z'}],next_cursor:path.includes('cursor=')?'':'next-event'});
      return environment(path);
    });
    const dialog=await openEnvironment();fireEvent.click(within(dialog).getByRole('button',{name:'Historique'}));
    expect(await within(dialog).findByText('fixture-application')).toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button',{name:'Suivant'}));
    await waitFor(()=>expect(fetcher.mock.calls.some(([input])=>String(input).includes('/api/discovery/events?device_id=device-fixture&scope=runtime%2Ffixture&entity_id=container%2Ffixture&limit=50&cursor=next-event'))).toBe(true));
  });
  it.each([false,true])('shows an explicit empty state or error for environment proofs, invalid=%s',async invalid=>{
    serve(path=>path.includes('/evidence?')?response(invalid?{items:{image:'data:image/png'},next_cursor:''}:{items:[],next_cursor:''}):environment(path));
    const dialog=await openEnvironment();fireEvent.click(within(dialog).getByRole('button',{name:'Preuves'}));
    if(invalid)expect(await within(dialog).findByRole('alert')).toBeInTheDocument();
    else expect(await within(dialog).findByText('Aucune preuve disponible pour cette vue.')).toBeInTheDocument();
  });
});

it('loads historical evidence only after the reader expands its timeline entry',async()=>{
  const id='33333333-3333-4333-8333-333333333333';
  const fetcher=serve(path=>{
    if(path.startsWith('/api/discovery/events?'))return response({items:[{id,kind:'identified',application_id:'openclaw',occurred_at:'2026-10-27T00:00:00Z'}],next_cursor:''});
    if(path==='/api/discovery/evidence/'+id)return response({id,evidence:[{source:'container_metadata',fact_id:'proof/synthetic-history',observed_at:100,fields:['image_repository']}]});
    return undefined;
  });
  show();fireEvent.click(await screen.findByRole('button',{name:'OpenClaw'}));
  const dialog=await screen.findByRole('dialog');
  fireEvent.click(await within(dialog).findByRole('button',{name:'Historique'}));
  expect(await within(dialog).findByText('Application identifiée')).toBeInTheDocument();
  expect(fetcher.mock.calls.some(([input])=>String(input).includes('/api/discovery/evidence/'))).toBe(false);
  const details=dialog.querySelector('details.history-proof') as HTMLDetailsElement;
  details.open=true;fireEvent(details,new Event('toggle'));
  expect(await within(dialog).findByText('proof/synthetic-history')).toBeInTheDocument();
  expect(fetcher.mock.calls.filter(([input])=>String(input)==='/api/discovery/evidence/'+id)).toHaveLength(1);
});
