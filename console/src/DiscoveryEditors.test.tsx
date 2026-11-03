import {useState} from 'react';
import {cleanup,fireEvent,render,screen,waitFor,within} from '@testing-library/react';
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {DiscoveryCondition,DiscoveryEvidence,DiscoverySignature,DiscoverySimulation,discoveryCatalogDiff} from './DiscoveryEditors';
import {Context} from './ui';
import type {Session} from './api';
import type {ReactNode} from 'react';
const session:Session={user:{id:'user',email:'user@example.test',display_name:'User'},organization:{id:'org',name:'Fixture',role:'admin'},organizations:[],permissions:[],csrf_token:'fixture',edition:'community'};
const signature={id:'fixture.rule',application_id:'hermes',name:'Hermes',revision:4,sources:['guest_process'],state:'executed',condition:{op:'all',args:[{op:'in',field:'executable',values:['python3','python']},{op:'not',arg:{op:'eq',field:'argument_token',value:'other'}}]},provenance:'Fixture rationale'};
function show(children:ReactNode){return render(<Context.Provider value={{session,language:'fr',refreshSession:async()=>undefined}}>{children}</Context.Provider>);}
beforeEach(()=>{Object.defineProperty(HTMLDialogElement.prototype,'showModal',{configurable:true,value(){this.setAttribute('open','');}});Object.defineProperty(HTMLDialogElement.prototype,'close',{configurable:true,value(){this.removeAttribute('open');}});});
afterEach(()=>{cleanup();vi.restoreAllMocks();});
describe('Discovery evidence and catalogue editors',()=>{
  it('explains HTTP responses read inside a VM without inventing execution or provider contact',()=>{
    show(<DiscoveryEvidence value={{from:'vm/fixture',to:'endpoint/fixture',source:'guest-channel-http-connection',raw_body:'PRIVATE_FIXTURE'}}/>);
    expect(screen.getByText('Réponse HTTP de la VM via l’accès invité autorisé')).toBeInTheDocument();
    expect(screen.getByText('vm/fixture → endpoint/fixture')).toBeInTheDocument();
    expect(screen.queryByText('guest-channel-http-connection')).not.toBeInTheDocument();
    expect(screen.queryByText('Exécution observée')).not.toBeInTheDocument();
    expect(screen.queryByText(/Connexion à un fournisseur observée/)).not.toBeInTheDocument();
    expect(screen.queryByText('PRIVATE_FIXTURE')).not.toBeInTheDocument();
  });

  it('labels saturated simulations as partial while preserving positive results',()=>{
    show(<DiscoverySimulation value={{saturated:true,identifications:[{application_id:'fixture',entity_id:'process/fixture',state:'executed',evidence:[]}],communications:[]}}/>);
    expect(screen.getByText(/Ces résultats sont partiels/)).toBeInTheDocument();
    expect(screen.getByText('fixture · Exécution observée')).toBeInTheDocument();
    expect(screen.getByText('Identifications dans cet exemple: 1')).toBeInTheDocument();
  });

  it('handles a non-list response group without treating an image string as conditions',()=>{
    const change=vi.fn();show(<DiscoveryCondition value={{op:'all_http_responses',args:'data:image/png;base64,fixture'}} change={change}/>);
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button',{name:'Ajouter une condition'}));
    expect(change).toHaveBeenCalledWith({op:'all_http_responses',args:[{op:'all',args:[{op:'eq',field:'http_path',value:'/change-me'},{op:'eq',field:'http_status',value:'200'},{op:'contains',field:'http_body',value:''}]}]});
  });
  it('edits correlated responses with a root-only operator and two mandatory groups',()=>{
    function Editor(){const [value,setValue]=useState<Record<string,unknown>>({op:'eq',field:'http_body',value:'fixture'});return <><DiscoveryCondition value={value} change={setValue}/><output>{JSON.stringify(value)}</output></>;}
    show(<Editor/>);
    fireEvent.change(screen.getByRole('combobox',{name:'Comparaison'}),{target:{value:'all_http_responses'}});
    expect(screen.getByText(/Exige 2 à 8 chemins distincts/)).toBeInTheDocument();
    expect(screen.getAllByRole('option',{name:'Toutes les réponses HTTP'})).toHaveLength(1);
    const output=()=>JSON.parse(document.querySelector('output')!.textContent!);
    expect(output().args.map((group:{args:{value:string}[]})=>group.args[0].value)).toEqual(['/','/health']);
    const outer=document.querySelector('fieldset')!;
    const directButtons=()=>Array.from(outer.children).filter(child=>child.tagName==='BUTTON') as HTMLButtonElement[];
    fireEvent.click(directButtons()[0]);
    expect(output().args).toHaveLength(3);
    const group=Array.from(outer.children).find(child=>child.tagName==='DIV')!;
    const values=within(group as HTMLElement).getAllByRole('textbox',{name:'Valeur'});
    fireEvent.change(values[2],{target:{value:'alpha'}});
    expect(output().args[0].args[2].value).toBe('alpha');
    expect(output().args[1].args[0].value).toBe('/health');
  });
  it('explains a DNS hint when opening its activity evidence',()=>{
    show(<DiscoveryEvidence value={{provider:'openai',evidence:{source:'host_dns_query',observed_at:100,fields:['remote_host'],fact_id:'fact/dns'}}}/>);
    expect(screen.getByText('Requête DNS du poste')).toBeInTheDocument();
    expect(screen.getByText(/Elle ne prouve ni une connexion HTTPS/)).toBeInTheDocument();
    expect(screen.getByText('openai')).toBeInTheDocument();
  });
  it('shows DNS queries as hints without inventing a provider contact or application',()=>{
    show(<DiscoverySimulation value={{identifications:[],communications:[],queries:[{entity_id:'host/fixture',provider:'openai',evidence:{source:'host_dns_query',observed_at:100,fields:['remote_host'],raw:'PRIVATE_FIXTURE'}}]}}/>);
    expect(screen.getByText('Domaine fournisseur recherché · openai')).toBeInTheDocument();
    expect(screen.getByText('Requête DNS du poste')).toBeInTheDocument();
    expect(screen.getByText(/Elle ne prouve ni une connexion HTTPS/)).toBeInTheDocument();
    expect(screen.queryByText(/Connexion à un fournisseur observée/)).not.toBeInTheDocument();
    expect(screen.queryByText(/PRIVATE_FIXTURE/)).not.toBeInTheDocument();
    expect(screen.getByText('Identifications dans cet exemple: 0')).toBeInTheDocument();
  });
  it('distinguishes a runtime publication claim from an observed local socket',()=>{
    show(<DiscoveryEvidence value={[{from:'container/fixture',to:'endpoint/fixture',source:'container-api-publication'},{from:'process/fixture',to:'endpoint/fixture',source:'socket-map'}]}/>);
    expect(screen.getByText('Publication déclarée par le moteur de conteneurs')).toBeInTheDocument();
    expect(screen.getByText('Inventaire local des sockets')).toBeInTheDocument();
  });
  it('treats inherited object property names as unrecognized proof labels',()=>{
    show(<DiscoverySimulation value={{identifications:[{application_id:'fixture',entity_id:'process/fixture',state:'__proto__',evidence:[{source:'constructor',fields:['toString','__proto__'],fact_id:'fact/fixture'}]}],communications:[]}}/>);
    expect(screen.getByText('fixture · __proto__')).toBeInTheDocument();
    expect(screen.getByText('constructor')).toBeInTheDocument();
    expect(screen.getByText('toString, __proto__')).toBeInTheDocument();
  });
  it('unwraps a provider event without losing its VM scope or rendering raw payloads',()=>{
    show(<DiscoveryEvidence value={{provider:'openai',evidence:{source:'vm_flow',fields:['remote_host'],fact_id:'fact/vm',observed_at:1792972800,raw_body:'PRIVATE_PROMPT'},raw_body:'PRIVATE_OUTER'}}/>);
    expect(screen.getByText('openai')).toBeInTheDocument();expect(screen.getByText('fact/vm')).toBeInTheDocument();expect(screen.getByText('Hôte distant')).toBeInTheDocument();expect(screen.getByText('Connexion de la VM')).toBeInTheDocument();expect(screen.queryByText(/PRIVATE/)).not.toBeInTheDocument();
  });
  it('renders proof metadata with readable fields and never dumps unknown payloads',()=>{
    show(<DiscoveryEvidence value={[{source:'guest_process',observed_at:1792972800,fields:['executable','argument_token'],fact_id:'fact/fixture',raw_body:'PRIVATE_PROMPT'}]}/>);
    expect(screen.getByText('Processus invité')).toBeInTheDocument();expect(screen.getByText('Nom de l’exécutable, Point d’entrée de l’application')).toBeInTheDocument();expect(screen.getByText('fact/fixture')).toBeInTheDocument();expect(screen.queryByText(/PRIVATE_PROMPT/)).not.toBeInTheDocument();expect(document.querySelector('pre')).toBeNull();
  });
  it('handles absent, malformed and out-of-range evidence dates without a crash',()=>{
    const view=show(<DiscoveryEvidence value="data:image/png"/>);expect(screen.getByText(/Aucune preuve disponible/)).toBeInTheDocument();
    view.rerender(<Context.Provider value={{session,language:'fr',refreshSession:async()=>undefined}}><DiscoveryEvidence value={[{source:'http',observed_at:1e100,fields:[]}]} /></Context.Provider>);expect(screen.getByText('Interface reconnue')).toBeInTheDocument();
  });
  it('keeps network-only simulation results separate from application matches',()=>{
    show(<DiscoverySimulation value={{identifications:[],communications:[{entity_id:'vm/fixture',provider:'openai',evidence:{source:'vm_flow',observed_at:100,fields:['remote_host']}}]}}/>);
    expect(screen.getByText('Identifications dans cet exemple: 0')).toBeInTheDocument();expect(screen.getByText('Connexion à un fournisseur observée · openai')).toBeInTheDocument();expect(screen.queryByText('OpenClaw')).not.toBeInTheDocument();
  });
  it('preserves every nested condition and signature attribute when renaming',async()=>{
    const save=vi.fn();show(<DiscoverySignature initial={signature} save={save} remove={vi.fn()} close={vi.fn()}/>);
    const dialog=await screen.findByRole('dialog');const name=await within(dialog).findByRole('textbox',{name:'Nom'});fireEvent.change(name,{target:{value:'Hermes verified'}});fireEvent.click(within(dialog).getByRole('button',{name:'Enregistrer'}));
    expect(within(dialog).getAllByRole('checkbox')).toHaveLength(6);
    expect(within(dialog).queryByRole('checkbox',{name:'Publication déclarée par le moteur de conteneurs'})).not.toBeInTheDocument();
    expect(save).toHaveBeenCalledWith({...signature,name:'Hermes verified',revision:5});
  });
  it('edits one nested predicate while keeping its siblings and negation',()=>{
    function Editor(){const [value,setValue]=useState<Record<string,unknown>>(signature.condition);return <><DiscoveryCondition value={value} change={setValue}/><output>{JSON.stringify(value)}</output></>;}
    show(<Editor/>);const field=screen.getByRole('textbox',{name:'Valeur'});fireEvent.change(field,{target:{value:'hermes_cli.main'}});
    expect(JSON.parse(document.querySelector('output')!.textContent!)).toEqual({...signature.condition,args:[signature.condition.args[0],{op:'not',arg:{op:'eq',field:'argument_token',value:'hermes_cli.main'}}]});
  });
  it('previews added, removed and changed signatures without treating key order as a change',()=>{
    const reordered=Object.fromEntries(Object.entries(signature).reverse());expect(discoveryCatalogDiff([signature],[reordered])).toEqual({added:[],changed:[],removed:[]});
    const changed={...signature,name:'Changed'};const added={...signature,id:'new.rule'};const removed={...signature,id:'removed.rule'};
    expect(discoveryCatalogDiff([signature,removed],[changed,added])).toEqual({added:[added],changed:[changed],removed:[removed]});
  });
  it('asks before discarding an edited signature',async()=>{
    const close=vi.fn();show(<DiscoverySignature initial={signature} save={vi.fn()} remove={vi.fn()} close={close}/>);const dialog=await screen.findByRole('dialog');
    fireEvent.change(await within(dialog).findByRole('textbox',{name:'Nom'}),{target:{value:'Changed'}});fireEvent.click(within(dialog).getAllByRole('button',{name:'Fermer'})[0]);
    await waitFor(()=>expect(screen.getAllByRole('dialog')).toHaveLength(2));expect(close).not.toHaveBeenCalled();
  });
});
