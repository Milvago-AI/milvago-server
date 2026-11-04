import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AIGovernanceDevice, AIGovernancePanel, GovernanceLocation } from './AIGovernance';
import { Context } from './ui';
import type { Session } from './api';
const session:Session={user:{id:'u',email:'owner@example.test',display_name:'Owner'},organization:{id:'o',name:'Fixture',role:'owner'},organizations:[],permissions:['policy.manage','devices.read','discovery.read'],csrf_token:'csrf',edition:'community'};
const reply=(value:unknown,status=200)=>new Response(JSON.stringify(value),{status,headers:{'Content-Type':'application/json'}});
function serve(override:(path:string,init?:RequestInit)=>Response|undefined=()=>undefined){return vi.spyOn(globalThis,'fetch').mockImplementation(async(input,init)=>override(String(input),init)??(String(input).startsWith('/api/ai-governance/history?')?reply({items:[],next_cursor:''}):reply(String(input)==='/api/ai-governance/framework'?{framework:'NIST AI RMF 1.0',controls:[{id:'MEASURE',coverage:'not_covered'}]}:{revision:0,document:{version:1,rules:[]},ancestors:[]})));}
function show(child:React.ReactNode,value=session){return render(<Context.Provider value={{session:value,language:'fr',refreshSession:async()=>undefined}}>{child}</Context.Provider>);}
afterEach(()=>{cleanup();vi.restoreAllMocks();});
describe('NIST AI governance',()=>{
 it('publishes a justified rule with a revision and no implicit blocking',async()=>{
  let saved:Record<string,unknown>|undefined;serve((path,init)=>{
   if(path==='/api/ai-governance/policy'&&init?.method==='PUT'){saved=JSON.parse(String(init.body));return reply({revision:1});}
   if(path==='/api/ai-governance/policy'&&saved)return reply({revision:1,document:saved.document,ancestors:[]});
   if(path.startsWith('/api/ai-governance/history?'))return reply({items:saved?[{id:'decision',action:'ai.governance.publish',created_at:'2026-10-28T00:00:00Z',details:{reason:'Published decision now visible',revision:1}}]:[],next_cursor:''});
  });
  show(<AIGovernancePanel/>);fireEvent.click(await screen.findByRole('button',{name:'Ajouter une règle d’autorisation'}));
  fireEvent.change(screen.getByRole('combobox',{name:/^Application/}),{target:{value:'fixture'}});
  fireEvent.change(screen.getByLabelText('Responsable'),{target:{value:'<img src=x onerror=alert(1)>'}});
  fireEvent.change(screen.getByLabelText('Objectif et conditions'),{target:{value:'Temporary authorized engineering use'}});
  fireEvent.change(screen.getByLabelText('Motif du changement'),{target:{value:'Organization approval for testing'}});
  fireEvent.click(screen.getByRole('checkbox',{name:/Restriction obligatoire/}));
  fireEvent.click(screen.getByRole('button',{name:'Publier la politique'}));
  await waitFor(()=>expect(saved).toBeDefined());
  expect(saved).toMatchObject({revision:0,reason:'Organization approval for testing',document:{version:1,rules:[{application_id:'fixture',scope:'organization',activity:'execution',decision:'deny',mandatory:true,owner:'<img src=x onerror=alert(1)>'}]}});
  expect(screen.getByText(/Elles ne bloquent pas les logiciels/)).toBeInTheDocument();expect(document.querySelector('img')).toBeNull();
  expect(await screen.findByText('Published decision now visible')).toBeInTheDocument();
 });
 it('keeps a failed publication visible without claiming it was saved',async()=>{
  serve((path,init)=>path==='/api/ai-governance/validate'&&init?.method==='POST'?reply({error:'invalid_source',message:'Invalid governance YAML.'},400):undefined);
  show(<AIGovernancePanel/>);await screen.findByRole('button',{name:'Ajouter une règle d’autorisation'});
  fireEvent.click(screen.getByText('Importer un brouillon YAML ou JSON'));fireEvent.change(screen.getByLabelText('YAML / JSON'),{target:{value:'rules: image'}});fireEvent.click(screen.getByRole('button',{name:'Valider sans publier'}));
  expect(await screen.findByRole('alert')).toBeInTheDocument();expect(screen.queryByRole('button',{name:'Utiliser comme brouillon'})).not.toBeInTheDocument();
 });
 it('shows partial and absent framework coverage without a certification claim',async()=>{
  serve();show(<AIGovernancePanel/>);fireEvent.click(await screen.findByText('Couverture NIST et limites'));
  expect(await screen.findByText(/Non évalué par la découverte/)).toBeInTheDocument();expect(screen.getByText(/ne constitue ni une certification/)).toBeInTheDocument();
 });
 it('keeps the current device assessment separate from an exception approval right',async()=>{
  const fetcher=serve(path=>path.startsWith('/api/ai-governance/effective?')?reply({governance:{presence:{status:'allowed',rule_id:'presence',revision:3},execution:{status:'insufficient_evidence',rule_id:'execution',revision:3},evaluated_at:'2026-10-28T00:00:00Z'}}):undefined);
  show(<AIGovernanceDevice device="d" application="fixture"/>);
  expect(await screen.findByText(/Preuves insuffisantes pour cette action/)).toBeInTheDocument();expect(screen.getByText(/Autorisé par la règle actuelle/)).toBeInTheDocument();
  expect(screen.getByRole('link',{name:'Gérer les règles d’autorisation'})).toHaveAttribute('href','#shadow?area=governance');
  expect(screen.queryByText('Exceptions du poste')).not.toBeInTheDocument();expect(fetcher.mock.calls.some(([path])=>String(path).startsWith('/api/ai-governance/exceptions'))).toBe(false);
 });
 it('renders hostile or unknown assessment states as unknown',()=>{
  show(<GovernanceLocation value={{presence:{status:'__proto__'},execution:{status:'<script>alert(1)</script>'}}}/>);expect(document.querySelector('script')).toBeNull();expect(screen.getAllByText(/Non déterminée/)).toHaveLength(2);
 });
 it('rechecks an expired authorization when returning to the view and stops after leaving',async()=>{
  vi.spyOn(document,'visibilityState','get').mockReturnValue('visible');let expired=false;
  const fetcher=serve(path=>path.startsWith('/api/ai-governance/effective?')?reply({governance:{presence:{status:'no_rule'},execution:{status:expired?'deviation':'allowed'},evaluated_at:'2026-10-28T00:00:00Z'}}):undefined);
  const view=show(<AIGovernanceDevice device="d" application="fixture"/>);
  await screen.findByText(/Autorisé par la règle actuelle/);expired=true;fireEvent(window,new Event('focus'));
  await screen.findByText(/Écart observé/);expect(screen.queryByText(/Autorisé par la règle actuelle/)).not.toBeInTheDocument();
  view.unmount();const count=fetcher.mock.calls.length;fireEvent(window,new Event('focus'));await new Promise(resolve=>setTimeout(resolve,0));expect(fetcher.mock.calls.length).toBe(count);
 });
 it('lets a delegated approver approve an applicable exception without publication rights',async()=>{
  let saved:Record<string,unknown>|undefined;
  const fetcher=serve((path,init)=>{
   if(path.startsWith('/api/ai-governance/effective?'))return reply({governance:{presence:{status:'no_rule'},execution:{status:'deviation'},evaluated_at:'2026-10-28T00:00:00Z'}});
   if(path.startsWith('/api/ai-governance/approval-options?'))return reply({revision:9,rules:[{id:'exception-rule',application_id:'fixture',activity:'execution'}]});
   if(path==='/api/ai-governance/exceptions'&&init?.method==='POST'){saved=JSON.parse(String(init.body));return reply({id:'approved'},201);}
   if(path.startsWith('/api/ai-governance/exceptions?'))return reply({items:[]});
  });
  show(<AIGovernanceDevice device="d" application="fixture"/>,{...session,permissions:['discovery.read','devices.read','ai.governance.approve']});
  fireEvent.click(await screen.findByText('Exceptions du poste'));
  fireEvent.change(await screen.findByLabelText('Règle'),{target:{value:'exception-rule'}});
  fireEvent.change(screen.getByLabelText('Motif du changement'),{target:{value:'Approved temporary engineering use'}});
  fireEvent.change(screen.getByLabelText('Valable jusqu’au'),{target:{value:new Date(Date.now()+86400000).toISOString().slice(0,10)}});
  fireEvent.click(screen.getByRole('button',{name:'Approuver l’exception'}));
  await waitFor(()=>expect(saved).toMatchObject({device_id:'d',rule_id:'exception-rule',revision:9,reason:'Approved temporary engineering use'}));
  expect(screen.queryByRole('link',{name:'Gérer les règles d’autorisation'})).not.toBeInTheDocument();
  expect(fetcher.mock.calls.some(([path])=>String(path)==='/api/ai-governance/policy')).toBe(false);
 });
});
