import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AIDeclaredSystems } from './AIDeclaredSystems';
import { Context } from './ui';
import type { Session } from './api';

const session:Session={user:{id:'u',email:'owner@example.test',display_name:'Owner'},organization:{id:'o',name:'Fixture',role:'owner'},organizations:[],permissions:['policy.manage'],csrf_token:'csrf',edition:'community'};
const reply=(value:unknown,status=200)=>new Response(JSON.stringify(value),{status,headers:{'Content-Type':'application/json'}});
const record=()=>({id:'synthetic-use',name:'Synthetic assistant',owner:'Engineering',purpose:'Synthetic documentation assistance',scope:'organization',target_id:'',application_ids:['ollama'],providers:[],models:[],data_categories:[],risk_level:'unassessed',risk_summary:'',safeguards:'',status:'review',review_due:new Date(Date.now()+86400000).toISOString()});
function show(value=session,changed=vi.fn()){return render(<Context.Provider value={{session:value,language:'en',refreshSession:async()=>undefined}}><AIDeclaredSystems changed={changed}/></Context.Provider>);}
beforeEach(()=>{
 Object.defineProperty(HTMLDialogElement.prototype,'showModal',{configurable:true,value(){this.setAttribute('open','');}});
 Object.defineProperty(HTMLDialogElement.prototype,'close',{configurable:true,value(){this.removeAttribute('open');}});
});
afterEach(()=>{cleanup();vi.restoreAllMocks();});

describe('Declared AI systems',()=>{
 it('handles an out-of-range review year without throwing or retaining an invalid date',async()=>{
  vi.spyOn(globalThis,'fetch').mockResolvedValue(reply({revision:0,document:{version:1,systems:[]}}));
  show();fireEvent.click(await screen.findByRole('button',{name:'Declare a use'}));
  const review=await screen.findByLabelText('Review by');
  expect(()=>fireEvent.change(review,{target:{value:'999999-12-31'}})).not.toThrow();
  expect(review).toHaveValue('');
 });
 it('saves business context independently from authorization and collection, with escaped text',async()=>{
  let saved:Record<string,unknown>|undefined;
  const fetcher=vi.spyOn(globalThis,'fetch').mockImplementation(async(input,init)=>{
   expect(String(input)).toBe('/api/ai-governance/systems');
   if(init?.method==='PUT'){saved=JSON.parse(String(init.body));return reply({revision:8,document:saved?.document});}
   return reply(saved?{revision:8,document:saved.document}:{revision:7,document:{version:1,systems:[]}});
  });
  const changed=vi.fn();show(session,changed);
  fireEvent.click(await screen.findByRole('button',{name:'Declare a use'}));
  fireEvent.change(await screen.findByLabelText('Use or system name'),{target:{value:'<img src=x onerror=alert(1)>'}});
  fireEvent.change(screen.getByLabelText('Responsible owner'),{target:{value:'Engineering'}});
  fireEvent.change(screen.getByLabelText('Business purpose'),{target:{value:'Synthetic documentation assistance'}});
  fireEvent.change(screen.getByLabelText(/^Related application identifiers/),{target:{value:'ollama, openclaw'}});
  fireEvent.change(screen.getByLabelText('Provider identifiers'),{target:{value:'openai'}});
  fireEvent.click(screen.getByRole('checkbox',{name:'Internal'}));
  fireEvent.change(screen.getByLabelText('Reason for the change'),{target:{value:'Document an approved business purpose'}});
  fireEvent.click(screen.getByRole('button',{name:'Save registry'}));
  await waitFor(()=>expect(saved).toMatchObject({revision:7,reason:'Document an approved business purpose',document:{version:1,systems:[{name:'<img src=x onerror=alert(1)>',application_ids:['ollama','openclaw'],providers:['openai'],data_categories:['internal'],risk_level:'unassessed',status:'review'}]}}));
  expect(await screen.findByRole('button',{name:'<img src=x onerror=alert(1)>'})).toBeInTheDocument();
  expect(document.querySelector('img')).toBeNull();expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  expect(JSON.stringify(saved)).not.toContain('store_content');expect(JSON.stringify(saved)).not.toContain('rules');
  expect(changed).toHaveBeenCalledOnce();expect(fetcher.mock.calls.filter(([,init])=>init?.method==='PUT')).toHaveLength(1);
 });

 it('retains the draft on a revision conflict',async()=>{
  vi.spyOn(globalThis,'fetch').mockImplementation(async(_input,init)=>init?.method==='PUT'?reply({error:'revision_conflict',message:'Refresh the declared systems registry before saving.'},409):reply({revision:3,document:{version:1,systems:[record()]}}));
  show();fireEvent.click(await screen.findByRole('button',{name:'Synthetic assistant'}));
  fireEvent.change(await screen.findByLabelText('Business purpose'),{target:{value:'Unsaved synthetic purpose'}});
  fireEvent.change(screen.getByLabelText('Reason for the change'),{target:{value:'Revise a business description'}});
  fireEvent.click(screen.getByRole('button',{name:'Save registry'}));
  expect(await screen.findByRole('alert')).toBeInTheDocument();expect(screen.getByDisplayValue('Unsaved synthetic purpose')).toBeInTheDocument();
  expect(screen.getByRole('dialog',{name:'Synthetic assistant'})).toBeInTheDocument();
 });

 it('requires confirmation before deleting and preserves other declarations',async()=>{
  const other={...record(),id:'other-use',name:'Other declared use'};let saved:Record<string,unknown>|undefined;
  vi.spyOn(globalThis,'fetch').mockImplementation(async(_input,init)=>{
   if(init?.method==='PUT'){saved=JSON.parse(String(init.body));return reply({revision:4,document:saved?.document});}
   return reply(saved?{revision:4,document:saved.document}:{revision:3,document:{version:1,systems:[record(),other]}});
  });
  show();fireEvent.click(await screen.findByRole('button',{name:'Synthetic assistant'}));
  await screen.findByLabelText('Business purpose');expect(screen.getByRole('button',{name:'Delete'})).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Reason for the change'),{target:{value:'Retire a duplicate declaration'}});
  fireEvent.click(screen.getByRole('button',{name:'Delete'}));
  expect(saved).toBeUndefined();
  const confirmation=await screen.findByRole('dialog',{name:'Remove declaration?'});
  fireEvent.click(within(confirmation).getByRole('button',{name:'Delete'}));
  await waitFor(()=>expect(saved).toMatchObject({revision:3,document:{version:1,systems:[other]}}));
  expect(await screen.findByRole('button',{name:'Other declared use'})).toBeInTheDocument();
 });

 it('keeps a read-only session from submitting even through a synthetic form event',async()=>{
  const fetcher=vi.spyOn(globalThis,'fetch').mockResolvedValue(reply({revision:3,document:{version:1,systems:[record()]}}));
  show({...session,demo_read_only:true});expect(await screen.findByRole('button',{name:'Declare a use'})).toBeDisabled();
  fireEvent.click(screen.getByRole('button',{name:'Synthetic assistant'}));
  const purpose=await screen.findByLabelText('Business purpose');expect(purpose).toBeDisabled();
  fireEvent.submit(purpose.closest('form')!);
  expect(fetcher.mock.calls.some(([,init])=>init?.method==='PUT')).toBe(false);
 });

 it('filters the list and marks overdue reviews without inferring authorization',async()=>{
  vi.spyOn(globalThis,'fetch').mockResolvedValue(reply({revision:3,document:{version:1,systems:[{...record(),review_due:new Date(Date.now()-86400000).toISOString()},{...record(),id:'other',name:'Different project'}]}}));
  show();expect(await screen.findByText(/Review overdue/)).toBeInTheDocument();
  fireEvent.change(screen.getByRole('searchbox',{name:'Search declared uses'}),{target:{value:'Different'}});
  expect(screen.getByRole('button',{name:'Different project'})).toBeInTheDocument();expect(screen.queryByRole('button',{name:'Synthetic assistant'})).not.toBeInTheDocument();
  fireEvent.change(screen.getByRole('searchbox'),{target:{value:'No matching use'}});expect(screen.getByText('No declared use matches this search.')).toBeInTheDocument();
 });
});
