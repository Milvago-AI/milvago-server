import { TargetPicker } from './TargetPicker';
import { ScopeEditor } from './ScopeEditor';
import { ExpressionEditor } from './ExpressionEditor';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import type { Session } from '../api';
import { Context } from '../ui';
import { DlpPage } from './DlpPage';
import { DlpDecisionList } from './DlpDecisions';
import type { DlpSettings } from './types';

const requests = vi.hoisted(() => [] as unknown[]);
vi.mock('./engine', async () => {
  const { readFileSync } = await import('node:fs');
  const module = await WebAssembly.compile(readFileSync('public/dlp_engine.wasm'));
  return { createDlpEngine: () => ({ close: vi.fn(), call: async (request: unknown) => {
    requests.push(request);
    const instance = await WebAssembly.instantiate(module, {});
    const exports = instance.exports as unknown as { memory: WebAssembly.Memory; dlp_alloc: (size: number) => number; dlp_call: (pointer: number, size: number) => bigint; dlp_free: (pointer: number, size: number) => void };
    const input = new TextEncoder().encode(JSON.stringify(request)); const pointer = exports.dlp_alloc(input.length);
    new Uint8Array(exports.memory.buffer, pointer, input.length).set(input);
    const packed = exports.dlp_call(pointer, input.length); const address = Number(packed & 0xffffffffn); const length = Number(packed >> 32n);
    const result = JSON.parse(new TextDecoder().decode(new Uint8Array(exports.memory.buffer, address, length)));
    exports.dlp_free(address, length);
    if (!result.ok) throw new Error(result.error);
    return result;
  } }) };
});

const session: Session = { user: { id: 'fixture-user', email: 'fixture@example.invalid', display_name: 'Fixture' }, organization: { id: 'fixture-org', name: 'Fixture organization', role: 'owner' }, organizations: [], permissions: ['policy.manage', 'events.read'], csrf_token: 'fixture-csrf', edition: 'community' };
const settings: DlpSettings = { revision: 1, inherited: false, fingerprint: 'a'.repeat(64), capabilities: { native: false, mcp: false, builtins: false }, policy: { schema_version: 1, domain: 'endpoint', inspection: true, native_inspection: false, journal: true, detectors: [], rules: [{ id: 'fixture-rule', revision: 1, name: 'Example rule', mode: 'simulation', priority: 100, condition: { op: 'contains', field: 'prompt', value: 'Tomate', ignore_case: false, whole_word: false }, scope: { op: 'eq', field: 'channel', value: 'browser' }, consequence: { action: 'replace', value: 'Tomate', replacement: 'Carotte', ignore_case: false, whole_word: false }, review: false, message: '' }] } };
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
function show(current = session) { return render(<Context.Provider value={{ session: current, language: 'en', refreshSession: async () => {} }}><DlpPage /></Context.Provider>); }
beforeEach(() => {
 requests.length = 0; location.hash = '#dlp';
 Object.defineProperty(HTMLDialogElement.prototype,'showModal',{configurable:true,value(){this.setAttribute('open','');}});
 Object.defineProperty(HTMLDialogElement.prototype,'close',{configurable:true,value(){this.removeAttribute('open');}});
});


function mockPolicy(initial:DlpSettings=settings,conflict=false){
 let current=structuredClone(initial);
 return vi.spyOn(globalThis,'fetch').mockImplementation(async(_url,init)=>{
  if(init?.method==='PUT'){
   if(conflict)return response({code:'revision_conflict',message:'Configuration changed; reload before saving.'},409);
   const body=JSON.parse(String(init.body));current={...current,...body,revision:current.revision+1};return response(current);
  }
  return response(current);
 });
}
async function openExample(){fireEvent.click(await screen.findByRole('button',{name:'Example rule'}));return await screen.findByLabelText('Rule name');}

it('starts with a searchable rule list and opens a right-hand editor with split selected and icon controls',async()=>{
 mockPolicy();show();await screen.findByRole('button',{name:'Example rule'});
 expect(screen.queryByLabelText('Rule name')).toBeNull();
 expect(screen.queryByText('Milvago outputs · REST and MCP')).toBeNull();
 expect(screen.getByPlaceholderText('Search rules by name, mode or action…')).toBeVisible();
 await openExample();expect(screen.getByRole('dialog')).toHaveClass('drawer');
 expect(screen.getByRole('button',{name:'Side by side'})).toHaveAttribute('aria-pressed','true');
 expect(screen.getByRole('button',{name:'Language'})).toHaveAttribute('title','Language');
 expect(screen.getByText('On the Web')).toBeVisible();expect(screen.queryByText('browser')).toBeNull();
 expect(screen.getAllByText('Organization · Fixture organization')[0]).toBeVisible();
});

it('filters rules by translated action and opens a new draft without inserting it before save',async()=>{
 mockPolicy();show();await screen.findByRole('button',{name:'Example rule'});
 const search=screen.getByPlaceholderText('Search rules by name, mode or action…');
 fireEvent.change(search,{target:{value:'missing'}});expect(screen.queryByRole('button',{name:'Example rule'})).toBeNull();
 fireEvent.change(search,{target:{value:'replace'}});expect(screen.getByRole('button',{name:'Example rule'})).toBeVisible();
 fireEvent.click(screen.getByRole('button',{name:'New rule'}));expect(await screen.findByLabelText('Rule name')).toHaveValue('New rule');
 expect(screen.getByText('1 objects')).toBeVisible();
});

it('saves an explicit device-group application with the rule while preserving the language model',async()=>{
 const fetch=mockPolicy();show();const name=await openExample();
 fireEvent.change(name,{target:{value:'Scoped rule'}});
 fireEvent.change(screen.getByLabelText('Applies to'),{target:{value:'groups'}});
 fireEvent.click(screen.getByRole('button',{name:/Device groups Select one/}));
 const targetSearch=await screen.findByRole('combobox',{name:'Enter a target UUID…'});
 for(const id of ['11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222']){fireEvent.change(targetSearch,{target:{value:id}});fireEvent.keyDown(targetSearch,{key:'Enter'});}
 fireEvent.keyDown(targetSearch,{key:'Escape'});
 await waitFor(()=>expect((screen.getByLabelText('DLP rule source') as HTMLTextAreaElement).value).toContain('WHEN'));
 fireEvent.click(screen.getByRole('button',{name:'Save changes'}));
 await waitFor(()=>expect(screen.queryByRole('dialog')).toBeNull());
 const call=fetch.mock.calls.find(([,init])=>init?.method==='PUT')!;const body=JSON.parse(String(call[1]?.body));
 expect(body.policy.rules[0].application).toEqual({kind:'groups',ids:['11111111-1111-4111-8111-111111111111','22222222-2222-4222-8222-222222222222']});
 expect(await screen.findByRole('button',{name:'Scoped rule'})).toBeVisible();
});

it('preserves conflicting and invalid object drafts instead of saving another rule',async()=>{
 mockPolicy(settings,true);show();fireEvent.change(await openExample(),{target:{value:'Changed name'}});
 await waitFor(()=>expect((screen.getByLabelText('DLP rule source') as HTMLTextAreaElement).value).toContain('WHEN'));
 fireEvent.click(screen.getByRole('button',{name:'Save changes'}));
 await screen.findAllByText('Configuration changed; reload before saving.');expect(screen.getByLabelText('Rule name')).toHaveValue('Changed name');
 fireEvent.change(screen.getByLabelText('DLP rule source'),{target:{value:'WHEN image CONTAINS 42'}});
 await screen.findAllByRole('alert');expect(screen.getByRole('button',{name:'Save changes'})).toBeDisabled();
});

it('guards closing an edited object and supports both keeping and discarding the draft',async()=>{
 mockPolicy();show();fireEvent.change(await openExample(),{target:{value:'Unsaved name'}});
 fireEvent.click(screen.getAllByRole('button',{name:'Close'})[0]);
 await screen.findByRole('dialog',{name:'Discard changes?'});
 fireEvent.click(screen.getByRole('button',{name:'Keep editing'}));expect(screen.getByLabelText('Rule name')).toHaveValue('Unsaved name');
 fireEvent.click(screen.getAllByRole('button',{name:'Close'})[0]);fireEvent.click(await screen.findByRole('button',{name:'Discard and close'}));
 await waitFor(()=>expect(screen.queryByRole('dialog')).toBeNull());expect(screen.getByRole('button',{name:'Example rule'})).toBeVisible();
});

it('separates dictionaries from detectors and reuses a saved dictionary in a custom detector',async()=>{
 const fetch=mockPolicy();show();await screen.findByRole('button',{name:'Example rule'});
 fireEvent.click(screen.getByRole('button',{name:'Dictionaries'}));fireEvent.click(screen.getByRole('button',{name:'New dictionary'}));
 fireEvent.change(await screen.findByLabelText('Dictionary name'),{target:{value:'Project terms'}});
 expect(screen.queryByLabelText('Exceptions')).toBeNull();
 fireEvent.change(screen.getByLabelText('Phrases · one per line'),{target:{value:'ProjectOne\nProjectTwo'}});
 fireEvent.click(screen.getByRole('button',{name:'Save changes'}));await waitFor(()=>expect(screen.queryByRole('dialog')).toBeNull());
 expect(screen.getByRole('button',{name:'Project terms'})).toBeVisible();
 fireEvent.click(screen.getByRole('button',{name:'Detectors'}));expect(screen.queryByRole('button',{name:'Project terms'})).toBeNull();
 fireEvent.click(screen.getByRole('button',{name:'New detector'}));fireEvent.change(await screen.findByLabelText('Detector name'),{target:{value:'Project detector'}});
 fireEvent.change(screen.getByLabelText('Detector type'),{target:{value:'keyword_tier'}});
 fireEvent.click(screen.getByRole('button',{name:'Save changes'}));await waitFor(()=>expect(screen.queryByRole('dialog')).toBeNull());
 const calls=fetch.mock.calls.filter(([,init])=>init?.method==='PUT');const body=JSON.parse(String(calls[1][1]?.body));
 expect(body.policy.detectors[1].definition.dictionary).toBe(body.policy.detectors[0].id);
 expect(screen.getByRole('button',{name:'Project detector'})).toBeVisible();
});

it('keeps predefined Enterprise detectors read-only with explicit country names',async()=>{
 const enterprise={...settings,capabilities:{...settings.capabilities,builtins:true,native:true},policy:{...settings.policy,detectors:[{id:'builtin-ca_sin',name:'Canadian Social Insurance Number (SIN)',definition:{kind:'builtin',category:'ca_sin'}}]}} as DlpSettings;
 mockPolicy(enterprise);show({...session,edition:'commercial'});await screen.findByRole('button',{name:'Example rule'});fireEvent.click(screen.getByRole('button',{name:'Detectors'}));
 fireEvent.click(screen.getByRole('button',{name:'Canada · Social Insurance Number (SIN)'}));
 expect(await screen.findByLabelText('Detector name')).toBeDisabled();expect(screen.queryByRole('button',{name:'Delete detector'})).toBeNull();
 expect(screen.queryByRole('heading',{name:'Usage sensitivity'})).toBeNull();
});

it('keeps demonstration forms inert and historical attribution independent of live names',async()=>{
 const fetch=mockPolicy();show({...session,demo_read_only:true});await openExample();
 expect(screen.getByLabelText('Rule name')).toBeDisabled();expect(screen.getByRole('button',{name:'Save changes'})).toBeDisabled();
 expect(fetch.mock.calls.some(([,init])=>init?.method==='PUT')).toBe(false);
 render(<Context.Provider value={{session,language:'en',refreshSession:async()=>{}}}><DlpDecisionList decisions={[{rule_id:'deleted-rule',rule_revision:3,rule_name:'Historical rule',mode:'active',consequence:'block',condition:'true',scope:'true',outcome:'blocked',occurrences:1}]}/></Context.Provider>);
 expect(screen.getByText('Historical rule')).toBeVisible();expect(screen.getByText(/Active · Block/)).toBeVisible();
});

it('combines AI services and browsers and never turns an empty explicit selection into all services',()=>{
 let value:any={op:'eq',field:'channel',value:'browser'};
 const options={browsers:[{id:'chrome',label:'Chrome'},{id:'firefox',label:'Firefox'}],services:[{id:'chatgpt',label:'ChatGPT'},{id:'claude',label:'Claude'}],applications:[{id:'synthetic-local',label:'Synthetic local AI'}]};
 const wrapper=(scope:any)=><Context.Provider value={{session,language:'en',refreshSession:async()=>{}}}><ScopeEditor value={scope} change={next=>{value=next;}} options={options} advanced={()=>{}}/></Context.Provider>;
 const view=render(wrapper(value));fireEvent.click(screen.getByLabelText('ChatGPT'));view.rerender(wrapper(value));
 fireEvent.click(screen.getByLabelText('Firefox'));view.rerender(wrapper(value));
 expect(value.children).toEqual(expect.arrayContaining([{op:'in',field:'provider',values:['chatgpt']},{op:'in',field:'tool',values:['firefox']}]));
 fireEvent.click(screen.getByLabelText('ChatGPT'));view.rerender(wrapper(value));
 expect(value.children).toContainEqual({op:'in',field:'provider',values:[]});expect(screen.getByLabelText('All supported AI websites')).not.toBeChecked();
 expect(screen.getByText('Select at least one item or choose all.')).toBeVisible();
 fireEvent.click(screen.getByLabelText('In a local application'));view.rerender(wrapper(value));expect(screen.getByText('Synthetic local AI')).toBeVisible();
});

it('preserves advanced scopes until an explicit edit and preserves nested XOR in the advanced editor',()=>{
 const change=vi.fn(),advanced=vi.fn();
 render(<Context.Provider value={{session,language:'en',refreshSession:async()=>{}}}><ScopeEditor value={{op:'not',child:{op:'eq',field:'model',value:'synthetic-model'}}} change={change} advanced={advanced}/><ExpressionEditor value={{op:'one',children:[{op:'true'},{op:'true'}]}} change={()=>{}} scope field="prompt" detectors={[]} depth={6}/></Context.Provider>);
 expect(change).not.toHaveBeenCalled();fireEvent.click(screen.getByRole('button',{name:'Language'}));expect(advanced).toHaveBeenCalledOnce();
 expect(screen.getAllByRole('combobox')[0]).toHaveValue('one');
});

it('starts Community with an empty detector list and never inserts predefined items',async()=>{
 const fetch=mockPolicy();show();await screen.findByRole('button',{name:'Example rule'});
 fireEvent.click(screen.getByRole('button',{name:'Detectors'}));expect(screen.getByText('0 objects')).toBeVisible();
 expect(screen.queryByText('Email address')).toBeNull();fireEvent.click(screen.getByRole('button',{name:'New detector'}));
 expect(await screen.findByLabelText('Detector type')).toHaveValue('literal');
 expect(screen.queryByRole('option',{name:'Built-in detector'})).toBeNull();
 expect(fetch.mock.calls.some(([,init])=>init?.method==='PUT')).toBe(false);
});

it('evaluates samples locally, previews simulation without changing policy, and clears stale results',async()=>{
 const fetch=mockPolicy();show();await screen.findByRole('button',{name:'Example rule'});
 fireEvent.click(screen.getByRole('button',{name:'Laboratory'}));fireEvent.change(screen.getByLabelText('Original text'),{target:{value:'Tomate'}});
 fireEvent.click(screen.getByRole('button',{name:'Run simulation'}));await screen.findByText('Carotte',{exact:true});
 expect(requests.filter((r:any)=>r.op==='evaluate').map((r:any)=>r.input.policy.rules[0].mode)).toEqual(['simulation','active']);
 expect(fetch.mock.calls.every(([,init])=>!init?.method||init.method==='GET')).toBe(true);
 fireEvent.change(screen.getByLabelText('Original text'),{target:{value:'Other sample'}});expect(screen.queryByText('Carotte',{exact:true})).toBeNull();
});

it('searches within the multi-select dropdown and retains selections while filtering and reopening',async()=>{
 let current=structuredClone(settings);const groups=[{id:'11111111-1111-4111-8111-111111111111',name:'Synthetic Alpha'},{id:'22222222-2222-4222-8222-222222222222',name:'Synthetic Beta'}];
 const fetch=vi.spyOn(globalThis,'fetch').mockImplementation(async(url,init)=>{
  if(String(url)==='/api/groups')return response({items:groups});
  if(init?.method==='PUT'){const body=JSON.parse(String(init.body));current={...current,...body,revision:2};return response(current);}return response(current);
 });
 show({...session,permissions:[...session.permissions,'devices.read']});await openExample();fireEvent.change(screen.getByLabelText('Applies to'),{target:{value:'groups'}});
 expect(screen.queryByRole('combobox',{name:'Search this list by name…'})).toBeNull();
 fireEvent.click(screen.getByRole('button',{name:/Device groups Select one/}));
 fireEvent.click(await screen.findByRole('option',{name:'Synthetic Alpha'}));
 const search=screen.getByRole('combobox',{name:'Search this list by name…'});fireEvent.change(search,{target:{value:'Beta'}});
 expect(screen.queryByRole('option',{name:'Synthetic Alpha'})).toBeNull();fireEvent.click(screen.getByRole('option',{name:'Synthetic Beta'}));
 fireEvent.keyDown(search,{key:'Escape'});expect(screen.getByLabelText('Rule name')).toBeVisible();expect(screen.getByRole('button',{name:/Device groups Selected: 2/})).toBeVisible();
 fireEvent.click(screen.getByRole('button',{name:/Device groups Selected: 2/}));expect(await screen.findByRole('option',{name:'Synthetic Alpha'})).toHaveAttribute('aria-selected','true');expect(screen.getByRole('option',{name:'Synthetic Beta'})).toHaveAttribute('aria-selected','true');
 fireEvent.click(screen.getByRole('button',{name:'Clear selection'}));fireEvent.keyDown(screen.getByRole('combobox',{name:'Search this list by name…'}),{key:'Escape'});
 fireEvent.click(screen.getByRole('button',{name:'Save changes'}));await screen.findAllByText(/Choose 1 to 128 rule targets/);expect(fetch.mock.calls.some(([,init])=>init?.method==='PUT')).toBe(false);
});

it('keeps device selections across pages and a debounced name search without widening the target',async()=>{
 const first={id:'11111111-1111-4111-8111-111111111111',hostname:'Synthetic first'},second={id:'22222222-2222-4222-8222-222222222222',hostname:'Synthetic second'};
 const fetch=vi.spyOn(globalThis,'fetch').mockImplementation(async(url)=>{const request=new URL(String(url),'https://fixture.invalid');return response({items:request.searchParams.get('query')==='second'||request.searchParams.get('offset')==='50'?[second]:[first],total:request.searchParams.get('query')?1:51});});
 let value:any={kind:'devices',ids:[]};const current={...session,permissions:[...session.permissions,'devices.read']};
 const wrapper=()=><Context.Provider value={{session:current,language:'en',refreshSession:async()=>{}}}><TargetPicker value={value} change={next=>{value=next;view.rerender(wrapper());}}/></Context.Provider>;
 const view=render(wrapper());fireEvent.click(screen.getByRole('button',{name:/Devices Select one/}));
 fireEvent.click(await screen.findByRole('option',{name:'Synthetic first'}));fireEvent.click(screen.getByRole('button',{name:'Next'}));
 fireEvent.click(await screen.findByRole('option',{name:'Synthetic second'}));expect(value).toEqual({kind:'devices',ids:[first.id,second.id]});
 const search=screen.getByRole('combobox',{name:'Search this list by name…'});fireEvent.change(search,{target:{value:'second'}});
 await waitFor(()=>expect(screen.getByRole('option',{name:'Synthetic second'})).toHaveAttribute('aria-selected','true'));
 expect(fetch.mock.calls.some(([url])=>String(url).includes('offset=0&query=second'))).toBe(true);
 expect(screen.getByRole('button',{name:'Next'})).toBeDisabled();fireEvent.keyDown(search,{key:'Enter'});expect(value.ids).toEqual([first.id]);
 fireEvent.keyDown(search,{key:'Escape'});expect(screen.getByRole('button',{name:/Devices Selected: 1/})).toHaveAttribute('aria-expanded','false');
});

it('displays deployment device names from the authorized status projection',async()=>{
 vi.spyOn(globalThis,'fetch').mockImplementation(async(url)=>response(String(url).startsWith('/api/dlp/status')?{items:[{device_id:'11111111-1111-4111-8111-111111111111',hostname:'Synthetic workstation',channel:'browser',status:'pending',expected_fingerprint:'a'.repeat(64),applied_fingerprint:''}],counts:{pending:1}}:settings));
 show();await screen.findByRole('button',{name:'Example rule'});fireEvent.click(screen.getByRole('button',{name:'Deployment'}));
 expect(await screen.findByRole('cell',{name:'Synthetic workstation'})).toBeVisible();expect(screen.queryByRole('cell',{name:'11111111-1111-4111-8111-111111111111'})).toBeNull();
});

it('activates and disables a retained rule directly without opening its editor',async()=>{
 const fetch=mockPolicy();show();await screen.findByRole('button',{name:'Example rule'});
 fireEvent.click(screen.getByRole('button',{name:'Disable rule: Example rule'}));await screen.findByRole('button',{name:'Activate rule: Example rule'});
 expect(screen.queryByRole('dialog')).toBeNull();
 fireEvent.click(screen.getByRole('button',{name:'Activate rule: Example rule'}));await screen.findByRole('button',{name:'Disable rule: Example rule'});
 const writes=fetch.mock.calls.filter(([,init])=>init?.method==='PUT');expect(writes).toHaveLength(2);
 expect(JSON.parse(String(writes[0][1]?.body)).policy.rules[0].mode).toBe('disabled');expect(JSON.parse(String(writes[1][1]?.body)).policy.rules[0]).toEqual({...settings.policy.rules[0],mode:'active'});
 expect(screen.queryByRole('dialog')).toBeNull();
});

it('retains a disabled rule when activation is refused by the server',async()=>{
 mockPolicy({...settings,policy:{...settings.policy,rules:[{...settings.policy.rules[0],mode:'disabled'}]}},true);show();
 fireEvent.click(await screen.findByRole('button',{name:'Activate rule: Example rule'}));await screen.findAllByText('Configuration changed; reload before saving.');
 expect(screen.getByRole('button',{name:'Activate rule: Example rule'})).toBeEnabled();expect(screen.queryByRole('dialog')).toBeNull();
});

it('shows removable named target tags outside the closed menu and preserves a deliberate empty selection',async()=>{
 const groups=[{id:'11111111-1111-4111-8111-111111111111',name:'Synthetic Alpha'},{id:'22222222-2222-4222-8222-222222222222',name:'Synthetic Beta'}];
 vi.spyOn(globalThis,'fetch').mockImplementation(async()=>response({items:groups}));
 let value:any={kind:'groups',ids:groups.map(g=>g.id)};const current={...session,permissions:[...session.permissions,'devices.read']};
 const wrapper=()=><Context.Provider value={{session:current,language:'en',refreshSession:async()=>{}}}><TargetPicker value={value} change={next=>{value=next;view.rerender(wrapper());}}/></Context.Provider>;
 const view=render(wrapper());expect(screen.queryByRole('dialog')).toBeNull();
 expect(await screen.findByRole('button',{name:'Remove Synthetic Alpha'})).toBeVisible();expect(screen.getByRole('list',{name:'Selected groups or devices'})).toHaveTextContent('Synthetic Beta');
 fireEvent.click(screen.getByRole('button',{name:'Remove Synthetic Alpha'}));expect(value.ids).toEqual([groups[1].id]);expect(screen.queryByRole('button',{name:'Remove Synthetic Alpha'})).toBeNull();
 fireEvent.click(screen.getByRole('button',{name:'Remove Synthetic Beta'}));expect(value).toEqual({kind:'groups',ids:[]});expect(screen.queryByRole('list')).toBeNull();
});

it('uses identifiers in tags without device-read permission and drops personal labels when permission changes',async()=>{
 const id='11111111-1111-4111-8111-111111111111',fetch=vi.spyOn(globalThis,'fetch').mockImplementation(async()=>response({items:[{id,hostname:'Synthetic protected workstation'}]}));
 let current=session;const wrapper=()=><Context.Provider value={{session:current,language:'en',refreshSession:async()=>{}}}><TargetPicker value={{kind:'devices',ids:[id]}} change={()=>{}}/></Context.Provider>;
 const view=render(wrapper());expect(screen.getByRole('button',{name:'Remove '+id})).toBeVisible();expect(fetch).not.toHaveBeenCalled();
 current={...session,permissions:[...session.permissions,'devices.read']};view.rerender(wrapper());await screen.findByRole('button',{name:'Remove Synthetic protected workstation'});
 current={...current,privacy:{aggregate_only:true} as Session['privacy']};view.rerender(wrapper());expect(screen.queryByText('Synthetic protected workstation')).toBeNull();expect(screen.getByRole('button',{name:'Remove '+id})).toBeVisible();
});

it('localizes disabled predefined rules and activates a ready-made mask in one click',async()=>{
 const rule={...settings.policy.rules[0],id:'preset-mask-iban',name:'Mask: International bank account number (IBAN)',mode:'disabled',condition:{op:'matches',field:'prompt',detector:'builtin-iban',minimum:1},consequence:{action:'mask',detector:'builtin-iban',label:'IBAN'}};
 const predefined={...settings,policy:{...settings.policy,detectors:[{id:'builtin-iban',name:'International bank account number (IBAN)',definition:{kind:'builtin',category:'iban'}}],rules:[rule]}} as DlpSettings;
 const fetch=mockPolicy(predefined);show();
 fireEvent.click(await screen.findByRole('button',{name:'Activate rule: Mask · Bank account number (IBAN)'}));await screen.findByRole('button',{name:'Disable rule: Mask · Bank account number (IBAN)'});
 const writes=fetch.mock.calls.filter(([,init])=>init?.method==='PUT');expect(writes).toHaveLength(1);expect(JSON.parse(String(writes[0][1]?.body)).policy.rules[0]).toEqual({...rule,mode:'active'});
});

it.each(['condition type', 'condition text', 'usage scope'])('resets the complete consequence after changing %s',async criterion=>{
 const original={...settings.policy.rules[0],review:true,message:'Synthetic review message'};
 const fetch=mockPolicy({...settings,policy:{...settings.policy,rules:[original]}});show();await openExample();
 await waitFor(()=>expect((screen.getByLabelText('DLP rule source') as HTMLTextAreaElement).value).toContain('REPLACE'));
 expect(screen.getByLabelText('Consequence')).toHaveValue('replace');
 if(criterion==='condition type')fireEvent.change(screen.getByLabelText('Condition operator'),{target:{value:'upload'}});
 else if(criterion==='condition text')fireEvent.change(screen.getByLabelText('Text expression'),{target:{value:'Changed literal'}});
 else fireEvent.click(screen.getByRole('checkbox',{name:'ChatGPT'}));
 expect(screen.getByLabelText('Consequence')).toHaveValue('block');
 expect(screen.queryByLabelText('Replacement text')).toBeNull();
 expect(screen.getByLabelText('Message shown to the user')).toHaveValue('');
 await waitFor(()=>expect((screen.getByLabelText('DLP rule source') as HTMLTextAreaElement).value).toContain('THEN BLOCK'));
 expect(fetch.mock.calls.some(([,init])=>init?.method==='PUT')).toBe(false);
 fireEvent.click(screen.getByRole('button',{name:'Save changes'}));
 await waitFor(()=>expect(screen.queryByRole('dialog')).toBeNull());
 const write=fetch.mock.calls.find(([,init])=>init?.method==='PUT')!;
 const saved=JSON.parse(String(write[1]?.body)).policy.rules[0];
 expect(saved.consequence).toEqual({action:'block'});expect(saved.review).toBe(false);expect(saved.message).toBe('');
 expect(saved.id).toBe(original.id);expect(saved.mode).toBe(original.mode);
 if(criterion==='usage scope')expect(saved.scope).toEqual({op:'all',children:[original.scope,{op:'in',field:'provider',values:['chatgpt']}]});
 else expect(saved.scope).toEqual(original.scope);
 if(criterion==='condition text')expect(saved.condition.value).toBe('Changed literal');
 if(criterion==='condition type')expect(saved.condition).toEqual({op:'upload'});
});

it('clears masking and review when a nested positive detector condition is removed',async()=>{
 const detector={id:'synthetic-detector',name:'Synthetic detector',definition:{kind:'literal' as const,value:'Synthetic',ignore_case:false,whole_word:false,unicode:false}};
 const original={...settings.policy.rules[0],condition:{op:'all' as const,children:[{op:'matches' as const,field:'prompt',detector:detector.id,minimum:1},settings.policy.rules[0].condition]},consequence:{action:'mask' as const,detector:detector.id,label:'REDACTED'},review:true,message:'Synthetic review message'};
 const fetch=mockPolicy({...settings,policy:{...settings.policy,detectors:[detector],rules:[original]}});show();await openExample();
 await waitFor(()=>expect((screen.getByLabelText('DLP rule source') as HTMLTextAreaElement).value).toContain('MASK'));
 fireEvent.click(screen.getAllByRole('button',{name:'Remove condition'})[0]);
 expect(screen.getByLabelText('Consequence')).toHaveValue('block');
 expect(screen.queryByLabelText('Mask label')).toBeNull();
 await waitFor(()=>expect(screen.getByRole('option',{name:'Mask'})).toBeDisabled());
 fireEvent.click(screen.getByRole('button',{name:'Save changes'}));
 await waitFor(()=>expect(screen.queryByRole('dialog')).toBeNull());
 const write=fetch.mock.calls.find(([,init])=>init?.method==='PUT')!;const saved=JSON.parse(String(write[1]?.body)).policy.rules[0];
 expect(saved.condition).toEqual(settings.policy.rules[0].condition);expect(saved.consequence).toEqual({action:'block'});expect(saved.review).toBe(false);expect(saved.message).toBe('');
});

it('resets a warning when its application changes and keeps an empty target selection invalid',async()=>{
 const fetch=mockPolicy({...settings,policy:{...settings.policy,rules:[{...settings.policy.rules[0],consequence:{action:'warn'},message:'Synthetic warning'}]}});show();await openExample();
 fireEvent.change(screen.getByLabelText('Applies to'),{target:{value:'groups'}});
 expect(screen.getByLabelText('Consequence')).toHaveValue('block');expect(screen.getByLabelText('Message shown to the user')).toHaveValue('');
 await waitFor(()=>expect((screen.getByLabelText('DLP rule source') as HTMLTextAreaElement).value).toContain('THEN BLOCK'));
 fireEvent.click(screen.getByRole('button',{name:'Save changes'}));
 await screen.findAllByText('Choose 1 to 128 rule targets');expect(screen.getByLabelText('Rule name')).toHaveValue('Example rule');
 expect(fetch.mock.calls.some(([,init])=>init?.method==='PUT')).toBe(false);
});

it('preserves a configured consequence when opening a rule or editing its metadata',async()=>{
 const original={...settings.policy.rules[0],review:true,message:'Synthetic review message'};
 const fetch=mockPolicy({...settings,policy:{...settings.policy,rules:[original]}});show();await openExample();
 fireEvent.change(screen.getByLabelText('Rule name'),{target:{value:'Renamed rule'}});
 fireEvent.change(screen.getByLabelText('Priority'),{target:{value:'42'}});
 await waitFor(()=>expect((screen.getByLabelText('DLP rule source') as HTMLTextAreaElement).value).toContain('REPLACE'));
 expect(screen.getByLabelText('Consequence')).toHaveValue('replace');
 fireEvent.click(screen.getByRole('button',{name:'Save changes'}));await waitFor(()=>expect(screen.queryByRole('dialog')).toBeNull());
 const write=fetch.mock.calls.find(([,init])=>init?.method==='PUT')!;const saved=JSON.parse(String(write[1]?.body)).policy.rules[0];
 expect(saved.consequence).toEqual(original.consequence);expect(saved.review).toBe(true);expect(saved.message).toBe(original.message);
});

it('derives consequences from the condition and makes confirmation explicit',async()=>{
 mockPolicy();show();await openExample();
 const effect=screen.getByLabelText('Consequence');
 await waitFor(()=>expect(screen.getByRole('option',{name:'Warn and require confirmation'})).toBeEnabled());
 fireEvent.change(effect,{target:{value:'warn'}});
 expect(screen.getByLabelText('Message shown to the user')).toHaveValue('This submission matches a data protection rule. Check the content before confirming.');
 expect(screen.getByText('Show the message and wait for explicit confirmation before sending. Another rule can still block the submission.')).toBeVisible();
 fireEvent.change(effect,{target:{value:'observe'}});
 expect(screen.queryByLabelText('Message shown to the user')).toBeNull();
 expect(screen.getByText('Sending remains allowed. Log the matching rule when decision logging is enabled; no user message is shown.')).toBeVisible();
});

it('selects custom rules without opening a drawer, confirms and deletes the selection atomically',async()=>{
 const first=settings.policy.rules[0],second={...first,id:'second',name:'Second custom'},third={...first,id:'third',name:'Keep custom'};
 const fetch=mockPolicy({...settings,policy:{...settings.policy,rules:[first,second,third]}});show();
 fireEvent.click(await screen.findByRole('checkbox',{name:'Select rule: Example rule'}));fireEvent.click(screen.getByRole('checkbox',{name:'Select rule: Second custom'}));
 expect(screen.queryByRole('dialog')).toBeNull();expect(screen.getByText('2 rules selected')).toBeVisible();
 fireEvent.click(screen.getByRole('button',{name:'Delete selected rules'}));let dialog=await screen.findByRole('dialog',{name:'Delete selected rules?'});
 expect(dialog).toHaveTextContent('Example rule');expect(dialog).toHaveTextContent('Second custom');expect(dialog).not.toHaveTextContent('Keep custom');
 fireEvent.click(within(dialog).getByRole('button',{name:'Cancel'}));expect(fetch.mock.calls.some(([,init])=>init?.method==='PUT')).toBe(false);
 fireEvent.click(screen.getByRole('button',{name:'Delete selected rules'}));dialog=await screen.findByRole('dialog',{name:'Delete selected rules?'});fireEvent.click(within(dialog).getByRole('button',{name:'Delete selected rules'}));
 await waitFor(()=>expect(screen.queryByRole('dialog')).toBeNull());expect(screen.getByRole('button',{name:'Keep custom'})).toBeVisible();expect(screen.queryByRole('button',{name:'Example rule'})).toBeNull();
 const writes=fetch.mock.calls.filter(([,init])=>init?.method==='PUT');expect(writes).toHaveLength(1);expect(JSON.parse(String(writes[0][1]?.body)).policy.rules.map((r:any)=>r.id)).toEqual(['third']);
});

it('protects server-identified defaults in selection and drawers, including renamed defaults',async()=>{
 const first={...settings.policy.rules[0],id:'unusual-id',name:'Renamed default'},custom={...settings.policy.rules[0],id:'preset-mask-email-custom',name:'Custom prefix'};
 mockPolicy({...settings,default_rule_ids:[first.id],policy:{...settings.policy,rules:[first,custom]}});show();
 expect(await screen.findByRole('checkbox',{name:'Select rule: Renamed default'})).toBeDisabled();expect(screen.getByRole('checkbox',{name:'Select rule: Custom prefix'})).toBeEnabled();
 fireEvent.click(screen.getByRole('checkbox',{name:'Select custom rules on this page'}));expect(screen.getByRole('checkbox',{name:'Select rule: Custom prefix'})).toBeChecked();expect(screen.getByRole('checkbox',{name:'Select rule: Renamed default'})).not.toBeChecked();
 fireEvent.click(screen.getByRole('button',{name:'Renamed default'}));await screen.findByLabelText('Rule name');expect(screen.queryByRole('button',{name:'Delete rule'})).toBeNull();expect(screen.getByText('Default rules cannot be deleted. You can edit or disable them.')).toBeVisible();
});

it('selects only this filtered page and retains an explicit selection across filters',async()=>{
 const rules=Array.from({length:22},(_,i)=>({...settings.policy.rules[0],id:'custom-'+i,name:'Custom '+String(i).padStart(2,'0')}));mockPolicy({...settings,policy:{...settings.policy,rules}});show();await screen.findByRole('button',{name:'Custom 00'});
 fireEvent.click(screen.getByRole('checkbox',{name:'Select custom rules on this page'}));expect(screen.getByText('20 rules selected')).toBeVisible();
 fireEvent.click(screen.getByRole('button',{name:'Next'}));expect(screen.getByRole('checkbox',{name:'Select custom rules on this page'})).not.toBeChecked();fireEvent.click(screen.getByRole('checkbox',{name:'Select rule: Custom 20'}));expect(screen.getByText('21 rules selected')).toBeVisible();
 fireEvent.change(screen.getByRole('searchbox'),{target:{value:'Custom 21'}});expect(screen.getByRole('checkbox',{name:'Select custom rules on this page'})).not.toBeChecked();fireEvent.click(screen.getByRole('checkbox',{name:'Select custom rules on this page'}));expect(screen.getByText('22 rules selected')).toBeVisible();
 fireEvent.click(screen.getByRole('button',{name:'Clear selection'}));expect(screen.queryByText('22 rules selected')).toBeNull();
});

it('keeps every selected rule on a rejected bulk deletion and respects inherited/demo policies',async()=>{
 mockPolicy(settings,true);show();fireEvent.click(await screen.findByRole('checkbox',{name:'Select rule: Example rule'}));fireEvent.click(screen.getByRole('button',{name:'Delete selected rules'}));const dialog=await screen.findByRole('dialog',{name:'Delete selected rules?'});fireEvent.click(within(dialog).getByRole('button',{name:'Delete selected rules'}));await within(dialog).findAllByText('Configuration changed; reload before saving.');expect(screen.getByRole('button',{name:'Example rule'})).toBeVisible();
});

it('saves and reopens a contextual dictionary detector with a distinct-expression threshold',async()=>{
 const fixture=structuredClone(settings);
 fixture.policy.detectors=[{id:'terms',name:'Project terms',definition:{kind:'dictionary',values:['alpha','beta'],exceptions:[]}}];
 const fetch=mockPolicy(fixture);show();await screen.findByRole('button',{name:'Example rule'});
 fireEvent.click(screen.getByRole('button',{name:'Detectors'}));fireEvent.click(screen.getByRole('button',{name:'New detector'}));
 fireEvent.change(await screen.findByLabelText('Detector name'),{target:{value:'Project context'}});
 fireEvent.change(screen.getByLabelText('Detector type'),{target:{value:'dictionary_context'}});
 expect(screen.getByLabelText('Dictionary')).toHaveValue('terms');
 fireEvent.change(screen.getByLabelText('Minimum different expressions'),{target:{value:'0'}});
 fireEvent.click(screen.getByRole('button',{name:'Save changes'}));
 await screen.findAllByRole('alert');expect(fetch.mock.calls.some(([,init])=>init?.method==='PUT')).toBe(false);
 fireEvent.change(screen.getByLabelText('Minimum different expressions'),{target:{value:'2'}});
 fireEvent.click(screen.getByRole('button',{name:'Save changes'}));await waitFor(()=>expect(screen.queryByRole('dialog')).toBeNull());
 expect(screen.getByText('Project terms · at least 2 different expressions')).toBeVisible();
 fireEvent.click(screen.getByRole('button',{name:'Project context'}));
 expect(await screen.findByLabelText('Minimum different expressions')).toHaveValue(2);
 const put=fetch.mock.calls.find(([,init])=>init?.method==='PUT')!;
 const body=JSON.parse(String(put[1]?.body));expect(body.policy.detectors[1].definition).toEqual({kind:'dictionary_context',dictionary:'terms',minimum:2});
});

it('protects a dictionary referenced by a contextual detector from deletion',async()=>{
 const fixture=structuredClone(settings);fixture.policy.detectors=[
  {id:'terms',name:'Project terms',definition:{kind:'dictionary',values:['alpha','beta'],exceptions:[]}},
  {id:'context',name:'Project context',definition:{kind:'dictionary_context',dictionary:'terms',minimum:2}}];
 const fetch=mockPolicy(fixture);show();await screen.findByRole('button',{name:'Example rule'});
 fireEvent.click(screen.getByRole('button',{name:'Dictionaries'}));fireEvent.click(screen.getByRole('button',{name:'Project terms'}));
 fireEvent.click(await screen.findByRole('button',{name:'Delete dictionary'}));
 await screen.findAllByRole('alert');expect(fetch.mock.calls.some(([,init])=>init?.method==='PUT')).toBe(false);
 expect(screen.getByLabelText('Dictionary name')).toHaveValue('Project terms');
});
