import { useContext, useEffect, useId, useRef, useState } from 'react';
import { Context, ErrorNotice, Icon, can, useResource, useText } from '../ui';
import type { DlpApplication } from './types';

type Kind = 'groups' | 'devices';
type Item = { id: string; name?: string; hostname?: string };
export function targetIds(value?: DlpApplication): string[] { return !value || value.kind === 'organization' ? [] : 'ids' in value ? value.ids : [value.id]; }
export function targetKind(value?: DlpApplication): Kind { return value?.kind === 'group' || value?.kind === 'groups' ? 'groups' : 'devices'; }

export function TargetPicker({ value, change }: Readonly<{ value: Exclude<DlpApplication, { kind: 'organization' }>; change: (value: DlpApplication) => void }>) {
 const t=useText(),{session}=useContext(Context);const [open,setOpen]=useState(false);const root=useRef<HTMLDivElement>(null),trigger=useRef<HTMLButtonElement>(null);const menuId=useId();
 const kind=targetKind(value),ids=targetIds(value);const names=can(session,'devices.read')&&!session.privacy?.aggregate_only;
 const close=()=>{setOpen(false);trigger.current?.focus();};
 useEffect(()=>{if(!open)return;const outside=(event:PointerEvent)=>{if(!root.current?.contains(event.target as Node))setOpen(false);};document.addEventListener('pointerdown',outside);return()=>document.removeEventListener('pointerdown',outside);},[open]);
 function toggle(id:string){change({kind,ids:ids.includes(id)?ids.filter(item=>item!==id):ids.length<128?[...ids,id]:ids});}
 return <div className="dlp-target-picker" ref={root} onKeyDown={event=>{if(open&&event.key==='Escape'){event.preventDefault();event.stopPropagation();close();}}}>
  <span className="dlp-target-label" id={menuId+'-label'}>{t(kind==='groups'?'dlpChooseGroups':'dlpChooseDevices')}</span>
  <button ref={trigger} type="button" className="dlp-target-trigger" aria-labelledby={menuId+'-label '+menuId+'-summary'} aria-expanded={open} aria-haspopup="dialog" aria-controls={open?menuId:undefined} onClick={()=>setOpen(!open)} onKeyDown={event=>{if(event.key==='ArrowDown'){event.preventDefault();setOpen(true);}}}><span id={menuId+'-summary'}>{ids.length?t('dlpTargetsSelected',[ids.length]):t('dlpSelectTargets')}</span><Icon name="chevron" /></button>
  {ids.length>0&&<SelectedTargets key={session.organization.id+":"+kind+":"+names} kind={kind} ids={ids} names={names} remove={id=>{toggle(id);trigger.current?.focus();}}/>}
  {open&&<div className="dlp-target-menu" id={menuId} role="dialog" aria-label={t(kind==='groups'?'dlpChooseGroups':'dlpChooseDevices')}>
   {names?<LoadedMenu kind={kind} selected={ids} toggle={toggle} clear={()=>change({kind,ids:[]})}/>:<IdentifierMenu selected={ids} toggle={toggle} clear={()=>change({kind,ids:[]})}/>}
  </div>}
 </div>;
}

type Selection = { selected:string[];toggle:(id:string)=>void;clear:()=>void };
function LoadedMenu({kind,...selection}:Readonly<Selection&{kind:Kind}>) {
 const [query,setQuery]=useState(''),[settled,setSettled]=useState(''),[page,setPage]=useState(0);
 useEffect(()=>{const timer=window.setTimeout(()=>setSettled(query),180);return()=>clearTimeout(timer);},[query]);
 const resource=useResource<{items:Item[];total?:number}>(kind==='groups'?'/api/groups':`/api/devices?limit=50&offset=${page*50}&query=${encodeURIComponent(settled)}`);
 const items=(resource.data?.items||[]).filter(item=>kind!=='groups'||(item.name||'').toLocaleLowerCase().includes(query.toLocaleLowerCase()));
 return <Menu {...selection} query={query} search={value=>{setQuery(value);setPage(0);}} items={kind==='devices'&&query!==settled?[]:items} loading={resource.loading||kind==='devices'&&query!==settled} error={resource.error} page={kind==='devices'?page:undefined} previous={()=>setPage(page-1)} next={()=>setPage(page+1)} hasNext={(page+1)*50<(resource.data?.total||0)} />;
}
function IdentifierMenu(selection:Readonly<Selection>) {
 const [query,setQuery]=useState('');const id=query.trim().toLowerCase();
 const ids=[...new Set([...selection.selected,...(/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(id)?[id]:[])])].filter(value=>value.includes(id));
 return <Menu {...selection} query={query} search={setQuery} items={ids.map(id=>({id,name:id}))} identifiers />;
}
function Menu({selected,toggle,clear,query,search,items,loading,error,page,previous,next,hasNext,identifiers}:Readonly<Selection&{query:string;search:(value:string)=>void;items:Item[];loading?:boolean;error?:unknown;page?:number;previous?:()=>void;next?:()=>void;hasNext?:boolean;identifiers?:boolean}>) {
 const t=useText();const id=useId();const [active,setActive]=useState(0);const panel=useRef<HTMLDivElement>(null);
 useEffect(()=>setActive(0),[query,page]);
 useEffect(()=>{panel.current?.querySelector('input')?.focus();panel.current?.scrollIntoView?.({block:'nearest'});},[]);
 useEffect(()=>{panel.current?.querySelector('[data-active="true"]')?.scrollIntoView?.({block:'nearest'});},[active]);
 return <div ref={panel}>
  <label className="dlp-target-search"><Icon name="search" /><input type="search" role="combobox" aria-label={t(identifiers?'dlpSearchTargetIds':'dlpSearchTargetList')} aria-expanded="true" aria-controls={id} aria-autocomplete="list" aria-activedescendant={items[active]?id+'-'+active:undefined} placeholder={t(identifiers?'dlpSearchTargetIds':'dlpSearchTargetList')} maxLength={200} value={query} onChange={event=>search(event.target.value)} onKeyDown={event=>{if(event.key==='ArrowDown'||event.key==='ArrowUp'){event.preventDefault();setActive(current=>items.length?(current+(event.key==='ArrowDown'?1:-1)+items.length)%items.length:0);}else if(event.key==='Enter'){event.preventDefault();if(items[active])toggle(items[active].id);}}}/></label>
  {identifiers&&<p className="field-help">{t('dlpTargetNamesRestricted')}</p>}
  <div className="dlp-target-selection"><span>{t('dlpTargetsSelected',[selected.length])}</span><button type="button" className="button ghost small" disabled={!selected.length} onClick={clear}>{t('dlpClearTargets')}</button></div>
  <ErrorNotice error={error}/>
  <div className="dlp-target-options" role="listbox" id={id} aria-label={t('dlpTargetList')} aria-multiselectable="true" aria-busy={!!loading}>
   {items.map((item,index)=><button type="button" role="option" tabIndex={-1} id={id+'-'+index} data-active={active===index} aria-selected={selected.includes(item.id)} disabled={!selected.includes(item.id)&&selected.length>=128} key={item.id} onMouseDown={event=>event.preventDefault()} onClick={()=>toggle(item.id)}><span className={'dlp-target-check'+(selected.includes(item.id)?' checked':'')} aria-hidden="true">{selected.includes(item.id)&&<Icon name="check" size={12}/>}</span><span>{item.name||item.hostname||item.id}</span></button>)}
  </div>
  {loading?<p className="field-help" role="status">{t('loading')}</p>:!items.length&&!error&&<p className="field-help">{t('dlpNoSearchResults')}</p>}
  {selected.length>=128&&<p className="field-help">{t('dlpTargetLimit')}</p>}
  {page!==undefined&&<div className="dlp-target-pages"><button type="button" className="button secondary small" disabled={!page} onClick={previous}>{t('previous')}</button><span>{page+1}</span><button type="button" className="button secondary small" disabled={!hasNext} onClick={next}>{t('next')}</button></div>}
 </div>;
}

function SelectedTargets({kind,ids,names,remove}:Readonly<{kind:Kind;ids:string[];names:boolean;remove:(id:string)=>void}>){
 const t=useText();
 return <ul className="dlp-target-tags" aria-label={t('dlpSelectedTargets')}>{ids.map(id=><li key={id}>{names?<NamedTargetTag kind={kind} id={id} remove={()=>remove(id)}/>:<TargetTag label={id} remove={()=>remove(id)}/>}</li>)}</ul>;
}
function NamedTargetTag({kind,id,remove}:Readonly<{kind:Kind;id:string;remove:()=>void}>){
 const resource=useResource<{items:Item[]}>(kind==='groups'?'/api/groups':`/api/devices?device_id=${encodeURIComponent(id)}`);
 const item=resource.data?.items.find(item=>item.id===id);
 return <TargetTag label={item?.name||item?.hostname||id} remove={remove}/>;
}
function TargetTag({label,remove}:Readonly<{label:string;remove:()=>void}>){
 const t=useText();
 return <span className="dlp-target-tag"><span>{label}</span><button type="button" aria-label={t('dlpRemoveTargetNamed',[label])} title={t('dlpRemoveTargetNamed',[label])} onClick={remove}><Icon name="close" size={13}/></button></span>;
}
