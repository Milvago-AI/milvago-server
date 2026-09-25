import { PublisherPanel } from "./PublisherPanel";
import { DetectionCatalog } from "./DetectionCatalog";
import { useContext, useState } from "react";
import type { SubmitEvent } from "react";
import { AliasRotation } from "./AliasRotation";
import { Badge, Card, can, Context, Empty, ErrorNotice, Icon, Notice, ResourceView, Tabs, useMutation, useResource, useText } from "./ui";
import { FlowDiagram } from "./shadow/FlowDiagram";
import type { Selection } from "./shadow/FlowDiagram";
import type { TranslationKey } from "./locales/en";
import type { Session } from "./api";
export type PrivacyConfig = {pseudonymous:boolean;aggregate_only:boolean;k_anonymity:number;identity_link_days:number;lock_descendants:boolean;retention_justification:string;team_claim:string;discovery_enabled:boolean;ignored_domains:string[];auto_catalog:boolean;share_health:boolean;share_fleet:boolean};
export type Privacy={config:PrivacyConfig;revision:number;locked_by?:string};
type ReportCell={tool:string;provider:string;model:string;prompts:number;responses:number;subjects:number};
// Two breakdowns of one week, published side by side: by team (the OIDC claim carried by
// the person) and by device group (Fleet > Groups). A week published before the group
// breakdown existed carries no `group_cells` at all — a published report is never
// recomputed — and that absence means "not available", never "zero requests".
type Aggregate={items:Array<{week_start:string;k:number;report:{suppressed:boolean;cells:Array<ReportCell&{team:string}>;group_cells?:Array<ReportCell&{group:string}>;group_suppressed?:boolean}}>;teams_available?:boolean;groups_available?:boolean};
type Health={items:{provider:string;state:string;catalog_revision:number;devices:number;network_prompts:number;dom_prompts:number}[];window_hours:number;thresholds:{min_devices:number;dom_ratio_percent:number};transport:{state:string;devices_reporting:number;devices_approved:number}};
// Shared by the diagnostic table and the banner so the two never name the same state
// differently; the detector verdicts themselves are computed server-side.
const detectionStates:Record<string,TranslationKey>={dom_only:"detectionDOMOnly",no_transport:"detectionNoTransport",partial:"detectionPartialTransport",degraded_dom:"detectionDegraded",suspect:"detectionSuspect",insufficient_data:"reportsInsufficientData",ok:"detectionHealthy"};
export function PrivacyPanel(){const r=useResource<Privacy>("/api/privacy"),{session}=useContext(Context);return <><ResourceView resource={r}>{v=><><PrivacyForm key={v.revision} value={v} reload={r.reload}/><PublisherSharingForm key={`publisher-${v.revision}`} value={v} reload={r.reload}/></>}</ResourceView>{can(session,"identity.erase")&&<AliasRotation done={r.reload}/ >}</>}
export function PrivacyForm({value,reload}:Readonly<{value:Privacy;reload:()=>void}>){
 const t=useText(),{session,refreshSession}=useContext(Context),m=useMutation(),[config,setConfig]=useState(value.config),[reason,setReason]=useState("");
 const set=<K extends keyof PrivacyConfig>(key:K,v:PrivacyConfig[K])=>setConfig(c=>({...c,[key]:v}));
 // Kept apart from the event handler so the second-factor notice can replay exactly
 // what was refused, without the person retyping the reason or the settings.
 async function submit(){if(reason.trim().length<8){return;}try{await m.run("/api/privacy","PUT",{config,revision:value.revision,reason:reason.trim()});window.dispatchEvent(new Event("milvago:privacy-changed"));await refreshSession();reload()}catch{/* Visible server error. */}}
 async function save(e:SubmitEvent){e.preventDefault();await submit()}
 return <Card title={t("privacy")}><form onSubmit={save} className="form-grid"><ErrorNotice error={m.error}/>{value.locked_by&&<Notice tone="warning" title={t("configurationLocked")}/>}
 <PrivacyFields config={config} set={set} locked={!!value.locked_by} edition={session.edition}/>
 <div className="privacy-setting"><label>{t("privacyChangeReason")}<textarea aria-describedby="privacy-help-change-reason" required minLength={8} maxLength={1000} value={reason} onChange={e=>setReason(e.target.value)}/></label><small className="field-help" id="privacy-help-change-reason">{t("privacyChangeReasonHelp")}</small></div>
 <button type="submit" className="button primary" disabled={m.pending||reason.trim().length<8}>{t("save")}</button></form></Card>
}
// The privacy settings themselves, shared by this form and the first-run setup
// wizard, which sets them before any session exists.
export function PrivacyFields({config,set,locked,edition,teamClaim=true}:Readonly<{config:PrivacyConfig;set:<K extends keyof PrivacyConfig>(key:K,v:PrivacyConfig[K])=>void;locked:boolean;edition:Session["edition"];teamClaim?:boolean}>){
 const t=useText();
 const check=(key:"pseudonymous"|"aggregate_only"|"lock_descendants",label:TranslationKey,help:TranslationKey,disabled=false)=><div className="privacy-setting"><label className="checkbox-label"><input type="checkbox" aria-describedby={"privacy-help-"+key} checked={config[key]} disabled={disabled} onChange={e=>set(key,e.target.checked)}/>{t(label)}</label><small className="field-help" id={"privacy-help-"+key}>{t(help)}</small></div>;
 return <>
 {check("pseudonymous","pseudonymous","privacyPseudonymousHelp",locked)}
 {check("aggregate_only","aggregateOnly","privacyAggregateOnlyHelp",locked)}
 <div className="privacy-setting"><label>{t("kAnonymity")}<input type="number" aria-describedby="privacy-help-k" required min={1} max={100} disabled={locked} value={config.k_anonymity} onChange={e=>set("k_anonymity",Number(e.target.value))}/></label><small className="field-help" id="privacy-help-k">{t("privacyKAnonymityHelp")}</small></div>
 <div className="privacy-setting"><label>{t("identityLinkDays")}<input type="number" aria-describedby="privacy-help-identity-days" required min={7} max={365} disabled={locked} value={config.identity_link_days} onChange={e=>set("identity_link_days",Number(e.target.value))}/></label><small className="field-help" id="privacy-help-identity-days">{t("privacyIdentityLinkDaysHelp")}</small></div>
 {edition==="commercial"&&check("lock_descendants","privacyLockDescendants","privacyLockDescendantsHelp")}
 <div className="privacy-setting"><label>{t("privacyRetentionReason")}<textarea aria-describedby="privacy-help-retention-reason" maxLength={1000} value={config.retention_justification} onChange={e=>set("retention_justification",e.target.value)}/></label><small className="field-help" id="privacy-help-retention-reason">{t("privacyRetentionReasonHelp")}</small></div>
 {teamClaim&&<div className="privacy-setting"><label>{t("privacyTeamClaim")}<input aria-describedby="privacy-help-team-claim" maxLength={100} value={config.team_claim} onChange={e=>set("team_claim",e.target.value)}/></label><small className="field-help" id="privacy-help-team-claim">{t("privacyTeamClaimHelp")}</small></div>}
 </>;
}
export function PublisherSharingForm({value,reload}:Readonly<{value:Privacy;reload:()=>void}>){
 const t=useText(),{session,refreshSession}=useContext(Context),m=useMutation();
 const [choices,setChoices]=useState({auto_catalog:value.config.auto_catalog,share_health:value.config.share_health,share_fleet:value.config.share_fleet});
 const [reason,setReason]=useState("");
 const currentOrg=session.organizations.find(org=>org.id===session.organization.id);
 const rootOrg=session.edition!=="commercial"||!currentOrg?.parent_id;
 async function save(e:SubmitEvent){e.preventDefault();if(reason.trim().length<8){return;}try{
  await m.run("/api/privacy","PUT",{config:{...value.config,...choices},revision:value.revision,reason:reason.trim()});
  window.dispatchEvent(new Event("milvago:privacy-changed"));await refreshSession();reload();
 }catch{/* Visible server error. */}}
 const check=(key:keyof typeof choices,label:TranslationKey,help:TranslationKey)=><div className="privacy-setting"><label className="checkbox-label"><input type="checkbox" aria-describedby={"publisher-help-"+key} checked={choices[key]} onChange={e=>setChoices(c=>({...c,[key]:e.target.checked}))}/>{t(label)}</label><small className="field-help" id={"publisher-help-"+key}>{t(help)}</small></div>;
 return <Card title={t("publisherSharing")}><form onSubmit={save} className="form-grid"><ErrorNotice error={m.error}/>
  {rootOrg&&check("auto_catalog","autoCatalog","autoCatalogHelp")}
  {check("share_health","shareHealth","shareHealthHelp")}
  {check("share_fleet","shareFleet","shareFleetHelp")}
  <Notice>{t("privacyPublisherConsent")}</Notice>
  <div className="privacy-setting"><label>{t("privacyChangeReason")}<textarea aria-describedby="publisher-help-change-reason" required minLength={8} maxLength={1000} value={reason} onChange={e=>setReason(e.target.value)}/></label><small className="field-help" id="publisher-help-change-reason">{t("privacyChangeReasonHelp")}</small></div>
  <button type="submit" className="button primary" disabled={m.pending||reason.trim().length<8}>{t("save")}</button>
 </form>{session.is_instance_owner&&<PublisherPanel/>}</Card>;
}
type Breakdown="teams"|"groups";
function resolveBreakdown(teams:boolean,groups:boolean,chosen:Breakdown):Breakdown{
 if(!teams)return "groups";
 return groups?chosen:"teams";
}
function toggleSelection(current:Selection[],node:Selection):Selection[]{
 return current.some(item=>item.value===node.value&&item.dimension===node.dimension)
  ?current.filter(item=>!(item.value===node.value&&item.dimension===node.dimension))
  :[...current,node];
}
function WeekBody({cells,shape,breakdown,heading,selected,setSelected,nameOf}:Readonly<{
 cells:Array<ReportCell&{team?:string;group?:string}>|undefined;
 shape:"table"|"map";
 breakdown:Breakdown;
 heading:string;
 selected:Selection[];
 setSelected:(updater:(current:Selection[])=>Selection[])=>void;
 nameOf:(c:{team?:string;group?:string})=>string;
}>){
 const t=useText();
 if(!cells)return <Notice>{t("reportsGroupsUnavailableWeek")}</Notice>;
 if(shape==="map")return <FlowDiagram flows={cells.map(c=>({actor_id:nameOf(c),actor_name:nameOf(c),tool:c.tool,provider:c.provider,model:c.model,count:c.prompts,blocked:0}))} selected={selected} select={node=>setSelected(current=>toggleSelection(current,node))} sensitivity={false} tableToggle={false} actorLabels={{plural:breakdown==="teams"?t("teams"):t("groups"),singular:heading,map:breakdown==="teams"?t("requestMapTeamToolServiceModel"):t("requestMapGroupToolServiceModel")}}/>;
 return <div className="table-scroll"><table className="privacy-table"><thead><tr>{[heading,t("tool"),t("service"),t("model"),t("requests"),t("responses"),t("privacySubjects")].map(title=><th key={title}>{title}</th>)}</tr></thead><tbody>{cells.map(c=><tr key={`${nameOf(c)}|${c.tool}|${c.provider}|${c.model}`}><td>{nameOf(c)}</td><td>{c.tool}</td><td>{c.provider}</td><td>{c.model||t("unknown")}</td><td>{c.prompts}</td><td>{c.responses}</td><td>{c.subjects}</td></tr>)}</tbody></table></div>;
}
function WeekSection({week,cells,suppressed,shape,breakdown,heading,selected,setSelected,nameOf}:Readonly<{
 week:string;
 cells:Array<ReportCell&{team?:string;group?:string}>|undefined;
 suppressed:boolean|undefined;
 shape:"table"|"map";
 breakdown:Breakdown;
 heading:string;
 selected:Selection[];
 setSelected:(updater:(current:Selection[])=>Selection[])=>void;
 nameOf:(c:{team?:string;group?:string})=>string;
}>){
 const t=useText();
 return <section><h3 className="report-week-heading">{t("reportsWeekStarting",[week])}{suppressed&&<Badge tone="warning">{t("suppressed")}</Badge>}</h3>
  <WeekBody cells={cells} shape={shape} breakdown={breakdown} heading={heading} selected={selected} setSelected={setSelected} nameOf={nameOf}/>
 </section>;
}
// Excel reads a CSV by its own locale rules. The BOM keeps the accents and the `sep=`
// line states the separator, so one file opens correctly without an import wizard.
const SEPARATOR=";";
// Same rule as the server's csvSafe (server/internal/app/shadow_analysis.go:472-477): a
// value opening on one of these characters is a formula to a spreadsheet. A team name
// comes from an identity token and a group name from a console field — neither is trusted.
function csvSafe(value:string){return /^[=+\-@\t\r]/.test(value)?`'${value}`:value}
function csvField(value:string|number){const text=csvSafe(String(value));return /["\r\n;,]/.test(text)?`"${text.replaceAll('"','""')}"`:text}
export function csvDocument(header:string[],rows:(string|number)[][]){return `﻿sep=${SEPARATOR}\r\n`+[header,...rows].map(row=>row.map(csvField).join(SEPARATOR)).join("\r\n")+"\r\n"}
// Why rows are missing, said once above the weeks rather than repeated on each of them.
// Closing it is a per-browser convenience; the badge on each week stays, so which weeks
// are partial is never hidden, and "Why?" brings the explanation back.
const WITHHELD_HELP="milvago.reports.withheldHelp";
function WithheldExplanation({k}:Readonly<{k:number}>){
 const t=useText(),[hidden,setHidden]=useState(()=>{try{return localStorage.getItem(WITHHELD_HELP)==="hidden"}catch{return false}});
 const toggle=(next:boolean)=>{setHidden(next);try{localStorage.setItem(WITHHELD_HELP,next?"hidden":"shown")}catch{/* optional */}};
 if(hidden)return <p className="report-withheld-why"><button type="button" className="text-link" onClick={()=>toggle(false)}><Icon name="info"/>{t("reportsWithheldWhy")}</button></p>;
 return <Notice tone="warning" title={t("reportsWithheldTitle")} action={<button type="button" className="icon-button" aria-label={t("reportsWithheldDismiss")} title={t("reportsWithheldDismiss")} onClick={()=>toggle(true)}><Icon name="close"/></button>}>{t("reportsWithheldHelp",[String(k)])}</Notice>;
}
function download(name:string,content:string){const url=URL.createObjectURL(new Blob([content],{type:"text/csv;charset=utf-8"}));const link=document.createElement("a");link.href=url;link.download=name;link.click();URL.revokeObjectURL(url)}
export function ReportsPanel(){
 const t=useText(),r=useResource<Aggregate>("/api/shadow/aggregate");
 // The tab and the shape live above ResourceView: reload() sets its data to undefined and
 // unmounts its children, which would silently reset any state held inside them.
 const [chosen,setChosen]=useState<Breakdown>("teams"),[shape,setShape]=useState<"table"|"map">("table"),[selected,setSelected]=useState<Selection[]>([]);
 return <ResourceView resource={r}>{d=>{
  const teams=d.teams_available??false,groups=d.groups_available??false;
  // Only a breakdown the organization can actually read is offered. Both missing leaves
  // the group view, which then reads "unattributed" everywhere, under a notice saying so.
  const breakdown:Breakdown=resolveBreakdown(teams,groups,chosen);
  const cellsOf=(x:Aggregate["items"][number])=>breakdown==="teams"?x.report.cells:x.report.group_cells;
  const nameOf=(c:{team?:string;group?:string})=>{const value=breakdown==="teams"?c.team:c.group;return value==="unassigned"||!value?t("unattributed"):value};
  const suppressedOf=(x:Aggregate["items"][number])=>breakdown==="teams"?x.report.suppressed:x.report.group_suppressed;
  const heading=breakdown==="teams"?t("privacyTeam"):t("group");
  function exportCsv(){
   const rows=d.items.flatMap(x=>(cellsOf(x)??[]).map(c=>[x.week_start,nameOf(c),c.tool,c.provider,c.model||t("unknown"),c.prompts,c.responses,c.subjects]));
   const weeks=d.items.map(x=>x.week_start);
   download(`milvago-${breakdown}-${weeks.at(-1)??"empty"}-${weeks[0]??"empty"}.csv`,csvDocument([t("week"),heading,t("tool"),t("service"),t("model"),t("requests"),t("responses"),t("privacySubjects")],rows));
  }
  return <Card title={t("reports")} description={t("reportsFixedWeeks")} actions={d.items.length>0&&<button className="button small secondary" onClick={exportCsv}>{t("export")}</button>}>
   {!teams&&!groups&&<Notice tone="warning">{t("reportsNoBreakdown")}</Notice>}
   {teams&&groups&&<Tabs label={t("reportsSections")} selected={breakdown} onSelect={value=>{setChosen(value as Breakdown);setSelected([])}} items={[{id:"teams",name:t("teams")},{id:"groups",name:t("groups")}]}/>}
   <fieldset className="segment" aria-label={t("reports")}>
    <button type="button" aria-pressed={shape==="table"} onClick={()=>setShape("table")}>{t("table")}</button>
    <button type="button" aria-pressed={shape==="map"} onClick={()=>setShape("map")}>{t("cartography")}</button>
   </fieldset>
   {!d.items.length&&<Empty title={t("reportsInsufficientData")}/>}
   {(()=>{const withheld=d.items.find(x=>suppressedOf(x));return withheld&&<WithheldExplanation k={withheld.k}/>})()}
   {d.items.map(x=><WeekSection key={x.week_start} week={x.week_start} cells={cellsOf(x)} suppressed={suppressedOf(x)} shape={shape} breakdown={breakdown} heading={heading} selected={selected} setSelected={setSelected} nameOf={nameOf}/>)}
  </Card>;
 }}</ResourceView>
}
// The engineer's view of the detectors, kept behind MILVAGO_DEBUG with the editor it
// diagnoses. Its verdicts read in catalogue terms — a network rule that no longer
// matches, selectors the site has renamed — and its real consumer is the publisher
// service, which collects them across consenting fleets to know a site has changed.
// What a customer needs out of it is one sentence, and that is CoverageNotice below.
export function DetectionPanel(){const t=useText(),h=useResource<Health>("/api/detection/health");
 return <><DetectionCatalog/><ResourceView resource={h}>{d=><Card title={t("coverage")}>{/* The state belongs in the title: Notice already wraps its children in a <p>, so a
     <p> passed as a child nested one inside the other. */}
{d.transport&&<Notice tone={d.transport.state==="ok"?"neutral":"warning"} title={detectionStates[d.transport.state]?t(detectionStates[d.transport.state]):t("unknown")}>{t("detectionReporting",[d.transport.devices_reporting,d.transport.devices_approved])}</Notice>}{d.thresholds&&<p>{t("detectionWindow",[d.window_hours])} / {t("detectionThresholds",[d.thresholds.min_devices,d.thresholds.dom_ratio_percent])}</p>}<div className="table-scroll"><table className="privacy-table"><thead><tr><th>{t("service")}</th><th>{t("status")}</th><th>{t("appliedRevision")}</th><th>{t("devices")}</th><th>{t("detectionNetworkPrompts")}</th><th>{t("detectionDOMPrompts")}</th></tr></thead><tbody>{d.items.map(x=><tr key={x.provider+":"+x.catalog_revision}><td>{x.provider}</td><td>{detectionStates[x.state]?t(detectionStates[x.state]):t("unknown")}</td><td>{x.catalog_revision}</td><td>{x.devices}</td><td>{x.network_prompts}</td><td>{x.dom_prompts}</td></tr>)}</tbody></table></div>{!d.items.length&&<Empty title={t("reportsInsufficientData")}/>}</Card>}</ResourceView></>
}
// Ordered worst first. `insufficient_data` and `ok` are deliberately absent: an
// unvisited service is unmeasured, not broken, and neither deserves a banner.
const degradations=["suspect","dom_only","degraded_dom"] as const;
// Says, where the figures are read, that they are incomplete. Without it a fleet that
// stopped capturing looks exactly like a fleet that stopped using AI, and the page
// showing the smaller number gives no hint which one it is.
//
// Mounted only for policy.manage: /api/detection/health demands it, so mounting it for
// anyone else would guarantee a 403 on every render rather than a quieter banner.
export function CoverageNotice(){
 const t=useText(),{session}=useContext(Context),h=useResource<Health>("/api/detection/health");
 const d=h.data;
 if(!d)return null;
 const worst=degradations.find(state=>d.items.some(x=>x.state===state));
 const transport=d.transport&&d.transport.state!=="ok"?d.transport.state:undefined;
 if(!worst&&!transport)return null;
 const affected=worst?d.items.filter(x=>x.state===worst).map(x=>x.provider):[];
 const unique=[...new Set(affected)];
 return <Notice tone="warning" role="status" title={t("coverageIncomplete")} action={session.console_debug?<a className="button small" href="#detection">{t("catalogCoverageDetails")}</a>:undefined}>
  {worst?t("coverageIncompleteServices",[unique.join(", "),t(detectionStates[worst])]):t(detectionStates[transport as string])}
 </Notice>;
}
