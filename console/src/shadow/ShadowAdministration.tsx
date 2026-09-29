import { useContext, useEffect, useState } from 'react';
import { ApiError } from '../api';
import { Badge, can, Context, Dialog, ErrorNotice, Notice, PageBar, ResourceView, readOnly, useMutation, useResource, useText } from '../ui';
import { InheritanceContext } from './ConfigFields';
import { KnownPlatformsPanel } from './KnownPlatformsPanel';
import { CapturePanel, ClassificationPanel, OperationsPanel, PrivacyPanel, ProtectionPanel, ServicesPanel, labelMatchesPattern } from './ConfigurationPanels';
import type { ShadowConfig, ShadowSection, ShadowSettings } from './types';

type Area = 'capture' | 'services' | 'protection' | 'privacy' | 'classification' | 'platforms' | 'operations';
// `platforms` maps to no configuration section: which platforms Discovery may name is
// stored on its own and never travels in the signed policy, so it inherits nothing and
// has nothing to save with the rest.
const areaSections: Record<Area, ShadowSection[]> = { capture: ['enrollment', 'collection'], services: ['services', 'model_access'], protection: ['protection'], privacy: ['privacy'], classification: ['classification'], platforms: [], operations: ['operations'] };
function cleanConfiguration(value: ShadowConfig): ShadowConfig {
  const next = structuredClone(value); const lines = (items: string[]) => items.map(item => item.trim()).filter(Boolean);
  next.enrollment.cidrs = lines(next.enrollment.cidrs); next.protection.keywords = lines(next.protection.keywords); next.protection.exceptions = lines(next.protection.exceptions); next.operations.updates.device_ids = lines(next.operations.updates.device_ids); next.operations.updates.paused_versions = lines(next.operations.updates.paused_versions); next.model_access = (next.model_access ?? []).map(item => ({ ...item, models: lines(item.models) })); next.classification.medical_terms = lines(next.classification.medical_terms ?? []);
  return next;
}

export function ShadowAdministration() {
  const t = useText();
  // Every other page in the console titles itself through PageBar. This one carried its
  // own section heading, which is why its title sat higher than every other section.
  // PageBar has to be a direct child of `.main`: it bleeds edge to edge through negative
  // margins and sticks to the top, and `.main>*:not(.pagebar)` is what keeps everything
  // else inside the content width. Nested in the section it would sit 24px off.
  return <><PageBar title={t("shadowAiAdministration")} info={t("collectionProtectionAndOperationsInOne")} /><section className="shadow-admin"><ScopedSettings device="" /></section></>;
}
/** Scope of one settings editor: the organization policy, a device group's override, or a single device's override. */
type Scope = 'organization' | 'group' | 'device';
export function ScopedSettings({ device, group, dirtyChanged, capabilitiesChanged }: Readonly<{ device: string; group?: string; dirtyChanged?: (dirty: boolean) => void; capabilitiesChanged?: (value: Record<string, boolean>) => void }>) {
  let path = '/api/shadow/settings';
  let scope: Scope = 'organization';
  if (group) { path = '/api/groups/' + encodeURIComponent(group) + '/shadow'; scope = 'group'; }
  else if (device) { path = '/api/devices/' + encodeURIComponent(device) + '/shadow'; scope = 'device'; }
  const resource = useResource<ShadowSettings>(path);
  return <ResourceView resource={resource}>{settings => <SettingsEditor key={settings.revision} initial={settings} path={path} scope={scope} reload={resource.reload} dirtyChanged={dirtyChanged} capabilitiesChanged={capabilitiesChanged} />}</ResourceView>;
}

function SettingsEditor({ initial, path, scope, reload, dirtyChanged, capabilitiesChanged }: Readonly<{ initial: ShadowSettings; path: string; scope: Scope; reload: () => void; dirtyChanged?: (dirty: boolean) => void; capabilitiesChanged?: (value: Record<string, boolean>) => void }>) {
  const t = useText(); const { session } = useContext(Context); const [area, setArea] = useState<Area>('capture'); const [config, setConfig] = useState(initial.config); const [inherit, setInherit] = useState(initial.inherit_sections ?? []); const [revision, setRevision] = useState(initial.revision); const [baseline, setBaseline] = useState({ config: initial.config, inherit: initial.inherit_sections ?? [] }); const [saved, setSaved] = useState(false); const mutation = useMutation();
  // A demonstration instance shows this configuration and refuses to change it. The
  // panels stay rendered with their real values -- that is what a visitor came to
  // see -- but the fields are inert and the save bar is replaced by a notice, so
  // nothing invites a click that the server would answer with a refusal.
  const frozen = readOnly(session);
  // A group or a device overrides the organization: same six sections, no enrollment, no operations.
  const device = scope !== 'organization';
  useEffect(() => capabilitiesChanged?.(initial.capabilities), [initial.capabilities, capabilitiesChanged]);
  const dirty = JSON.stringify({ config, inherit }) !== JSON.stringify(baseline);
  // Usage sensitivity is an Enterprise capability: without it the section does not
  // exist at all rather than showing an empty, unusable grid.
  const sensitivity = Boolean(initial.capabilities.usage_sensitivity);
  const modelControl = Boolean(initial.capabilities.model_access_browser || initial.capabilities.model_access_native);
  // Both editions receive signed security updates, and they are on by default, so the
  // section has nothing an administrator has to decide. It is a maintenance surface --
  // pilot rings, paused versions -- kept behind MILVAGO_DEBUG like the catalogue editor.
  // Hidden, the policy still travels: the draft carries the operations section it was
  // loaded with, so saving another panel never turns updates off by omission.
  const operations = Boolean(session.console_debug);
  const availableAreas: Area[] = ([
    'capture', 'services', 'protection', 'privacy',
    ...(sensitivity ? ['classification' as Area] : []),
    // Discovery is read at the organization, so the platforms it may name are chosen
    // there too -- a group or a device override would have nothing to act on.
    ...(device ? [] : ['platforms' as Area, ...(operations ? ['operations' as Area] : [])]),
  ] as Area[]);
  const names: Record<Area, string> = { capture: t("enrollmentCollection"), services: t("services"), protection: t("protections"), privacy: t("localMasking"), classification: t("usageSensitivity"), platforms: t("aiPlatforms"), operations: t("operations") };
  const sectionName: Record<ShadowSection, string> = { enrollment: t("enrollment"), collection: t("collection"), services: names.services, model_access: t("modelControls"), protection: names.protection, privacy: names.privacy, classification: names.classification, operations: names.operations };
  useEffect(() => { dirtyChanged?.(dirty); if (!dirty) { return; } const warn = (event: BeforeUnloadEvent) => event.preventDefault(); window.addEventListener('beforeunload', warn); return () => window.removeEventListener('beforeunload', warn); }, [dirty, dirtyChanged]);
  function update<K extends keyof ShadowConfig>(section: K, value: ShadowConfig[K]) { setSaved(false); setConfig(current => ({ ...current, [section]: value })); }
  async function submit() { setSaved(false); const cleaned = cleanConfiguration(config); const payload = device ? { collection: cleaned.collection, services: cleaned.services, model_access: cleaned.model_access, protection: cleaned.protection, privacy: cleaned.privacy, classification: cleaned.classification } : cleaned; try { const response = await mutation.run<ShadowSettings>(path, 'PUT', { revision, config: payload, inherit_sections: inherit }); if (response?.config) { setConfig(response.config); setInherit(response.inherit_sections ?? []); setBaseline({ config: response.config, inherit: response.inherit_sections ?? [] }); setRevision(response.revision); setSaved(true); } else reload(); } catch { /* A conflicting or unsupported policy never replaces the draft. */ } }
  const props = { config, update, capabilities: initial.capabilities, device, modelCatalog: initial.model_catalog ?? [] };
  let inheritanceAllowed = initial.capabilities.organization_inheritance;
  if (scope === 'group') inheritanceAllowed = initial.capabilities.group_overrides;
  else if (scope === 'device') inheritanceAllowed = initial.capabilities.device_overrides;
  let scopeName = t("organizationPolicy");
  if (scope === 'group') scopeName = t("groupOverride");
  else if (scope === 'device') scopeName = t("deviceOverride");
  function configPanel() {
    if (area === 'capture') return <CapturePanel {...props} />;
    if (area === 'services') return <ServicesPanel {...props} />;
    if (area === 'protection') return <ProtectionPanel {...props} />;
    if (area === 'privacy') return <PrivacyPanel {...props} />;
    if (area === 'classification') return <ClassificationPanel {...props} />;
    return <OperationsPanel {...props} />;
  }
  const panel = configPanel();
  function platformView() { return <section className="panel shadow-config"><div className="section-heading"><div><h2>{names.platforms}</h2><p>{scopeName} · {t("platformsDisplayOnly")}</p></div></div><KnownPlatformsPanel /></section>; }
  function toggleInheritance(section: ShadowSection, checked: boolean) {
    setSaved(false);
    setInherit(current => checked ? [...current, section] : current.filter(item => item !== section));
  }
  function inheritanceControls() {
    const sections = areaSections[area].filter(section => (!device || section !== 'enrollment') && (section !== 'model_access' || modelControl));
    return <div className="inheritance-controls">{sections.map(section => <label className="checkbox-label" key={section}><input type="checkbox" checked={inherit.includes(section)} disabled={mutation.pending || frozen} onChange={event => toggleInheritance(section, event.target.checked)} /><span>{t("inherit")} · {sectionName[section]}{initial.inherited_from[section] && <small>{initial.inherited_from[section].name}</small>}</span></label>)}</div>;
  }
  function policyForm() { return <form className="panel shadow-config" onSubmit={event => { event.preventDefault(); void submit(); }}><div className="section-heading"><div><h2>{names[area]}</h2><p>{scopeName} · {t("revision")} {revision}</p></div>{dirty && <Badge tone="warning">{t("draft")}</Badge>}</div><ErrorNotice error={mutation.error} />{saved && <Notice tone="success">{t("configurationSavedInstallationsWillReceiveIt")}</Notice>}{inheritanceAllowed && inheritanceControls()}<fieldset disabled={mutation.pending || frozen}><InheritanceContext.Provider value={inherit}>{panel}</InheritanceContext.Provider></fieldset>{frozen ? <Notice>{t("demonstrationReadOnly")}</Notice> : <div className="config-save-bar"><p>{dirty ? t("changesWillApplyAfterServerValidation") : t("configurationSynchronizedWithTheServer")}</p><button type="button" className="button secondary" disabled={!dirty || mutation.pending} onClick={() => { setConfig(baseline.config); setInherit(baseline.inherit); setSaved(false); mutation.clear(); }}>{t("discardDraft")}</button><button type="submit" className="button primary" disabled={config.privacy.custom_rules.some(labelMatchesPattern) || !dirty || mutation.pending}>{mutation.pending ? t("validating") : t("saveChanges")}</button></div>}</form>; }
  return <><div className="shadow-settings-layout"><nav className="vnav" aria-label={t("shadowAiSections")}>{availableAreas.map((item, index) => <button key={item} type="button" aria-pressed={area === item} className={`vnav-item${area === item ? ' active' : ''}`} onClick={() => setArea(item)}><span className="n" aria-hidden="true">0{index + 1}</span><span>{names[item]}</span></button>)}</nav>{area === 'platforms' ? platformView() : policyForm()}</div>{mutation.error instanceof ApiError && mutation.error.status === 409 && <Notice tone="warning" action={<button type="button" className="button secondary" onClick={reload}>{t("discardAndReload")}</button>}>{t("yourDraftIsPreservedForA")}</Notice>}{/* Beside the setting that retains the text it deletes, not under masking: it purges
        stored request and response text, which masking has nothing to do with. */}
      {!device && area === 'capture' && can(session, 'content.purge') && <ContentPurge />}</>;
}

function ContentPurge() {
  const t = useText(); const [open, setOpen] = useState(false); const [before, setBefore] = useState(''); const [success, setSuccess] = useState(false); const mutation = useMutation();
  async function purge() { try { await mutation.run('/api/shadow/content/purge', 'POST', { before: new Date(before).toISOString() }); setOpen(false); setSuccess(true); } catch { /* MFA and scope are server-enforced. */ } }
  return <section className="panel content-purge"><h3>{t("deleteRetainedContent")}</h3><p>{t("thisOperationAffectsTextOlderThan")}</p>{success && <Notice tone="success">{t("theServerConfirmedPurgingTheMatching")}</Notice>}<button type="button" className="button secondary" onClick={() => { mutation.clear(); setOpen(true); }}>{t("prepareAPurge")}</button>{open && <Dialog title={t("purgeContent")} close={() => !mutation.pending && setOpen(false)}><form onSubmit={event => { event.preventDefault(); void purge(); }}><p>{t("matchingTextWillBePermanentlyDeleted")}</p><label>{t("contentOlderThan")}<input type="datetime-local" required value={before} onChange={e => setBefore(e.target.value)} /></label><ErrorNotice error={mutation.error} /><div className="dialog-actions"><button type="button" className="button secondary" disabled={mutation.pending} onClick={() => setOpen(false)}>{t("cancel")}</button><button type="submit" className="button primary" disabled={mutation.pending || !before}>{mutation.pending ? t("deleting") : t("confirmDeletion")}</button></div></form></Dialog>}</section>;
}
