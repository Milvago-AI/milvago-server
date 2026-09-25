import { useContext } from 'react';
import { UpdateStatus } from './UpdateStatus';
import { Badge, Context, Empty, Icon, Notice, ResourceView, useResource, useText } from '../ui';
import { Categories, CapabilityNote, ConfigBlock, Lines, Mode, Toggle } from './ConfigFields';
import type { ModelAccessCount, ModelAccessStatus, ModelCatalogEntry, Operations, ShadowConfig } from './types';

type SettingsPanelProps = Readonly<{
  config: ShadowConfig;
  update: <K extends keyof ShadowConfig>(section: K, value: ShadowConfig[K]) => void;
}>;
type CapturePanelProps = SettingsPanelProps & Readonly<{ device: boolean }>;
type ServicesPanelProps = SettingsPanelProps & Readonly<{ capabilities: Record<string, boolean>; modelCatalog: ModelCatalogEntry[] }>;
type PrivacyPanelProps = SettingsPanelProps & Readonly<{ capabilities: Record<string, boolean> }>;
type ModelAccessPanelProps = SettingsPanelProps & Readonly<{ capabilities: Record<string, boolean>; modelCatalog: ModelCatalogEntry[] }>;
const pii = ['email', 'phone', 'iban', 'card', 'social_id', 'ssn_us', 'ip'];
function modelStatusTone(status: ModelAccessStatus['status']) {
  if (status === 'applied') return 'success' as const;
  if (status === 'unavailable') return 'danger' as const;
  return 'warning' as const;
}

function modelStatusLabel(status: ModelAccessStatus['status'], t: ReturnType<typeof useText>) {
  if (status === 'needs_update') return t("needsUpdate");
  if (status === 'pending') return t("pending");
  if (status === 'applied') return t("applied");
  return t("unavailable");
}

// Product decision of 2026-09-23: rules mixing network and domain. Each rule requires a CIDR;
// the domain, declared by the machine, only narrows the rule. The old `cidrs` are
// presented as rules with no domain and rewritten into `rules` on save.
function ApprovalRules({ enrollment, change }: Readonly<{ enrollment: ShadowConfig['enrollment']; change: (next: ShadowConfig['enrollment']) => void }>) {
  const t = useText();
  const rules = [...(enrollment.cidrs ?? []).map(cidr => ({ cidr, domain: '' })), ...(enrollment.rules ?? [])];
  const set = (next: typeof rules) => change({ ...enrollment, cidrs: [], rules: next });
  const edit = (index: number, field: 'cidr' | 'domain', value: string) => set(rules.map((rule, position) => position === index ? { ...rule, [field]: value } : rule));
  return <div className="approval-rules">
    <Notice tone="warning">{t("approvalDomainDeclaredNotProof")}</Notice>
    {rules.map((rule, index) => <div className="config-inline approval-rule" key={index}>
      <label>{t("approvalRuleNetwork")}<input className="mono" required maxLength={49} value={rule.cidr} placeholder="198.51.100.0/24" onChange={e => edit(index, 'cidr', e.target.value.trim())} /></label>
      <label>{t("approvalRuleDomain")}<input className="mono" maxLength={253} value={rule.domain} placeholder="corp.example.com" onChange={e => edit(index, 'domain', e.target.value.trim())} /></label>
      <button type="button" className="button danger small" aria-label={`${t("deleteApprovalRule")} ${index + 1}`} onClick={() => set(rules.filter((_, position) => position !== index))}>{t("delete")}</button>
    </div>)}
    <button type="button" className="button secondary" onClick={() => set([...rules, { cidr: '', domain: '' }])}><Icon name="plus" />{t("addApprovalRule")}</button>
    <p className="field-help">{t("approvalRulesHelp")}</p>
  </div>;
}

export function CapturePanel({ config, update, device }: CapturePanelProps) {
  const t = useText(); const enrollment = config.enrollment; const collection = config.collection;
  return <>{!device && <ConfigBlock section="enrollment" title={t("deviceApproval")} description={t("chooseHowANewInstallationReceives")}><label>{t("approvalMode")}<select value={enrollment.approval} onChange={e => update('enrollment', { ...enrollment, approval: e.target.value as typeof enrollment.approval })}><option value="manual">{t("manualApproval")}</option><option value="automatic">{t("automaticApproval")}</option><option value="network">{t("allowedNetwork")}</option></select></label>{enrollment.approval === 'network' && <ApprovalRules enrollment={enrollment} change={next => update('enrollment', next)} />}</ConfigBlock>}<ConfigBlock section="collection" title={t("browserCollection")} description={t("communityConnectsTheExtensionToThe")}><Toggle label={t("enableCollection")} checked={collection.enabled} change={enabled => update('collection', { ...collection, enabled })} /><Toggle label={t("retainRequestAndResponseText")} checked={collection.store_content} change={store_content => update('collection', { ...collection, store_content })} help={t("offByDefaultEnablingRequiresA")} /><label>{t("textRetentionDays")}<input type="number" min={1} max={30} required value={collection.content_retention_days} onChange={e => update('collection', { ...collection, content_retention_days: Number(e.target.value) })} /></label><Toggle label={t("retainSubmittedFileNames")} checked={collection.store_file_names} change={store_file_names => update('collection', { ...collection, store_file_names })} help={t("namesOnlyNeverContentsTheyAre")} /><p className="field-help">{t("turningContentOffStopsNewCollection")}</p></ConfigBlock></>;
}

export function ServicesPanel({ config, update, capabilities, modelCatalog }: ServicesPanelProps) {
  const t = useText(); const names: Record<string, string> = { chatgpt: 'ChatGPT', claude: 'Claude', lechat: 'Le Chat', copilot: 'Copilot', gemini: 'Gemini', notebooklm: 'NotebookLM', deepseek: 'DeepSeek', perplexity: 'Perplexity', grok: 'Grok' };
  return <><ConfigBlock section="services" title={t("coveredServices")} description={t("theCatalogAndAllowedDomainsCome")}><div className="service-list">{config.services.map(service => <div className="service-card" key={service.id}><div className="service-card-heading"><Toggle label={names[service.id] ?? service.id} checked={service.enabled} change={enabled => update('services', config.services.map(item => item.id === service.id ? { ...item, enabled } : item))} /><span className="mono">{service.domains.join(', ')}</span></div><Mode label={t("behavior")} value={service.mode} redirect change={mode => update('services', config.services.map(item => item.id === service.id ? { ...item, mode: mode as typeof service.mode } : item))} />{service.mode === 'redirect' && <label>{t("redirectDestination")}<input required type="url" maxLength={2000} value={service.redirect_url} placeholder="https://ai.example.org" onChange={e => update('services', config.services.map(item => item.id === service.id ? { ...item, redirect_url: e.target.value } : item))} /></label>}</div>)}</div></ConfigBlock>{(capabilities.model_access_browser || capabilities.model_access_native) && <ModelAccessPanel config={config} update={update} capabilities={capabilities} modelCatalog={modelCatalog} />}</>;
}

export function ProtectionPanel({ config, update }: SettingsPanelProps) {
  const t = useText(); const value = config.protection;
  return <><ConfigBlock section="protection" title={t("attachments")}><Toggle label={t("blockFileUploads")} checked={value.block_uploads} change={block_uploads => update('protection', { ...value, block_uploads })} help={t("interceptionDependsOnTheBrowserAnd")} /></ConfigBlock><ConfigBlock section="protection" title={t("protectedWordsAndPhrases")} description={t("detectionsAreAppliedLocallyAccordingTo")}><Lines label={t("protectedPhrases")} values={value.keywords} change={keywords => update('protection', { ...value, keywords })} help={t("onePhrasePerLineDoNot")} /><div className="config-inline"><Mode label={t("exactMatch")} value={value.exact} change={exact => update('protection', { ...value, exact: exact as typeof value.exact })} /><Mode label={t("unicodeVariants")} value={value.unicode} change={unicode => update('protection', { ...value, unicode: unicode as typeof value.unicode })} /><Mode label={t("approximateMatch")} value={value.fuzzy} off change={fuzzy => update('protection', { ...value, fuzzy: fuzzy as typeof value.fuzzy })} /></div><Lines label={t("exceptions")} values={value.exceptions} change={exceptions => update('protection', { ...value, exceptions })} help={t("oneExceptionPerLineExceptionsReduce")} /><label>{t("messageShownWhenBlocked")}<textarea rows={3} maxLength={1000} value={value.message} onChange={e => update('protection', { ...value, message: e.target.value })} /></label></ConfigBlock></>;
}

// Product decision of 2026-09-16: a label that its own expression matches is refused.
// The label becomes the placeholder inserted into the masked text (`[LABEL]`, `[LABEL1]`...); if
// the expression recognises it, the placeholder would itself be masked again on every pass, endlessly.
// Same test as the server: the label alone, with the rule's case sensitivity -- not the placeholder's
// number, without which any numeric rule ("NUMERO", `[0-9]+`) would be refused when
// `[NUMERO1]` is exactly the intended form.
export function labelMatchesPattern(rule: { label: string; pattern: string; case_insensitive: boolean }): boolean {
  if (!rule.label || !rule.pattern) return false;
  try { return new RegExp(rule.pattern, rule.case_insensitive ? 'i' : '').test(rule.label); } catch { return false; }
}
export function PrivacyPanel({ config, update, capabilities }: PrivacyPanelProps) {
  const t = useText(); const value = config.privacy;
  return <><ConfigBlock section="privacy" title={t("localDataMasking")} description={t("actsOnTheCapturedTextOn")}><Toggle label={t("enableMasking")} checked={value.enabled} change={enabled => update('privacy', { ...value, enabled })} /><Toggle label={t("requireReviewBeforeSending")} checked={value.review} change={review => update('privacy', { ...value, review })} />{capabilities.local_privacy_patterns && <Categories values={value.types} allowed={pii} change={types => update('privacy', { ...value, types })} />}<CapabilityNote available={Boolean(capabilities.local_privacy_patterns)}>{t("thisEditionShipsNoBuiltIn")}</CapabilityNote></ConfigBlock><ConfigBlock section="privacy" title={t("customMaskingRules")} description={t("boundedRegularExpressionsWithoutBackreferenc")}><div className="custom-rule-list">{value.custom_rules.map((rule, index) => <div className="custom-rule" key={rule.id}><label>{t("label")}<input required maxLength={60} value={rule.label} onChange={e => update('privacy', { ...value, custom_rules: value.custom_rules.map(item => item.id === rule.id ? { ...item, label: e.target.value } : item) })} /></label><label>{t("regularExpression")}<input className="mono" required maxLength={200} value={rule.pattern} aria-invalid={labelMatchesPattern(rule)} onChange={e => update('privacy', { ...value, custom_rules: value.custom_rules.map(item => item.id === rule.id ? { ...item, pattern: e.target.value } : item) })} /></label>{labelMatchesPattern(rule) && <Notice tone="danger">{t("customRuleLabelMatchesItsOwnPattern")}</Notice>}<div className="config-inline"><Toggle label={t("enabled")} checked={rule.enabled} change={enabled => update('privacy', { ...value, custom_rules: value.custom_rules.map(item => item.id === rule.id ? { ...item, enabled } : item) })} /><Toggle label={t("ignoreCase")} checked={rule.case_insensitive} change={case_insensitive => update('privacy', { ...value, custom_rules: value.custom_rules.map(item => item.id === rule.id ? { ...item, case_insensitive } : item) })} /><button type="button" className="button danger small" aria-label={`${t("deleteCustomRule")} ${index + 1}`} onClick={() => update('privacy', { ...value, custom_rules: value.custom_rules.filter(item => item.id !== rule.id) })}>{t("delete")}</button></div></div>)}</div><button type="button" className="button secondary" onClick={() => update('privacy', { ...value, custom_rules: [...value.custom_rules, { id: crypto.randomUUID(), label: '', pattern: '', case_insensitive: true, enabled: true }] })}><Icon name="plus" />{t("addRule")}</button></ConfigBlock></>;
}

export function ClassificationPanel({ config, update }: SettingsPanelProps) {
  const t = useText(); const allowed = [...pii, 'source_code', 'medical', 'keyword']; const hints: Record<string, string> = { keyword: t("keywordsAreDefinedUnder03Protections"), medical: t("triggeredByTheTermsListedIn") };
  return <><ConfigBlock section="classification" title={t("browserUsageSensitivity")} description={t("decidesWhichDetectedCategoriesMarkAn")}><Categories allowed={allowed} hints={hints} values={config.classification.browser} change={browser => update('classification', { ...config.classification, browser })} /></ConfigBlock><ConfigBlock section="classification" title={t("localApplicationSensitivity")}><Categories allowed={allowed} hints={hints} values={config.classification.coding} change={coding => update('classification', { ...config.classification, coding })} /></ConfigBlock><ConfigBlock section="classification" title={t("medicalTerms")} description={t("aTextContainingOneOfThese")}><Lines label={t("triggerTerms")} values={config.classification.medical_terms ?? []} change={medical_terms => update('classification', { ...config.classification, medical_terms })} help={t("oneTermPerLineAtMost")} /></ConfigBlock></>;
}

export function OperationsPanel({ config, update, capabilities }: PrivacyPanelProps) {
  const t = useText(); const { session } = useContext(Context); const value = config.operations; const resource = useResource<Operations>('/api/shadow/operations');
  return <><ConfigBlock section="operations" title={t("updatesAndPilotDevices")}><Toggle label={t("enableSignedUpdates")} checked={value.updates.enabled} disabled={!capabilities.signed_updates} change={enabled => update('operations', { ...value, updates: { ...value.updates, enabled } })} /><label>{t("pilotDevicePercentage")}<input type="number" min={0} max={100} required disabled={!capabilities.signed_updates} value={value.updates.percentage} onChange={e => update('operations', { ...value, updates: { ...value.updates, percentage: Number(e.target.value) } })} /></label><Lines label={t("pilotDeviceIdentifiers")} disabled={!capabilities.signed_updates} values={value.updates.device_ids} change={device_ids => update('operations', { ...value, updates: { ...value.updates, device_ids } })} /><Lines label={t("pausedVersions")} disabled={!capabilities.signed_updates} values={value.updates.paused_versions} change={paused_versions => update('operations', { ...value, updates: { ...value.updates, paused_versions } })} /><CapabilityNote available={Boolean(capabilities.signed_updates)}>{t("noSignedUpdateDeliveryChainIs")}</CapabilityNote>{capabilities.signed_updates && !value.updates.enabled && <Notice tone="warning" title={t("devicesWillReceiveNoFix")}>{t("signedUpdatesAreOffAgentsStay")}</Notice>}</ConfigBlock><section className="config-block"><div><h3>{t("serverReportedStatus")}</h3><p>{session.organization.name}</p></div><div className="config-block-fields"><ResourceView resource={resource}>{status => <><Notice>{status.updates.available ? t("theServerReportsUpdatesAvailable") : status.updates.reason || t("updatesUnavailable")}</Notice><UpdateStatus updates={status.updates} /></>}</ResourceView></div></section></>;
}
const modelId = /^[a-zA-Z0-9][a-zA-Z0-9._:/+-]{0,199}$/;
function ModelAccessPanel({ config, update, capabilities, modelCatalog }: ModelAccessPanelProps) {
  const t = useText(); const access = config.model_access ?? [];
  const status = useResource<{ items: ModelAccessStatus[]; counts?: ModelAccessCount[] }>('/api/model-access/status');
  const catalog = modelCatalog.filter(item => item.channel === 'browser' || capabilities.model_access_native);
  function replace(next: typeof access[number]) {
    update('model_access', [...access.filter(item => item.platform_id !== next.platform_id || item.channel !== next.channel), next]);
  }
  return <ConfigBlock section="model_access" title={t("modelControls")} description={t("serviceRestrictionsTakePrecedenceTheseRules")}>
    <Notice tone="warning">{t("confinementCoversRegisteredExecutablesOnly")}</Notice>
    <div className="model-access-list">{catalog.map(item => {
      const rule = access.find(value => value.platform_id === item.platform_id && value.channel === item.channel) ?? { platform_id: item.platform_id, channel: item.channel, mode: 'off' as const, models: [] };
      const invalid = rule.models.some(model => !modelId.test(model)) || rule.models.length > 100;
      return <article className="model-access-card" key={`${item.platform_id}:${item.channel}`}>
        <div><h4>{item.name}</h4><p>{item.provider} · {item.channel === 'browser' ? t("browser") : t("localApplication")}</p></div>
        <label>{t("rule")}<select aria-label={`${t("rule")} ${item.name}`} value={rule.mode} onChange={e => replace({ ...rule, mode: e.target.value as typeof rule.mode })}>
          <option value="off">{t("noRestriction")}</option>
          <option value="denylist">{t("allowAllExceptListed")}</option>
          <option value="allowlist">{t("denyAllExceptListed")}</option>
        </select></label>        {rule.mode !== 'off' && <><label>{t("models")}<textarea aria-label={`${t("models")} ${item.name}`} rows={4} maxLength={20100} value={rule.models.join('\n')} onChange={e => replace({ ...rule, models: e.target.value.split('\n').map(value => value.trim()).filter(Boolean) })} /><span className="field-help">{t("oneExactIdentifierPerLineMaximum")}</span></label>
          {invalid && <p className="capability-note" role="alert">{t("eachIdentifierMustUse1To")}</p>}
          <p className="model-warning">{t("unverifiableUnknownOrAutoModelsAre")}</p>
        </>}
        
        
      </article>;
    })}</div>
    <section className="model-status"><h3>{t("appliedDeviceStatus")}</h3><p>{t("savedRulesRemainDistinctFromRevisions")}</p>
    <ResourceView resource={status}>{data => data.counts?.length ? <div className="table-scroll"><table><thead><tr><th>{t("platform")}</th><th>{t("status")}</th><th>{t("devices")}</th></tr></thead><tbody>{data.counts.map(item => <tr key={`${item.platform_id}:${item.channel}:${item.status}`}><td>{item.platform_id}<span className="cell-detail">{item.channel}</span></td><td><Badge tone={modelStatusTone(item.status)}>{modelStatusLabel(item.status, t)}</Badge></td><td>{item.devices}</td></tr>)}</tbody></table></div> : data.items.length ? <div className="table-scroll"><table><thead><tr><th>{t("device")}</th><th>{t("platform")}</th><th>{t("status")}</th><th>{t("revision")}</th><th>{t("reason")}</th></tr></thead><tbody>{data.items.map(item => <tr key={`${item.device_id}:${item.platform_id}:${item.channel}`}><td><strong>{item.hostname || t("machineNameUnavailable")}</strong><span className="cell-detail mono">{item.device_id}</span><span className="cell-detail">{item.version}</span></td><td>{item.platform_id}<span className="cell-detail">{item.channel}</span></td><td><Badge tone={modelStatusTone(item.status)}>{modelStatusLabel(item.status, t)}</Badge></td><td>{item.applied_revision} / {item.expected_revision}</td><td>{item.reason || '—'}</td></tr>)}</tbody></table></div> : <Empty title={t("noModelStatusReported")} />}</ResourceView>
    </section>
  </ConfigBlock>;
}
