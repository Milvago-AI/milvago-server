import { useState } from "react";
import type { SubmitEvent } from "react";
import { ApiError, request } from "./api";
import { Badge, Button, Card, DateValue, ErrorNotice, Field, Notice, PageBar, ResourceView, useMutation, useResource, useText } from "./ui";
import type { Translate } from "./ui";

type EventFilter = "all" | "blocked" | "sensitive" | "security";
type Destination = { id: "grafana" | "siem"; enabled: boolean; endpoint: string; authorization_configured: boolean; event_filter: EventFilter; metrics: boolean; shadow_events: boolean; audit: boolean };
type DeliveryStatus = { id: Destination["id"]; last_attempt: string | null; last_success: string | null; last_error: string; consecutive_failures: number; rejected_records: number; next_attempt: string | null };
type Provenance = { id: string; name: string } | null;
type Configuration = { privacy_outbox?:Record<string,number>; inherit?: boolean; inheritance_available?: boolean; inherited_from?: Provenance; lock_descendants?: boolean; locked_by?: Provenance; custom_inactive?: boolean; revision: number; destinations: Destination[]; status: DeliveryStatus[] };
type Draft = Destination & { authorization: string; clear_authorization: boolean };
function drafts(value: Configuration): Draft[] { return value.destinations.map(d => ({ ...d, event_filter: d.event_filter ?? (d.id === "siem" ? "security" : "all"), authorization: "", clear_authorization: false })); }
function authorizationPatch(inherit: boolean, d: Draft): Partial<Draft> {
  if (inherit) return {};
  if (d.clear_authorization) return { clear_authorization: true };
  if (d.authorization) return { authorization: d.authorization };
  return {};
}
function secretStatusLabel(t: Translate, d: Draft): string {
  if (d.clear_authorization) return t("removalPendingSave");
  if (d.authorization_configured) return t("secretSaved");
  return t("noSavedSecret");
}
function streamLabel(t: Translate, key: "metrics" | "shadow_events" | "audit"): string {
  if (key === "metrics") return t("metrics2");
  if (key === "shadow_events") return t("shadowAiEvents");
  return t("auditLog");
}
export function ObservabilityPage() {
  const t = useText();
  const resource = useResource<Configuration>("/api/observability");
  return <>
    <PageBar title={t("observability")} info={t("exportThisOrganizationSDataTo")} />
    <ResourceView resource={resource}>{initial => <ObservabilityEditor initial={initial} />}</ResourceView>
  </>;
}
function ObservabilityEditor({ initial }: Readonly<{ initial: Configuration }>) {
  const t = useText();
  const [savedConfig, setSavedConfig] = useState(initial);
  const [inherit, setInherit] = useState(initial.inherit ?? false);
  const [lockDescendants, setLockDescendants] = useState(initial.lock_descendants ?? false);
  const [destinations, setDestinations] = useState(() => drafts(initial));
  const [statuses, setStatuses] = useState(initial.status);
  const [outbox,setOutbox]=useState(initial.privacy_outbox);
  const [notice, setNotice] = useState("");
  const [statusError, setStatusError] = useState<unknown>();
  const [refreshing, setRefreshing] = useState(false);
  const mutation = useMutation();
  const dirty = inherit !== (savedConfig.inherit ?? false) || lockDescendants !== (savedConfig.lock_descendants ?? false) || JSON.stringify(destinations) !== JSON.stringify(drafts(savedConfig));
  const noExport = !inherit && destinations.every(d => !d.enabled);
  const locked = Boolean(savedConfig.locked_by);
  function change(id: Destination["id"], value: Partial<Draft>) { setNotice(""); setDestinations(items => items.map(d => d.id === id ? { ...d, ...value } : d)); }
  async function refreshStatus() {
    setRefreshing(true); setStatusError(undefined);
    try { const updated=await request<Configuration>("/api/observability");setStatuses(updated.status);setOutbox(updated.privacy_outbox); }
    catch (error) { setStatusError(error); }
    finally { setRefreshing(false); }
  }
  async function discardAndReload() {
    setRefreshing(true); setStatusError(undefined);
    try {
      const updated = await request<Configuration>("/api/observability");
      setSavedConfig(updated); setInherit(updated.inherit ?? false); setLockDescendants(updated.lock_descendants ?? false); setDestinations(drafts(updated)); setStatuses(updated.status);setOutbox(updated.privacy_outbox);
      setNotice(""); mutation.clear();
    } catch (error) { setStatusError(error); }
    finally { setRefreshing(false); }
  }
  async function save(event: SubmitEvent) {
    event.preventDefault(); setNotice("");
    try {
      const updated = await mutation.run<Configuration>("/api/observability", "PUT", {
        revision: savedConfig.revision, inherit, lock_descendants: !inherit && lockDescendants,
        destinations: destinations.map(d => ({
          id: d.id, enabled: d.enabled, endpoint: d.endpoint, metrics: d.metrics, shadow_events: d.shadow_events, audit: d.audit, event_filter: d.event_filter,
          ...authorizationPatch(inherit, d),
        })),
      });
      if (updated) { setSavedConfig(updated); setInherit(updated.inherit ?? false); setLockDescendants(updated.lock_descendants ?? false); setDestinations(drafts(updated)); setStatuses(updated.status);setOutbox(updated.privacy_outbox); setNotice(t("configurationSavedDeliveryIsReportedIn")); }
    } catch { /* Keep edits and display the server error. */ }
  }
  async function test(id: Destination["id"]) {
    setNotice("");
    try {
      await mutation.run("/api/observability/test", "POST", { destination_id: id });
      setNotice(t("theCollectorAcceptedTheSyntheticTest"));
      await refreshStatus();
    } catch { await refreshStatus(); }
  }
  return <>
    <Card title={t("exportedData")}>
      <p>{t("anOpentelemetryCollectorReceivesOtlpHttp")}</p>
      <ul>
        <li>{t("metricsEventsByActionAndSource")}</li>
        <li>{t("shadowAiEventsTimestampProviderAction")}</li>
        <li>{t("auditAdministrativeActionsAndTechnicalIdenti")}</li>
      </ul>
      <p className="muted">{t("logsAreExportedFromActivationWithout")}</p>
    </Card>
    <form onSubmit={save} className="observability-form">
      <ErrorNotice error={mutation.error} />
      {mutation.error instanceof ApiError && mutation.error.status === 409 && <Notice tone="warning" action={<Button disabled={refreshing} onClick={() => void discardAndReload()}>{t("discardDraftAndReload")}</Button>}>{t("yourDraftIsPreservedReloadThe")}</Notice>}
      {notice && <Notice>{notice}</Notice>}
      {savedConfig.inheritance_available && <Card title={t("configurationInheritance")}>
        <p>{savedConfig.inherit && savedConfig.inherited_from ? t("inheritedFrom") + savedConfig.inherited_from.name : t("configurationSpecificToThisOrganization")}</p>
        {locked && savedConfig.locked_by ? <Notice title={t("enforcedConfiguration")}>{t("configurationEnforcedBy") + savedConfig.locked_by.name + t("thisOrganizationCannotCustomizeItOr") + (savedConfig.custom_inactive ? " " + t("yourCustomConfigurationIsKeptBut") : "")}</Notice> : <>
        <p className="muted">{t("inheritanceAppliesToAllDestinations")}</p>
        {inherit ? <Button disabled={mutation.pending || refreshing} onClick={() => {
          setInherit(false); setNotice("");
          if (savedConfig.inherit) setDestinations(items => items.map(d => ({ ...d, authorization_configured: false, authorization: "", clear_authorization: false })));
        }}>{t("customize")}</Button> : <Button disabled={mutation.pending || refreshing} onClick={() => { setInherit(true); setNotice(""); }}>{t("restoreInheritance")}</Button>}
        <Button disabled={mutation.pending || refreshing || noExport} onClick={() => {
          setInherit(false); setNotice("");
          setDestinations(items => items.map(d => ({ ...d, enabled: false, ...(savedConfig.inherit ? { authorization_configured: false, authorization: "", clear_authorization: false } : {}) })));
        }}>{t("doNotExportAnything")}</Button>
        {noExport && <Notice title={t("noExport")}>{t("saveToDisableBothDestinationsFor")}</Notice>}
        {!inherit && !noExport && savedConfig.inherit && <Notice tone="warning">{t("inheritedSecretsAreNotCopiedEnter")}</Notice>}
        {inherit && !savedConfig.inherit && <Notice>{t("saveToReplaceThisConfigurationWith")}</Notice>}
        </>}
      </Card>}
      {!inherit && <Card title={t("childOrganizations")}>
        <label className="checkbox-label"><input type="checkbox" checked={lockDescendants} disabled={mutation.pending || refreshing} onChange={e => { setNotice(""); setLockDescendants(e.target.checked); }} />{t("enforceThisConfigurationOnChildOrganizations")}</label>
        <p className="field-help">{t("currentAndFutureChildOrganizationsAnd")}</p>
      </Card>}
      {destinations.map(d => <Card key={d.id} title={d.id === "grafana" ? "Grafana" : t("exportToSiem")} actions={d.id === "grafana" ? <a className="button secondary small" href="/api/observability/dashboard" download="milvago-grafana.json">{t("downloadDashboard")}</a> : undefined}>
        {d.id === "grafana" && <h3>{t("exportToGrafana")}</h3>}
        {d.id === "siem" && <p className="field-help">{t("sensitiveAuditsFollowSiemDestination")}</p>}
        <fieldset disabled={inherit || mutation.pending || refreshing}>
          <label className="checkbox-label"><input type="checkbox" checked={d.enabled} onChange={e => change(d.id, { enabled: e.target.checked })} />{t("enableExport")} · {d.id === "grafana" ? "Grafana" : "SIEM"}</label>
          <Field label={t("otlpHttpCollectorBaseUrl") + " · " + d.id} help={t("theServerAppendsV1MetricsAnd")}><input type="url" required={d.enabled} value={d.endpoint} onChange={e => change(d.id, { endpoint: e.target.value })} /></Field>
          <Field label={"Authorization · " + d.id} help={t(d.id === "grafana" ? "grafanaCloudOtlpAuthorizationHelp" : "completeHeaderBearerOrBasicAn")}><input type="password" autoComplete="new-password" value={d.authorization} disabled={d.clear_authorization} onChange={e => change(d.id, { authorization: e.target.value })} /></Field>
          <div className="actions">
            <Badge>{secretStatusLabel(t, d)}</Badge>
            {(d.authorization_configured || d.clear_authorization) && <Button size="small" variant={d.clear_authorization ? "secondary" : "danger"} onClick={() => change(d.id, { clear_authorization: !d.clear_authorization, authorization: "" })}>{d.clear_authorization ? t("cancelRemoval") : t("removeSecret")} · {d.id}</Button>}
          </div>
          <div className="observability-streams">
            {(["metrics", "shadow_events", "audit"] as const).map(key => <label className="checkbox-label" key={key}><input type="checkbox" checked={d[key]} onChange={e => change(d.id, { [key]: e.target.checked })} />{streamLabel(t, key)} · {d.id}</label>)}
          </div>
          <Field label={t("usageEventsToExport") + " · " + d.id} help={t("filtersOnlyShadowAiLogsAggregate")}>
            <select disabled={!d.shadow_events} value={d.event_filter} onChange={e => change(d.id, { event_filter: e.target.value as EventFilter })}>
              <option value="all">{t("allUsageEvents")}</option>
              <option value="blocked">{t("blockedEventsOnly")}</option>
              <option value="sensitive">{t("sensitiveDataOnly")}</option>
              <option value="security">{t("securityEventsBlockedRedirectedOrSensitive")}</option>
            </select>
          </Field>
        </fieldset>
        <Button disabled={dirty || mutation.pending || refreshing || !d.endpoint || !(d.metrics || d.shadow_events || d.audit)} onClick={() => void test(d.id)}>{t("testSavedConfiguration")} · {d.id}</Button>
        <p className="field-help">{t("saveBeforeTestingTheTestCan")}</p>
      </Card>)}
      <div className="settings-actions"><Button variant="primary" type="submit" disabled={!dirty || mutation.pending || refreshing}>{t("saveObservability")}</Button></div>
    </form>
    <Card title={t("deliveryStatus")} actions={<Button icon="refresh" disabled={refreshing || mutation.pending} onClick={() => void refreshStatus()}>{t("refreshStatuses")}</Button>}>
      <ErrorNotice error={statusError} />
      {outbox&&<section><h3>{t("privacyAuditQueue")}</h3><p>{t("queueOldestPending",[outbox.oldest_pending_seconds??0])}</p><dl className="dl">{Object.entries({pending:"queuePending",held:"queueHeld",failed:"queueFailed"} as const).map(([state,label])=><div key={state}><dt>{t(label)}</dt><dd>{outbox[state]??0}</dd></div>)}</dl></section>}
      <p className="muted">{t("collectorAcceptanceDoesNotConfirmArrival")}</p>
      <div className="table-scroll"><table><thead><tr><th>{t("destination")}</th><th>{t("lastAttempt")}</th><th>{t("lastAcceptance")}</th><th>{t("consecutiveFailures")}</th><th>{t("rejectedRecords")}</th><th>{t("nextAttempt")}</th><th>{t("error")}</th></tr></thead><tbody>{destinations.map(d => {
        const status = statuses.find(s => s.id === d.id);
        return <tr key={d.id}><td>{d.id === "grafana" ? "Grafana" : "SIEM"}</td><td>{status?.last_attempt ? <DateValue value={status.last_attempt} /> : t("noAttempt")}</td><td><DateValue value={status?.last_success ?? null} /></td><td>{status?.consecutive_failures ?? 0}</td><td>{status?.rejected_records ?? 0}</td><td><DateValue value={status?.next_attempt ?? null} /></td><td>{status?.last_error || "—"}</td></tr>;
      })}</tbody></table></div>
    </Card>
  </>;
}
