import { useContext, useState } from "react";
import { Card, clampPage, Context, DateValue, Dialog, Empty, ErrorNotice, Icon, Notice, PageNumbers, PageSize, ResourceView, readOnly, useMutation, useResource, useText } from "./ui";

/**
 * Pages one list the server already sent whole. Both tables here are bounded by the
 * server (500 candidate domains, the reached platforms of a signed catalogue), so the
 * paging is a reading aid, not a way to fetch less. Shrinking the list under a page
 * that no longer exists — filtering, a reload — falls back to the last one rather than
 * showing an empty table.
 */
function usePaged<T>(items: T[], initial = 20) {
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(initial);
  const pages = Math.max(1, Math.ceil(items.length / size));
  const current = clampPage(page, pages);
  return {
    page: current, pages, size, go: setPage,
    resize: (value: number) => { setSize(value); setPage(1); },
    rows: items.slice((current - 1) * size, current * size),
  };
}

type Platform = { provider: string; visits: number; devices: number; accounts: number; last_seen: string };
type Candidates = { items: { domain: string; count: number; status: string }[]; platforms?: Platform[] };
type CandidateDevices = { items: { device_id: string; hostname: string; observations: number; last_seen: string }[]; window_days: number };
// Only the published domains matter here, so the catalogue is read for those alone
// rather than through the editor's full shape.
type PublishedCatalog = { content: { providers: { domains: string[]; aliases: string[] }[] } };

// What the fleet reached that the catalogue does not cover. The one screen here that
// answers a question a customer actually asks — which AI are my people using that I do
// not watch — so it lives in Monitoring rather than under Administration.
export function DiscoveryPage() {
  const t = useText();
  const { session } = useContext(Context);
  const candidates = useResource<Candidates>("/api/detection/candidates");
  // Promotion used to be offered only if this browsing session had just published a
  // catalogue, which no customer ever does, so the button never appeared. The
  // catalogue is read directly instead. The server remains the authority: promoting a
  // domain it does not carry still answers 409 catalog_publication_required.
  const catalog = useResource<PublishedCatalog>("/api/detection/catalog");
  const mutation = useMutation();
  const frozen = readOnly(session);
  // Which machines reached a known platform is answered in both editions . Which reached a candidate domain stays Enterprise's answer: that route
  // exists only there, so Community keeps plain text rather than a control answering 404.
  const [inspected, setInspected] = useState<{ title: string; path: string; platform: boolean } | null>(null);
  const inventoried = session.edition === "commercial";
  // Read from the resource rather than from inside ResourceView: its children unmount on
  // every reload, and the page a reader had reached would go with them.
  const platforms = usePaged(candidates.data?.platforms ?? []);
  const domains = usePaged(candidates.data?.items ?? []);
  const published = new Set((catalog.data?.content.providers ?? []).flatMap(provider => [...provider.domains, ...provider.aliases]));
  async function set(domain: string, status: string) {
    try { await mutation.run("/api/detection/candidates", "PATCH", { domain, status }); candidates.reload(); }
    catch { /* Visible server error. */ }
  }
  return <ResourceView resource={candidates}>{data => <>
    {/* Presence, not coverage: the host was reached and nothing was read from the page.
        Which machine and which OS account are behind a visit are read through
        Conversations, where identities stay under the organization's pseudonymisation. */}
    <Card title={t("knownPlatforms")} actions={data.platforms?.length ? <div className="heading-controls"><span className="muted">{t("resultsCount", [data.platforms.length])}</span><PageSize value={platforms.size} label={t("perPage")} change={platforms.resize} /></div> : undefined}>
      <Notice>{t("knownPlatformsNotice")} {t("knownPlatformsEnterprise")}</Notice>
      {data.platforms?.length
        ? <><div className="table-scroll"><table className="privacy-table">
          <thead><tr><th>{t("service")}</th><th>{t("visits")}</th><th>{t("devices")}</th><th>{t("osAccounts")}</th><th>{t("lastSeen")}</th></tr></thead>
          <tbody>{platforms.rows.map(platform => <tr key={platform.provider}>
            <td><button type="button" className="text-link" title={t("reachedByDevices")} onClick={() => setInspected({ title: platform.provider, path: `/api/detection/platforms/${encodeURIComponent(platform.provider)}/devices`, platform: true })}><strong>{platform.provider}</strong></button></td>
            <td>{platform.visits}</td>
            <td>{platform.devices}</td>
            <td>{platform.accounts}</td>
            <td><DateValue value={platform.last_seen} /></td>
          </tr>)}</tbody>
        </table></div>
        <PageNumbers page={platforms.page} pages={platforms.pages} go={platforms.go} label={t("pagination")} /></>
        : <Empty title={t("knownPlatformsNone")} />}
    </Card>
    <Card title={t("candidateDomains")} actions={data.items.length ? <div className="heading-controls"><span className="muted">{t("resultsCount", [data.items.length])}</span><PageSize value={domains.size} label={t("perPage")} change={domains.resize} /></div> : undefined}>
    <ErrorNotice error={mutation.error} />
    {data.items.length
      ? <><div className="table-scroll"><table className="privacy-table">
        <thead><tr><th>{t("domain")}</th><th>{t("detectionObservations")}</th><th>{t("actions")}</th></tr></thead>
        <tbody>{domains.rows.map(row => <tr key={row.domain}>
          <td>{inventoried
            ? <button type="button" className="text-link" title={t("reachedByDevices")} onClick={() => setInspected({ title: row.domain, path: `/api/detection/candidates/${encodeURIComponent(row.domain)}/devices`, platform: false })}>{row.domain}</button>
            : row.domain}</td>
          <td>{row.count}</td>
          {/* A demo instance shows the discovered domains and does not
              classify them: the column stays, empty, rather than carrying buttons
              that the server would refuse. */}
          <td><div className="row-actions">
            {!frozen && published.has(row.domain) && row.status !== "promoted" && <button className="button secondary small" disabled={mutation.pending} onClick={() => void set(row.domain, "promoted")}>{t("catalogPromoteCandidate")}</button>}
            {!frozen && <button className="button secondary small" disabled={mutation.pending} onClick={() => void set(row.domain, row.status === "ignored" ? "new" : "ignored")}>{t(row.status === "ignored" ? "detectionReconsider" : "detectionIgnore")}</button>}
          </div></td>
        </tr>)}</tbody>
      </table></div>
      <PageNumbers page={domains.page} pages={domains.pages} go={domains.go} label={t("pagination")} /></>
      // An empty table is the normal state, not a failure: discovery is off unless the
      // organization turned it on, and nothing else on this page would say so.
      : <Empty title={t("discoveryNoCandidates")}><a className="text-link" href="#shadow">{t("discoveryDisabledHint")}</a></Empty>}
    </Card>
    {inspected && <ReachedByDialog title={inspected.title} path={inspected.path} platform={inspected.platform} close={() => setInspected(null)} />}
  </>}</ResourceView>;
}

/**
 * The machines behind one line of this screen, read on demand.
 *
 * Both halves answer the same question — which machines went there — from different
 * records: a candidate domain is counted by the detector reports, a known platform by
 * its presence events. One dialog, two routes, because a reader asking "who reached
 * this" does not care which table holds the answer.
 */
function ReachedByDialog({ title, path, platform, close }: Readonly<{ title: string; path: string; platform: boolean; close: () => void }>) {
  const t = useText();
  const devices = useResource<CandidateDevices>(path);
  // A platform reached by an entire fleet yields hundreds of rows: the
  // search filters as you type and pagination bounds what is rendered. The
  // filter also matches the identifier, because that is what a reader coming from a
  // device sheet has at hand.
  const [query, setQuery] = useState("");
  const term = query.trim().toLowerCase();
  const items = (devices.data?.items ?? []).filter(row => !term || row.hostname.toLowerCase().includes(term) || row.device_id.toLowerCase().includes(term));
  const paged = usePaged(items);
  return <Dialog title={title} close={close} side="list">
    <ResourceView resource={devices}>{data => <div className="dialog-body">
      {/* A platform counts presence events, kept for the organization's retention; a
          candidate domain counts detector reports, purged at thirty days. */}
      <Notice>{t(platform ? "platformDevicesWindow" : "candidateDevicesWindow", [data.window_days])}</Notice>
      {data.items.length ? <>
        <div className="dialog-toolbar">
          <label className="dialog-search"><Icon name="search" /><input type="search" value={query} onChange={event => setQuery(event.target.value)} aria-label={t("candidateDevicesSearch")} placeholder={t("candidateDevicesSearchPlaceholder")} maxLength={100} /></label>
          <div className="heading-controls"><span className="muted">{t("resultsCount", [items.length])}</span><PageSize value={paged.size} label={t("perPage")} change={paged.resize} /></div>
        </div>
        {paged.rows.length
          ? <><div className="table-scroll"><table className="privacy-table">
            <thead><tr><th>{t("device")}</th><th>{t("detectionObservations")}</th><th>{t("lastSeen")}</th></tr></thead>
            <tbody>{paged.rows.map(row => <tr key={row.device_id}>
              <td><a className="text-link" href={`#devices?id=${row.device_id}`}>{row.hostname}</a></td>
              <td>{row.observations}</td>
              <td><DateValue value={row.last_seen} /></td>
            </tr>)}</tbody>
          </table></div>
          <PageNumbers page={paged.page} pages={paged.pages} go={paged.go} label={t("pagination")} /></>
          : <Empty title={t("candidateDevicesNoMatch")} />}
      </>
        : <Empty title={t("candidateDevicesNone")} />}
    </div>}</ResourceView>
  </Dialog>;
}
