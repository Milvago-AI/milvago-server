import { useContext, useEffect, useMemo, useState } from 'react';
import { Card, Context, DateValue, Empty, Icon, Kpi, ResourceView, useResource, useText } from '../ui';
import type { TranslationKey } from '../locales/en';
import { criteriaFromHash, serializeCriteria, valueOf as criteriaValue } from './filters';
import { labelOf, safe, valueOf } from './flowLayout';
import type { Dimension } from './flowLayout';
import { normalise } from './flowView';
import type { Cartography, Criteria, Flow } from './types';

/**
 * The printable report of what the fleet asked of AI, over the scope the reader is
 * looking at.
 *
 * A page rather than a document forged by the server (product decision, 2026-09-17): the
 * browser prints it, so accents, the four languages and the product's own look come
 * for free and the server keeps no PDF library. What it replaces was a single A4
 * sheet in Helvetica without an encoding — six lines, no table, no chart, no accent.
 *
 * It reads `/api/shadow/cartography`, the aggregate the map itself is drawn from, with
 * the same criteria, so it inherits that route's gates: individual reporting required
 * (`aggregate_only` refuses outright), machine and person names already projected by
 * the server, subject filters already audited. No second route is asked to enrich the
 * figures, and the payload it reads carries no prompt, no response and no file name.
 *
 * Printing: one `.report-sheet` is one printed page (`break-before:page` plus a
 * minimum height in `styles.css`), which is what makes the per-sheet page numbers
 * true. Chromium implements no `@page` margin box, so a running page counter is not
 * available; the real-browser check asserts pages == sheets rather than trusting it.
 */

/** One ranked line: a value of the scope with its totals. */
type Rank = { value: string; label: string; count: number; blocked: number; sensitive: number };
/** Ten ranked lines per table, five bars above it. Measured, not guessed: a sheet is
 *  one printed page, and twelve values with ten bars ran 143 px past the A4 content
 *  box, which pushed the page numbers out of step with the pages. */
const TOP = 10;
const BARS = 5;

function rank(flows: Flow[], dimension: Dimension): Rank[] {
  const rows = new Map<string, Rank>();
  for (const flow of flows) {
    const value = valueOf(flow, dimension);
    const row = rows.get(value) ?? { value, label: labelOf(flow, dimension), count: 0, blocked: 0, sensitive: 0 };
    row.count += safe(flow.count);
    row.blocked += safe(flow.blocked);
    row.sensitive += safe(flow.sensitive);
    rows.set(value, row);
  }
  return [...rows.values()].sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
}

/** The filters the reader narrowed to, spelled out: a report without its scope is unreadable. */
const SCOPE: { key: string; label: TranslationKey }[] = [
  { key: 'actor_id', label: 'actorIdentifier' },
  { key: 'device_id', label: 'deviceIdentifier' },
  { key: 'tool', label: 'browserApplication' },
  { key: 'provider', label: 'service' },
  { key: 'model', label: 'model' },
  { key: 'sensitivity', label: 'sensitivity' },
  { key: 'action', label: 'action' },
  { key: 'kind', label: 'kind' },
  { key: 'attachment', label: 'attachedFiles' },
  { key: 'query', label: 'search2' },
];

/**
 * Requests over time. The overview's timeline chart without its blocked stack, which
 * `series` does not carry: same viewBox, same classes, same tokens, so it reads in
 * both themes and prints with the rest of the sheet.
 */
function HourlyBars({ points, label }: Readonly<{ points: Cartography['series']; label: string }>) {
  const { language } = useContext(Context);
  const width = 760, height = 210, left = 44, top = 10, bottom = 180;
  const shown = points.slice(-336);
  const max = Math.max(...shown.map(point => safe(point.requests)), 1);
  const step = (width - left) / Math.max(shown.length, 1);
  const bar = Math.max(1, Math.min(18, step - 2));
  const every = Math.max(1, Math.ceil(shown.length / 6));
  const when = (iso: string) => Number.isNaN(Date.parse(iso)) ? String(iso ?? '') : new Intl.DateTimeFormat(language, { day: '2-digit', month: '2-digit', hour: '2-digit' }).format(new Date(iso));
  return <svg className="chart-svg" viewBox={`0 0 ${width} ${height}`} role="img" aria-label={label}>
    {[0, 0.5, 1].map(tick => {
      const y = bottom - tick * (bottom - top);
      return <g key={tick}>
        <line className="grid" x1={left} x2={width} y1={y} y2={y} />
        <text className="axis" x={left - 8} y={y + 4} textAnchor="end">{Math.round(max * tick)}</text>
      </g>;
    })}
    {shown.map((point, index) => {
      const value = safe(point.requests);
      const full = (value / max) * (bottom - top);
      const x = left + index * step + (step - bar) / 2;
      return <g key={point.at ?? index} className="bar-group">
        <title>{`${when(point.at)} · ${value}`}</title>
        <rect className="bar" x={x} y={bottom - full} width={bar} height={full} />
        {index % every === 0 && <text className="axis" x={x} y={height - 4}>{when(point.at)}</text>}
      </g>;
    })}
  </svg>;
}

/** The overview's ranked bar list, reused as it stands: no new stylesheet for the report. */
function Ranking({ rows, total }: Readonly<{ rows: Rank[]; total: number }>) {
  const t = useText();
  const share = (value: number) => total > 0 ? (value / total) * 100 : 0;
  return <div className="providers">
    {rows.map(row => <div className="provider" key={row.value}>
      <div className="provider-name">
        <strong>{row.label}</strong>
        <div className="provider-track">
          <span style={{ width: `${share(row.count - row.blocked)}%` }} />
          <span className="blocked" style={{ width: `${share(row.blocked)}%` }} />
        </div>
      </div>
      <span className="provider-count">{row.count.toLocaleString()}<small>{row.blocked.toLocaleString()} {t("blocked2")}</small></span>
    </div>)}
  </div>;
}

function RankTable({ rows, total, head, sensitivity }: Readonly<{ rows: Rank[]; total: number; head: string; sensitivity: boolean }>) {
  const t = useText();
  const shown = rows.slice(0, TOP);
  const rest = rows.slice(TOP);
  const sum = (pick: (row: Rank) => number) => rest.reduce((total, row) => total + pick(row), 0);
  const share = (value: number) => total > 0 ? `${Math.round((value / total) * 100)} %` : '—';
  return <div className="table-scroll"><table className="privacy-table">
    <thead><tr><th>{head}</th><th>{t("requests")}</th><th>{t("share")}</th><th>{t("blocked")}</th>{sensitivity && <th>{t("sensitive")}</th>}</tr></thead>
    <tbody>
      {shown.map(row => <tr key={row.value}>
        <td>{row.label}</td>
        <td>{row.count.toLocaleString()}</td>
        <td>{share(row.count)}</td>
        <td>{row.blocked.toLocaleString()}</td>
        {sensitivity && <td>{row.sensitive.toLocaleString()}</td>}
      </tr>)}
      {rest.length > 0 && <tr>
        <td>{t("reportOthers", [rest.length])}</td>
        <td>{sum(row => row.count).toLocaleString()}</td>
        <td>{share(sum(row => row.count))}</td>
        <td>{sum(row => row.blocked).toLocaleString()}</td>
        {sensitivity && <td>{sum(row => row.sensitive).toLocaleString()}</td>}
      </tr>}
    </tbody>
  </table></div>;
}

export function ReportPage() {
  const t = useText();
  const { session, language } = useContext(Context);
  const sensitivity = session.edition === 'commercial';
  // The scope travels in the hash, written by the screen the reader came from.
  // `criteriaFromHash` keeps only the filter keys the server knows, so a forged
  // parameter never reaches the query.
  const [criteria, setCriteria] = useState<Criteria>(criteriaFromHash);
  useEffect(() => {
    const changed = () => setCriteria(criteriaFromHash());
    window.addEventListener('hashchange', changed);
    return () => window.removeEventListener('hashchange', changed);
  }, []);
  const resource = useResource<Cartography>(`/api/shadow/cartography?${serializeCriteria(criteria)}`);
  const data = useMemo(() => normalise(resource.data), [resource.data]);
  const issued = useMemo(() => new Intl.DateTimeFormat(language, { dateStyle: 'long', timeStyle: 'short' }).format(new Date()), [language]);
  const narrowed = SCOPE.filter(item => criteriaValue(criteria, item.key));
  const cover = {
    key: 'cover',
    body: <div className="report-cover">
      <img className="report-mark" src="/milvago-symbol-mono-black.svg" alt="" width={40} height={40} />
      <h1>{t("synthesisReport")}</h1>
      <dl className="report-meta">
        <div><dt>{t("organization")}</dt><dd>{session.organization.name}</dd></div>
        <div><dt>{t("period")}</dt><dd><DateValue value={criteriaValue(criteria, 'from')} /> → <DateValue value={criteriaValue(criteria, 'to')} /></dd></div>
        <div><dt>{t("appliedFilters")}</dt><dd>{narrowed.length
          ? <ul className="report-filters">{narrowed.map(item => <li key={item.key}><span>{t(item.label)}</span> {criteriaValue(criteria, item.key)}</li>)}</ul>
          : t("noFilterBeyondThePeriod")}</dd></div>
        <div><dt>{t("issuedOn")}</dt><dd>{issued}</dd></div>
        <div><dt>{t("issuedBy")}</dt><dd>{session.user.display_name || session.user.email}</dd></div>
      </dl>
      <p className="fine-print">{t("thisReportCarriesMetadataOnlyNo")}</p>
    </div>,
  };
  function synthesis(data: Cartography) {
    const requests = data.totals.requests;
    return <>
      <section className="kpis">
        <Kpi label={t("requests")} value={requests.toLocaleString()} />
        <Kpi label={t("responses")} value={data.totals.responses.toLocaleString()} />
        <Kpi label={t("blocked")} value={data.totals.blocked.toLocaleString()} tone={data.totals.blocked > 0 ? 'warning' : undefined} />
        <Kpi label={t("identifiedConversations")} value={data.totals.conversations.toLocaleString()} />
        <Kpi label={t("people")} value={data.totals.actors.toLocaleString()} hint={t("unattributed") + ' ' + data.unattributed.toLocaleString()} />
        <Kpi label={t("services")} value={data.totals.providers.toLocaleString()} />
        <Kpi label={t("browsersApplications")} value={data.totals.tools.toLocaleString()} />
        <Kpi label={t("models")} value={data.totals.models.toLocaleString()} />
        {sensitivity && <Kpi label={t("sensitiveEvents")} value={(data.totals.sensitive ?? 0).toLocaleString()} tone={(data.totals.sensitive ?? 0) > 0 ? 'warning' : undefined} />}
      </section>
      <Card title={t("requestsReceivedPerHour")}>
        {data.series.length ? <HourlyBars points={data.series} label={t("requestsReceivedPerHour")} /> : <Empty title={t("noRequestsInThisPeriod")} />}
      </Card>
    </>;
  }
  return <div className="report" data-theme="light">
    <div className="report-controls">
      <button type="button" className="button primary" onClick={() => window.print()}><Icon name="download" />{t("printOrSaveAsPdf")}</button>
      <a className="button secondary" href={`#map?${serializeCriteria(criteria)}`}>{t("backToCartography")}</a>
    </div>
    <ResourceView resource={{ ...resource, data }}>{data => {
      const sheets: { key: string; title?: string; body: React.ReactNode }[] = [cover, { key: 'synthesis', title: t("synthesis"), body: synthesis(data) }];
      // The ranked sheets exist only once there are flows to rank: an empty scope
      // prints its cover and its synthesis, not four empty tables.
      for (const [key, dimension, title, head] of [
        ['services', 'provider', t("topServices"), t("service")],
        ['tools', 'tool', t("topBrowsersApplications"), t("browserApplication")],
        ['models', 'model', t("topModels"), t("model")],
        ['people', 'actor_id', t("topPeople"), t("people")],
      ] as [string, Dimension, string, string][]) {
        if (!data.flows.length) break;
        const rows = rank(data.flows, dimension);
        sheets.push({
          key, title,
          body: <>
            <Ranking rows={rows.slice(0, BARS)} total={data.totals.requests} />
            <RankTable rows={rows} total={data.totals.requests} head={head} sensitivity={sensitivity} />
          </>,
        });
      }
      return <>{sheets.map((sheet, index) => <section className="report-sheet" key={sheet.key}>
        {sheet.title && <h2 className="card-title">{sheet.title}</h2>}
        {sheet.body}
        <footer className="report-foot">
          <span>Milvago · {session.organization.name}</span>
          <span>{t("metadataOnlyNoConversationContent")}</span>
          <span>{t("page0Of1", [index + 1, sheets.length])}</span>
        </footer>
      </section>)}</>;
    }}</ResourceView>
  </div>;
}
