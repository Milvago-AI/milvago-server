import { useContext, useMemo, useState } from 'react';
// Capture health is no longer shown here: it lives in Discovery, with the
// rest of what speaks to coverage (known platforms, candidate domains, detector
// status). Cartography answers "who talks to what", not "am I
// observing well" -- two questions the same page used to mix together.
import { Card, Context, Empty, Icon, Kpi, PageBar, ResourceView, useResource, useText } from '../ui';
import { FilterBar, SavedFilters, ExportMenu } from './FilterBar';
import { FlowDiagram } from './FlowDiagram';
import { Facet, FacetRail, PeoplePicker } from './FlowFacets';
import { ALL_DIMENSIONS, GLOBAL_DIMENSIONS, valueOf } from './flowLayout';
import type { Selection } from './flowLayout';
import { applyView, emptyView, hasRestriction, normalise, viewCriteria } from './flowView';
import type { View } from './flowView';
import { conversationsLink, periodCriteria, serializeCriteria } from './filters';
import type { Cartography, Criteria, Flow } from './types';

const NO_FLOWS: Flow[] = [];

export function CartographyPage() {
  // Usage sensitivity is an Enterprise capability; Community reports none.
  const t = useText(); const { session } = useContext(Context); const sensitivity = session.edition === 'commercial';
  const [criteria, setCriteria] = useState<Criteria>(() => periodCriteria(24)); const [selected, setSelected] = useState<Selection[]>([]);
  // The side panels, the ten-people window and "hide people" are a client-side view
  // over the flows of the period: they never widen what the server returned.
  const [view, setView] = useState<View>(emptyView); const [railsOpen, setRailsOpen] = useState(false);
  const resource = useResource<Cartography>(`/api/shadow/cartography?${serializeCriteria(criteria)}`);
  const data = useMemo(() => normalise(resource.data), [resource.data]);
  const flows = data?.flows ?? NO_FLOWS;
  const result = useMemo(() => applyView(flows, view), [flows, view]);
  const dimensions = view.peopleHidden ? GLOBAL_DIMENSIONS : ALL_DIMENSIONS;
  const restricted = hasRestriction(view);
  function select(node: Selection) { setSelected(current => current.some(item => item.dimension === node.dimension && item.value === node.value) ? current.filter(item => item.dimension !== node.dimension || item.value !== node.value) : [...current, node]); }
  function change(next: Criteria) { setCriteria(next); setSelected([]); }
  // A selection that the new view no longer draws would silently narrow the journal link: prune it.
  function changeView(next: View) {
    const preview = applyView(flows, next);
    setSelected(current => current.filter(item => !(next.peopleHidden && item.dimension === 'actor_id') && preview.visible.some(flow => valueOf(flow, item.dimension) === item.value)));
    setView(next);
  }
  const journal = () => conversationsLink({ ...viewCriteria(criteria, selected, result), kind: 'prompt' });
  function drill(flow: Flow) { location.hash = conversationsLink({ ...viewCriteria(criteria, [], result), kind: 'prompt', ...(view.peopleHidden ? {} : { actor_id: flow.actor_id || 'unknown' }), tool: flow.tool || 'unknown', provider: flow.provider || 'unknown', model: flow.model || 'unknown' }); }
  return <>
    {/* The report covers what the reader is looking at, not the bare filter bar:
        chip selections and rail exclusions fold in exactly as the drill-down links
        already do (product decision, 2026-09-17). */}
    <PageBar title={t("cartography")} actions={<><ExportMenu criteria={criteria} report={viewCriteria(criteria, selected, result)} /><a className="button secondary" href={conversationsLink(criteria)}>{t("openConversations")}<Icon name="arrow" /></a></>} />
    <FilterBar criteria={criteria} change={change} collapsible>
      <PeoplePicker people={result.people} view={view} apply={changeView} />
      <label className="checkbox-label fd-hide-people"><input type="checkbox" checked={view.peopleHidden} onChange={event => changeView({ ...view, peopleHidden: event.target.checked })} />{t("hidePeopleOverallUsage")}</label>
    </FilterBar>
    <SavedFilters criteria={criteria} apply={change} />
    <ResourceView resource={{ ...resource, data }}>{data => <>
      <div className="info-line"><Icon name="info" /><span>{t("n0EventsWithoutAnAttributedPerson", [data.unattributed, data.totals.navigations])}</span></div>
      <section className="kpis">
        <Kpi label={t("requests")} value={data.totals.requests.toLocaleString()} />
        <Kpi label={t("responses")} value={data.totals.responses.toLocaleString()} />
        <Kpi label={t("identifiedConversations")} value={data.totals.conversations.toLocaleString()} />
        {sensitivity && <Kpi label={t("sensitiveEvents")} value={(data.totals.sensitive ?? 0).toLocaleString()} tone={(data.totals.sensitive ?? 0) > 0 ? 'warning' : undefined} />}
      </section>
      <Card
        title={view.peopleHidden ? t("toolsServicesModels") : t("peopleToolsServicesModels")}
        description={sensitivity
          ? t("ribbonWidthRepresentsRequestsTheirColor")
          : t("ribbonWidthRepresentsRequestsTheirColor2")}
        actions={<div className="fd-legend">{sensitivity && <span><i className="fd-sensitive-swatch" />{t("sensitive")}</span>}<span><i className="fd-unknown-swatch" />{t("unattributed")}</span></div>}
        flush
        footer={selected.length > 0 || restricted ? <div className="fd-selection">
          {selected.length > 0 && <>
            <span className="muted">{t("selection")}</span>
            <div className="fd-chips">{selected.map(item => { const label = item.value === 'unknown' ? t("unattributed") : item.label; return <button key={`${item.dimension}:${item.value}`} className="fd-chip" title={label} onClick={() => select(item)}><span>{label}</span><Icon name="close" size={12} /></button>; })}</div>
            <button className="button secondary small" onClick={() => setSelected([])}>{t("clear")}</button>
          </>}
          {restricted && <>
            <span className="muted">{t("sideFiltersApplied")}</span>
            <button className="button secondary small" onClick={() => changeView({ ...view, excluded: emptyView().excluded })}>{t("reset")}</button>
          </>}
          <a className="button primary small" href={journal()}>{t("viewTheseRequests")}<Icon name="arrow" /></a>
        </div> : undefined}
      >
        {data.flows.length ? <>
          <button type="button" className="button secondary small fd-rails-toggle" aria-expanded={railsOpen} onClick={() => setRailsOpen(!railsOpen)}><Icon name="filter" />{t("sideFilters")}</button>
          <div className={`fd-layout${railsOpen ? ' rails-open' : ''}`}>
            <FacetRail side="left" icons={['users', 'device']}>
              <Facet dimension="actor_id" title={t("people")} options={result.people} view={view} change={changeView} window={view.peopleHidden ? undefined : { shown: result.displayedPeople.length, total: result.people.length }} />
              <Facet dimension="tool" title={t("browsersApplications")} options={result.facets.tool} view={view} change={changeView} />
            </FacetRail>
            <div className="fd-main">
              {result.visible.length
                ? <FlowDiagram flows={result.visible} dimensions={dimensions} selected={selected} select={select} drill={drill} sensitivity={sensitivity} totals={{ actor_id: result.people.length, tool: result.facets.tool.length, provider: result.facets.provider.length, model: result.facets.model.length }} />
                : <Empty title={t("noRequestsInThisPeriod")}>{t("sideFiltersApplied")}</Empty>}
            </div>
            <FacetRail side="right" icons={['globe', 'activity']}>
              <Facet dimension="provider" title={t("services")} options={result.facets.provider} view={view} change={changeView} />
              <Facet dimension="model" title={t("models")} options={result.facets.model} view={view} change={changeView} />
            </FacetRail>
          </div>
        </> : <Empty title={t("noRequestsInThisPeriod")}>{t("navigationsAndInventoriesAreNotConverted")}</Empty>}
      </Card>
    </>}</ResourceView>
  </>;
}
