import { useContext, useId, useState } from 'react';
import type { KeyboardEvent, PointerEvent } from 'react';
import type { Overview } from './api';
import { Context, Empty, Icon, can, canAnalyze, useText } from './ui';

const count = (value: number) => Number.isFinite(value) ? Math.max(0, value) : 0;
const fraction = (value: number, total: number) => total > 0 ? Math.min(100, count(value) / total * 100) : 0;

/** Keep the overview a single aggregate read, including for people who cannot open detail pages. */
export function UsageOverview({ data }: Readonly<{ data: Overview }>) {
  const t = useText();
  const { language, session } = useContext(Context);
  const number = (value: number) => new Intl.NumberFormat(language).format(value);
  const percent = (value: number) => new Intl.NumberFormat(language, { style: 'percent', maximumFractionDigits: 1 }).format(value / 100);
  const blockedShare = fraction(data.blocked, data.events);
  const inactive = Math.max(0, data.devices - data.active_devices);
  return <section className="usage-overview" aria-label={t('metrics')}>
    <section className="usage-activity" aria-labelledby="usage-activity-title">
      <header className="usage-activity-head">
        <div><p className="workspace-eyebrow">{t('requests')}</p><div className="usage-total">{number(data.events)}</div></div>
        <span className="usage-period"><Icon name="activity" size={14}/>{t('observationWindowLast0Hours', [data.period_hours])}</span>
      </header>
      <div className="usage-chart-heading"><h2 id="usage-activity-title">{t('usageRhythm')}</h2><span>{t('requestsReceivedPerHour')}</span></div>
      <div className="usage-chart">
        {data.events === 0 || data.timeline.length === 0
          ? <Empty title={t('noEventsReceived')}>{t('eventsWillAppearAsSoonAs')}</Empty>
          : <UsageChart timeline={data.timeline} label={t('n0EventsIncluding1BlockedOver', [data.events, data.blocked, data.period_hours])}/>}
      </div>
      <footer className="usage-activity-foot">
        <div className="usage-legend"><span><i/>{t('observed')}</span><span><i className="blocked"/>{t('blocked')}</span></div>
        {canAnalyze(session) && <a href="#events">{t('openConversations')}<Icon name="arrow" size={14}/></a>}
      </footer>
    </section>
    <div className="usage-signals">
      <section className="usage-signal">
        <header><h2>{t('activeDevices')}</h2><Icon name="device" size={17}/></header>
        <div className="usage-signal-value">{number(data.active_devices)}<small>/ {number(data.devices)}</small></div>
        <div className="usage-meter" aria-hidden="true"><span style={{ width: fraction(data.active_devices, data.devices) + '%' }}/></div>
        <p>{t('n0InactivePendingOrRevoked', [number(inactive)])}</p>
        {can(session, 'devices.read') && <a href="#devices">{t('openDevices')}<Icon name="arrow" size={14}/></a>}
      </section>
      <section className="usage-signal">
        <header><h2>{t('blocked')}</h2><Icon name="shield" size={17}/></header>
        <div className={'usage-signal-value' + (data.blocked > 0 ? ' is-blocked' : '')}>{number(data.blocked)}<small>{data.events > 0 ? percent(blockedShare) : '—'}</small></div>
        <div className="usage-meter" aria-hidden="true"><span className="blocked" style={{ width: blockedShare + '%' }}/></div>
        <p>{data.events > 0 ? t('n0OfRequests', [new Intl.NumberFormat(language, { maximumFractionDigits: 1 }).format(blockedShare)]) : t('accordingToAppliedRules')}</p>
      </section>
      <section className="usage-signal">
        <header><h2>{t('observedProviders')}</h2><Icon name="globe" size={17}/></header>
        <div className="usage-signal-value">{number(data.providers.length)}</div>
        <p>{t('last0Hours1Navigations', [data.period_hours, number(data.navigations)])}</p>
      </section>
    </div>
    <section className="usage-provider-panel" aria-labelledby="usage-provider-title">
      <header className="usage-provider-head">
        <div><h2 id="usage-provider-title">{t('observedProviders')}</h2><p>{t('distributionOfReceivedEvents')}</p></div>
        {canAnalyze(session) && <a href="#map">{t('openCartography')}<Icon name="arrow" size={14}/></a>}
      </header>
      {data.providers.length === 0
        ? <Empty title={t('noProvidersObserved')}>{t('thisListReflectsOnlyEventsActually')}</Empty>
        : <ol className="usage-provider-grid">{data.providers.map((provider, index) => <li key={provider.name}>
          <div className="usage-provider-name"><span className="usage-rank">{String(index + 1).padStart(2, '0')}</span><strong>{provider.name}</strong></div>
          <div className="usage-provider-volume"><strong>{number(provider.events)}</strong><span>{percent(fraction(provider.events, data.events))}</span></div>
          <div className="usage-provider-track" aria-hidden="true">
            <span style={{ width: fraction(provider.events - provider.blocked, data.events) + '%' }}/>
            <span className="blocked" style={{ width: fraction(provider.blocked, data.events) + '%' }}/>
          </div>
          <p className={provider.blocked > 0 ? 'is-blocked' : ''}>{number(provider.blocked)} {t('blocked2')}</p>
        </li>)}</ol>}
    </section>
  </section>;
}

function UsageChart({ timeline, label }: Readonly<{ timeline: Overview['timeline']; label: string }>) {
  const t = useText();
  const { language } = useContext(Context);
  const tooltipId = useId();
  const [active, setActive] = useState<number | null>(null);
  const [keyboard, setKeyboard] = useState(false);
  const width = 880, height = 240, left = 48, right = 12, top = 14, bottom = 210;
  const max = Math.max(...timeline.map(point => count(point.events)), 1);
  const x = (index: number) => left + (timeline.length === 1 ? .5 : index / (timeline.length - 1)) * (width - left - right);
  const y = (value: number) => bottom - count(value) / max * (bottom - top);
  const points = timeline.map((point, index) => x(index) + ',' + y(point.events)).join(' ');
  const blocked = timeline.map((point, index) => x(index) + ',' + y(Math.min(count(point.blocked), count(point.events)))).join(' ');
  const every = Math.max(1, Math.ceil(timeline.length / 6));
  const time = (iso: string) => Number.isNaN(Date.parse(iso)) ? iso : new Intl.DateTimeFormat(language, { hour: '2-digit', minute: '2-digit' }).format(new Date(iso));
  const selected = active === null ? undefined : timeline[active];
  const number = (value: number) => new Intl.NumberFormat(language).format(count(value));
  const date = (iso: string) => Number.isNaN(Date.parse(iso)) ? iso : new Intl.DateTimeFormat(language, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(iso));
  function inspect(event: PointerEvent<SVGRectElement>) {
    const bounds = event.currentTarget.getBoundingClientRect();
    if (bounds.width <= 0 || !Number.isFinite(event.clientX)) return;
    const position = Math.max(0, Math.min(1, (event.clientX - bounds.left) / bounds.width));
    setKeyboard(false); setActive(Math.round(position * (timeline.length - 1)));
  }
  function navigate(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === 'Escape') { setActive(null); return; }
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault(); setKeyboard(true);
    const current = selected ? active! : timeline.length - 1;
    setActive(event.key === 'Home' ? 0 : event.key === 'End' ? timeline.length - 1 : Math.max(0, Math.min(timeline.length - 1, current + (event.key === 'ArrowLeft' ? -1 : 1))));
  }
  return <div className="usage-chart-interactive" role="group" aria-label={t('usageRhythm')} aria-describedby={selected ? tooltipId : undefined} tabIndex={0}
    onFocus={() => { setKeyboard(true); setActive(timeline.length - 1); }} onBlur={() => setActive(null)} onKeyDown={navigate}
    onPointerLeave={event => { if (event.pointerType !== 'touch' && !keyboard) setActive(null); }}>
    <svg className="usage-chart-svg" viewBox={'0 0 ' + width + ' ' + height} role="img" aria-label={label}>
    {[0, .25, .5, .75, 1].map(tick => <g key={tick}>
      <line className="usage-gridline" x1={left} x2={width - right} y1={y(max * tick)} y2={y(max * tick)}/>
      <text className="usage-axis" x={left - 12} y={y(max * tick) + 4} textAnchor="end">{new Intl.NumberFormat(language, { notation: 'compact', maximumFractionDigits: 1 }).format(max * tick)}</text>
    </g>)}
    <polygon className="usage-area" points={left + ',' + bottom + ' ' + points + ' ' + x(timeline.length - 1) + ',' + bottom}/>
    <polyline className="usage-line" points={points}/>
    <polyline className="usage-blocked-line" points={blocked}/>
    {timeline.map((point, index) => <g key={point.hour}>
      <circle className="usage-point" cx={x(index)} cy={y(point.events)} r="3"/>
      {(index % every === 0 || index === timeline.length - 1) && <text className="usage-axis" x={x(index)} y={height - 5} textAnchor={index === timeline.length - 1 ? 'end' : 'middle'}>{time(point.hour)}</text>}
    </g>)}
    {selected && active !== null && <g aria-hidden="true" className="usage-chart-selection">
      <line className="usage-crosshair" x1={x(active)} x2={x(active)} y1={top} y2={bottom}/>
      <circle className="usage-point" cx={x(active)} cy={y(selected.events)} r="5"/>
      <circle className="usage-blocked-point" cx={x(active)} cy={y(Math.min(count(selected.blocked), count(selected.events)))} r="4"/>
    </g>}
    <rect className="usage-chart-hit" x={left} y={top} width={width - left - right} height={bottom - top}
      fill="transparent" onPointerMove={inspect} onPointerDown={inspect}/>
    </svg>
    {selected && active !== null && <div id={tooltipId} role="tooltip" aria-live={keyboard ? 'polite' : undefined}
      className={'usage-chart-tooltip' + (active >= timeline.length / 2 ? ' align-end' : '')}
      style={{ left: x(active) / width * 100 + '%' }}>
      <time dateTime={Number.isNaN(Date.parse(selected.hour)) ? undefined : selected.hour}>{date(selected.hour)}</time>
      <div><span>{t('requests')}</span><strong>{number(selected.events)}</strong></div>
      <div><span>{t('blocked')}</span><strong className="is-blocked">{number(selected.blocked)}</strong></div>
    </div>}
  </div>;
}
