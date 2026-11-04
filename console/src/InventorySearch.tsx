import { useContext, useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Card, Context, can, DateValue, Empty, ErrorNotice, readOnly, ResourceView, useMutation, useResource, useText } from './ui';
import { ReachedByDialog } from './DiscoveryPage';
import { EventFilters } from './shadow/EventFilters';
import type { Criteria } from './shadow/types';

export const inventoryOperators = { app: 'app', service: 'service', device: 'device', vendor: 'vendor', type: 'type', environment: 'environment', source: 'source', state: 'state', text: 'query' } as const;
const keys = [...Object.values(inventoryOperators), 'regex'];
export function serializeInventory(criteria: Criteria): string {
  const params = new URLSearchParams();
  for (const key of keys) for (const value of Array.isArray(criteria[key]) ? criteria[key] : [criteria[key]]) if (value) params.append(key, value);
  return params.toString();
}
export function inventoryFromHash(): Criteria {
  const params = new URLSearchParams(location.hash.split('?')[1] ?? '');
  const result: Criteria = {};
  for (const key of keys) { const values = params.getAll(key); if (values.length) result[key] = values.length === 1 ? values[0] : values; }
  if (result.type === 'web' && !result.regex) result.regex = ['type'];
  return result;
}
type Item = { family: 'application' | 'platform' | 'candidate'; id: string; name: string; vendor: string; type: string; devices: number | null; observations: number; states: string[]; status: string; last_seen: string; promotable?: boolean; accounts?: number; blocked?: number };
type Page = { items: Item[]; total: number; next_cursor: string; discovery_enabled?: boolean };
type Selection = { type: 'application'; id: string; name: string };
const stateLabels = { indication: 'discoveryIndication', installed: 'discoveryInstalled', executed: 'discoveryExecuted', interface_recognized: 'discoveryInterface', presence: 'inventoryPresence', new: 'discoveryReview', review: 'discoveryReview', authorized: 'discoveryAuthorized', unauthorized: 'discoveryUnauthorized', false_positive: 'discoveryFalsePositive', ignored: 'detectionIgnore', promoted: 'catalogPromoteCandidate' } as const;
function validPage(data: Page) {
  return !!data && Number.isSafeInteger(data.total) && data.total >= 0 && typeof data.next_cursor === 'string' && data.next_cursor.length <= 1024 && Array.isArray(data.items) && data.items.length <= 100 && data.items.every(row =>
    !!row && ['application', 'platform', 'candidate'].includes(row.family) && typeof row.id === 'string' && typeof row.name === 'string' && typeof row.vendor === 'string' && typeof row.type === 'string' &&
    (row.devices === null || (Number.isSafeInteger(row.devices) && row.devices >= 0)) && Number.isSafeInteger(row.observations) && row.observations >= 0 &&
    (row.accounts === undefined || Number.isSafeInteger(row.accounts) && row.accounts >= 0) && (row.blocked === undefined || Number.isSafeInteger(row.blocked) && row.blocked >= 0) &&
    (row.promotable === undefined || typeof row.promotable === 'boolean') && typeof row.status === 'string' && typeof row.last_seen === 'string' && Array.isArray(row.states) && row.states.every(value => typeof value === 'string'));
}

export function InventorySearch({ select, nativeDetail }: Readonly<{ select: (value: Selection) => void; nativeDetail?: (id: string, close: () => void) => ReactNode }>) {
  const t = useText(); const { session } = useContext(Context);
  const [criteria, setCriteria] = useState<Criteria>(inventoryFromHash);
  const [cursors, setCursors] = useState(['']);
  const [inspected, setInspected] = useState<{ title: string; path: string; platform: boolean }>();
  const [native, setNative] = useState<string>();
  const scope = serializeInventory(criteria);
  const cursor = cursors[cursors.length - 1];
  const resource = useResource<Page>(`/api/discovery/inventory?${scope}${scope ? '&' : ''}limit=50${cursor ? '&cursor=' + encodeURIComponent(cursor) : ''}`);
  const manage = can(session, 'policy.manage');
  const mutation = useMutation();
  const reload = useRef(resource.reload); reload.current = resource.reload;
  useEffect(() => {
    const sync = () => { setCriteria(inventoryFromHash()); setCursors(['']); setInspected(undefined); setNative(undefined); };
    const refresh = () => reload.current();
    window.addEventListener('hashchange', sync); window.addEventListener('milvago:privacy-changed', sync); window.addEventListener('milvago:inventory-changed', refresh);
    return () => { window.removeEventListener('hashchange', sync); window.removeEventListener('milvago:privacy-changed', sync); window.removeEventListener('milvago:inventory-changed', refresh); };
  }, []);
  function change(next: Criteria) {
    setCriteria(next); setCursors(['']); setInspected(undefined); setNative(undefined);
    const params = serializeInventory(next);
    history.replaceState(null, '', '#applications' + (params ? '?' + params : ''));
  }
  async function update(domain: string, status: string) {
    try { await mutation.run('/api/detection/candidates', 'PATCH', { domain, status }); resource.reload(); }
    catch { /* ErrorNotice retains the server response. */ }
  }
  const fields = [
    { key: 'app', label: t('application') },
    ...(can(session, 'devices.read') || manage ? [{ key: 'service', label: t('service') }] : []),
    ...(can(session, 'devices.read') ? [{ key: 'device', label: t('device') }] : []),
    { key: 'vendor', label: t('vendor') },
    { key: 'type', label: t('type'), options: [['software', t('discoveryLocalApps')], ['web', t('discoveryWebApps')]] as [string, string][] },
    ...(can(session, 'devices.read') ? [{ key: 'environment', label: t('inventoryEnvironment') }] : []),
    { key: 'source', label: t('source') }, { key: 'state', label: t('status') },
  ];
  return <>
    <EventFilters criteria={criteria} change={change} configuration={{ fields, operators: inventoryOperators, label: t('inventorySearch'), placeholder: t('inventorySearchPlaceholder'), help: t('inventorySearchHelp'), example: 'app:(claude|cursor) device:^LT-COM environment:host|wsl', period: false }}/>
    <Card title={t('discoverySoftwareServices')} description={t('inventorySearchScope')} actions={resource.data && validPage(resource.data) ? <span className="muted" role="status">{t('resultsCount', [resource.data.total])}</span> : undefined}>
      <ErrorNotice error={mutation.error}/>
      <ResourceView resource={resource}>{data => !validPage(data) ? <ErrorNotice error={new Error('Invalid inventory response')} retry={resource.reload}/> : <>
        {!data.items.length ? <Empty title={t('discoveryNoObservation')}>{t('inventoryNoMatch')}{manage && <p><a className="text-link" href="#shadow?area=platforms">{t(data.discovery_enabled === false ? 'discoveryDisabledHint' : data.discovery_enabled === true ? 'discoveryEnabledEmptyHint' : 'discoveryEmptyHint')}</a></p>}</Empty> : <div className="table-scroll discovery-table"><table><thead><tr>
          <th>{t('application')}</th><th>{t('type')}</th><th>{t('vendor')}</th><th>{t('discoveryEvidence')}</th><th>{t('devices')}</th><th>{t('aiGovTechnicalReview')}</th><th>{t('lastObservation')}</th>{manage && <th>{t('actions')}</th>}
        </tr></thead><tbody>{data.items.map(row => {
          const actionable = row.family === 'application' ? can(session, 'discovery.read') && can(session, 'devices.read') || !!nativeDetail : row.family === 'platform' || session.edition === 'commercial';
          function inspect() {
            if (row.family === 'application') {
              if (can(session, 'discovery.read') && can(session, 'devices.read')) select({ type: 'application', id: row.id, name: row.name });
              else if (nativeDetail) setNative(row.id);
            } else setInspected({ title: row.name, path: `/api/detection/${row.family === 'platform' ? 'platforms' : 'candidates'}/${encodeURIComponent(row.id)}/devices`, platform: row.family === 'platform' });
          }
          return <tr key={row.family + ':' + row.id}>
            <td>{actionable ? <button type="button" className="text-link" onClick={inspect}>{row.name}</button> : row.name}</td>
            <td>{t(row.type === 'web' ? 'discoveryWebApps' : 'discoveryLocalApps')}</td><td>{row.vendor || '—'}</td>
            <td>{row.states.map(state => Object.hasOwn(stateLabels, state) ? t(stateLabels[state as keyof typeof stateLabels]) : state).join(', ')}{row.family !== 'application' && <details><summary>{t('discoveryObservationCount')}: {row.observations}</summary>{row.family === 'platform' && <dl><dt>{t('osAccounts')}</dt><dd>{row.accounts ?? '—'}</dd>{session.edition === 'commercial' && <><dt>{t('blockedAttempts')}</dt><dd>{row.blocked ?? 0}</dd></>}</dl>}</details>}</td>
            <td>{row.devices ?? '—'}</td><td>{row.family === 'application' && Object.hasOwn(stateLabels, row.status) ? t(stateLabels[row.status as keyof typeof stateLabels]) : '—'}</td><td><DateValue value={row.last_seen}/></td>
            {manage && <td>{row.family === 'candidate' && !readOnly(session) && <div className="row-actions">
              {row.promotable && row.status !== 'promoted' && <button className="button secondary small" disabled={mutation.pending} onClick={() => void update(row.id, 'promoted')}>{t('catalogPromoteCandidate')}</button>}
              <button className="button secondary small" disabled={mutation.pending} onClick={() => void update(row.id, row.status === 'ignored' ? 'new' : 'ignored')}>{t(row.status === 'ignored' ? 'detectionReconsider' : 'detectionIgnore')}</button>
            </div>}</td>}
          </tr>;
        })}</tbody></table></div>}
        <nav className="discovery-pagination" aria-label={t('pagination')}>
          <button type="button" className="button secondary" disabled={cursors.length === 1} onClick={() => setCursors(value => value.slice(0, -1))}>{t('discoveryPrevious')}</button>
          <button type="button" className="button secondary" disabled={!data.next_cursor} onClick={() => setCursors(value => [...value, data.next_cursor])}>{t('discoveryNext')}</button>
        </nav>
      </>}</ResourceView>
    </Card>
    {inspected && <ReachedByDialog {...inspected} close={() => setInspected(undefined)}/>}
    {native && nativeDetail?.(native, () => setNative(undefined))}
  </>;
}
