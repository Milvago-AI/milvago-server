import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { Session } from './api';

const permissions = ['overview.read', 'events.read', 'devices.read', 'members.read', 'settings.manage', 'policy.manage'];
const base: Session = { user: { id: 'user-1', email: 'admin@example.org', display_name: 'Administrateur' }, organization: { id: 'org-1', name: 'Organisation de test', role: 'admin' }, organizations: [{ id: 'org-1', name: 'Organisation de test', role: 'admin' }], permissions, csrf_token: 'session-csrf', edition: 'community' };
const settings = { name: 'Organisation de test', event_retention_days: 30, public_url: 'https://console.example.org', public_url_confirmed: true, public_url_editable: true };
const catalog = { revision: 7, can_publish: false, content: { providers: [{ id: 'synthetic', label: 'Synthetic', domains: ['ai.example.invalid'], aliases: ['alias.example.invalid'], conversation_path: '', conversation_segment: 0, qualified_at: '2026-09-01T00:00:00Z', dom: { editor: '', send: '', response: '' }, network: [] }], native_tools: [], heuristics: { keys: [], mime_types: [] } } };
const healthy = { items: [{ provider: 'chatgpt', state: 'ok', catalog_revision: 7, devices: 4, network_prompts: 10, dom_prompts: 9 }], window_hours: 24, thresholds: { min_devices: 3, dom_ratio_percent: 20 }, transport: { state: 'ok', devices_reporting: 4, devices_approved: 4 } };
const degraded = { ...healthy, items: [{ provider: 'chatgpt', state: 'suspect', catalog_revision: 7, devices: 5, network_prompts: 0, dom_prompts: 0 }] };
const overview = { '/api/overview': { events: 0, devices: 0, providers: [] }, '/api/devices': { items: [] } };

function reply(body: unknown, status = 200) { return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }); }
function serve(session: Session, routes: Record<string, unknown>) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
    const url = String(input);
    if (url === '/api/session') return reply(session);
    // Longest prefix first, so /api/detection/catalog never answers for /api/detection/candidates.
    const route = Object.keys(routes).sort((a, b) => b.length - a.length).find(key => url.startsWith(key));
    return route ? reply(routes[route]) : reply({ error: 'unexpected_request', message: url }, 404);
  });
}
beforeEach(() => {
  vi.unstubAllGlobals(); localStorage.clear(); document.cookie = 'milvago_theme=;Max-Age=0;Path=/'; window.location.hash = '';
  Object.defineProperty(HTMLDialogElement.prototype, 'showModal', { configurable: true, value() { this.setAttribute('open', ''); } });
  Object.defineProperty(HTMLDialogElement.prototype, 'close', { configurable: true, value() { this.removeAttribute('open'); } });
});

describe('Catalogue editor behind MILVAGO_DEBUG', () => {
  it('hides the page and refuses the hash typed by hand when the instance runs without the flag', async () => {
    window.location.hash = '#detection';
    serve(base, { '/api/settings': settings, '/api/detection': catalog });
    render(<App />);
    // Reaching the page by its hash is as easy as following a link, so the refusal has
    // to come from the page itself and not only from the missing navigation entry.
    expect(await screen.findByText('Accès réservé')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Catalogue de détection' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Ajouter une couverture' })).not.toBeInTheDocument();
  });
  it('carries the editor when the operator asked for it', async () => {
    window.location.hash = '#detection';
    serve({ ...base, console_debug: true }, { '/api/settings': settings, '/api/detection/health': healthy, '/api/detection/catalog': catalog });
    render(<App />);
    expect(await screen.findByRole('heading', { level: 1, name: 'Catalogue de détection' })).toBeInTheDocument();
    expect(screen.queryByText('Accès réservé')).not.toBeInTheDocument();
  });
});

describe('Discovery', () => {
  it('refuses the page to a reader without policy.manage, hash typed by hand included', async () => {
    window.location.hash = '#discovery';
    const fetcher = serve({ ...base, permissions: ['overview.read', 'events.read', 'devices.read'] }, { '/api/settings': settings, '/api/detection/catalog': catalog, '/api/detection/candidates': { items: [{ domain: 'ai.example.invalid', count: 12, status: 'new' }] } });
    render(<App />);
    expect(await screen.findByText('Accès réservé')).toBeInTheDocument();
    expect(screen.queryByText('ai.example.invalid')).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Découverte' })).not.toBeInTheDocument();
    // The refusal is the page's, so the candidates are never even asked for.
    expect(fetcher).not.toHaveBeenCalledWith('/api/detection/candidates', expect.anything());
  });
  it('offers promotion for a domain the catalogue already carries, without a publication in this session', async () => {
    window.location.hash = '#discovery';
    serve(base, {
      '/api/settings': settings,
      '/api/detection/catalog': catalog,
      '/api/detection/candidates': { items: [{ domain: 'ai.example.invalid', count: 12, status: 'new' }, { domain: 'other.example.invalid', count: 3, status: 'new' }] },
    });
    render(<App />);
    expect(await screen.findByText('ai.example.invalid')).toBeInTheDocument();
    // The published domain may be promoted; the one the catalogue does not carry may
    // not, which is exactly what the server would answer with 409.
    await waitFor(() => expect(screen.getAllByRole('button', { name: 'Marquer le candidat publié comme promu' })).toHaveLength(1));
    expect(screen.getAllByRole('button', { name: 'Ignorer' })).toHaveLength(2);
  });
  it('reports the known platforms reached, and names the OS accounts column only in Enterprise', async () => {
    window.location.hash = '#discovery';
    const platforms = { items: [], platforms: [{ provider: 'aggregator.example.invalid', visits: 12, devices: 3, accounts: 2, last_seen: '2026-09-16T09:00:00Z' }] };
    serve(base, { '/api/settings': settings, '/api/detection/catalog': catalog, '/api/detection/candidates': platforms });
    const { unmount } = render(<App />);
    expect(await screen.findByText('aggregator.example.invalid')).toBeInTheDocument();
    // The promise the card makes, in the reader's own language.
    expect(screen.getByText(/Aucun prompt, aucune réponse, aucune adresse/)).toBeInTheDocument();
    expect(screen.queryByRole('columnheader', { name: 'Comptes OS' })).not.toBeInTheDocument();
    unmount();
    serve({ ...base, edition: 'commercial' }, { '/api/settings': settings, '/api/detection/catalog': catalog, '/api/detection/candidates': platforms });
    render(<App />);
    expect(await screen.findByRole('columnheader', { name: 'Comptes OS' })).toBeInTheDocument();
  });
  it('names the machines behind a candidate domain, in Enterprise only', async () => {
    window.location.hash = '#discovery';
    const candidates = { items: [{ domain: 'ai.example.invalid', count: 12, status: 'new' }] };
    const devices = { window_days: 30, items: [{ device_id: '10000000-0000-4000-8000-000000000001', hostname: 'LT-ENG-1042', observations: 9, last_seen: '2026-09-16T09:00:00Z' }] };
    // Community has no local inventory and the route is not even registered there, so
    // the domain stays plain text rather than a control that would answer 404.
    serve(base, { '/api/settings': settings, '/api/detection/catalog': catalog, '/api/detection/candidates': candidates });
    const { unmount } = render(<App />);
    expect(await screen.findByText('ai.example.invalid')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'ai.example.invalid' })).not.toBeInTheDocument();
    unmount();
    serve({ ...base, edition: 'commercial' }, {
      '/api/settings': settings, '/api/detection/catalog': catalog,
      '/api/detection/candidates/ai.example.invalid/devices': devices,
      '/api/detection/candidates': candidates,
    });
    render(<App />);
    fireEvent.click(await screen.findByRole('button', { name: 'ai.example.invalid' }));
    // The machine is named and leads to its own page; the window it answers for is
    // said out loud, because detector reports are purged at thirty days.
    expect(await screen.findByRole('link', { name: 'LT-ENG-1042' })).toHaveAttribute('href', '#devices?id=10000000-0000-4000-8000-000000000001');
    expect(screen.getByText(/30 derniers jours/)).toBeInTheDocument();
  });
  it('names the machines behind a platform reached, in Enterprise only', async () => {
    window.location.hash = '#discovery';
    const platforms = { items: [], platforms: [{ provider: 'aggregator.example.invalid', visits: 12, devices: 3, accounts: 2, last_seen: '2026-09-16T09:00:00Z' }] };
    const devices = { window_days: 90, items: [{ device_id: '20000000-0000-4000-8000-000000000002', hostname: 'LT-FIN-2051', observations: 12, last_seen: '2026-09-16T09:00:00Z' }] };
    // Community reports the platform and nothing about who reached it.
    serve(base, { '/api/settings': settings, '/api/detection/catalog': catalog, '/api/detection/candidates': platforms });
    const { unmount } = render(<App />);
    expect(await screen.findByText('aggregator.example.invalid')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'aggregator.example.invalid' })).not.toBeInTheDocument();
    unmount();
    serve({ ...base, edition: 'commercial' }, {
      '/api/settings': settings, '/api/detection/catalog': catalog,
      '/api/detection/platforms/aggregator.example.invalid/devices': devices,
      '/api/detection/candidates': platforms,
    });
    render(<App />);
    fireEvent.click(await screen.findByRole('button', { name: 'aggregator.example.invalid' }));
    expect(await screen.findByRole('link', { name: 'LT-FIN-2051' })).toHaveAttribute('href', '#devices?id=20000000-0000-4000-8000-000000000002');
    // The announced window is the organization's retention, not a fixed number.
    expect(screen.getByText(/90 derniers jours/)).toBeInTheDocument();
  });
  it('pages and filters the machines behind a platform, in the dialog itself', async () => {
    window.location.hash = '#discovery';
    const platforms = { items: [], platforms: [{ provider: 'aggregator.example.invalid', visits: 120, devices: 24, accounts: 20, last_seen: '2026-09-16T09:00:00Z' }] };
    // An entire fleet behind a single platform: this is the case that made the
    // window unreadable, not the single row of previous attempts.
    const items = Array.from({ length: 24 }, (_, index) => ({
      device_id: `30000000-0000-4000-8000-0000000000${String(index + 10)}`,
      hostname: `${index % 2 ? 'LT-FIN' : 'LT-ENG'}-${2000 + index}`,
      observations: index + 1, last_seen: '2026-09-16T09:00:00Z',
    }));
    serve({ ...base, edition: 'commercial' }, {
      '/api/settings': settings, '/api/detection/catalog': catalog,
      '/api/detection/platforms/aggregator.example.invalid/devices': { window_days: 90, items },
      '/api/detection/candidates': platforms,
    });
    render(<App />);
    fireEvent.click(await screen.findByRole('button', { name: 'aggregator.example.invalid' }));
    const dialog = await screen.findByRole('dialog');
    // Twenty rows rendered out of twenty-four, and the twenty-first is one click away.
    expect(await within(dialog).findByRole('link', { name: 'LT-ENG-2000' })).toBeInTheDocument();
    expect(within(dialog).getAllByRole('link')).toHaveLength(20);
    expect(within(dialog).queryByRole('link', { name: 'LT-FIN-2023' })).not.toBeInTheDocument();
    fireEvent.click(within(dialog).getByRole('button', { name: '2' }));
    expect(within(dialog).getByRole('link', { name: 'LT-FIN-2023' })).toBeInTheDocument();
    // The search filters as you type, over the whole list and not just the page read.
    fireEvent.change(within(dialog).getByRole('searchbox'), { target: { value: 'lt-fin-2023' } });
    await waitFor(() => expect(within(dialog).getAllByRole('link')).toHaveLength(1));
    expect(within(dialog).getByRole('link', { name: 'LT-FIN-2023' })).toBeInTheDocument();
    fireEvent.change(within(dialog).getByRole('searchbox'), { target: { value: 'LT-RH' } });
    expect(await within(dialog).findByText('Aucun poste ne correspond à cette recherche')).toBeInTheDocument();
  });
  it('explains that discovery is off rather than showing a bare empty table', async () => {
    window.location.hash = '#discovery';
    serve(base, { '/api/settings': settings, '/api/detection/catalog': catalog, '/api/detection/candidates': { items: [] } });
    render(<App />);
    expect(await screen.findByText('Aucun domaine candidat observé')).toBeInTheDocument();
    // The switch moved to Shadow AI > AI platforms on 2026-09-16, so the hint has to lead
    // where it is now: a link still pointing at Privacy would send the reader to a page
    // that no longer carries the control.
    expect(screen.getByRole('link', { name: /La découverte des domaines candidats est désactivée/ })).toHaveAttribute('href', '#shadow');
  });
  it('pages the candidate domains and sets the rows per page', async () => {
    window.location.hash = '#discovery';
    const items = Array.from({ length: 25 }, (_, index) => ({ domain: `ai-${String(index).padStart(2, '0')}.example.invalid`, count: 25 - index, status: 'new' }));
    serve(base, { '/api/settings': settings, '/api/detection/catalog': catalog, '/api/detection/candidates': { items } });
    render(<App />);
    expect(await screen.findByText('25 résultats')).toBeInTheDocument();
    expect(screen.getByText('ai-00.example.invalid')).toBeInTheDocument();
    expect(screen.queryByText('ai-20.example.invalid')).not.toBeInTheDocument();
    const pager = screen.getByRole('navigation', { name: 'Pagination' });
    fireEvent.click(within(pager).getByRole('button', { name: '2' }));
    expect(screen.getByText('ai-20.example.invalid')).toBeInTheDocument();
    expect(screen.queryByText('ai-00.example.invalid')).not.toBeInTheDocument();
    // Ten rows a page makes three of them, and the reader is put back on the first.
    fireEvent.click(screen.getByRole('button', { name: '10' }));
    expect(screen.getByText('ai-00.example.invalid')).toBeInTheDocument();
    expect(within(screen.getByRole('navigation', { name: 'Pagination' })).getByRole('button', { name: '3' })).toBeInTheDocument();
  });
});

describe('Coverage banner', () => {
  it('warns on the pages where the figures are read', async () => {
    window.location.hash = '#overview';
    serve(base, { '/api/settings': settings, '/api/detection/health': degraded, ...overview });
    render(<App />);
    expect(await screen.findByText('Ces chiffres sont peut-être incomplets')).toBeInTheDocument();
    expect(screen.getByText(/chatgpt/)).toBeInTheDocument();
  });
  it('stays silent when every detector reports, and for a reader without policy.manage', async () => {
    window.location.hash = '#overview';
    serve(base, { '/api/settings': settings, '/api/detection/health': healthy, ...overview });
    const { unmount } = render(<App />);
    await screen.findByRole('heading', { level: 1, name: 'Vue d’ensemble' });
    expect(screen.queryByText('Ces chiffres sont peut-être incomplets')).not.toBeInTheDocument();
    unmount();
    // /api/detection/health demands policy.manage, so a reader without it must not even
    // reach for it: a banner that always 403s is worse than no banner.
    const fetcher = serve({ ...base, permissions: ['overview.read', 'events.read', 'devices.read'] }, { '/api/settings': settings, '/api/detection/health': degraded, ...overview });
    render(<App />);
    await screen.findByRole('heading', { level: 1, name: 'Vue d’ensemble' });
    expect(screen.queryByText('Ces chiffres sont peut-être incomplets')).not.toBeInTheDocument();
    expect(fetcher).not.toHaveBeenCalledWith('/api/detection/health', expect.anything());
  });
});
