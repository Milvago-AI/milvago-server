import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Context } from '../ui';
import type { Session } from '../api';
import { CartographyPage } from './CartographyPage';
import { ConversationsPage } from './ConversationsPage';
import { ShadowAdministration } from './ShadowAdministration';
import { browser } from '../secondFactor';
import type { Cartography, Conversation, ShadowEvent, ShadowSettings, Thread, ThreadMessage } from './types';

const session: Session = { user: { id: 'user-1', email: 'owner@example.org', display_name: 'Propriétaire de test' }, organization: { id: 'org-1', name: 'Organisation de test', role: 'owner' }, organizations: [{ id: 'org-1', name: 'Organisation de test', role: 'owner' }], permissions: ['overview.read', 'events.read', 'devices.read', 'devices.manage', 'members.read', 'members.manage', 'settings.manage', 'policy.manage', 'installers.manage', 'content.read', 'audit.read', 'roles.manage', 'organizations.manage'], csrf_token: 'shadow-csrf', edition: 'community' };
// The Operations section only exists on an instance started with MILVAGO_DEBUG.
const debugSession: Session = { ...session, console_debug: true };
const settings: ShadowSettings = { revision: 5, inherit_sections: [], inherited_from: {}, capabilities: { model_access_browser: false, model_access_native: false, browser: true, native: false, organization_inheritance: false, content_storage: true, device_overrides: false, local_privacy: true, local_privacy_patterns: false, usage_sensitivity: false, file_names: true, signed_updates: false }, config: { enrollment: { approval: 'manual', cidrs: [] }, collection: { enabled: true, store_content: false, store_file_names: true, content_retention_days: 7 }, services: [{ id: 'chatgpt', domains: ['chatgpt.com'], mode: 'observe', redirect_url: '', enabled: true }], protection: { block_uploads: false, keywords: [], exact: 'observe', unicode: 'observe', fuzzy: 'off', exceptions: [], message: '' }, privacy: { enabled: false, review: false, types: [], custom_rules: [] }, classification: { browser: ['iban', 'card', 'social_id'], coding: [], medical_terms: ['diagnostic'] }, operations: { metrics_enabled: false, destinations: [], updates: { enabled: false, device_ids: [], percentage: 0, paused_versions: [] } } } };
const map: Cartography = { capture: [{ provider: 'chatgpt.com', navigations: 8, requests: 5, devices_seen: 2, devices_reporting: 1 }, { provider: 'claude.ai', navigations: 4, requests: 0, devices_seen: 2, devices_reporting: 0 }], totals: { requests: 5, responses: 2, navigations: 8, conversations: 1, actors: 1, tools: 2, providers: 1, models: 1, sensitive: 2, blocked: 1 }, flows: [{ actor_id: 'actor-1', actor_name: 'Personne de test', tool: 'chrome', provider: 'chatgpt.com', model: 'unknown', count: 3, sensitive: 2, blocked: 1 }, { actor_id: 'actor-1', actor_name: 'Personne de test', tool: 'firefox', provider: 'chatgpt.com', model: 'unknown', count: 2, sensitive: 0, blocked: 0 }], series: [], unattributed: 0 };
const event: ShadowEvent = { id: 'event-1', device_id: 'device-1', hostname: 'Poste de test', actor_id: 'actor-1', actor_name: 'Personne de test', kind: 'prompt', occurred_at: '2026-09-07T08:00:00Z', provider: 'chatgpt.com', source: 'browser', tool: 'chrome', action: 'observed', characters: 12, labels: ['iban'], sensitivity: 'sensitive', has_content: true, policy_revision: 5 };
const response: ShadowEvent = { ...event, id: 'event-2', kind: 'response', occurred_at: '2026-09-07T08:00:30Z', characters: 40 };
const older: ShadowEvent = { ...event, id: 'event-0', occurred_at: '2026-09-07T07:00:00Z' };
const conversation: Conversation = { key: 'conv:thread-1', started_at: '2026-09-07T07:00:00Z', last_at: '2026-09-07T08:00:30Z', prompts: 2, responses: 1, navigations: 0, blocked: 0, redirected: 0, model: 'claude-fable-5-1', effort: 'medium', latest: response };
function thread(items: ThreadMessage[], older_cursor = '', can_read_content = true): Thread { return { key: conversation.key, device_id: 'device-1', items, older_cursor, can_read_content }; }
function message(base: ShadowEvent, content_state: ThreadMessage['content_state'], content?: ThreadMessage['content']): ThreadMessage { return { ...base, content_state, content }; }
function reply(body: unknown, status = 200) { return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }); }
function serve(handler: (url: string, init?: RequestInit) => Response | undefined) { return vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => handler(String(url), init) ?? (String(url).startsWith('/api/shadow/filters') ? reply({ items: [] }) : reply({ error: 'unexpected_request', message: String(url) }, 404))); }
function show(children: React.ReactNode, current = session) { return render(<Context.Provider value={{ session: current, language: 'fr', refreshSession: async () => {} }}>{children}</Context.Provider>); }
beforeEach(() => { location.hash = ''; Object.defineProperty(HTMLDialogElement.prototype, 'showModal', { configurable: true, value() { this.setAttribute('open', ''); } }); Object.defineProperty(HTMLDialogElement.prototype, 'close', { configurable: true, value() { this.removeAttribute('open'); } }); });

describe('Shadow AI workflows', () => {
  it('combines keyboard-selected graph nodes into exact repeated journal filters', async () => {
    serve(url => url.startsWith('/api/shadow/cartography') ? reply(map) : undefined); show(<CartographyPage />);
    const diagram = await screen.findByRole('group', { name: /Cartographie des requêtes/ });
    const user = userEvent.setup();
    within(diagram).getByRole('button', { name: 'Personne de test · 5 requêtes' }).focus();
    await user.keyboard('{Enter}');
    within(diagram).getByRole('button', { name: 'chrome · 3 requêtes' }).focus();
    await user.keyboard(' ');
    within(diagram).getByRole('button', { name: 'firefox · 2 requêtes' }).focus();
    await user.keyboard('{Enter}');
    const link = screen.getByRole('link', { name: /Voir ces requêtes/ }); const params = new URLSearchParams(link.getAttribute('href')!.split('?')[1]);
    expect(params.getAll('actor_id')).toEqual(['actor-1']); expect(params.getAll('tool')).toEqual(['chrome', 'firefox']); expect(params.get('kind')).toBe('prompt'); expect(params.get('from')).toBeTruthy(); expect(params.get('to')).toBeTruthy();
  });
  it('preserves unknown model values when drilling a flow and never infers a model', async () => {
    serve(url => url.startsWith('/api/shadow/cartography') ? reply(map) : undefined); show(<CartographyPage />);
    await screen.findByRole('group', { name: /Cartographie des requêtes/ });
    fireEvent.click(screen.getByRole('button', { name: 'Voir le tableau' }));
    fireEvent.click(screen.getAllByRole('button', { name: 'Journal' })[0]);
    const params = new URLSearchParams(location.hash.split('?')[1]); expect(params.get('model')).toBe('unknown'); expect(params.get('provider')).toBe('chatgpt.com'); expect(params.get('actor_id')).toBe('actor-1');
  });
  // The "Capture health" table left Cartography: everything that speaks to
  // coverage is now grouped in Discovery, where `/api/detection/health` gives the same
  // signal, better (verdict per service, transport status, applied thresholds). The test
  // that kept this table here is therefore removed rather than repaired; the behavior is
  // covered by the Discovery page and by `detectorState` on the server side.
  it('does not carry the capture-health table any more, which now lives in Discovery', async () => {
    serve(url => url.startsWith('/api/shadow/cartography') ? reply(map) : undefined); show(<CartographyPage />);
    await screen.findByRole('group', { name: /Cartographie des requêtes/ });
    expect(screen.queryByText('Santé de la capture')).toBeNull();
  });
  // A person the server could name only by the OS account their records carry. The
  // name is real and the map must show it — the journal always did — but the
  // attribution is informational, so the rail says which kind it is. "Unattributed"
  // stays for the records that carry no account at all.
  const bucket = 'os:' + 'a'.repeat(64);
  const osMap: Cartography = {
    ...map, unattributed: 1, totals: { ...map.totals, requests: 5, actors: 1 },
    flows: [{ actor_id: bucket, actor_name: 'Compte-analyste', tool: 'chrome', provider: 'chatgpt.com', model: 'unknown', count: 4, sensitive: 0, blocked: 0 },
      { actor_id: 'unknown', actor_name: 'Unattributed', tool: 'firefox', provider: 'chatgpt.com', model: 'unknown', count: 1, sensitive: 0, blocked: 0 }],
  };
  it('names a person by their OS account, marks that attribution and keeps unattributed for records without one', async () => {
    serve(url => url.startsWith('/api/shadow/cartography') ? reply(osMap) : undefined); show(<CartographyPage />);
    const diagram = await screen.findByRole('group', { name: /Cartographie des requêtes/ });
    expect(within(diagram).getByRole('button', { name: 'Compte-analyste · 4 requêtes' })).toBeInTheDocument();
    expect(within(diagram).getByRole('button', { name: 'Non attribué · 1 requêtes' })).toBeInTheDocument();
    const named = screen.getByRole('checkbox', { name: 'Compte-analyste · 4 requêtes' }).closest('label')!;
    expect(within(named).getByText('Utilisateur OS')).toBeInTheDocument();
    const anonymous = screen.getByRole('checkbox', { name: 'Non attribué · 1 requêtes' }).closest('label')!;
    expect(within(anonymous).queryByText('Utilisateur OS')).not.toBeInTheDocument();
    // Selecting that person hands the journal the bucket the server understands.
    within(diagram).getByRole('button', { name: 'Compte-analyste · 4 requêtes' }).focus();
    await userEvent.setup().keyboard('{Enter}');
    const params = new URLSearchParams(screen.getByRole('link', { name: /Voir ces requêtes/ }).getAttribute('href')!.split('?')[1]);
    expect(params.getAll('actor_id')).toEqual([bucket]);
  });
  // Twelve people, busiest first (120, 110, … 10 requests), alternating browsers: more
  // than the ten-people window holds.
  const wide: Cartography = { ...map, totals: { ...map.totals, requests: 780, actors: 12 }, flows: Array.from({ length: 12 }, (_, i) => ({ actor_id: `actor-${String(i + 1).padStart(2, '0')}`, actor_name: `Personne ${String(i + 1).padStart(2, '0')}`, tool: i % 2 ? 'firefox' : 'chrome', provider: 'chatgpt.com', model: 'unknown', count: 120 - 10 * i, sensitive: 0, blocked: i === 0 ? 3 : 0 })) };
  const personTile = /^Personne \d\d · \d+ requêtes$/;
  it('shows the ten busiest people and lets the eleventh in when one is unchecked', async () => {
    serve(url => url.startsWith('/api/shadow/cartography') ? reply(wide) : undefined); show(<CartographyPage />);
    const diagram = await screen.findByRole('group', { name: /Cartographie des requêtes/ });
    expect(within(diagram).getAllByRole('button', { name: personTile })).toHaveLength(10);
    expect(within(diagram).queryByRole('button', { name: 'Personne 11 · 20 requêtes' })).not.toBeInTheDocument();
    expect(screen.getByText('10 affichées / 12')).toBeInTheDocument();
    // The rail lists everyone; the two beyond the window wait their turn.
    expect(screen.getByText('En attente · n° 11')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('checkbox', { name: 'Personne 03 · 100 requêtes' }));
    expect(within(diagram).queryByRole('button', { name: 'Personne 03 · 100 requêtes' })).not.toBeInTheDocument();
    expect(within(diagram).getByRole('button', { name: 'Personne 11 · 20 requêtes' })).toBeInTheDocument();
    expect(within(diagram).getAllByRole('button', { name: personTile })).toHaveLength(10);
    expect(screen.getByText('En attente · n° 12')).toBeInTheDocument(); expect(screen.queryByText('En attente · n° 11')).not.toBeInTheDocument();
    // The journal link names exactly the people drawn.
    const params = new URLSearchParams(screen.getByRole('link', { name: /Voir ces requêtes/ }).getAttribute('href')!.split('?')[1]);
    expect(params.getAll('actor_id')).toHaveLength(10); expect(params.getAll('actor_id')).toContain('actor-11'); expect(params.getAll('actor_id')).not.toContain('actor-03');
  });
  it('hides people to show overall usage across three columns', async () => {
    serve(url => url.startsWith('/api/shadow/cartography') ? reply(wide) : undefined); show(<CartographyPage />);
    await screen.findByRole('group', { name: /Cartographie des requêtes/ });
    fireEvent.click(screen.getByRole('checkbox', { name: 'Masquer les personnes (usage global)' }));
    const diagram = await screen.findByRole('group', { name: /outil, service, modèle/ });
    expect(within(diagram).queryAllByRole('button', { name: personTile })).toHaveLength(0);
    expect(within(diagram).getByRole('button', { name: 'chrome · 420 requêtes' })).toBeInTheDocument();
    expect(screen.getByText('Outils → services → modèles')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Voir le tableau' }));
    expect(screen.queryByRole('columnheader', { name: 'Personnes' })).not.toBeInTheDocument();
    fireEvent.click(screen.getAllByRole('button', { name: 'Journal' })[0]);
    const params = new URLSearchParams(location.hash.split('?')[1]);
    expect(params.get('actor_id')).toBeNull(); expect(params.get('tool')).toBe('chrome'); expect(params.get('provider')).toBe('chatgpt.com'); expect(params.get('model')).toBe('unknown');
  });
  it('restricts the map to the people chosen in the top filter bar', async () => {
    serve(url => url.startsWith('/api/shadow/cartography') ? reply(wide) : undefined); show(<CartographyPage />);
    const diagram = await screen.findByRole('group', { name: /Cartographie des requêtes/ });
    fireEvent.click(screen.getByRole('button', { name: /Personnes : toutes/ }));
    const dialog = screen.getByRole('dialog', { name: 'Seulement ces personnes' });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Tout décocher' }));
    fireEvent.click(within(dialog).getByRole('checkbox', { name: 'Personne 05 · 80 requêtes' }));
    fireEvent.click(within(dialog).getByRole('checkbox', { name: 'Personne 07 · 60 requêtes' }));
    fireEvent.click(within(dialog).getByRole('button', { name: 'Appliquer' }));
    expect(screen.getByRole('button', { name: /2 personnes/ })).toBeInTheDocument();
    expect(within(diagram).getAllByRole('button', { name: personTile }).map(tile => tile.getAttribute('aria-label'))).toEqual(['Personne 05 · 80 requêtes', 'Personne 07 · 60 requêtes']);
    const params = new URLSearchParams(screen.getByRole('link', { name: /Voir ces requêtes/ }).getAttribute('href')!.split('?')[1]);
    expect(params.getAll('actor_id')).toEqual(['actor-05', 'actor-07']);
  });
  it('cross-filters the side panels and names the kept values in the journal link', async () => {
    serve(url => url.startsWith('/api/shadow/cartography') ? reply(map) : undefined); show(<CartographyPage />);
    const diagram = await screen.findByRole('group', { name: /Cartographie des requêtes/ });
    fireEvent.click(screen.getByRole('checkbox', { name: 'firefox · 2 requêtes' }));
    expect(within(diagram).queryByRole('button', { name: 'firefox · 2 requêtes' })).not.toBeInTheDocument();
    // The person is recounted against the remaining browser.
    expect(within(diagram).getByRole('button', { name: 'Personne de test · 3 requêtes' })).toBeInTheDocument();
    expect(screen.getByText('Réglages latéraux appliqués')).toBeInTheDocument();
    const params = new URLSearchParams(screen.getByRole('link', { name: /Voir ces requêtes/ }).getAttribute('href')!.split('?')[1]);
    expect(params.getAll('tool')).toEqual(['chrome']); expect(params.getAll('actor_id')).toEqual([]);
    fireEvent.click(screen.getByRole('button', { name: 'Réinitialiser' }));
    expect(within(diagram).getByRole('button', { name: 'firefox · 2 requêtes' })).toBeInTheDocument();
  });
  it('shows a cartography server error instead of a false empty graph', async () => {
    serve(url => url.startsWith('/api/shadow/cartography') ? reply({ error: 'unavailable', message: 'Analyse indisponible.' }, 503) : undefined); show(<CartographyPage />);
    expect(await screen.findByRole('alert')).toHaveTextContent('Analyse indisponible.'); expect(screen.queryByText('Aucune requête dans cette période')).not.toBeInTheDocument();
  });
  it('degrades a truncated cartography payload to zeros and an empty graph instead of a blank page', async () => {
    serve(url => url.startsWith('/api/shadow/cartography') ? reply({ flows: { not: 'a list' }, totals: null, capture: [null, { provider: 42 }], series: null, unattributed: null }) : undefined); show(<CartographyPage />);
    expect(await screen.findByText('Aucune requête dans cette période')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument(); expect(screen.getByText('Requêtes', { selector: '.kpi-label span' }).closest('article')).toHaveTextContent('0');
  });
  it('never shows usage sensitivity in Community, on the map or in the journal', async () => {
    serve(url => url.startsWith('/api/shadow/cartography') ? reply(map) : url.startsWith('/api/shadow/events?') ? reply({ items: [event], next_cursor: null }) : undefined);
    const graph = show(<CartographyPage />);
    await screen.findByRole('group', { name: /Cartographie des requêtes/ });
    expect(screen.queryByText('Événements sensibles')).not.toBeInTheDocument();
    expect(screen.queryByText('Sensible')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Voir le tableau' }));
    expect(screen.queryByRole('columnheader', { name: 'Sensibles' })).not.toBeInTheDocument();
    graph.unmount();
    serve(url => url.startsWith('/api/shadow/conversations?') ? reply({ items: [conversation], next_cursor: null }) : undefined);
    show(<ConversationsPage />);
    await screen.findByText('Poste de test');
    expect(screen.queryByRole('columnheader', { name: 'Sensibilité' })).not.toBeInTheDocument();
    expect(screen.queryByText('Sensible')).not.toBeInTheDocument();
    // The conversation filters are always on screen: no toggle to open first.
    expect(screen.queryByRole('combobox', { name: 'Sensibilité' })).not.toBeInTheDocument();
  });
  it('reaches every page of the conversations and sets the rows per page', async () => {
    const calls: string[] = [];
    serve(url => { if (!url.startsWith('/api/shadow/conversations?')) return undefined; calls.push(url); return reply({ items: [conversation], total: 125 }); });
    show(<ConversationsPage />);
    await screen.findByText('Poste de test');
    expect(calls[0]).toContain('limit=50');
    expect(calls[0]).toContain('offset=0');
    expect(screen.getByText('125 résultats')).toBeInTheDocument();
    // 125 rows in pages of 50 is three pages, and the last one is one click away.
    const pager = screen.getByRole('navigation', { name: 'Pagination' });
    expect(within(pager).getByRole('button', { name: '3' })).toBeInTheDocument();
    expect(within(pager).queryByRole('button', { name: '4' })).toBeNull();
    fireEvent.click(within(pager).getByRole('button', { name: '3' }));
    await waitFor(() => expect(calls.at(-1)).toContain('offset=100'));
    // A new page size restarts at the first page: the old offset would land elsewhere.
    fireEvent.click(screen.getByRole('button', { name: '200' }));
    await waitFor(() => expect(calls.at(-1)).toContain('limit=200'));
    expect(calls.at(-1)).toContain('offset=0');
  });
  it('returns to the last valid conversation page when the matching total shrinks', async () => {
    let total = 125;
    const calls: string[] = [];
    serve(url => {
      if (!url.startsWith('/api/shadow/conversations?')) return undefined;
      calls.push(url);
      return reply({ items: total === 25 && url.includes('offset=100') ? [] : [conversation], total });
    });
    show(<ConversationsPage />);
    await screen.findByText('Poste de test');
    fireEvent.click(within(screen.getByRole('navigation', { name: 'Pagination' })).getByRole('button', { name: '3' }));
    await waitFor(() => expect(calls.at(-1)).toContain('offset=100'));
    total = 25;
    fireEvent.click(screen.getByRole('button', { name: 'Actualiser' }));
    await waitFor(() => expect(calls.at(-1)).toContain('offset=0'));
    expect(await screen.findByText('Poste de test')).toBeInTheDocument();
    expect(screen.queryByText('Aucune conversation ne correspond à ces filtres')).not.toBeInTheDocument();
  });
  it('shows the conversation filters directly, without a refine button, while the map keeps its toggle', async () => {
    serve(url => url.startsWith('/api/shadow/conversations?') ? reply({ items: [conversation], next_cursor: null }) : undefined);
    const journal = show(<ConversationsPage />);
    await screen.findByText('Poste de test');
    // Product decision, 2026-09-14: on #events the fields are visible at once.
    expect(screen.queryByRole('button', { name: 'Affiner les filtres' })).not.toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Action' })).toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Nature' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Appliquer' })).toBeInTheDocument();
    journal.unmount();
    serve(url => url.startsWith('/api/shadow/cartography') ? reply(map) : undefined); show(<CartographyPage />);
    await screen.findByRole('group', { name: /Cartographie des requêtes/ });
    expect(screen.queryByRole('combobox', { name: 'Action' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Affiner les filtres' }));
    expect(screen.getByRole('combobox', { name: 'Action' })).toBeInTheDocument();
  });
  function conversations(handler: (url: string) => Response | undefined) {
    return serve(url => url.startsWith('/api/shadow/conversations?') ? reply({ items: [conversation], next_cursor: null }) : handler(url));
  }
  async function openThread() {
    show(<ConversationsPage />);
    fireEvent.click(await screen.findByRole('button', { name: /Ouvrir la conversation conv:thread-1/ }));
  }
  it('opens the conversation from a click anywhere on the row', async () => {
    conversations(url => url.startsWith('/api/shadow/conversation?') ? reply(thread([message(event, 'not_retained')], '', false)) : undefined);
    show(<ConversationsPage />);
    // No action column any more: the row itself is the control (product decision,
    // 2026-09-14). The cell button stays for keyboard and assistive technology.
    const row = (await screen.findByText('Poste de test')).closest('tr')!;
    // The model is a label the site displays, spaces and capitals included.
    // The model is the provider's own identifier; the reasoning effort is a
    // separate setting and gets its own field, never folded into the model.
    expect(within(row).getByText('claude-fable-5-1')).toBeInTheDocument();
    expect(within(row).getByText(/Effort\s*:\s*medium/)).toBeInTheDocument();
    expect(within(row).queryByRole('button', { name: 'Ouvrir la conversation conv:thread-1' })).not.toBeInTheDocument();
    fireEvent.click(row);
    expect(await screen.findByRole('button', { name: 'PROMPT CACHÉ · texte non conservé' })).toBeInTheDocument();
  });
  it('names the reason a message carries no readable text', async () => {
    conversations(url => url.startsWith('/api/shadow/conversation?') ? reply(thread([
      message(older, 'denied'), message(event, 'not_retained'), message(response, 'identity'),
    ], '', false)) : undefined);
    await openThread();
    // The three refusals are distinct: a reader must not confuse a missing right
    // with a text that was never kept.
    expect(await screen.findByRole('button', { name: 'PROMPT CACHÉ · lecture non autorisée' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'PROMPT CACHÉ · texte non conservé' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'RÉPONSE CACHÉE · identité non levée' })).toBeInTheDocument();
  });
  it('renders authorized thread text as text, oldest first, without executing markup', async () => {
    const fetchMock = conversations(url => url.startsWith('/api/shadow/conversation?') ? reply(thread([
      message(event, 'available', { prompt: '<img src=x onerror=alert(1)>' }),
      message(response, 'available', { response: 'Réponse de test.' }),
    ])) : undefined);
    await openThread();
    expect(await screen.findByText('<img src=x onerror=alert(1)>')).toBeInTheDocument();
    expect(within(screen.getAllByRole('dialog')[0]).queryByRole('img')).not.toBeInTheDocument();
    const texts = screen.getAllByText(/<img src=x onerror=alert\(1\)>|Réponse de test\./).map(node => node.textContent);
    expect(texts).toEqual(['<img src=x onerror=alert(1)>', 'Réponse de test.']);
    expect(fetchMock).toHaveBeenCalledWith('/api/shadow/conversation?key=conv%3Athread-1&device_id=device-1', expect.anything());
  });
  it('loads ten messages then reaches further back only on request', async () => {
    const fetchMock = conversations(url => url.startsWith('/api/shadow/conversation?') && url.includes('cursor=older-page')
      ? reply(thread([message(older, 'available', { prompt: 'Première question.' })]))
      : url.startsWith('/api/shadow/conversation?') ? reply(thread([message(response, 'available', { response: 'Réponse de test.' })], 'older-page')) : undefined);
    await openThread();
    await screen.findByText('Réponse de test.');
    expect(screen.queryByText('Première question.')).not.toBeInTheDocument();
    // The button appears on the state update that follows the page, one tick after
    // its bubbles: waiting for the bubble alone made this race.
    fireEvent.click(await screen.findByRole('button', { name: 'Charger les messages précédents' }));
    expect(await screen.findByText('Première question.')).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith('/api/shadow/conversation?key=conv%3Athread-1&device_id=device-1&cursor=older-page', expect.anything());
  });
  it('opens the event detail from a message, over the conversation', async () => {
    conversations(url => url.startsWith('/api/shadow/conversation?') ? reply(thread([message(event, 'not_retained')], '', false))
      : url.startsWith('/api/shadow/events/event-1') ? reply({ event, can_read_content: false }) : undefined);
    await openThread();
    fireEvent.click(await screen.findByRole('button', { name: 'PROMPT CACHÉ · texte non conservé' }));
    expect(await screen.findByText(/Aucun texte n’a été communiqué/)).toBeInTheDocument();
    expect(screen.getAllByRole('dialog')).toHaveLength(2);
  });
  // A send accompanied by a file leaves TWO records under the same
  // correlation: the file leaves as soon as it is attached, so it is recorded before the text.
  // Displayed as-is, they produced two bubbles, one of them empty.
  const attachment: ShadowEvent = { ...event, id: 'event-file', occurred_at: '2026-09-07T07:59:55Z', characters: 0, correlation_id: 'corr-1', files: ['schema-synthetique.png'] };
  const sent: ShadowEvent = { ...event, correlation_id: 'corr-1' };

  it('shows one bubble per send, the attached file named under its message', async () => {
    conversations(url => url.startsWith('/api/shadow/conversation?') ? reply(thread([
      message(attachment, 'not_retained'),
      message(sent, 'available', { prompt: 'Analyse ce document.' }),
    ])) : undefined);
    await openThread();
    await screen.findByText('Analyse ce document.');
    const bubbles = document.querySelectorAll('.bubble');
    expect(bubbles).toHaveLength(1);
    const bubble = bubbles[0];
    expect(within(bubble as HTMLElement).getByText('Analyse ce document.')).toBeInTheDocument();
    const files = within(bubble as HTMLElement).getByRole('list', { name: 'Fichiers joints' });
    expect(within(files).getByText('schema-synthetique.png')).toBeInTheDocument();
    // The file is below the message, not above: that is what the DOM says.
    expect(bubble.querySelector('pre')!.compareDocumentPosition(files) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it('keeps a lone attachment as its own bubble, with no claim of a hidden text', async () => {
    conversations(url => url.startsWith('/api/shadow/conversation?') ? reply(thread([message(attachment, 'not_retained')])) : undefined);
    await openThread();
    expect(await screen.findByText('schema-synthetique.png')).toBeInTheDocument();
    // There is no text to conceal: announcing "hidden prompt" would be false.
    expect(screen.queryByRole('button', { name: /PROMPT CACHÉ/ })).not.toBeInTheDocument();
  });

  it('a click on the message opens its detail, and selecting text does not', async () => {
    conversations(url => url.startsWith('/api/shadow/conversation?') ? reply(thread([message(sent, 'available', { prompt: 'Analyse ce document.' })]))
      : url.startsWith('/api/shadow/events/event-1') ? reply({ event: sent, can_read_content: true, content: { prompt: 'Analyse ce document.' } }) : undefined);
    await openThread();
    await screen.findByText('Analyse ce document.');
    const bubble = document.querySelector('.bubble') as HTMLElement;
    // A selection in progress: re-reading a message by highlighting it must not open
    // a dialog on release.
    const selection = vi.spyOn(window, 'getSelection').mockReturnValue({ isCollapsed: false } as Selection);
    fireEvent.click(bubble);
    expect(screen.getAllByRole('dialog')).toHaveLength(1);
    selection.mockReturnValue({ isCollapsed: true } as Selection);
    fireEvent.click(bubble);
    expect(await screen.findByRole('heading', { name: 'Requête' })).toBeInTheDocument();
    selection.mockRestore();
  });

  it('opens a message detail with the keyboard from the bubble', async () => {
    conversations(url => url.startsWith('/api/shadow/conversation?') ? reply(thread([message(sent, 'available', { prompt: 'Analyse ce document.' })]))
      : url.startsWith('/api/shadow/events/event-1') ? reply({ event: sent, can_read_content: true, content: { prompt: 'Analyse ce document.' } }) : undefined);
    await openThread();
    const bubble = await screen.findByRole('button', { name: /Analyse ce document/ });
    bubble.focus();
    await userEvent.setup().keyboard('{Enter}');
    expect(await screen.findByRole('heading', { name: 'Requête' })).toBeInTheDocument();
  });

  it('names the detail after the record it describes, and shows that side only', async () => {
    conversations(url => url.startsWith('/api/shadow/conversation?') ? reply(thread([message(response, 'available', { response: 'Réponse de test.' })]))
      : url.startsWith('/api/shadow/events/event-2') ? reply({ event: response, can_read_content: true, content: { response: 'Réponse de test.' } }) : undefined);
    await openThread();
    fireEvent.click(await screen.findByRole('button', { name: /Détail du message event-2/ }));
    expect(await screen.findByRole('heading', { name: 'Réponse' })).toBeInTheDocument();
    // A response detail does not show an empty request frame, and vice versa.
    expect(screen.queryByRole('heading', { name: 'Requête' })).not.toBeInTheDocument();
    expect(screen.queryByText(/conservée/)).not.toBeInTheDocument();
  });

  // The detail stated two attributions at once — a "Personne vérifiée" field reading
  // "Non attribué" and the account itself as a separate field — which contradicted
  // the list and the thread header, where the account is the person. One field now,
  // and it says which attribution it carries.
  it('states one attribution in the event detail: the OS account when no association is verified', async () => {
    const pseudonymous: ShadowEvent = { ...event, actor_id: 'unknown', actor_name: 'Unattributed', user: 'compte-poste' };
    conversations(url => url.startsWith('/api/shadow/conversation?') ? reply(thread([message(pseudonymous, 'not_retained')]))
      : url.startsWith('/api/shadow/events/event-1') ? reply({ event: pseudonymous, can_read_content: false }) : undefined);
    await openThread();
    fireEvent.click(await screen.findByRole('button', { name: /Détail du message event-1/ }));
    const detail = screen.getAllByRole('dialog').at(-1)!;
    expect(await within(detail).findByText('Personne')).toBeInTheDocument();
    expect(within(detail).getByText('compte-poste')).toBeInTheDocument();
    expect(within(detail).getByText('Utilisateur OS')).toBeInTheDocument();
    expect(within(detail).queryByText('Personne vérifiée')).not.toBeInTheDocument();
    expect(within(detail).queryByText('Non attribué')).not.toBeInTheDocument();
  });
  it('marks the verified association as such when there is one', async () => {
    conversations(url => url.startsWith('/api/shadow/conversation?') ? reply(thread([message(event, 'not_retained')]))
      : url.startsWith('/api/shadow/events/event-1') ? reply({ event, can_read_content: false }) : undefined);
    await openThread();
    fireEvent.click(await screen.findByRole('button', { name: /Détail du message event-1/ }));
    const detail = screen.getAllByRole('dialog').at(-1)!;
    expect(await within(detail).findByText('Personne de test')).toBeInTheDocument();
    expect(within(detail).getByText('Personne vérifiée')).toBeInTheDocument();
    expect(within(detail).queryByText('Utilisateur OS')).not.toBeInTheDocument();
  });

  it('preserves a content-collection draft when MFA validation fails', async () => {
    vi.spyOn(browser, 'navigate').mockImplementation(() => {});
    const fetchMock = serve((url, init) => url === '/api/shadow/settings' ? init?.method === 'PUT' ? reply({ error: 'mfa_required', message: 'Un second facteur vérifié est requis.' }, 409) : reply(settings) : undefined); show(<ShadowAdministration />);
    const content = await screen.findByRole('checkbox', { name: 'Conserver le texte des requêtes et réponses' }); expect(content).not.toBeChecked();
    fireEvent.click(content); fireEvent.click(screen.getByRole('button', { name: 'Enregistrer les changements' }));
    // The demand is announced in the reader's language as a step, not as a refusal,
    // and the draft it was refused for is kept exactly as it was.
    expect(await screen.findByText(/Vérification du second facteur requise/)).toBeInTheDocument();
    expect(screen.queryByText('Un second facteur vérifié est requis.')).not.toBeInTheDocument();
    expect(content).toBeChecked(); expect(screen.queryByText(/Configuration enregistrée/)).not.toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith('/api/shadow/settings', expect.objectContaining({ method: 'PUT', headers: expect.objectContaining({ 'X-CSRF-Token': 'shadow-csrf' }), body: expect.stringContaining('"revision":5') }));
  });
  it('saves a real service redirect using the current revision', async () => {
    const fetchMock = serve((url, init) => url === '/api/shadow/settings' ? init?.method === 'PUT' ? reply({ ...settings, revision: 6, config: JSON.parse(String(init.body)).config }) : reply(settings) : undefined); show(<ShadowAdministration />); const user = userEvent.setup();
    await screen.findByText('Administration Shadow AI'); await screen.findByRole('checkbox', { name: 'Activer la collecte' });
    await user.click(screen.getByRole('button', { name: /02 Services/ })); await user.selectOptions(screen.getByRole('combobox', { name: 'Comportement' }), 'redirect'); await user.type(screen.getByRole('textbox', { name: 'Destination de redirection' }), 'https://ai.example.org'); await user.click(screen.getByRole('button', { name: 'Enregistrer les changements' }));
    expect(await screen.findByRole('status')).toHaveTextContent('Configuration enregistrée.'); const call = fetchMock.mock.calls.find(([, init]) => init?.method === 'PUT')!; expect(JSON.parse(String(call[1]!.body))).toMatchObject({ revision: 5, config: { services: [{ id: 'chatgpt', mode: 'redirect', redirect_url: 'https://ai.example.org' }] } });
  });

  // Product decision of 2026-09-16: a label that its own expression matches is refused --
  // the `[LABEL]` placeholder inserted into the masked text would itself be masked again, endlessly. The
  // console explains it and withholds the save; the server refuses on its side.
  it('refuses a custom masking rule whose label matches its own expression, and explains the loop', async () => {
    serve((url, init) => url === '/api/shadow/settings' && init?.method !== 'PUT' ? reply(settings) : undefined); show(<ShadowAdministration />); const user = userEvent.setup();
    await screen.findByText('Administration Shadow AI'); await screen.findByRole('checkbox', { name: 'Activer la collecte' });
    await user.click(screen.getByRole('button', { name: /Masquage local/ })); await user.click(screen.getByRole('button', { name: 'Ajouter une règle' }));
    const label = screen.getAllByRole('textbox', { name: 'Libellé' }).at(-1)!, pattern = screen.getAllByRole('textbox', { name: 'Expression régulière' }).at(-1)!;
    await user.type(label, 'ABC'); await user.type(pattern, 'A.C');
    expect(await screen.findByRole('alert')).toHaveTextContent(/Le libellé correspond à l'expression de la règle/); expect(pattern).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByRole('button', { name: 'Enregistrer les changements' })).toBeDisabled();
    // An expression that does not match the label lifts the warning and enables the save.
    await user.clear(pattern); await user.type(pattern, 'X.Z');
    await waitFor(() => expect(screen.queryByRole('alert')).toBeNull()); expect(screen.getByRole('button', { name: 'Enregistrer les changements' })).toBeEnabled();
  });
  // The File column answers for the whole thread, not the last message: an attachment
  // leaves with the request, and the last record of a thread is most often the
  // response, which carries none.
  it('marks a conversation that carried a file, and lets it be filtered on', async () => {
    const withFile = { key: 'conv:file-1', started_at: '2026-09-07T08:00:00Z', last_at: '2026-09-07T08:00:30Z', prompts: 1, responses: 1, navigations: 0, blocked: 0, redirected: 0, has_attachment: true, model: 'gpt-6-astra', effort: '', latest: response };
    const without = { ...withFile, key: 'conv:file-0', has_attachment: false };
    const seen: string[] = [];
    serve(url => {
      if (!url.startsWith('/api/shadow/conversations')) return undefined;
      seen.push(url);
      return reply({ items: url.includes('attachment=yes') ? [withFile] : [withFile, without], next_cursor: '' });
    });
    show(<ConversationsPage />);
    await screen.findByRole('columnheader', { name: 'Fichiers joints' });
    // One conversation carrying a file is marked, the other is not. The search is bounded to the
    // table: the filter option carries the same label, and counting it would skew everything.
    expect(within(screen.getByRole('table')).getAllByText('Avec fichier')).toHaveLength(1);
    // And the filter does travel all the way to the request.
    const user = userEvent.setup();
    await user.selectOptions(screen.getByRole('combobox', { name: 'Fichiers joints' }), 'yes');
    await user.click(screen.getByRole('button', { name: /Appliquer/ }));
    await waitFor(() => expect(seen.some(url => url.includes('attachment=yes'))).toBe(true));
  });
  // A demo instance must show its Shadow AI configuration and forbid
  // changing it. Both halves matter: hiding the page would amount to hiding the
  // product, leaving the button would amount to promising an action the server refuses.
  it('shows the Shadow AI configuration on a demonstration instance, without any way to save it', async () => {
    serve(url => url === '/api/shadow/settings' ? reply(settings) : undefined);
    show(<ShadowAdministration />, { ...session, demo_read_only: true });
    // The server's actual value is shown, not an empty screen nor a refusal.
    const collection = await screen.findByRole('checkbox', { name: 'Activer la collecte' });
    expect(collection).toBeChecked();
    // ... and it is inert, with the reason spelled out in full.
    expect(collection).toBeDisabled();
    expect(screen.queryByRole('button', { name: 'Enregistrer les changements' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Abandonner le brouillon' })).toBeNull();
    expect(screen.getByText(/toute modification est interdite et désactivée/)).toBeInTheDocument();
  });
  it('hides the operations section entirely without MILVAGO_DEBUG', async () => {
    // Nothing on that screen has to be decided: signed updates are on by default and
    // the rest -- pilot ring, paused versions -- is maintenance.
    serve(url => url === '/api/shadow/settings' ? reply(settings) : undefined); show(<ShadowAdministration />, { ...session, edition: 'commercial' as const });
    await screen.findByRole('checkbox', { name: 'Activer la collecte' });
    expect(screen.queryByRole('button', { name: /Exploitation/ })).toBeNull();
  });
  it('shows signed-update operations in Community while its capability is unavailable', async () => {
    serve(url => url === '/api/shadow/settings' ? reply(settings) : undefined); show(<ShadowAdministration />, debugSession);
    await screen.findByRole('checkbox', { name: 'Activer la collecte' });
    fireEvent.click(screen.getByRole('button', { name: /Exploitation/ }));
    expect(screen.getByRole('checkbox', { name: 'Activer les mises à jour signées' })).toBeDisabled();
  });
  it('allows Community signed-update configuration when the server capability permits it', async () => {
    const operational = { ...settings, capabilities: { ...settings.capabilities, signed_updates: true } };
    serve(url => url === '/api/shadow/settings' ? reply(operational) : url === '/api/shadow/operations' ? reply({ updates: { available: true, reason: '', versions: [], devices: [] } }) : undefined); show(<ShadowAdministration />, debugSession);
    await screen.findByRole('checkbox', { name: 'Activer la collecte' }); fireEvent.click(screen.getByRole('button', { name: /Exploitation/ }));
    expect(screen.getByRole('checkbox', { name: 'Activer les mises à jour signées' })).toBeEnabled();
  });
  it('disables unavailable signed updates and reports the actual operational reason', async () => {
    // Enterprise with no delivery chain: the section stays, so it can say why.
    const commercial = { ...debugSession, edition: 'commercial' as const };
    serve(url => url === '/api/shadow/settings' ? reply(settings) : url === '/api/shadow/operations' ? reply({ updates: { available: false, reason: 'Signature delivery is not available.', versions: [], devices: [] } }) : undefined); show(<ShadowAdministration />, commercial);
    await screen.findByRole('checkbox', { name: 'Activer la collecte' }); fireEvent.click(screen.getByRole('button', { name: /Exploitation/ }));
    expect(screen.getByRole('checkbox', { name: 'Activer les mises à jour signées' })).toBeDisabled(); expect(await screen.findByText('Signature delivery is not available.')).toBeInTheDocument();
  });
  it('warns when an Enterprise administrator turns signed updates off', async () => {
    const commercial = { ...debugSession, edition: 'commercial' as const };
    const operational = { ...settings, capabilities: { ...settings.capabilities, signed_updates: true } };
    serve(url => url === '/api/shadow/settings' ? reply(operational) : url === '/api/shadow/operations' ? reply({ updates: { available: true, reason: '', versions: [], devices: [] } }) : undefined); show(<ShadowAdministration />, commercial);
    await screen.findByRole('checkbox', { name: 'Activer la collecte' }); fireEvent.click(screen.getByRole('button', { name: /Exploitation/ }));
    const toggle = screen.getByRole('checkbox', { name: 'Activer les mises à jour signées' });
    expect(toggle).toBeEnabled();
    const warning = 'Les postes ne recevront aucun correctif';
    // The fixture starts disabled, so the warning is already the honest state.
    expect(await screen.findByText(warning)).toBeInTheDocument();
    fireEvent.click(toggle);
    await waitFor(() => expect(screen.queryByText(warning)).not.toBeInTheDocument());
    fireEvent.click(toggle);
    expect(await screen.findByText(warning)).toBeInTheDocument();
  });
  it('never renders a policy scope selector, even in Enterprise with device overrides', async () => {
    const commercial = { ...session, edition: 'commercial' as const };
    const fetchMock = serve(url => url === '/api/shadow/settings' ? reply({ ...settings, capabilities: { ...settings.capabilities, device_overrides: true } }) : undefined);
    show(<ShadowAdministration />, commercial);
    const collection = await screen.findByRole('checkbox', { name: 'Activer la collecte' });
    expect(screen.queryByRole('combobox', { name: 'Périmètre de la politique' })).not.toBeInTheDocument();
    fireEvent.click(collection);
    expect(screen.queryByText('Enregistrez ou abandonnez le brouillon avant de changer de périmètre.')).not.toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalledWith('/api/devices', expect.anything());
  });
  it('hides organization inheritance when the server reports no parent', async () => {
    const commercial = { ...session, edition: 'commercial' as const };
    serve(url => url === '/api/shadow/settings' ? reply({ ...settings, capabilities: { ...settings.capabilities, organization_inheritance: false } }) : undefined);
    show(<ShadowAdministration />, commercial);
    await screen.findByRole('checkbox', { name: 'Activer la collecte' });
    expect(screen.queryByRole('checkbox', { name: 'Hériter · Collecte' })).not.toBeInTheDocument();
  });
  it('shows organization inheritance for a child from the server capability, even with no inherited sections', async () => {
    const commercial = { ...session, edition: 'commercial' as const };
    serve(url => url === '/api/shadow/settings' ? reply({ ...settings, capabilities: { ...settings.capabilities, organization_inheritance: true } }) : undefined);
    show(<ShadowAdministration />, commercial);
    expect(await screen.findByRole('checkbox', { name: 'Hériter · Collecte' })).not.toBeChecked();
  });
  it('surfaces export rejection without claiming a file was generated', async () => {
    serve(url => url.startsWith('/api/shadow/cartography') ? reply(map) : url.startsWith('/api/shadow/export') ? reply({ error: 'forbidden', message: 'Export non autorisé.' }, 403) : undefined); show(<CartographyPage />);
    await screen.findByRole('group', { name: /Cartographie des requêtes/ }); fireEvent.click(screen.getByRole('button', { name: 'Exporter' })); expect(await screen.findByRole('alert')).toHaveTextContent('Export non autorisé.');
  });

  it('saves exact model allowlists and exposes applied status without treating unknown models as allowed', async () => {
    const modelSettings: ShadowSettings = { ...settings, capabilities: { ...settings.capabilities, model_access_browser: true }, model_catalog: [{ platform_id: 'chatgpt', channel: 'browser', name: 'ChatGPT', provider: 'OpenAI', models: ['gpt-4o'] }], config: { ...settings.config, model_access: [] } };
    const fetchMock = serve((url, init) => url === '/api/shadow/settings' ? init?.method === 'PUT' ? reply({ ...modelSettings, revision: 6, config: JSON.parse(String(init.body)).config }) : reply(modelSettings) : url === '/api/model-access/status' ? reply({ items: [{ device_id: 'device-1', hostname: 'Poste de test', version: '1.0', platform: 'windows', platform_id: 'chatgpt', channel: 'browser', expected_revision: 6, applied_revision: 5, status: 'needs_update', reason: 'Synchronisation en attente', reported_at: '2026-09-09T10:00:00Z' }] }) : undefined);
    show(<ShadowAdministration />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: /Services/ }));
    await user.selectOptions(screen.getByRole('combobox', { name: 'Règle ChatGPT' }), 'allowlist');
    const models = screen.getByRole('textbox', { name: 'Modèles ChatGPT' });
    fireEvent.change(models, { target: { value: 'bad model' } });
    expect(await screen.findByRole('alert')).toHaveTextContent('Chaque identifiant');
    await user.clear(models); await user.type(models, 'gpt-4o');
    expect(screen.getByText('À mettre à jour')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Enregistrer les changements' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/shadow/settings', expect.objectContaining({ method: 'PUT', body: expect.stringContaining('"model_access"') })));
  });

  it('shows applied status as counts under aggregate-only reporting, naming no device', async () => {
    const modelSettings: ShadowSettings = { ...settings, capabilities: { ...settings.capabilities, model_access_browser: true }, model_catalog: [{ platform_id: 'chatgpt', channel: 'browser', name: 'ChatGPT', provider: 'OpenAI', models: ['gpt-4o'] }], config: { ...settings.config, model_access: [] } };
    serve(url => url === '/api/shadow/settings' ? reply(modelSettings) : url === '/api/model-access/status' ? reply({ items: [], counts: [{ platform_id: 'chatgpt', channel: 'browser', status: 'applied', devices: 7 }] }) : undefined);
    show(<ShadowAdministration />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: /Services/ }));
    const row = (await screen.findByText('7')).closest('tr')!;
    expect(row).toHaveTextContent('chatgpt');
    expect(row).toHaveTextContent('Appliqué');
    expect(screen.queryByRole('columnheader', { name: 'Poste' })).not.toBeInTheDocument();
  });

  // One gesture for every second-factor demand: the console said what was missing but
  // not what to do, then made the person retype a change it had already refused. The
  // action is replayed on return, so a change is sent once.
  it('goes straight to the second-factor verification and keeps the refused call for the return', async () => {
    const navigate = vi.spyOn(browser, 'navigate').mockImplementation(() => {});
    serve((url, init) => url === '/api/shadow/settings'
      ? init?.method === 'PUT'
        ? reply({ error: 'mfa_required', message: 'Authenticate again with multi-factor authentication.' }, 403)
        : reply(settings)
      : undefined);
    show(<ShadowAdministration />);
    const content = await screen.findByRole('checkbox', { name: 'Conserver le texte des requêtes et réponses' });
    fireEvent.click(content);
    fireEvent.click(screen.getByRole('button', { name: 'Enregistrer les changements' }));

    // The person is taken to the verification rather than told, in English and under
    // an "access denied" heading, to go and find it themselves.
    await waitFor(() => expect(navigate).toHaveBeenCalledWith(expect.stringContaining('/auth/login?mfa=1')));
    expect(navigate).toHaveBeenCalledWith(expect.stringContaining('lang=fr'));
    expect(screen.queryByText(/Accès refusé/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Authenticate again/)).not.toBeInTheDocument();

    // The refused call is held so the return can replay it: the change is sent once.
    const held = JSON.parse(window.sessionStorage.getItem('milvago.second-factor-retry')!);
    expect(held.path).toBe('/api/shadow/settings');
    expect(held.method).toBe('PUT');
    expect(held.body.config.collection.store_content).toBe(true);
    navigate.mockRestore();
  });

  // A record without a verified person is not a record about nobody: the OS account
  // still designates someone, under a pseudonym. Calling that "unattributed" read as
  // "we do not know who", which is false whenever an OS account was collected — and
  // it is collected on every browser record.
  it('names an unverified person pseudonymised when an OS account is known, unattributed when none is', async () => {
    const pseudonymous: ShadowEvent = { ...event, actor_id: 'unknown', actor_name: 'Unattributed', user: 'compte-poste' };
    serve(url => url.startsWith('/api/shadow/conversations?') ? reply({ items: [{ ...conversation, latest: pseudonymous }], next_cursor: null })
      : url.startsWith('/api/shadow/conversation?') ? reply(thread([message(pseudonymous, 'not_retained')]))
      : url.startsWith('/api/shadow/events/') ? reply({ event: pseudonymous, can_read_content: false })
      : undefined);
    show(<ConversationsPage />);
    // The list already showed the OS account itself; the word under test is the one
    // the detail uses for the verified person.
    expect(await screen.findByText('compte-poste')).toBeInTheDocument();
    expect(screen.queryByText('Non attribué')).not.toBeInTheDocument();

    // Under pseudonymity the server withholds the account and only states that one
    // exists. The record still names someone, so it must not read as "unattributed".
    const withheld: ShadowEvent = { ...pseudonymous, user: undefined, user_known: true };
    serve(url => url.startsWith('/api/shadow/conversations?') ? reply({ items: [{ ...conversation, latest: withheld }], next_cursor: null }) : undefined);
    show(<ConversationsPage />);
    expect(await screen.findAllByText('Pseudonymisé')).not.toHaveLength(0);
    expect(screen.queryByText('Non attribué')).not.toBeInTheDocument();

    const anonymous = { ...pseudonymous, user: undefined };
    serve(url => url.startsWith('/api/shadow/conversations?') ? reply({ items: [{ ...conversation, latest: anonymous }], next_cursor: null }) : undefined);
    show(<ConversationsPage />);
    expect(await screen.findAllByText('Non attribué')).not.toHaveLength(0);
  });
});

// Section 05, added on the user's request 2026-09-16. It is the one area that is not a
// slice of the signed policy: which platforms Discovery may name is stored on its own, so
// it saves on the spot and pushes Operations to 06 rather than sharing its save bar.
describe('AI platforms (05)', () => {
  const privacy = { revision: 3, config: { pseudonymous: true, aggregate_only: false, k_anonymity: 5, identity_link_days: 90, lock_descendants: false, retention_justification: '', team_claim: '', discovery_enabled: false, ignored_domains: [], auto_catalog: false, share_health: false, share_fleet: false } };
  const platforms = { platforms: [
    { id: 'fireflies', label: 'Fireflies', domains: ['fireflies.ai'], muted: false },
    { id: 'poe', label: 'Poe', domains: ['poe.com'], muted: true },
    { id: 'github-copilot', label: 'GitHub Copilot', domains: ['github.com'], paths: ['/copilot*'], muted: false },
  ] };
  function servePlatforms(onPatch?: (body: unknown) => void) {
    return serve((url, init) => {
      if (url === '/api/shadow/settings') return reply(settings);
      if (url === '/api/privacy') return reply(privacy);
      if (url === '/api/detection/platforms') {
        if (init?.method === 'PATCH') { onPatch?.(JSON.parse(String(init.body))); return reply({ ok: true }); }
        return reply(platforms);
      }
      return undefined;
    });
  }
  it('numbers itself 05 and pushes Exploitation to 06 on a debug instance', async () => {
    servePlatforms(); show(<ShadowAdministration />, debugSession);
    await screen.findByRole('checkbox', { name: 'Activer la collecte' });
    expect(screen.getByRole('button', { name: /Plateformes IA/ })).toHaveTextContent('05');
    expect(screen.getByRole('button', { name: /Exploitation/ })).toHaveTextContent('06');
  });
  it('is the last section on an ordinary instance, where Exploitation is absent', async () => {
    servePlatforms(); show(<ShadowAdministration />);
    await screen.findByRole('checkbox', { name: 'Activer la collecte' });
    expect(screen.getByRole('button', { name: /Plateformes IA/ })).toHaveTextContent('05');
    expect(screen.queryByRole('button', { name: /Exploitation/ })).toBeNull();
  });
  it('groups the platforms under the inventory categories and keeps hidden ones listed', async () => {
    servePlatforms(); show(<ShadowAdministration />);
    await screen.findByRole('checkbox', { name: 'Activer la collecte' });
    fireEvent.click(screen.getByRole('button', { name: /Plateformes IA/ }));
    expect(await screen.findByText('Réunions et transcription')).toBeInTheDocument();
    expect(screen.getByText('Agrégateurs multi-modèles')).toBeInTheDocument();
    expect(screen.getByText('Hôte partagé exigeant un chemin')).toBeInTheDocument();
    // A hidden platform stays on this screen: it is where it is found again.
    expect(screen.getByRole('checkbox', { name: /Fireflies/ })).toBeChecked();
    expect(screen.getByRole('checkbox', { name: /Poe/ })).not.toBeChecked();
    // Worded so no count makes it ungrammatical: positional parameters cannot agree in
    // number, and "1 masquées" would be wrong exactly when one platform is hidden.
    expect(screen.getByText('Plateformes : 3 · masquées de Découverte : 1')).toBeInTheDocument();
  });
  it('sends the catalogue identifier when a platform is hidden, never its domain', async () => {
    const sent: unknown[] = []; servePlatforms(body => sent.push(body)); show(<ShadowAdministration />);
    await screen.findByRole('checkbox', { name: 'Activer la collecte' });
    fireEvent.click(screen.getByRole('button', { name: /Plateformes IA/ }));
    fireEvent.click(await screen.findByRole('checkbox', { name: /Fireflies/ }));
    // The identifier survives a catalogue revision that adds or drops a domain; the host
    // does not, and the server resolves one to the other.
    await waitFor(() => expect(sent).toEqual([{ id: 'fireflies', muted: true }]));
  });
  // Moved out of Privacy on the user's request the same day. It still writes through
  // PUT /api/privacy, so the written reason it demands moved with it.
  it('carries candidate discovery with its mandatory reason', async () => {
    const sent: unknown[] = [];
    serve((url, init) => {
      if (url === '/api/shadow/settings') return reply(settings);
      if (url === '/api/detection/platforms') return reply(platforms);
      if (url === '/api/privacy') { if (init?.method === 'PUT') { sent.push(JSON.parse(String(init.body))); return reply({ ok: true }); } return reply(privacy); }
      return undefined;
    });
    show(<ShadowAdministration />);
    await screen.findByRole('checkbox', { name: 'Activer la collecte' });
    fireEvent.click(screen.getByRole('button', { name: /Plateformes IA/ }));
    const toggle = await screen.findByRole('checkbox', { name: 'Découvrir les domaines candidats' });
    expect(toggle).toBeDisabled();
    fireEvent.change(screen.getByRole('textbox', { name: 'Motif de cette modification' }), { target: { value: 'Inventaire demandé par la direction' } });
    await waitFor(() => expect(toggle).toBeEnabled());
    fireEvent.click(toggle);
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0]).toMatchObject({ revision: 3, reason: 'Inventaire demandé par la direction' });
    expect((sent[0] as { config: { discovery_enabled: boolean; k_anonymity: number } }).config.discovery_enabled).toBe(true);
    // The whole document travels back: a partial write would reset what this screen never shows.
    expect((sent[0] as { config: { k_anonymity: number } }).config.k_anonymity).toBe(5);
  });
});
