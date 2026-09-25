import { fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Context } from '../ui';
import type { Session } from '../api';
import { CartographyPage } from './CartographyPage';
import { ReportPage } from './ReportPage';
import type { Cartography } from './types';

const session: Session = { user: { id: 'user-1', email: 'owner@example.org', display_name: 'Propriétaire de test' }, organization: { id: 'org-1', name: 'Organisation de test', role: 'owner' }, organizations: [{ id: 'org-1', name: 'Organisation de test', role: 'owner' }], permissions: ['overview.read', 'events.read', 'devices.read', 'policy.manage'], csrf_token: 'report-csrf', edition: 'commercial' };
const community: Session = { ...session, edition: 'community' };
const map: Cartography = {
  capture: [{ provider: 'chatgpt.com', navigations: 8, requests: 5, devices_seen: 2, devices_reporting: 1 }],
  totals: { requests: 5, responses: 2, navigations: 8, conversations: 1, actors: 1, tools: 2, providers: 1, models: 1, sensitive: 2, blocked: 1 },
  flows: [
    { actor_id: 'actor-1', actor_name: 'Personne de test', tool: 'chrome', provider: 'chatgpt.com', model: 'unknown', count: 3, sensitive: 2, blocked: 1 },
    { actor_id: 'actor-1', actor_name: 'Personne de test', tool: 'firefox', provider: 'chatgpt.com', model: 'unknown', count: 2, sensitive: 0, blocked: 0 },
  ],
  series: [{ at: '2026-09-17T08:00:00Z', requests: 3 }, { at: '2026-09-17T09:00:00Z', requests: 2 }],
  unattributed: 0,
};
function reply(body: unknown, status = 200) { return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }); }
function serve(handler: (url: string) => Response | undefined) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async url => handler(String(url)) ?? (String(url).startsWith('/api/shadow/filters') ? reply({ items: [] }) : reply({ error: 'unexpected_request', message: String(url) }, 404)));
}
function show(children: React.ReactNode, current = session) { return render(<Context.Provider value={{ session: current, language: 'fr', refreshSession: async () => {} }}>{children}</Context.Provider>); }
beforeEach(() => { location.hash = ''; });

describe('Printable synthesis report', () => {
  // The control used to export the bare filter bar and ignore everything the reader
  // had narrowed on the map. The report opens on what is actually drawn.
  it('opens on the scope the map shows, and no longer offers the retired PDF format', async () => {
    serve(url => url.startsWith('/api/shadow/cartography') ? reply(map) : undefined);
    show(<CartographyPage />);
    const diagram = await screen.findByRole('group', { name: /Cartographie des requêtes/ });
    const format = screen.getByRole('combobox', { name: /Format d.export/ });
    expect(within(format).queryByRole('option', { name: 'PDF' })).toBeNull();
    expect(within(format).getAllByRole('option').map(option => (option as HTMLOptionElement).value)).toEqual(['json', 'csv']);
    within(diagram).getByRole('button', { name: 'chrome · 3 requêtes' }).focus();
    await userEvent.setup().keyboard('{Enter}');
    const link = screen.getByRole('link', { name: 'Rapport de synthèse' });
    const href = link.getAttribute('href')!;
    expect(href.startsWith('#report?')).toBe(true);
    const params = new URLSearchParams(href.split('?')[1]);
    expect(params.getAll('tool')).toEqual(['chrome']);
    expect(params.get('from')).toBeTruthy();
    expect(params.get('to')).toBeTruthy();
  });

  it('prints the synthesis of its scope, and nothing of a conversation', async () => {
    location.hash = '#report?from=2026-09-17T00:00:00.000Z&to=2026-09-17T12:00:00.000Z&provider=chatgpt.com';
    const fetcher = serve(url => url.startsWith('/api/shadow/cartography') ? reply(map) : undefined);
    show(<ReportPage />);
    expect(await screen.findByRole('heading', { level: 1, name: 'Rapport de synthèse' })).toBeInTheDocument();
    // One call, carrying the scope, and no identity mode: the report reads the map's
    // own aggregate and never asks for a reveal.
    const calls = fetcher.mock.calls.map(call => String(call[0])).filter(url => url.startsWith('/api/shadow/cartography'));
    expect(calls).toHaveLength(1);
    expect(calls[0]).toContain('provider=chatgpt.com');
    expect(calls[0]).not.toContain('identity=');
    // The scope is spelled out, because a report without it cannot be read.
    expect(screen.getByText('Filtres appliqués')).toBeInTheDocument();
    expect(within(screen.getByText('Filtres appliqués').closest('div')!).getByText(/chatgpt\.com/)).toBeInTheDocument();
    expect(screen.getByText('Organisation de test')).toBeInTheDocument();
    // Six sheets: cover, synthesis, services, browsers, models, people.
    expect(screen.getAllByText(/^Page \d+ \/ 6$/)).toHaveLength(6);
    expect(screen.getAllByText('Métadonnées seules — aucun contenu de conversation')).toHaveLength(6);
    expect(screen.getByRole('heading', { name: 'Principales personnes' })).toBeInTheDocument();
  });

  it('asks the browser to print and calls nothing else', async () => {
    location.hash = '#report?from=2026-09-17T00:00:00.000Z&to=2026-09-17T12:00:00.000Z';
    const fetcher = serve(url => url.startsWith('/api/shadow/cartography') ? reply(map) : undefined);
    const print = vi.spyOn(window, 'print').mockImplementation(() => {});
    show(<ReportPage />);
    await screen.findByRole('heading', { level: 1, name: 'Rapport de synthèse' });
    fireEvent.click(screen.getByRole('button', { name: 'Imprimer ou enregistrer en PDF' }));
    expect(print).toHaveBeenCalledTimes(1);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('names no sensitivity at all in Community', async () => {
    location.hash = '#report?from=2026-09-17T00:00:00.000Z&to=2026-09-17T12:00:00.000Z';
    serve(url => url.startsWith('/api/shadow/cartography') ? reply(map) : undefined);
    show(<ReportPage />, community);
    await screen.findByRole('heading', { level: 1, name: 'Rapport de synthèse' });
    expect(screen.queryByText('Événements sensibles')).toBeNull();
    expect(screen.queryAllByRole('columnheader', { name: 'Sensible' })).toHaveLength(0);
  });

  it('degrades a forged payload to zeros instead of blanking the report', async () => {
    location.hash = '#report?from=2026-09-17T00:00:00.000Z&to=2026-09-17T12:00:00.000Z';
    serve(url => url.startsWith('/api/shadow/cartography') ? reply({ totals: null, flows: null, capture: 'x', series: null, unattributed: 'x' }) : undefined);
    show(<ReportPage />);
    await screen.findByRole('heading', { level: 1, name: 'Rapport de synthèse' });
    // Cover and synthesis only: nothing to rank, so no empty ranking sheet.
    expect(screen.getAllByText(/^Page \d+ \/ 2$/)).toHaveLength(2);
    expect(screen.getByText('Aucune requête dans cette période')).toBeInTheDocument();
  });
});
