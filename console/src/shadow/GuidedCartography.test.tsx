import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import type { Session } from '../api';
import { Context } from '../ui';
import { CartographyPage } from './CartographyPage';
import type { Cartography } from './types';

const session: Session = { user: { id: 'reader', email: 'reader@example.invalid', display_name: 'Reader' }, organization: { id: 'org', name: 'Synthetic organization', role: 'viewer' }, organizations: [], permissions: ['events.read'], csrf_token: 'fixture', edition: 'community' };
const flows = Array.from({ length: 12 }, (_, index) => ({ actor_id: 'person-' + (index + 1), actor_name: 'Person ' + (index + 1), tool: index % 2 ? 'firefox' : 'chrome', provider: 'service.example', model: 'unknown', count: 120 - index * 10, blocked: index === 0 ? 2 : 0, sensitive: 0 }));
const payload: Cartography = { flows, totals: { requests: 780, responses: 10, navigations: 4, conversations: 12, actors: 12, tools: 2, providers: 1, models: 0, blocked: 2 }, capture: [], series: [], unattributed: 0 };
function show(data = payload) {
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async input => new Response(JSON.stringify(String(input).startsWith('/api/shadow/cartography?') ? data : { items: [] }), { headers: { 'Content-Type': 'application/json' } }));
  render(<Context.Provider value={{ session, language: 'fr', refreshSession: async () => undefined }}><CartographyPage/></Context.Provider>);
  return fetch;
}
afterEach(() => { cleanup();vi.restoreAllMocks();location.hash = ''; });

it('starts with service cards across all twelve people, without ribbons, rails or an arbitrary ten-person window', async () => {
  show();
  const service = await screen.findByRole('button', { name: /service.example.*780/ });
  expect(service).toHaveTextContent('12 Personnes');
  expect(document.querySelector('.fd-canvas')).toBeNull();
  expect(document.querySelector('.fd-rail')).toBeNull();
  expect(screen.getByRole('checkbox')).not.toBeVisible();
  expect(screen.getByRole('link', { name: 'Rapport de synthèse' })).not.toBeVisible();
});

it('supports keyboard service exploration and exact person filters, including people beyond the former window', async () => {
  const fetch = show();
  const user = userEvent.setup();
  (await screen.findByRole('button', { name: /service.example.*780/ })).focus();
  await user.keyboard('{Enter}');
  const people = screen.getByRole('region', { name: 'Personnes' });
  await user.click(within(people).getByRole('button', { name: 'Voir 6 de plus' }));
  await user.click(within(people).getByRole('button', { name: /Person 12.*10 requêtes/ }));
  const link = screen.getByRole('link', { name: 'Voir ces requêtes' });
  const query = new URLSearchParams(link.getAttribute('href')!.split('?')[1]);
  expect(query.getAll('provider')).toEqual(['service.example']);
  expect(query.getAll('actor_id')).toEqual(['person-12']);
  expect(query.get('kind')).toBe('prompt');
  expect(screen.getByRole('region', { name: 'Navigateurs / applications' })).toHaveTextContent('firefox');
  expect(screen.getByRole('region', { name: 'Modèles' })).toHaveTextContent('Non attribué');
  expect(fetch.mock.calls.every(([, init]) => !init?.method || init.method === 'GET')).toBe(true);
  await user.click(screen.getByRole('button', { name: 'Tous les services' }));
  expect(screen.getByRole('button', { name: /service.example.*780/ })).toBeVisible();
});

it('opens the observed path table on demand and preserves unknown model values in journal links', async () => {
  show();
  fireEvent.click(await screen.findByRole('button', { name: /service.example.*780/ }));
  expect(screen.getByRole('table')).not.toBeVisible();
  fireEvent.click(screen.getByText('Parcours observés (12)'));
  const table = screen.getByRole('table');
  expect(within(table).getAllByRole('row')).toHaveLength(11);
  fireEvent.click(within(table).getAllByRole('button', { name: 'Journal' })[0]);
  const query = new URLSearchParams(location.hash.split('?')[1]);
  expect(query.get('model')).toBe('unknown');
  expect(query.get('provider')).toBe('service.example');
  expect(query.get('actor_id')).toBe('person-1');
  fireEvent.click(screen.getByRole('button', { name: 'Suivant' }));
  expect(within(table).getAllByRole('row')).toHaveLength(3);
});

it('keeps the full diagram as an explicit mode and closes person dimensions in overall-usage mode', async () => {
  show();
  await screen.findByRole('button', { name: /service.example.*780/ });
  fireEvent.click(screen.getByText('Options avancées'));
  fireEvent.click(screen.getByRole('checkbox', { name: 'Masquer les personnes (usage global)' }));
  fireEvent.click(screen.getByRole('button', { name: /service.example.*780/ }));
  expect(screen.queryByRole('region', { name: 'Personnes' })).toBeNull();
  fireEvent.click(screen.getByText('Parcours observés (2)'));
  expect(screen.queryByRole('columnheader', { name: 'Personnes' })).toBeNull();
  fireEvent.click(screen.getAllByRole('button', { name: 'Journal' })[0]);
  expect(new URLSearchParams(location.hash.split('?')[1]).has('actor_id')).toBe(false);
  fireEvent.click(screen.getByRole('button', { name: 'Diagramme complet' }));
  await waitFor(() => expect(document.querySelector('.fd-canvas')).not.toBeNull());
});

it('renders hostile names as text and never invents a model or usage sensitivity in Community', async () => {
  const name = '<img src=x onerror=alert(1)>';
  show({ ...payload, flows: [{ ...flows[0], provider: name }] });
  fireEvent.click(await screen.findByRole('button', { name: /<img src=x/ }));
  expect(document.querySelector('img[src=x]')).toBeNull();
  expect(screen.getByRole('region', { name: 'Modèles' })).toHaveTextContent('Non attribué');
  expect(screen.queryByText('Sensible')).toBeNull();
  fireEvent.click(screen.getByText('Parcours observés (1)'));
  expect(screen.queryByRole('columnheader', { name: 'Sensibles' })).toBeNull();
});
