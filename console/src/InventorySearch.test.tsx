import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { InventorySearch, inventoryFromHash, inventoryOperators, serializeInventory } from './InventorySearch';
import { parseEventQuery, formatEventQuery } from './shadow/eventQuery';
import { Context } from './ui';
import type { Session } from './api';

const session = { user: { id: 'fixture-reader' }, organization: { id: 'fixture-org', role: 'admin' }, permissions: ['discovery.read', 'devices.read', 'policy.manage'], edition: 'community' } as Session;
const item = { family: 'application', id: 'cursor', name: 'Cursor', vendor: 'Fixture vendor', type: 'software', devices: 2, observations: 3, states: ['indication'], status: '', last_seen: '2026-10-31T00:00:00Z' };
function mock() {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
    const url = new URL(String(input), 'https://fixture.invalid');
    const second = url.searchParams.has('cursor');
    return new Response(JSON.stringify({ items: [{ ...item, id: second ? 'z-next' : 'cursor', name: second ? 'Next app' : 'Cursor' }], total: 123, next_cursor: second ? '' : 'fixture-next' }), { headers: { 'Content-Type': 'application/json' } });
  });
}
function show(value = session) { return render(<Context.Provider value={{ session: value, language: 'en', refreshSession: async () => undefined }}><InventorySearch select={vi.fn()}/></Context.Provider>); }
beforeEach(() => { history.replaceState(null, '', '#applications'); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it('uses the same bounded parser with every inventory operator and an unqualified global query', () => {
  for (const [operator, field] of Object.entries(inventoryOperators)) {
    const result = parseEventQuery(operator + ':(alpha|beta)', {}, undefined, inventoryOperators);
    expect(result.ok, operator).toBe(true);
    if (result.ok) expect(result.criteria).toEqual({ [field]: '(alpha|beta)', regex: [field] });
  }
  const result = parseEventQuery('LT-COM app:cursor environment:host|wsl', {}, undefined, inventoryOperators);
  expect(result).toEqual({ ok: true, criteria: { query: 'LT-COM', app: 'cursor', environment: 'host|wsl', regex: ['app', 'environment', 'query'] } });
  if (result.ok) {
    const formatted = formatEventQuery(result.criteria, inventoryOperators);
    expect(formatted).toBe('app:cursor environment:host|wsl LT-COM');
    history.replaceState(null, '', '#applications?' + serializeInventory(result.criteria));
    expect(inventoryFromHash()).toEqual(result.criteria);
  }
  expect(parseEventQuery('model:gpt', {}, undefined, inventoryOperators).ok).toBe(false);
  expect(parseEventQuery('app:(?=bad)', {}, undefined, inventoryOperators).ok).toBe(false);
});

it('synchronizes the visual filter with the pending global query and clears immediately without Enter', async () => {
  const fetcher = mock(), user = userEvent.setup(); show();
  expect(await screen.findByText('123 results')).toBeInTheDocument();
  expect(screen.queryByText('Last 24 hours')).not.toBeInTheDocument();
  await user.type(screen.getByRole('searchbox'), 'LT-COM');
  await user.click(screen.getByRole('button', { name: 'Add filter' }));
  await user.click(screen.getByRole('button', { name: 'Application' }));
  await user.type(screen.getByLabelText('Application'), 'cursor|claude{Enter}');
  await waitFor(() => expect(fetcher.mock.calls.some(([url]) => { const q = new URL(String(url), 'https://fixture.invalid').searchParams; return q.get('app') === 'cursor|claude' && q.get('query') === 'LT-COM' && q.getAll('regex').includes('app'); })).toBe(true));
  expect(screen.getByRole('searchbox')).toHaveValue('app:cursor|claude LT-COM');
  await user.clear(screen.getByRole('searchbox'));
  await waitFor(() => expect(String(fetcher.mock.calls.at(-1)?.[0])).toBe('/api/discovery/inventory?limit=50'));
  expect(location.hash).toBe('#applications');
});

it('keeps the server total and criteria across pages and resets the cursor on the next search', async () => {
  const fetcher = mock(), user = userEvent.setup(); show();
  await screen.findByText('Cursor');
  await user.click(screen.getByRole('button', { name: 'Next' }));
  await screen.findByText('Next app');
  expect(screen.getByText('123 results')).toBeInTheDocument();
  await user.type(screen.getByRole('searchbox'), 'service:gemini|gpt{Enter}');
  await waitFor(() => { const q = new URL(String(fetcher.mock.calls.at(-1)?.[0]), 'https://fixture.invalid').searchParams; expect(q.has('cursor')).toBe(false); expect(q.get('service')).toBe('gemini|gpt'); });
  fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'app:[' } });
  await user.type(screen.getByRole('searchbox'), '{Enter}');
  expect(screen.getByRole('alert')).toBeInTheDocument();
  expect(String(fetcher.mock.calls.at(-1)?.[0])).toContain('service=gemini');
});

it('renders hostile names as text and offers no device picker without devices.read', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ items: [{ ...item, name: '<img src=x onerror=alert(1)>' }], total: 1, next_cursor: '' }), { headers: { 'Content-Type': 'application/json' } }));
  show({ ...session, permissions: ['discovery.read'] });
  expect(await screen.findByText('<img src=x onerror=alert(1)>')).toBeInTheDocument();
  expect(document.querySelector('img')).toBeNull();
  await userEvent.setup().click(screen.getByRole('button', { name: 'Add filter' }));
  expect(screen.queryByRole('button', { name: 'Device' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Environment' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Service' })).not.toBeInTheDocument();
});

it('refreshes after a review change without dropping the query and releases its listener on unmount', async () => {
  history.replaceState(null, '', '#applications?app=cursor&regex=app');
  const fetcher = mock(), view = show();
  await screen.findByText('Cursor');
  const count = fetcher.mock.calls.length;
  fireEvent(window, new Event('milvago:inventory-changed'));
  await waitFor(() => expect(fetcher.mock.calls.length).toBe(count + 1));
  expect(String(fetcher.mock.calls.at(-1)?.[0])).toContain('app=cursor&regex=app');
  view.unmount();
  fireEvent(window, new Event('milvago:inventory-changed'));
  expect(fetcher.mock.calls.length).toBe(count + 1);
});

it('contains malformed web counters instead of rendering server objects', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ items: [{ ...item, family: 'platform', accounts: { unsafe: true } }], total: 1, next_cursor: '' }), { headers: { 'Content-Type': 'application/json' } }));
  show();
  expect(await screen.findByRole('alert')).toBeInTheDocument();
  expect(screen.queryByText('Cursor')).not.toBeInTheDocument();
});
