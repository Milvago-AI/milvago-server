import { useState } from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, expect, it, vi } from 'vitest';
import type { Session } from '../api';
import { Context } from '../ui';
import { EventFilters } from './EventFilters';
import { SavedFilters } from './FilterBar';
import { ConversationsPage } from './ConversationsPage';
import type { Criteria } from './types';

const session: Session = { user: { id: 'synthetic-viewer', email: 'viewer@example.invalid', display_name: 'Synthetic viewer' }, organization: { id: 'org', name: 'Synthetic organization', role: 'viewer' }, organizations: [], permissions: ['events.read'], csrf_token: 'fixture', edition: 'community' };
const period = { from: '2026-10-30T12:00:00Z', to: '2026-10-31T12:00:00Z' };
function Harness({ initial, changed, saved = false }: { initial: Criteria; changed: (value: Criteria) => void; saved?: boolean }) {
  const [criteria, set] = useState(initial);
  const change = (next: Criteria) => { set(next); changed(next); };
  return <Context.Provider value={{ session, language: 'en', refreshSession: async () => undefined }}>
    <EventFilters criteria={criteria} change={change} views={saved ? <SavedFilters compact criteria={criteria} apply={change}/> : undefined}/>
  </Context.Provider>;
}
beforeEach(() => {
  location.hash = '';
  Object.defineProperty(HTMLDialogElement.prototype, 'showModal', { configurable: true, value() { this.setAttribute('open', ''); } });
  Object.defineProperty(HTMLDialogElement.prototype, 'close', { configurable: true, value() { this.removeAttribute('open'); } });
});
it('keeps search and period visible and applies metadata only on submission, preserving commas', async () => {
  const changed = vi.fn(), user = userEvent.setup();
  render(<Harness initial={period} changed={changed}/>);
  expect(screen.getByRole('button', { name: 'Period: 24 h' })).toBeVisible();
  expect(screen.queryByRole('textbox')).toBeNull();
  expect(screen.queryByRole('combobox')).toBeNull();
  await user.type(screen.getByRole('searchbox'), 'alpha, beta'); expect(changed).not.toHaveBeenCalled();
  await user.keyboard('{Enter}'); expect(changed).toHaveBeenLastCalledWith({ ...period, query: 'alpha, beta', regex: ['query'] });
  expect(screen.getByRole('button', { name: 'Remove Search: alpha, beta' })).toBeVisible();
  await user.click(screen.getByRole('button', { name: 'Remove Search: alpha, beta' }));
  expect(changed).toHaveBeenLastCalledWith(period); expect(screen.getByRole('searchbox')).toHaveValue('');
});
it('edits and removes repeated inherited criteria without discarding the other filters', async () => {
  const changed = vi.fn(), user = userEvent.setup();
  const initial = { ...period, provider: ['first.example', 'second.example'], tool: ['chrome', 'firefox'], kind: 'prompt' };
  render(<Harness initial={initial} changed={changed}/>);
  await user.click(screen.getByRole('button', { name: 'Service: first.example' }));
  expect(screen.getByRole('textbox', { name: 'Service' })).toHaveValue('first.example, second.example');
  await user.click(screen.getByRole('button', { name: 'Apply' }));
  expect(changed).toHaveBeenLastCalledWith(initial);
  await user.click(screen.getByRole('button', { name: 'Remove Service: first.example' }));
  expect(changed).toHaveBeenLastCalledWith({ ...initial, provider: 'second.example' });
  expect(screen.getByRole('button', { name: 'Service: second.example' })).toBeVisible();
  expect(screen.getByRole('button', { name: 'Browser / application: firefox' })).toBeVisible();
});
it('preserves a search draft when hash synchronization repeats the applied criteria', async () => {
  const changed = vi.fn(), user = userEvent.setup();
  const view = (criteria: Criteria) => <Context.Provider value={{ session, language: 'en', refreshSession: async () => undefined }}><EventFilters criteria={criteria} change={changed}/></Context.Provider>;
  const { rerender } = render(view({ ...period, provider: 'first.example' }));
  await user.clear(screen.getByRole('searchbox'));
  await user.type(screen.getByRole('searchbox'), 'service:first.example text:"new metadata"');
  rerender(view({ ...period, provider: 'first.example' }));
  expect(screen.getByRole('searchbox')).toHaveValue('service:first.example text:"new metadata"');
  await user.keyboard('{Enter}');
  expect(changed).toHaveBeenLastCalledWith({ ...period, provider: 'first.example', query: 'new metadata', regex: ['provider', 'query'] });
  await user.click(screen.getByRole('button', { name: 'Add filter (1)' }));
  await user.click(screen.getByRole('button', { name: 'Model' }));
  await user.type(screen.getByRole('textbox', { name: 'Model' }), 'pending model');
  rerender(view({ ...period, provider: 'first.example' }));
  expect(screen.getByRole('textbox', { name: 'Model' })).toHaveValue('pending model');
});
it('adds a criterion, cancels an edit with Escape and returns focus without changing results', async () => {
  const changed = vi.fn(), user = userEvent.setup();
  render(<Harness initial={period} changed={changed}/>);
  await user.click(screen.getByRole('button', { name: 'Add filter' }));
  expect(screen.queryByRole('textbox', { name: 'Model' })).toBeNull();
  await user.click(screen.getByRole('button', { name: 'Service' }));
  await user.type(screen.getByRole('textbox', { name: 'Service' }), 'third.example');
  await user.keyboard('{Escape}'); expect(changed).not.toHaveBeenCalled();
  expect(screen.getByRole('button', { name: 'Add filter' })).toHaveFocus();
  await user.click(screen.getByRole('button', { name: 'Add filter' }));
  await user.click(screen.getByRole('button', { name: 'Action' }));
  await user.type(screen.getByLabelText('Action'), 'blocked');
  await user.click(screen.getByRole('button', { name: 'Apply' }));
  expect(changed).toHaveBeenLastCalledWith({ ...period, action: 'blocked', regex: ['action'] });
  expect(screen.getByRole('button', { name: 'Action: Blocked' })).toBeVisible();
  await user.click(screen.getByRole('button', { name: 'Action: Blocked' }));
  await user.tab(); await user.keyboard('{Escape}');
  expect(screen.getByRole('button', { name: 'Action: Blocked' })).toHaveFocus();
});
it('changes only the period, validates custom dates and resets all criteria explicitly', async () => {
  const changed = vi.fn(), user = userEvent.setup();
  render(<Harness initial={{ ...period, provider: 'first.example', query: 'metadata' }} changed={changed}/>);
  await user.click(screen.getByRole('button', { name: 'Period: 24 h' }));
  await user.click(screen.getByRole('button', { name: '7 d' }));
  const next = changed.mock.lastCall![0]; expect(next.provider).toBe('first.example'); expect(next.query).toBe('metadata');
  expect(Date.parse(next.to) - Date.parse(next.from)).toBe(168 * 3600000);
  await user.click(screen.getByRole('button', { name: 'Period: 7 d' }));
  await user.click(screen.getByText('Custom', { selector: 'summary' }));
  fireEvent.change(screen.getByLabelText('From'), { target: { value: '2026-10-31T15:00' } });
  fireEvent.change(screen.getByLabelText('To'), { target: { value: '2026-10-30T12:00' } });
  fireEvent.submit(screen.getByLabelText('From').closest('form')!);
  expect(screen.getByRole('alert')).toHaveTextContent('Choose a valid period'); expect(changed).toHaveBeenCalledTimes(1);
  for (const end of ['2026-10-31T15:00', '2028-10-31T16:00']) {
    fireEvent.change(screen.getByLabelText('To'), { target: { value: end } });
    fireEvent.submit(screen.getByLabelText('From').closest('form')!);
    expect(screen.getByRole('alert')).toBeVisible(); expect(changed).toHaveBeenCalledTimes(1);
  }
  fireEvent.change(screen.getByLabelText('To'), { target: { value: '2026-10-31T16:00' } });
  fireEvent.submit(screen.getByLabelText('From').closest('form')!);
  expect(Date.parse(changed.mock.lastCall![0].to) - Date.parse(changed.mock.lastCall![0].from)).toBe(3600000);
  await user.click(screen.getByRole('button', { name: 'Reset' }));
  const reset = changed.mock.lastCall![0]; expect(Object.keys(reset).sort()).toEqual(['from', 'to']);
  expect(Date.parse(reset.to) - Date.parse(reset.from)).toBe(24 * 3600000);
});
it('shows unknown and hostile metadata as text, with technical filters on demand', async () => {
  const changed = vi.fn(), user = userEvent.setup();
  const hostile = '<img src=x onerror=alert(1)>';
  render(<Harness initial={{ ...period, provider: hostile, model: 'unknown', dlp_outcome: 'future_value' }} changed={changed}/>);
  expect(screen.getByRole('button', { name: 'Service: ' + hostile })).toBeVisible();
  expect(document.querySelector('img')).toBeNull();
  expect(screen.getByRole('button', { name: 'Model: unknown' })).toBeVisible();
  await user.click(screen.getByRole('button', { name: 'Add filter (3)' }));
  expect(screen.getByRole('button', { name: 'DLP outcome' })).not.toBeVisible();
  await user.click(screen.getByText('DLP and technical criteria', { selector: 'summary' }));
  await user.click(screen.getByRole('button', { name: 'DLP outcome' }));
  expect(screen.getByRole('combobox', { name: 'DLP outcome' })).toHaveValue('future_value');
  await user.click(screen.getByRole('button', { name: 'Apply' }));
  expect(changed.mock.lastCall![0].dlp_outcome).toBe('future_value');
});
it('closes a popover on outside focus while keeping the draft unapplied', async () => {
  const changed = vi.fn(), user = userEvent.setup();
  render(<Harness initial={period} changed={changed}/>);
  await user.click(screen.getByRole('button', { name: 'Add filter' }));
  await user.click(screen.getByRole('button', { name: 'Model' }));
  await user.type(screen.getByRole('textbox', { name: 'Model' }), 'draft');
  await user.click(screen.getByRole('searchbox')); expect(screen.queryByRole('textbox', { name: 'Model' })).toBeNull();
  expect(changed).not.toHaveBeenCalled();
});
it('loads saved views from a compact menu and saves the exact scope only on explicit submission', async () => {
  const user = userEvent.setup(), changed = vi.fn(), writes: { body: Criteria; method: string }[] = [];
  const saved = { id: 'saved', name: '<b>Synthetic view</b>', shared: false, owner_id: session.user.id, criteria: { ...period, provider: ['first.example', 'second.example'], kind: 'response' } };
  vi.stubGlobal('fetch', vi.fn(async (_input: unknown, init?: RequestInit) => {
    if (init?.method === 'POST') writes.push({ method: init.method, body: JSON.parse(String(init.body)) });
    return new Response(JSON.stringify({ items: [saved] }), { headers: { 'Content-Type': 'application/json' } });
  }));
  render(<Harness initial={period} changed={changed} saved/>);
  expect(screen.queryByRole('combobox', { name: 'Saved view' })).toBeNull();
  await user.click(screen.getByRole('button', { name: 'Views' }));
  await user.selectOptions(await screen.findByRole('combobox', { name: 'Saved view' }), 'saved');
  expect(changed).toHaveBeenLastCalledWith(saved.criteria); expect(screen.queryByRole('combobox', { name: 'Saved view' })).toBeNull();
  await user.click(screen.getByRole('button', { name: 'Views' }));
  await user.click(screen.getByRole('button', { name: 'Save this view' }));
  const dialog = screen.getByRole('dialog'); expect(writes).toHaveLength(0);
  await user.type(within(dialog).getByRole('textbox', { name: 'View name' }), 'Synthetic saved scope');
  await user.click(within(dialog).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(writes).toHaveLength(1));
  expect(writes[0].body).toEqual({ name: 'Synthetic saved scope', shared: false, criteria: saved.criteria });
  expect(document.querySelector('b')).toBeNull();
});
it('carries inherited repeated criteria through conversation requests and report links', async () => {
  const user = userEvent.setup(), reads: string[] = [];
  location.hash = '#events?from='+period.from+'&to='+period.to+'&provider=first.example&provider=second.example&tool=chrome&kind=prompt';
  vi.stubGlobal('fetch', vi.fn(async (input: unknown) => {
    const url = String(input); reads.push(url);
    return new Response(JSON.stringify(url.startsWith('/api/shadow/filters') ? { items: [] } : { items: [], total: 0 }), { headers: { 'Content-Type': 'application/json' } });
  }));
  render(<Context.Provider value={{ session, language: 'en', refreshSession: async () => undefined }}><ConversationsPage/></Context.Provider>);
  await waitFor(() => expect(reads.some(url => url.startsWith('/api/shadow/conversations?'))).toBe(true));
  await user.click(screen.getByRole('button', { name: 'Remove Service: first.example' }));
  await waitFor(() => expect(reads.filter(url => url.startsWith('/api/shadow/conversations?')).at(-1)).toContain('provider=second.example'));
  const last = new URLSearchParams(reads.filter(url => url.startsWith('/api/shadow/conversations?')).at(-1)!.split('?')[1]);
  expect(last.getAll('provider')).toEqual(['second.example']); expect(last.get('tool')).toBe('chrome'); expect(last.get('kind')).toBe('prompt'); expect(last.get('offset')).toBe('0');
  await user.click(screen.getByRole('button', { name: 'Reports and exports' }));
  const report = new URLSearchParams(screen.getByRole('link', { name: 'Synthesis report' }).getAttribute('href')!.split('?')[1]);
  expect(report.getAll('provider')).toEqual(['second.example']); expect(report.get('tool')).toBe('chrome'); expect(report.get('from')).toBe(period.from);
});
