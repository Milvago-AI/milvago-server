import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, expect, it, vi } from 'vitest';
import { DetectionCatalog } from './DetectionCatalog';
import { Context } from './ui';
import type { Session } from './api';

const provider = { id: 'synthetic-a', label: 'Synthetic A', domains: ['a.example.invalid'], aliases: [], conversation_path: '/chat/*', conversation_segment: 1, qualified_at: '2026-09-01T00:00:00Z', dom: { editor: 'textarea', send: 'button', response: '.response' }, network: [] };
const providers = [provider, { ...provider, id: 'synthetic-b', label: 'Synthetic B', domains: ['b.example.invalid'] }, { ...provider, id: 'synthetic-c', label: 'Synthetic C', domains: ['c.example.invalid'] }];
const catalog = { revision: 7, can_publish: true, content: { providers, native_tools: [], heuristics: { keys: [], mime_types: [] } } };
const session: Session = { user: { id: 'synthetic-user', email: 'operator@example.invalid', display_name: 'Test operator' }, organization: { id: 'synthetic-org', name: 'Test organization', role: 'owner' }, organizations: [], permissions: [], csrf_token: 'synthetic-csrf', edition: 'community' };
const response = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
beforeEach(() => {
  Object.defineProperty(HTMLDialogElement.prototype, 'showModal', { configurable: true, value() { this.setAttribute('open', ''); } });
  Object.defineProperty(HTMLDialogElement.prototype, 'close', { configurable: true, value() { this.removeAttribute('open'); } });
});
async function setup(value = catalog, failure = false) {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockImplementation(async (_, init) => init?.method === 'PUT'
    ? failure ? response({ error: 'revision_conflict', message: 'Revision changed' }, 409) : response({ ...value, revision: 8, content: JSON.parse(String(init.body)).content })
    : response(value));
  render(<Context.Provider value={{ session, language: 'en', refreshSession: async () => {} }}><DetectionCatalog /></Context.Provider>);
  await screen.findByRole('heading', { name: 'Detection catalogue' });
  expect(screen.getAllByRole('row')).toHaveLength(value.content.providers.length + 1);
  return fetcher;
}
async function publish(fetcher: Awaited<ReturnType<typeof setup>>) {
  fireEvent.click(screen.getByRole('button', { name: 'Preview changes' }));
  fireEvent.click(screen.getByRole('button', { name: 'Publish catalogue' }));
  await waitFor(() => expect(fetcher.mock.calls.filter(([, init]) => (init as RequestInit)?.method === 'PUT')).toHaveLength(1));
  const call = fetcher.mock.calls.find(([, init]) => (init as RequestInit)?.method === 'PUT')!;
  return JSON.parse(String((call[1] as RequestInit).body));
}

it('keeps the list compact, opens a row and cancels all unsaved field edits', async () => {
  const fetcher = await setup();
  expect(screen.queryByRole('textbox', { name: 'Name' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('row', { name: /Synthetic B/ }));
  expect(screen.getByRole('dialog', { name: 'Synthetic B' })).toBeInTheDocument();
  expect(screen.getByRole('textbox', { name: 'Domains (one per line)' })).toHaveValue('b.example.invalid');
  fireEvent.change(screen.getByRole('textbox', { name: 'Name' }), { target: { value: 'Cancelled draft' } });
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  expect(screen.queryByRole('button', { name: 'Cancelled draft' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Preview changes' })).not.toBeInTheDocument();
  expect(fetcher).toHaveBeenCalledTimes(1);
});

it('creates a coverage entry with multiline domains and sends it only after publication', async () => {
  const fetcher = await setup(), user = userEvent.setup();
  fireEvent.click(screen.getByRole('button', { name: 'Add coverage' }));
  await user.type(screen.getByRole('textbox', { name: 'Identifier' }), 'synthetic-new');
  await user.type(screen.getByRole('textbox', { name: 'Name' }), 'Synthetic new');
  await user.type(screen.getByRole('textbox', { name: 'Qualification date (RFC 3339)' }), '2026-09-12T00:00:00Z');
  await user.type(screen.getByRole('textbox', { name: 'Domains (one per line)' }), 'new.example.invalid\nsecond.example.invalid');
  await user.click(screen.getByRole('button', { name: 'Save changes' }));
  expect(screen.getByRole('button', { name: 'Synthetic new' })).toBeInTheDocument();
  expect(fetcher).toHaveBeenCalledTimes(1);
  const body = await publish(fetcher);
  expect(body.revision).toBe(7);
  expect(body.content.providers).toHaveLength(4);
  expect(body.content.providers[3].domains).toEqual(['new.example.invalid', 'second.example.invalid']);
  await waitFor(() => expect(screen.getByText('Catalogue published.')).toBeInTheDocument());
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  expect(screen.getByText('Catalogue published.')).toBeInTheDocument();
});

it('bulk edits only the chosen field on selected rows, including a selection hidden by search', async () => {
  const fetcher = await setup();
  fireEvent.click(screen.getByRole('checkbox', { name: 'Select Synthetic A' }));
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'b.example.invalid' } });
  expect(screen.getAllByRole('row')).toHaveLength(2);
  fireEvent.click(screen.getByRole('checkbox', { name: 'Select all visible entries' }));
  expect(screen.getByRole('region', { name: '2 selected' })).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Edit selected' }));
  fireEvent.change(screen.getByRole('combobox', { name: 'Field to change' }), { target: { value: 'editor' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'New value' }), { target: { value: '[contenteditable]' } });
  fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
  const body = await publish(fetcher);
  expect(body.content.providers).toEqual(providers.map((p, index) => index < 2 ? { ...p, dom: { ...p.dom, editor: '[contenteditable]' } } : p));
});

it('deletes selected rows after confirmation and protects the final browser service', async () => {
  const fetcher = await setup();
  fireEvent.click(screen.getByRole('checkbox', { name: 'Select all visible entries' }));
  expect(screen.getByRole('button', { name: 'Delete selected' })).toBeDisabled();
  fireEvent.click(screen.getByRole('checkbox', { name: 'Select Synthetic C' }));
  fireEvent.click(screen.getByRole('button', { name: 'Delete selected' }));
  const dialog = screen.getByRole('dialog', { name: 'Delete coverage' });
  expect(within(dialog).getAllByRole('listitem')).toHaveLength(2);
  fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
  expect(screen.getAllByRole('row')).toHaveLength(4);
  fireEvent.click(screen.getByRole('button', { name: 'Delete selected' }));
  fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }));
  expect(screen.getAllByRole('row')).toHaveLength(2);
  expect(screen.getByRole('button', { name: 'Delete Synthetic C' })).toBeDisabled();
  expect(screen.queryByRole('region')).not.toBeInTheDocument();
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect((await publish(fetcher)).content.providers).toEqual([providers[2]]);
});

it('discarding the draft restores deleted rows and clears selection', async () => {
  await setup();
  fireEvent.click(screen.getByRole('button', { name: 'Delete Synthetic B' }));
  fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }));
  expect(screen.queryByRole('button', { name: 'Synthetic B' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Discard draft' }));
  fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Discard draft' }));
  expect(screen.getAllByRole('row')).toHaveLength(4);
  expect(screen.queryByRole('button', { name: 'Preview changes' })).not.toBeInTheDocument();
});

it('exposes read-only details without mutation controls when publication is forbidden', async () => {
  const fetcher = await setup({ ...catalog, can_publish: false });
  expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Add coverage' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Synthetic A' }));
  expect(screen.getByRole('textbox', { name: 'Name' })).toBeDisabled();
  expect(screen.queryByRole('button', { name: 'Save changes' })).not.toBeInTheDocument();
  expect(fetcher).toHaveBeenCalledTimes(1);
});

it('retains the draft and exact revision on a publication conflict', async () => {
  const fetcher = await setup(catalog, true);
  fireEvent.click(screen.getByRole('button', { name: 'Synthetic A' }));
  fireEvent.change(screen.getByRole('textbox', { name: 'Name' }), { target: { value: 'Changed draft' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));
  expect((await publish(fetcher)).revision).toBe(7);
  await screen.findByText('Revision changed');
  expect(screen.queryByText('Catalogue published.')).not.toBeInTheDocument();
  fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Cancel' }));
  fireEvent.click(screen.getByRole('button', { name: 'Changed draft' }));
  expect(screen.getByRole('textbox', { name: 'Name' })).toHaveValue('Changed draft');
});
