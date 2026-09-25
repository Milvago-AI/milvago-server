// Closing a dialog: the button, Escape, and -- user request of 2026-09-15 -- a
// click on the backdrop. The backdrop belongs to the `<dialog>` itself, so only the
// pointer position separates the backdrop from the content; these cases pin what must NOT close.
import { fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { Context, Dialog } from './ui';
import type { Session } from './api';

const session: Session = { user: { id: 'synthetic-user', email: 'operator@example.invalid', display_name: 'Test operator' }, organization: { id: 'synthetic-org', name: 'Test organization', role: 'owner' }, organizations: [], permissions: [], csrf_token: 'synthetic-csrf', edition: 'community' };

beforeEach(() => {
  Object.defineProperty(HTMLDialogElement.prototype, 'showModal', { configurable: true, value() { this.setAttribute('open', ''); } });
  Object.defineProperty(HTMLDialogElement.prototype, 'close', { configurable: true, value() { this.removeAttribute('open'); } });
});

// jsdom lays out nothing: the dialog's box is declared here, and it
// defines what is inside (150, 150) and what is outside (10, 10).
function open() {
  const close = vi.fn();
  render(<Context.Provider value={{ session, language: 'en', refreshSession: async () => {} }}><Dialog title="Synthetic dialog" close={close}><p>Synthetic body</p></Dialog></Context.Provider>);
  const dialog = screen.getByRole('dialog', { hidden: true }) as HTMLDialogElement;
  dialog.getBoundingClientRect = () => ({ left: 100, right: 300, top: 100, bottom: 300, x: 100, y: 100, width: 200, height: 200, toJSON: () => ({}) });
  return { dialog, close };
}

const at = (x: number, y: number, detail = 1) => ({ clientX: x, clientY: y, detail, bubbles: true });

it('closes on a click on the backdrop', () => {
  const { dialog, close } = open();
  fireEvent.mouseDown(dialog, at(10, 10));
  fireEvent.click(dialog, at(10, 10));
  expect(close).toHaveBeenCalledTimes(1);
});

it('stays open when the click lands on the dialog itself', () => {
  const { dialog, close } = open();
  fireEvent.mouseDown(dialog, at(150, 150));
  fireEvent.click(dialog, at(150, 150));
  expect(close).not.toHaveBeenCalled();
});

it('stays open when a selection started inside is released on the backdrop', () => {
  const { dialog, close } = open();
  fireEvent.mouseDown(dialog, at(150, 150));
  fireEvent.click(dialog, at(10, 10));
  expect(close).not.toHaveBeenCalled();
});

it('stays open on a click with no pointer position, as the keyboard produces', () => {
  const { dialog, close } = open();
  fireEvent.mouseDown(dialog, at(0, 0, 0));
  fireEvent.click(dialog, at(0, 0, 0));
  expect(close).not.toHaveBeenCalled();
});

it('still closes from its own button', () => {
  const { close } = open();
  fireEvent.click(screen.getByRole('button', { name: 'Close' }));
  expect(close).toHaveBeenCalledTimes(1);
});

it('stays open when the click lands in a dialog nested inside it', () => {
  // The message detail is a drawer rendered inside the conversation dialog: a click on
  // its buttons bubbles up here, outside the conversation's box, and closed it too.
  const outer = vi.fn(), inner = vi.fn();
  render(<Context.Provider value={{ session, language: 'en', refreshSession: async () => {} }}><Dialog title="Synthetic conversation" close={outer}><Dialog title="Synthetic detail" close={inner}><button type="button">Synthetic action</button></Dialog></Dialog></Context.Provider>);
  const [conversation] = screen.getAllByRole('dialog', { hidden: true }) as HTMLDialogElement[];
  conversation.getBoundingClientRect = () => ({ left: 100, right: 300, top: 100, bottom: 300, x: 100, y: 100, width: 200, height: 200, toJSON: () => ({}) });
  const action = screen.getByRole('button', { name: 'Synthetic action', hidden: true });
  fireEvent.mouseDown(action, at(400, 150));
  fireEvent.click(action, at(400, 150));
  expect(outer).not.toHaveBeenCalled();
});

it('gives the page its scrollbar back once every dialog is closed, in any order', () => {
  // A conversation, then the detail of one of its messages: closed in the order
  // opposite to their opening, the page was left without a scrollbar.
  const shown = (title: string) => render(<Context.Provider value={{ session, language: 'en', refreshSession: async () => {} }}><Dialog title={title} close={() => {}}><p>{title}</p></Dialog></Context.Provider>);
  const conversation = shown('Synthetic conversation');
  const detail = shown('Synthetic detail');
  expect(document.documentElement.style.overflow).toBe('hidden');
  conversation.unmount();
  expect(document.documentElement.style.overflow).toBe('hidden');
  detail.unmount();
  expect(document.documentElement.style.overflow).toBe('');
});
