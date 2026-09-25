// The screen that decides who can register a connector on its own. What is pinned
// here is what bounds the feature: the section exists only in Enterprise and
// for an owner, the "open to everyone" state is named for what it
// is, and registration sends a list of hosts, not free text.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { Session } from './api';

const permissions = ['overview.read', 'events.read', 'devices.read', 'members.read', 'settings.manage'];
const owner: Session = {
  user: { id: 'user-1', email: 'admin@example.org', display_name: 'Administrateur' },
  organization: { id: 'org-1', name: 'Organisation de test', role: 'owner' },
  organizations: [{ id: 'org-1', name: 'Organisation de test', role: 'owner' }],
  permissions,
  csrf_token: 'session-csrf',
  edition: 'commercial',
};
const settings = { name: 'Organisation de test', event_retention_days: 30, public_url: 'https://console.example.org', public_url_confirmed: true, public_url_editable: true };
const closed = { enabled: false, unbounded: false, hosts: [], max_clients: 200, consent_required: true, scopes: ['milvago:mcp', 'milvago:content'], client_id: 'milvago-mcp-client' };
const unbounded = { ...closed, enabled: true, unbounded: true };

function reply(body: unknown, status = 200) { return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }); }

function serve(session: Session, registration: unknown, onPut?: (body: unknown) => void) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input);
    if (url === '/api/session') return reply(session);
    if (url === '/api/settings') return reply(settings);
    if (url === '/api/mcp/registration') {
      if (init?.method === 'PUT') {
        const body = JSON.parse(String(init.body));
        onPut?.(body);
        return reply({ ...closed, enabled: body.enabled, hosts: body.hosts, max_clients: body.max_clients });
      }
      return reply(registration);
    }
    return reply({ error: 'unexpected_request', message: url }, 404);
  });
}

beforeEach(() => {
  vi.unstubAllGlobals(); localStorage.clear(); window.location.hash = '';
  Object.defineProperty(HTMLDialogElement.prototype, 'showModal', { configurable: true, value() { this.setAttribute('open', ''); } });
  Object.defineProperty(HTMLDialogElement.prototype, 'close', { configurable: true, value() { this.removeAttribute('open'); } });
});

describe('Inscription automatique des connecteurs', () => {
  it('ne figure pas en Community', async () => {
    window.location.hash = '#settings';
    serve({ ...owner, edition: 'community' }, closed);
    render(<App />);
    expect(await screen.findByRole('heading', { level: 1, name: 'Paramètres' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Inscription automatique/ })).not.toBeInTheDocument();
  });

  it("ne figure pas pour un rôle qui n'est pas propriétaire", async () => {
    window.location.hash = '#settings';
    serve({ ...owner, organization: { ...owner.organization, role: 'admin' } }, closed);
    render(<App />);
    expect(await screen.findByRole('heading', { level: 1, name: 'Paramètres' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Inscription automatique/ })).not.toBeInTheDocument();
  });

  it('nomme un realm ouvert à tout le monde pour ce qu’il est', async () => {
    window.location.hash = '#settings';
    serve(owner, unbounded);
    render(<App />);
    fireEvent.click(await screen.findByRole('button', { name: /Inscription automatique/ }));
    expect(await screen.findByText('L’inscription est ouverte à tous les hôtes')).toBeInTheDocument();
  });

  it('enregistre une liste d’hôtes, pas un texte', async () => {
    window.location.hash = '#settings';
    const sent: unknown[] = [];
    serve(owner, closed, body => sent.push(body));
    render(<App />);
    fireEvent.click(await screen.findByRole('button', { name: /Inscription automatique/ }));
    fireEvent.click(await screen.findByRole('checkbox', { name: /Laisser un connecteur s’inscrire/ }));
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'claude.ai\n  claude.com  \n\n' } });
    fireEvent.click(screen.getByRole('button', { name: 'Enregistrer' }));
    await waitFor(() => expect(sent).toHaveLength(1));
    expect(sent[0]).toEqual({ enabled: true, hosts: ['claude.ai', 'claude.com'], max_clients: 200 });
  });
});
