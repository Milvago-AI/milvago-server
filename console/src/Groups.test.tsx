import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { DeviceGroup, Session } from './api';
import type { ShadowSettings } from './shadow/types';

const adminPermissions = ['overview.read', 'events.read', 'devices.read', 'devices.manage', 'members.read', 'members.manage', 'settings.manage', 'policy.manage', 'installers.manage'];
const session: Session = { user: { id: 'user-1', email: 'admin@example.org', display_name: 'Administrateur' }, organization: { id: 'org-1', name: 'Organisation de test', role: 'admin' }, organizations: [{ id: 'org-1', name: 'Organisation de test', role: 'admin' }], permissions: adminPermissions, csrf_token: 'session-csrf', edition: 'community' };
const GROUP_ID = '33333333-3333-4333-8333-333333333333';
const OTHER_ID = '44444444-4444-4444-8444-444444444444';
const ALPHA = '11111111-1111-4111-8111-111111111111';
const BETA = '22222222-2222-4222-8222-222222222222';
const group: DeviceGroup = { id: GROUP_ID, name: 'Groupe comptabilité', description: 'Postes du service comptable', device_count: 1, created_at: '2026-09-14T08:00:00Z', updated_at: '2026-09-14T08:00:00Z' };
const other: DeviceGroup = { id: OTHER_ID, name: 'Groupe direction', description: '', device_count: 0, created_at: '2026-09-14T08:00:00Z', updated_at: '2026-09-14T08:00:00Z' };
const alpha = { id: ALPHA, hostname: 'Poste alpha', platform: 'windows', version: '0.4.0', status: 'approved', last_seen: null, os_user: 'utilisateur-un', group_id: GROUP_ID, group_name: group.name };
const beta = { id: BETA, hostname: 'Poste beta', platform: 'linux', version: '0.4.0', status: 'approved', last_seen: null, os_user: '', group_id: null, group_name: null };
const settings: ShadowSettings = { revision: 9, inherit_sections: ['collection', 'services', 'protection', 'privacy', 'classification', 'model_access'], inherited_from: {}, capabilities: { model_access_browser: false, model_access_native: false, browser: true, native: false, organization_inheritance: false, content_storage: true, device_overrides: true, group_overrides: true, local_privacy: true, local_privacy_patterns: false, usage_sensitivity: false, file_names: true, signed_updates: false }, config: { enrollment: { approval: 'manual', cidrs: [] }, collection: { enabled: true, store_content: false, store_file_names: true, content_retention_days: 7 }, services: [{ id: 'chatgpt', domains: ['chatgpt.com'], mode: 'observe', redirect_url: '', enabled: true }], protection: { block_uploads: false, keywords: [], exact: 'observe', unicode: 'observe', fuzzy: 'off', exceptions: [], message: '' }, privacy: { enabled: false, review: false, types: [], custom_rules: [] }, classification: { browser: [], coding: [], medical_terms: [] }, operations: { metrics_enabled: false, destinations: [], updates: { enabled: false, device_ids: [], percentage: 0, paused_versions: [] } } } };

function reply(body: unknown, status = 200) { return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }); }
function serve(routes: Record<string, unknown>, handler?: (url: string, init?: RequestInit) => Response | undefined) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input); const handled = handler?.(url, init); if (handled) return handled;
    if (url === '/api/session') return reply(session);
    // Longest prefix first: '/api/groups/<id>/shadow' must not be answered by '/api/groups'.
    const route = Object.keys(routes).sort((a, b) => b.length - a.length).find(key => url.startsWith(key));
    if (route) return reply(routes[route]);
    return reply({ error: 'unexpected_request', message: url }, 404);
  });
}
beforeEach(() => {
  vi.unstubAllGlobals(); localStorage.clear(); localStorage.setItem('milvago.language', 'fr'); document.cookie = 'milvago_theme=;Max-Age=0;Path=/'; window.location.hash = '';
  Object.defineProperty(HTMLDialogElement.prototype, 'showModal', { configurable: true, value() { this.setAttribute('open', ''); } });
  Object.defineProperty(HTMLDialogElement.prototype, 'close', { configurable: true, value() { this.removeAttribute('open'); } });
});

describe('Device groups', () => {
  it('lists the groups under Devices in the sidebar and creates one from a dialog', async () => {
    window.location.hash = '#groups';
    const posted: unknown[] = [];
    serve({ '/api/groups': { items: [group] } }, (url, init) => {
      if (url === '/api/groups' && init?.method === 'POST') { posted.push(JSON.parse(String(init.body))); return reply({ ...other, name: 'Groupe direction' }, 201); }
      return undefined;
    });
    render(<App />); const user = userEvent.setup();
    const nav = await screen.findByRole('navigation', { name: 'Navigation principale' });
    const links = within(nav).getAllByRole('link').map(link => link.textContent);
    expect(links.indexOf('Groupes')).toBe(links.indexOf('Postes') + 1);
    expect(await screen.findByRole('link', { name: 'Groupe comptabilité' })).toHaveAttribute('href', `#groups?id=${GROUP_ID}`);
    await user.click(screen.getByRole('button', { name: 'Nouveau groupe' }));
    const dialog = screen.getByRole('dialog');
    await user.type(within(dialog).getByLabelText('Nom du groupe'), 'Groupe direction');
    await user.type(within(dialog).getByLabelText('Description'), 'Comité de direction');
    await user.click(within(dialog).getByRole('button', { name: 'Créer le groupe' }));
    expect(screen.getAllByRole('status')).toContain(await screen.findByText('Groupe créé.'));
    expect(posted).toEqual([{ name: 'Groupe direction', description: 'Comité de direction' }]);
  });
  it('opens a group, adds a device through the single assignment endpoint and reaches the group policy', async () => {
    window.location.hash = `#groups?id=${GROUP_ID}`;
    const assigned: { url: string; body: unknown }[] = [];
    serve({ '/api/groups': { items: [group, other] }, '/api/devices': { items: [alpha, beta] }, [`/api/groups/${GROUP_ID}/shadow`]: settings }, (url, init) => {
      if (url.endsWith('/group') && init?.method === 'PUT') { assigned.push({ url, body: JSON.parse(String(init.body)) }); return reply({ id: BETA, group_id: GROUP_ID }); }
      return undefined;
    });
    render(<App />); const user = userEvent.setup();
    expect(await screen.findByRole('heading', { level: 1, name: 'Groupe comptabilité' })).toBeInTheDocument();
    const tabs = screen.getByRole('group', { name: 'Sections du groupe' });
    expect(within(tabs).getByRole('button', { name: 'Informations' })).toBeInTheDocument();
    expect(await screen.findByRole('link', { name: 'Poste alpha' })).toHaveAttribute('href', `#devices?id=${ALPHA}`);
    expect(screen.queryByText('Poste beta')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Ajouter des postes' }));
    const dialog = screen.getByRole('dialog', { name: 'Ajouter des postes' });
    await user.click(within(dialog).getByRole('checkbox', { name: 'Poste beta' }));
    await user.click(within(dialog).getByRole('button', { name: 'Ajouter (1)' }));
    expect(screen.getAllByRole('status')).toContain(await screen.findByText('Groupe du poste mis à jour.'));
    expect(assigned).toEqual([{ url: `/api/devices/${BETA}/group`, body: { group_id: GROUP_ID } }]);
    // The reload after the move remounted the detail: query the tab bar again.
    await user.click(within(await screen.findByRole('group', { name: 'Sections du groupe' })).getByRole('button', { name: 'Politique du groupe' }));
    expect(await screen.findByText(/Dérogation du groupe · Révision 9/)).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Hériter · Collecte' })).toBeChecked();
  });
  it('lets a manager move a device from its page in Community and shows the device policy tab there', async () => {
    window.location.hash = `#devices?id=${BETA}`;
    const assigned: unknown[] = [];
    serve({ '/api/groups': { items: [group, other] }, '/api/devices': { items: [alpha, beta] }, [`/api/devices/${BETA}/shadow`]: settings }, (url, init) => {
      if (url === `/api/devices/${BETA}/group` && init?.method === 'PUT') { assigned.push(JSON.parse(String(init.body))); return reply({ id: BETA, group_id: OTHER_ID }); }
      return undefined;
    });
    render(<App />); const user = userEvent.setup();
    expect(await screen.findByRole('heading', { level: 1, name: 'Poste beta' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Politique du poste' })).toBeInTheDocument();
    await user.click(await screen.findByRole('button', { name: 'Aucun groupe', expanded: false }));
    const choices = await screen.findByRole('group', { name: 'Groupe' });
    await waitFor(() => expect(within(choices).getByRole('button', { name: 'Groupe direction' })).toBeInTheDocument());
    await user.click(within(choices).getByRole('button', { name: 'Groupe direction' }));
    expect(screen.getAllByRole('status')).toContain(await screen.findByText('Groupe du poste mis à jour.'));
    expect(assigned).toEqual([{ group_id: OTHER_ID }]);
  });
  it('deletes a group from its page and returns to the list with the confirmation', async () => {
    window.location.hash = `#groups?id=${GROUP_ID}`;
    let deleted = false;
    serve({ '/api/groups': { items: [group] }, '/api/devices': { items: [alpha] } }, (url, init) => {
      if (url === `/api/groups/${GROUP_ID}` && init?.method === 'DELETE') { deleted = true; return reply({ ok: true }); }
      if (url === '/api/groups' && deleted) return reply({ items: [] });
      return undefined;
    });
    render(<App />); const user = userEvent.setup();
    await screen.findByRole('heading', { level: 1, name: 'Groupe comptabilité' });
    await user.click(screen.getByRole('button', { name: 'Supprimer' }));
    const dialog = screen.getByRole('dialog', { name: 'Supprimer le groupe' });
    expect(within(dialog).getByText(/reviennent à la politique de l’organisation/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Confirmer la suppression' }));
    // jsdom fires hashchange itself when the page navigates back to #groups.
    expect(screen.getAllByRole('status')).toContain(await screen.findByText('Groupe supprimé.'));
    expect(await screen.findByText('Aucun groupe de postes')).toBeInTheDocument();
    expect(deleted).toBe(true);
  });
});
