import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import * as navigation from './navigation';
import type { Session } from './api';
import type { ShadowSettings } from './shadow/types';

const adminPermissions = ['overview.read', 'events.read', 'devices.read', 'devices.manage', 'members.read', 'members.manage', 'settings.manage', 'policy.manage', 'installers.manage'];
const session: Session = { user: { id: 'user-1', email: 'admin@example.org', display_name: 'Administrateur' }, organization: { id: 'org-1', name: 'Organisation de test', role: 'admin' }, organizations: [{ id: 'org-1', name: 'Organisation de test', role: 'admin' }], permissions: adminPermissions, csrf_token: 'session-csrf', edition: 'community' };
const confirmedSettings = { name: 'Organisation de test', event_retention_days: 30, public_url: 'https://console.example.org', public_url_confirmed: true, public_url_editable: true };
const deviceShadowSettings: ShadowSettings = { revision: 5, inherit_sections: [], inherited_from: {}, capabilities: { model_access_browser: false, model_access_native: false, browser: true, native: false, organization_inheritance: false, content_storage: true, device_overrides: true, local_privacy: true, local_privacy_patterns: false, usage_sensitivity: false, file_names: true, signed_updates: false }, config: { enrollment: { approval: 'manual', cidrs: [] }, collection: { enabled: true, store_content: false, store_file_names: true, content_retention_days: 7 }, services: [{ id: 'chatgpt', domains: ['chatgpt.com'], mode: 'observe', redirect_url: '', enabled: true }], protection: { block_uploads: false, keywords: [], exact: 'observe', unicode: 'observe', fuzzy: 'off', exceptions: [], message: '' }, privacy: { enabled: false, review: false, types: [], custom_rules: [] }, classification: { browser: ['iban', 'card', 'social_id'], coding: [], medical_terms: ['diagnostic'] }, operations: { metrics_enabled: false, destinations: [], updates: { enabled: false, device_ids: [], percentage: 0, paused_versions: [] } } } };
const KEY = { id: 'key-1', created_at: '2026-09-07T12:00:00Z', rotated_at: null, uses: 3 };
function reply(body: unknown, status = 200) { return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }); }
// What /api/devices answers: the facets travel with the rows, and the console no longer
// rebuilds them from the page it received. A mock without them is not a server.
function devices<T extends { platform: string }>(items: T[]) { return { items, total: items.length, fleet: items.length, platforms: Array.from(new Set(items.map(item => item.platform))).sort() }; }
function serve(routes: Record<string, unknown>, handler?: (url: string, init?: RequestInit) => Response | undefined) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input); const handled = handler?.(url, init); if (handled) return handled;
    if (url === '/api/session') return reply(session);
    const route = Object.keys(routes).find(key => url.startsWith(key));
    if (route) return reply(routes[route]);
    return reply({ error: 'unexpected_request', message: url }, 404);
  });
}
beforeEach(() => {
  vi.unstubAllGlobals(); localStorage.clear(); document.cookie = 'milvago_theme=;Max-Age=0;Path=/'; window.location.hash = '';
  Object.defineProperty(HTMLDialogElement.prototype, 'showModal', { configurable: true, value() { this.setAttribute('open', ''); } });
  Object.defineProperty(HTMLDialogElement.prototype, 'close', { configurable: true, value() { this.removeAttribute('open'); } });
});
describe('Console workflows', () => {
  it('renders dark whatever the system setting says and prioritizes the shared theme cookie', async () => {
    // Dark is the brand's default rendering: a system preference for light must
    // not override it (charte graphique v2.0).
    vi.stubGlobal('matchMedia', vi.fn().mockReturnValue({ matches: false }));
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(reply({ error: 'unauthorized' }, 401));
    const first = render(<App />);
    await screen.findByRole('link', { name: /Se connecter/ });
    expect(document.documentElement.dataset.theme).toBe('dark');
    first.unmount();
    document.cookie = 'milvago_theme=light;Path=/;SameSite=Lax';
    render(<App />);
    expect(document.documentElement.dataset.theme).toBe('light');
    expect(localStorage.getItem('milvago.theme')).toBe('light');
    fireEvent.click(screen.getByRole('button', { name: 'Activer le thème sombre' }));
    expect(document.cookie).toContain('milvago_theme=dark');
  });
  it('downloads an installer for the organization without creating any package', async () => {
    window.location.hash = '#devices';
    const createObjectURL = vi.fn().mockReturnValue('blob:installer-file');
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: createObjectURL });
    Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: vi.fn() });
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) { expect(this.download).toBe('milvago-windows-installer.msi'); });
    const automatic = { ...deviceShadowSettings, config: { ...deviceShadowSettings.config, enrollment: { approval: 'automatic' as const, cidrs: [] } } };
    const fetchMock = serve({ '/api/devices': devices([]), '/api/settings': confirmedSettings, '/api/shadow/settings': automatic }, url => url === '/api/installer/windows' ? new Response('package', { headers: { 'X-Milvago-Installer-Version': '0.5.10' } }) : undefined);
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: /Télécharger l’agent/ }));
    const windows = await screen.findByRole('button', { name: 'Windows MSI' });
    await waitFor(() => expect(windows).toBeEnabled());
    await user.click(windows);
    expect(click).toHaveBeenCalledOnce();
    expect(screen.getAllByRole('status')).toContain(await screen.findByText('Version téléchargée : 0.5.10'));
    expect(fetchMock).toHaveBeenCalledWith('/api/installer/windows', expect.objectContaining({ credentials: 'same-origin' }));
    // The durable key replaced the per-download package: nothing is created here.
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === 'POST')).toBe(false);
  });
  it('clears an old downloaded version when a later package does not confirm one', async () => {
    window.location.hash = '#devices';
    Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: vi.fn().mockReturnValue('blob:installer-file') });
    Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: vi.fn() });
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    const automatic = { ...deviceShadowSettings, config: { ...deviceShadowSettings.config, enrollment: { approval: 'automatic' as const, cidrs: [] } } };
    const headers = ['0.5.10', '', 'invalid'];
    let download = 0;
    serve({ '/api/devices': devices([]), '/api/settings': confirmedSettings, '/api/shadow/settings': automatic }, url => {
      if (url !== '/api/installer/windows') return undefined;
      const version = headers[download++];
      return new Response('package', { headers: version ? { 'X-Milvago-Installer-Version': version } : {} });
    });
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: /Télécharger l’agent/ }));
    const windows = await screen.findByRole('button', { name: 'Windows MSI' });
    await waitFor(() => expect(windows).toBeEnabled());
    await user.click(windows);
    expect(await screen.findByText('Version téléchargée : 0.5.10')).toBeInTheDocument();
    await user.click(windows);
    await waitFor(() => expect(screen.queryByText('Version téléchargée : 0.5.10')).not.toBeInTheDocument());
    await user.click(windows);
    await waitFor(() => expect(screen.queryByText('Version téléchargée : 0.5.10')).not.toBeInTheDocument());
  });
  it('shows the written reason of an audited privacy change, and nothing for other actions', async () => {
    window.location.hash = '#audit';
    const auditor = { ...session, permissions: [...adminPermissions, 'audit.read'] };
    serve({ '/api/settings': confirmedSettings }, url => {
      if (url === '/api/session') return reply(auditor);
      if (url === '/api/audit') return reply({ items: [
        { id: 'a1', occurred_at: '2026-09-20T10:00:00Z', actor: 'user-1', action: 'privacy.update', target: 'org-1', details: { reason: 'Quarterly privacy review' } },
        { id: 'a2', occurred_at: '2026-09-19T10:00:00Z', actor: 'user-1', action: 'member.role', target: 'member-2', details: null },
      ] });
    });
    render(<App />);
    expect(await screen.findByRole('columnheader', { name: 'Raison' })).toBeInTheDocument();
    const rows = screen.getAllByRole('row');
    expect(within(rows[1]).getByText('Quarterly privacy review')).toBeInTheDocument();
    expect(within(rows[2]).getAllByRole('cell').at(-1)).toHaveTextContent('');
  });
  it('updates a member role and reloads the actual membership after server success', async () => {
    window.location.hash = '#members';
    let member = { id: 'member-2', email: 'member@example.org', display_name: 'Membre de test', role: 'viewer', organization_id: 'org-1', organization_name: 'Organisation de test' };
    const fetchMock = serve({}, (url, init) => {
      if (url === '/api/members/member-2/role' && init?.method === 'PUT') { member = { ...member, role: 'admin' }; return reply({ id: member.id, role: member.role }); }
      if (url === '/api/members') return reply({ items: [member] });
    });
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Modifier le rôle' }));
    await user.selectOptions(screen.getByRole('combobox', { name: 'Nouveau rôle' }), 'admin');
    await user.click(screen.getByRole('button', { name: 'Enregistrer le rôle' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(fetchMock).toHaveBeenCalledWith('/api/members/member-2/role', expect.objectContaining({ method: 'PUT', body: JSON.stringify({ role: 'admin' }), headers: expect.objectContaining({ 'X-CSRF-Token': 'session-csrf' }) }));
  });
  // Reading retained text is the `content.read` permission of a role, like every other
  // permission (product decision, 2026-09-15). It used to be a per-person flag set from
  // this page, which no role could grant — an owner alone in an organization therefore
  // never obtained it. The Members page must no longer offer it at all; the Roles page
  // carries it. One's own row still refuses the role change and the removal.
  it('no longer offers a per-member content grant, and still refuses role changes on one own row', async () => {
    window.location.hash = '#members';
    const owner: Session = { ...session, organization: { ...session.organization, role: 'owner' }, permissions: [...adminPermissions, 'content.read'] };
    const self = { id: owner.user.id, email: owner.user.email, display_name: 'Administrateur', role: 'owner', organization_id: 'org-1', organization_name: 'Organisation de test' };
    serve({}, url => url === '/api/session' ? reply(owner) : url === '/api/members' ? reply({ items: [self] }) : undefined);
    render(<App />);
    await screen.findByText(owner.user.email);
    expect(screen.queryByRole('button', { name: 'Lecture des contenus' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Modifier le rôle' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Retirer l’accès' })).not.toBeInTheDocument();
  });
  // Regression: languageLabel was an if-ladder over fr and en, so a member whose
  // account is set to Spanish or Portuguese was shown as "Par défaut" — an
  // administrator could not tell a deliberate choice from no preference. It never
  // failed loudly, which is why it survived two rounds of fixing the same root
  // cause elsewhere.
  it.each([
    ['es', 'Español'],
    ['pt-BR', 'Português (Brasil)'],
    ['fr', 'Français'],
    ['', 'Par défaut'],
  ])('names a member account language of %s in the table', async (language, label) => {
    window.location.hash = '#members';
    serve({ '/api/members': { items: [{ id: 'member-2', email: 'member@example.org', display_name: 'Membre de test', role: 'viewer', language, organization_id: 'org-1', organization_name: 'Organisation de test' }] } });
    render(<App />);
    const row = (await screen.findByText('member@example.org')).closest('tr')!;
    expect(within(row).getByText(label)).toBeInTheDocument();
  });

  it('preserves the member dialog when the server denies a role change', async () => {
    window.location.hash = '#members';
    serve({ '/api/members': { items: [{ id: 'member-2', email: 'member@example.org', display_name: 'Membre de test', role: 'viewer', organization_id: 'org-1', organization_name: 'Organisation de test' }] } }, (url, init) => url.endsWith('/role') && init?.method === 'PUT' ? reply({ error: 'forbidden', message: 'Droits insuffisants.' }, 403) : undefined);
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Modifier le rôle' }));
    expect(screen.queryByRole('option', { name: 'Propriétaire' })).not.toBeInTheDocument();
    await user.selectOptions(screen.getByRole('combobox', { name: 'Nouveau rôle' }), 'admin');
    await user.click(screen.getByRole('button', { name: 'Enregistrer le rôle' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Droits insuffisants.');
    expect(screen.getByRole('combobox', { name: 'Nouveau rôle' })).toHaveValue('admin');
    expect(screen.queryByText(/Rôle mis à jour/)).not.toBeInTheDocument();
  });
  it('shows last-owner protection and does not remove access on a conflict', async () => {
    window.location.hash = '#members';
    serve({ '/api/members': { items: [{ id: 'owner-2', email: 'owner2@example.org', display_name: 'Autre propriétaire', role: 'owner', organization_id: 'org-1', organization_name: 'Organisation de test' }] } }, (url, init) => {
      if (url === '/api/session') return reply({ ...session, organization: { ...session.organization, role: 'owner' } });
      if (url === '/api/members/owner-2' && init?.method === 'DELETE') return reply({ error: 'last_owner', message: 'Le dernier propriétaire doit être conservé.' }, 409);
    });
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Retirer l’accès' }));
    await user.click(screen.getByRole('button', { name: 'Confirmer le retrait' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Le dernier propriétaire doit être conservé.');
    expect(screen.getByRole('alert')).toHaveTextContent('Action impossible');
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(screen.queryByText(/Accès retiré/)).not.toBeInTheDocument();
  });
  it('removes a member only after confirmation and reloads the resulting member list', async () => {
    window.location.hash = '#members'; let removed = false;
    const fetchMock = serve({}, (url, init) => {
      if (url === '/api/members/member-2' && init?.method === 'DELETE') { removed = true; return reply({ id: 'member-2', role: '' }); }
      if (url === '/api/members') return reply({ items: removed ? [] : [{ id: 'member-2', email: 'member@example.org', display_name: 'Membre de test', role: 'viewer', organization_id: 'org-1', organization_name: 'Organisation de test' }] });
    });
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Retirer l’accès' }));
    expect(fetchMock.mock.calls.some(([, init]) => init?.method === 'DELETE')).toBe(false);
    await user.click(screen.getByRole('button', { name: 'Confirmer le retrait' }));
    expect(await screen.findByText('Aucun membre visible')).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent('Accès retiré.');
  });
  it('locks the current user out of editing their own membership row', async () => {
    window.location.hash = '#members';
    serve({ '/api/members': { items: [{ id: 'user-1', email: 'admin@example.org', display_name: 'Administrateur', role: 'admin', organization_id: 'org-1', organization_name: 'Organisation de test' }] } });
    render(<App />);
    expect(await screen.findByText('admin@example.org')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Modifier le rôle' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Retirer l’accès' })).not.toBeInTheDocument();
  });
  it('ends the identity-provider session using the server logout redirect after a CSRF-protected request', async () => {
    const logoutUrl = 'https://identity.example.org/realms/milvago/protocol/openid-connect/logout?client_id=console&post_logout_redirect_uri=https%3A%2F%2Fconsole.example.org';
    const navigate = vi.spyOn(navigation, 'navigate').mockImplementation(() => {});
    const fetchMock = serve({ '/api/overview': { period_hours: 24, events: 0, navigations: 0, blocked: 0, devices: 0, active_devices: 0, providers: [], timeline: [] } }, (url, init) => url === '/auth/logout' && init?.method === 'POST' ? reply({ ok: true, logout_url: logoutUrl }) : undefined);
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Déconnexion' }));
    await waitFor(() => expect(navigate).toHaveBeenCalledWith(logoutUrl));
    expect(fetchMock).toHaveBeenCalledWith('/auth/logout', expect.objectContaining({ method: 'POST', headers: expect.objectContaining({ 'X-CSRF-Token': 'session-csrf' }) }));
    expect(await screen.findByRole('link', { name: /Se connecter/ })).toBeInTheDocument();
  });
  it('keeps the console visible and does not redirect when logout fails', async () => {
    const navigate = vi.spyOn(navigation, 'navigate').mockImplementation(() => {});
    serve({ '/api/overview': { period_hours: 24, events: 0, navigations: 0, blocked: 0, devices: 0, active_devices: 0, providers: [], timeline: [] } }, url => url === '/auth/logout' ? reply({ error: 'logout_failed', message: 'Déconnexion indisponible.' }, 502) : undefined);
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Déconnexion' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Déconnexion indisponible.');
    expect(navigate).not.toHaveBeenCalled();
    expect(screen.getByRole('navigation', { name: 'Navigation principale' })).toBeInTheDocument();
  });
  it('offers identity login when the session is absent', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(reply({ error: 'unauthorized' }, 401));
    render(<App />);
    expect(await screen.findByRole('link', { name: /Se connecter/ })).toHaveAttribute('href', '/auth/login?lang=fr');
    expect(screen.queryByRole('navigation')).not.toBeInTheDocument();
  });
  it('names the commercial edition Enterprise in the shell and on the entry page', async () => {
    serve({ '/api/overview': { period_hours: 24, events: 0, navigations: 0, blocked: 0, devices: 0, active_devices: 0, providers: [], timeline: [] }, '/api/bootstrap': { default_language: 'fr', edition: 'commercial' } }, url => url === '/api/session' ? reply({ ...session, edition: 'commercial' }) : undefined);
    const shell = render(<App />);
    await screen.findByRole('heading', { level: 1, name: 'Vue d’ensemble' });
    expect(screen.getAllByText('Enterprise').length).toBeGreaterThan(0);
    expect(screen.queryByText('Commercial')).not.toBeInTheDocument();
    shell.unmount();
    serve({ '/api/bootstrap': { default_language: 'fr', edition: 'commercial' } }, url => url === '/api/session' ? reply({ error: 'unauthorized' }, 401) : undefined);
    render(<App />);
    await screen.findByRole('link', { name: /Se connecter/ });
    expect(await screen.findByText('Enterprise')).toBeInTheDocument();
    expect(screen.queryByText('Community · Commercial')).not.toBeInTheDocument();
  });
  it('sets an invited member language and changes it afterwards', async () => {
    window.location.hash = '#members';
    const member = { id: '11111111-1111-4111-8111-111111111111', email: 'membre@example.org', display_name: 'Membre de test', role: 'viewer', organization_id: 'org-1', organization_name: 'Organisation de test', language: '' };
    const fetchMock = serve({ '/api/members': { items: [member] }, '/api/roles': { items: [{ name: 'viewer' }, { name: 'admin' }] } }, (url, init) => {
      if (url === '/api/members/invitations' && init?.method === 'POST') return reply({ id: 'new', email: 'invite@example.org', role: 'viewer', language: 'en' }, 201);
      if (url.endsWith('/language') && init?.method === 'PUT') return reply({ id: member.id, language: 'en' });
      return undefined;
    });
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Inviter un membre' }));
    await user.type(screen.getByRole('textbox', { name: 'Adresse e-mail' }), 'invite@example.org');
    await user.selectOptions(screen.getByRole('combobox', { name: 'Langue de la console' }), 'en');
    await user.click(screen.getByRole('button', { name: 'Envoyer l’invitation' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/members/invitations', expect.objectContaining({ body: JSON.stringify({ email: 'invite@example.org', role: 'viewer', language: 'en' }) })));
    await user.click(screen.getByRole('button', { name: 'Terminer' }));
    await user.click(screen.getByRole('button', { name: 'Modifier la langue' }));
    await user.selectOptions(screen.getByRole('combobox', { name: 'Langue de la console' }), 'en');
    await user.click(screen.getByRole('button', { name: 'Enregistrer la langue' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(`/api/members/${member.id}/language`, expect.objectContaining({ method: 'PUT', body: JSON.stringify({ language: 'en' }) })));
  });
  it('shows real empty overview and no organization selector in Community', async () => {
    serve({ '/api/overview': { period_hours: 24, events: 0, navigations: 0, blocked: 0, devices: 0, active_devices: 0, providers: [], timeline: [] } });
    render(<App />);
    expect(await screen.findByText('Aucun événement reçu')).toBeInTheDocument();
    // A visit and a submitted request are two distinct facts: the tile counts
    // requests, and names navigations apart instead of merging them in.
    expect(screen.getByText('Requêtes')).toBeInTheDocument();
    expect(screen.getByText('24 dernières heures · 0 navigations')).toBeInTheDocument();
    expect(screen.getByText('Aucun fournisseur observé')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^Organisation / })).not.toBeInTheDocument();
    expect(screen.getAllByText('0')).toHaveLength(4);
  });
  it('announces manual approval before a mass deployment', async () => {
    window.location.hash = '#devices';
    serve({ '/api/devices': devices([]), '/api/settings': confirmedSettings, '/api/shadow/settings': deviceShadowSettings });
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: /Télécharger l’agent/ }));
    const dialog = await screen.findByRole('dialog');
    // deviceShadowSettings carries approval: 'manual'.
    expect(await within(dialog).findByText(/Approbation manuelle active/)).toBeInTheDocument();
    expect(within(dialog).getByText(/ne transmettra rien avant votre approbation/)).toBeInTheDocument();
  });
  it('confirms deployment key rotation and revocation from Administration settings', async () => {
    window.location.hash = '#settings';
    const fetchMock = serve({ '/api/deployment-key': { key: KEY }, '/api/settings': confirmedSettings }, url => String(url).endsWith('/rotate') || String(url).endsWith('/revoke') ? reply({ key: KEY }) : undefined);
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: /Clé de déploiement/ }));
    // The secret itself is never rendered, only the fact that a key exists.
    await screen.findByText('Dernière rotation');
    await user.click(screen.getByRole('button', { name: 'Faire tourner' }));
    expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith('/rotate'))).toBe(false);
    expect(screen.getByText(/Un nouvel installateur sera nécessaire/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Confirmer la rotation' }));
    expect(fetchMock).toHaveBeenCalledWith('/api/deployment-key/rotate', expect.objectContaining({ method: 'POST', headers: expect.objectContaining({ 'X-CSRF-Token': 'session-csrf' }) }));
    await user.click(await screen.findByRole('button', { name: 'Révoquer' }));
    await user.click(screen.getByRole('button', { name: 'Confirmer la révocation' }));
    expect(fetchMock).toHaveBeenCalledWith('/api/deployment-key/revoke', expect.objectContaining({ method: 'POST' }));
  });
  it('blocks the agent download until the public URL is confirmed', async () => {
    window.location.hash = '#devices';
    serve({ '/api/devices': devices([]), '/api/installer-profiles': { items: [] }, '/api/settings': { ...confirmedSettings, public_url: '', public_url_confirmed: false } });
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: /Télécharger l’agent/ }));
    const dialog = await screen.findByRole('dialog');
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('URL publique de Milvago non confirmée');
    expect(within(dialog).queryByRole('button', { name: 'Windows MSI' })).not.toBeInTheDocument();
    expect(within(dialog).getByRole('link', { name: 'Configurer' })).toHaveAttribute('href', '#settings');
  });
  it('shows a refused installer download without exposing or downloading credentials', async () => {
    window.location.hash = '#devices';
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    serve({ '/api/devices': devices([]), '/api/settings': confirmedSettings, '/api/shadow/settings': deviceShadowSettings }, url => url === '/api/installer/linux' ? reply({ error: 'installer_build_failed', message: 'Paquet indisponible.' }, 503) : undefined);
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: /Télécharger l’agent/ }));
    const linux = await screen.findByRole('button', { name: 'Linux RPM' });
    await waitFor(() => expect(linux).toBeEnabled());
    await user.click(linux);
    expect(await screen.findByText('Paquet indisponible.')).toBeInTheDocument();
    expect(click).not.toHaveBeenCalled();
    expect(screen.queryByText('Code secret')).not.toBeInTheDocument();
  });
  it('opens an organization page and rotates that organization key', async () => {
    window.location.hash = '#organizations';
    const commercial: Session = { ...session, edition: 'commercial', permissions: [...adminPermissions, 'organizations.manage'], organizations: [...session.organizations, { id: '22222222-2222-4222-8222-222222222222', name: 'Filiale de test', role: 'owner', parent_id: 'org-1' }] };
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
      const url = String(input);
      if (url === '/api/session') return reply(commercial);
      if (url === '/api/organizations') return reply({ items: [{ id: 'org-1', name: 'Organisation de test', role: 'admin', parent_id: null, is_root: true }, { id: '22222222-2222-4222-8222-222222222222', name: 'Filiale de test', role: 'owner', parent_id: 'org-1', is_root: false }] });
      if (url.startsWith('/api/organizations/22222222-2222-4222-8222-222222222222/deployment-key')) return reply({ key: KEY });
      return reply({ error: 'unexpected_request', message: url }, 404);
    });
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('link', { name: 'Filiale de test' }));
    await screen.findByText('Dernière rotation');
    await user.click(screen.getByRole('button', { name: 'Faire tourner' }));
    await user.click(screen.getByRole('button', { name: 'Confirmer la rotation' }));
    // The permission is checked on the target organization, so the route names it.
    expect(fetchMock).toHaveBeenCalledWith('/api/organizations/22222222-2222-4222-8222-222222222222/deployment-key/rotate', expect.objectContaining({ method: 'POST' }));
  });
  it('requires confirmation before revoking an approved device', async () => {
    window.location.hash = '#devices';
    const fetchMock = serve({ '/api/devices': devices([{ id: 'device-1', hostname: 'Poste de test', platform: 'windows', version: '0.1.0', status: 'approved', last_seen: null, os_user: 'utilisateur-test' }]) }, url => url.endsWith('/revoke') ? reply({}) : undefined);
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Révoquer' }));
    expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith('/revoke'))).toBe(false);
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Confirmer la révocation' }));
    expect(await screen.findByRole('status')).toHaveTextContent('Le poste a été révoqué.');
  });
  it('offers device actions on devices.manage, the permission the server checks, not members.manage', async () => {
    window.location.hash = '#devices';
    const approved = { id: 'device-1', hostname: 'Poste de test', platform: 'windows', version: '0.1.0', status: 'approved', last_seen: null, os_user: 'utilisateur-test' };
    const withoutDevices = { ...session, permissions: adminPermissions.filter(p => p !== 'devices.manage') };
    serve({ '/api/devices': devices([approved]) }, url => url === '/api/session' ? reply(withoutDevices) : undefined);
    const first = render(<App />);
    expect(await screen.findByText('Poste de test')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Révoquer' })).not.toBeInTheDocument();
    first.unmount(); vi.restoreAllMocks();
    const devicesOnly = { ...session, permissions: ['overview.read', 'events.read', 'devices.read', 'devices.manage'] };
    serve({ '/api/devices': devices([approved]) }, url => url === '/api/session' ? reply(devicesOnly) : undefined);
    render(<App />);
    expect(await screen.findByRole('button', { name: 'Révoquer' })).toBeInTheDocument();
  });
  it('tells an empty fleet apart from a filter that matches nothing', async () => {
    // `fleet` counts the whole fleet whatever the filter, `total` the filtered rows: a
    // fleet of Windows devices with no row on this page is "no match", not "download your
    // first installer". `platforms` is the filter's option list and decides nothing here.
    window.location.hash = '#devices';
    serve({ '/api/devices': { items: [], total: 0, fleet: 1, platforms: ['windows'] }, '/api/settings': confirmedSettings, '/api/shadow/settings': deviceShadowSettings });
    const filtered = render(<App />);
    expect(await screen.findByText('Aucun poste ne correspond')).toBeInTheDocument();
    expect(screen.queryByText('Votre premier poste vous attend')).not.toBeInTheDocument();
    filtered.unmount();
    serve({ '/api/devices': { items: [], total: 0, fleet: 0, platforms: [] }, '/api/settings': confirmedSettings, '/api/shadow/settings': deviceShadowSettings });
    render(<App />);
    expect(await screen.findByText('Votre premier poste vous attend')).toBeInTheDocument();
    expect(screen.queryByText('Aucun poste ne correspond')).not.toBeInTheDocument();
  });
  it('changes the language from the profile form only, and the theme from the sidebar', async () => {
    // The sidebar lost its language control (product decision, 2026-09-11): the user
    // block at its foot leads to the profile, whose form saves the language on the
    // account. The sidebar keeps the theme toggle and sign-out.
    const profile = { email: 'admin@example.org', display_name: 'Administrateur', first_name: 'Administrateur', last_name: 'Local', language: '', identity_type: 'local', mfa_configured: false, editable: { profile: true, email: true, password: true, mfa: true } };
    // An explicit browser choice, so that going back to "default" below has to be
    // applied and not merely left alone: with the sidebar shortcut gone, the
    // account language is the only thing the profile save changes.
    localStorage.setItem('milvago.language', 'fr');
    let accountLanguage = '';
    serve({ '/api/overview': { period_hours: 24, events: 0, navigations: 0, blocked: 0, devices: 0, active_devices: 0, providers: [], timeline: [] }, '/api/profile/api-keys': { items: [], content_access_available: false }, '/api/profile': profile }, (url, init) => {
      if (url === '/api/session') return reply({ ...session, user: { ...session.user, language: accountLanguage } });
      if (url === '/api/profile' && init?.method === 'PUT') { accountLanguage = JSON.parse(String(init.body)).language; return reply({ ...profile, language: accountLanguage }); }
      return undefined;
    });
    render(<App />); await screen.findByRole('heading', { level: 1, name: 'Vue d’ensemble' });
    expect(screen.queryByRole('combobox', { name: 'Langue' })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Activer le thème clair' }));
    expect(document.documentElement.dataset.theme).toBe('light');
    const user = userEvent.setup();
    await user.click(screen.getByRole('link', { name: /Administrateur/ }));
    window.location.hash = '#profile'; fireEvent(window, new HashChangeEvent('hashchange'));
    await user.selectOptions(await screen.findByRole('combobox', { name: 'Langue de la console' }), 'es');
    await user.click(screen.getByRole('button', { name: 'Enregistrer mon profil' }));
    // Saving refreshes the session, whose account language now drives the console:
    // the page re-renders in Spanish and the document announces it.
    expect(await screen.findByRole('heading', { level: 1, name: 'Mi perfil' })).toBeInTheDocument();
    expect(document.documentElement.lang).toBe('es');
    expect(screen.queryByRole('combobox', { name: 'Idioma' })).not.toBeInTheDocument();
    // Back to "default": the account no longer says anything, so the browser's
    // explicit choice applies at once, without waiting for a reload.
    await user.selectOptions(screen.getByRole('combobox', { name: 'Idioma de la consola' }), '');
    await user.click(screen.getByRole('button', { name: 'Guardar mi perfil' }));
    expect(await screen.findByRole('heading', { level: 1, name: 'Mon profil' })).toBeInTheDocument();
    expect(document.documentElement.lang).toBe('fr');
    expect(accountLanguage).toBe('');
  });
  it('limits a viewer to readable administration settings', async () => {
    window.location.hash = '#settings';
    serve({ '/api/settings': { name: 'Organisation de test', event_retention_days: 30 } }, url => url === '/api/session' ? reply({ ...session, organization: { ...session.organization, role: 'viewer' } }) : undefined);
    render(<App />);
    expect(await screen.findByRole('textbox', { name: 'Nom de l’organisation' })).toBeDisabled();
    expect(screen.queryByRole('link', { name: /Activité/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Membres' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Enregistrer les paramètres' })).not.toBeInTheDocument();
    // MFA is no longer configured from Settings: the second-factor link lives on the profile page.
    expect(screen.queryByRole('link', { name: /Configurer mon second facteur|Gérer mes seconds facteurs/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('checkbox', { name: /multifacteur/ })).not.toBeInTheDocument();
  });
  it('requests inventory only for the Enterprise edition and reports an empty inventory honestly', async () => {
    const uuid = '11111111-1111-4111-8111-111111111111';
    window.location.hash = `#devices?id=${uuid}`;
    const device = { id: uuid, hostname: 'Poste de test', platform: 'windows', version: '0.4.0', status: 'approved', last_seen: null, os_user: 'utilisateur-test' };
    const fetchMock = serve({ '/api/devices': devices([device]) }, (url) => {
      if (url === '/api/session') return reply({ ...session, edition: 'commercial' });
      if (url === `/api/tools?device_id=${uuid}`) return reply({ items: [] });
      if (url === `/api/devices/${uuid}/shadow`) return reply(deviceShadowSettings);
    });
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Outils locaux' }));
    expect(await screen.findByText('Aucun outil local signalé')).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(`/api/tools?device_id=${uuid}`, expect.anything());
  });
  it('distinguishes a silent browser extension from an absence of AI use', async () => {
    const uuid = '33333333-3333-4333-8333-333333333333';
    window.location.hash = `#devices?id=${uuid}`;
    const recent = new Date(Date.now() - 60_000).toISOString();
    const old = new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString();
    const device = { id: uuid, hostname: 'Poste de test', platform: 'windows', version: '0.4.0', status: 'approved', last_seen: null, os_user: 'utilisateur-test', browsers: { chrome: recent, firefox: old } };
    serve({ '/api/devices': devices([device]) });
    render(<App />);
    const row = (await screen.findByText('Extensions navigateur')).nextElementSibling!;
    expect(within(row as HTMLElement).getByText('Active')).toBeInTheDocument();
    expect(within(row as HTMLElement).getByText('Silencieuse depuis')).toBeInTheDocument();
  });
  it('reports plainly when a device has never had an extension report', async () => {
    const uuid = '44444444-4444-4444-8444-444444444444';
    window.location.hash = `#devices?id=${uuid}`;
    const device = { id: uuid, hostname: 'Poste nu', platform: 'linux', version: '0.4.0', status: 'approved', last_seen: null, os_user: '' };
    serve({ '/api/devices': devices([device]) });
    render(<App />);
    expect(await screen.findByText('Aucune extension signalée')).toBeInTheDocument();
  });
  it('groups AI applications by organization and never presents a presence as a use', async () => {
    window.location.hash = '#applications';
    const observed = new Date(Date.now() - 3600_000).toISOString();
    const first = new Date(Date.now() - 30 * 86400_000).toISOString();
    serve({ '/api/tools': {
      items: [
        { device_id: 'd1', hostname: 'Poste alpha', tool: 'ollama', kind: 'port', observed_at: observed, first_seen: first },
        { device_id: 'd2', hostname: 'Poste beta', tool: 'ollama', kind: 'process', observed_at: observed, first_seen: observed },
        { device_id: 'd1', hostname: 'Poste alpha', tool: 'cursor', kind: 'installed', observed_at: observed, first_seen: observed },
      ],
      catalog: [
        { id: 'ollama', name: 'Ollama', vendor: 'Ollama', category: 'inference', hosting: 'local', risk: 'medium' },
        { id: 'cursor', name: 'Cursor', vendor: 'Anysphere', category: 'editor', hosting: 'cloud', risk: 'high' },
      ],
    } }, (url) => url === '/api/session' ? reply({ ...session, edition: 'commercial' }) : undefined);
    render(<App />);
    await screen.findAllByText('Ollama');
    // The vendor is also called Ollama, so the row is found by the identifier cell.
    const row = screen.getByText('ollama').closest('tr')!;
    // Two devices, two recognition surfaces, and the earliest sighting of either.
    expect(within(row).getByText('2')).toBeInTheDocument();
    expect(within(row).getByText(/Service local à l’écoute/)).toBeInTheDocument();
    expect(within(row).getByText(/Processus en cours/)).toBeInTheDocument();
    expect(screen.getByText(/Une présence détectée n’établit ni un usage, ni un envoi/)).toBeInTheDocument();
  });
  // The cell used to show three names then "and N more", and each
  // machine had to be reopened to find out which. The whole list is already in the payload.
  it('lists every device an AI application was found on, from the cell itself', async () => {
    window.location.hash = '#applications';
    const observed = new Date(Date.now() - 3600_000).toISOString();
    const devices = ['alpha', 'beta', 'gamma', 'delta', 'epsilon'];
    serve({ '/api/tools': {
      items: devices.map((name, index) => ({ device_id: `1111111${index}-1111-4111-8111-111111111111`, hostname: `Poste ${name}`, tool: 'ollama', kind: 'process', observed_at: observed, first_seen: observed })),
      catalog: [{ id: 'ollama', name: 'Ollama', vendor: 'Ollama', category: 'inference', hosting: 'local', risk: 'medium' }],
    } }, (url) => url === '/api/session' ? reply({ ...session, edition: 'commercial' }) : undefined);
    render(<App />); const user = userEvent.setup();
    await screen.findAllByText('Ollama');
    const cell = screen.getByRole('button', { name: /et 2 autres/ });
    await user.click(cell);
    const dialog = await screen.findByRole('dialog');
    // All five, not the three from the cell, and each one leads to its own page.
    for (const name of devices) expect(within(dialog).getByRole('link', { name: `Poste ${name}` })).toBeInTheDocument();
    expect(within(dialog).getByRole('link', { name: 'Poste alpha' })).toHaveAttribute('href', '#devices?id=11111110-1111-4111-8111-111111111111');
  });
  it('deletes several selected devices after one confirmation', async () => {
    window.location.hash = '#devices';
    const alpha = { id: '11111111-1111-4111-8111-111111111111', hostname: 'Poste alpha', platform: 'windows', version: '0.4.0', status: 'approved', last_seen: null, os_user: 'utilisateur-un' };
    const beta = { id: '22222222-2222-4222-8222-222222222222', hostname: 'Poste beta', platform: 'linux', version: '0.4.0', status: 'revoked', last_seen: null, os_user: 'utilisateur-deux' };
    const fetchMock = serve({ '/api/devices': devices([alpha, beta]) }, (_url, init) => init?.method === 'DELETE' ? reply({ ok: true }) : undefined);
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('checkbox', { name: 'Tout sélectionner' }));
    await user.click(screen.getByRole('button', { name: /Supprimer \(2\)/ }));
    // Nothing is sent before the confirmation.
    expect(fetchMock.mock.calls.some(([, init]) => (init as RequestInit | undefined)?.method === 'DELETE')).toBe(false);
    const dialog = screen.getByRole('dialog');
    expect(within(dialog).getByText('Poste alpha')).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Confirmer la suppression' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(`/api/devices/${alpha.id}`, expect.objectContaining({ method: 'DELETE', headers: expect.objectContaining({ 'X-CSRF-Token': 'session-csrf' }) })));
    expect(fetchMock).toHaveBeenCalledWith(`/api/devices/${beta.id}`, expect.objectContaining({ method: 'DELETE' }));
    expect(await screen.findByRole('status')).toHaveTextContent('Les postes ont été supprimés.');
  });
  it('reports devices the server refused to delete', async () => {
    window.location.hash = '#devices';
    const device = { id: '11111111-1111-4111-8111-111111111111', hostname: 'Poste alpha', platform: 'windows', version: '0.4.0', status: 'approved', last_seen: null, os_user: 'utilisateur-un' };
    serve({ '/api/devices': devices([device]) }, (_url, init) => init?.method === 'DELETE' ? reply({ error: 'forbidden', message: 'Droits insuffisants.' }, 403) : undefined);
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('checkbox', { name: 'Sélectionner Poste alpha' }));
    await user.click(screen.getByRole('button', { name: /Supprimer \(1\)/ }));
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Confirmer la suppression' }));
    expect(await screen.findByText(/Suppression impossible pour : Poste alpha/)).toBeInTheDocument();
  });
  it('does not request tool inventory from the devices list', async () => {
    window.location.hash = '#devices';
    const fetchMock = serve({ '/api/devices': devices([]) }, url => url === '/api/session' ? reply({ ...session, edition: 'commercial' }) : undefined);
    render(<App />);
    await screen.findByText('Votre premier poste vous attend');
    expect(fetchMock.mock.calls.some(([url]) => String(url).startsWith('/api/tools'))).toBe(false);
  });
  it('edits a device override from the device page through the server inheritance contract', async () => {
    const uuid = '22222222-2222-4222-8222-222222222222';
    window.location.hash = `#devices?id=${uuid}`;
    const device = { id: uuid, hostname: 'Poste de test', platform: 'windows', version: '0.4.0', status: 'approved', last_seen: null, os_user: 'utilisateur-test' };
    const inherited: ShadowSettings = { ...deviceShadowSettings, inherit_sections: ['collection', 'services', 'protection', 'privacy', 'classification'], capabilities: { ...deviceShadowSettings.capabilities, device_overrides: true, organization_inheritance: true, native: true } };
    const fetchMock = serve({ '/api/devices': devices([device]) }, (url, init) => {
      if (url === '/api/session') return reply({ ...session, edition: 'commercial' });
      if (url === `/api/tools?device_id=${uuid}`) return reply({ items: [] });
      if (url === `/api/devices/${uuid}/shadow`) return init?.method === 'PUT' ? reply({ ...inherited, revision: 6, inherit_sections: JSON.parse(String(init.body)).inherit_sections }) : reply(inherited);
    });
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Politique du poste' }));
    const inherit = await screen.findByRole('checkbox', { name: 'Hériter · Collecte' });
    expect(screen.getByRole('checkbox', { name: 'Activer la collecte' })).toBeDisabled();
    await user.click(inherit);
    expect(screen.getByRole('checkbox', { name: 'Activer la collecte' })).toBeEnabled();
    await user.click(screen.getByRole('button', { name: 'Enregistrer les changements' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(`/api/devices/${uuid}/shadow`, expect.objectContaining({ method: 'PUT', body: expect.not.stringContaining('"enrollment"') })));
  });
  it('filters devices by name, user and system and opens a device page', async () => {
    window.location.hash = '#devices';
    const alpha = { id: '11111111-1111-4111-8111-111111111111', hostname: 'Poste alpha', platform: 'windows', version: '0.4.0', status: 'approved', last_seen: null, os_user: 'utilisateur-un', update_status: 'needs_update', update_reported_at: '2026-09-10T08:00:00Z' };
    const beta = { id: '22222222-2222-4222-8222-222222222222', hostname: 'Poste beta', platform: 'linux', version: '0.4.0', status: 'approved', last_seen: null, os_user: 'utilisateur-deux' };
    // The console now renders the server's own filtering, so this mock filters
    // like `privateDevices` does (hostname/os_user/platform), instead of always
    // returning the full list and relying on a client-side re-filter.
    serve({}, (url) => {
      if (!url.startsWith('/api/devices')) return undefined;
      const params = new URLSearchParams(url.split('?')[1]);
      const deviceId = params.get('device_id');
      const all = [alpha, beta];
      if (deviceId) { const one = all.filter((d) => d.id === deviceId); return reply({ ...devices(all), items: one, total: one.length }); }
      const query = (params.get('query') ?? '').toLowerCase();
      const userQuery = (params.get('user') ?? '').toLowerCase();
      const platform = params.get('platform') ?? '';
      const items = all.filter(
        (d) =>
          d.hostname.toLowerCase().includes(query) &&
          (d.os_user ?? '').toLowerCase().includes(userQuery) &&
          (!platform || d.platform === platform),
      );
      // Like the server: `fleet` and `platforms` describe every machine, `total` the match.
      return reply({ ...devices(all), items, total: items.length });
    });
    render(<App />); const user = userEvent.setup();
    await screen.findByRole('link', { name: 'Poste alpha' });
    await user.type(screen.getByRole('textbox', { name: 'Utilisateur' }), 'deux');
    expect(screen.queryByRole('link', { name: 'Poste alpha' })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Poste beta' })).toBeInTheDocument();
    await user.clear(screen.getByRole('textbox', { name: 'Utilisateur' }));
    await user.selectOptions(screen.getByRole('combobox', { name: 'Système' }), 'windows');
    expect(screen.getByRole('link', { name: 'Poste alpha' })).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Poste beta' })).not.toBeInTheDocument();
    await user.selectOptions(screen.getByRole('combobox', { name: 'Système' }), '');
    await user.type(screen.getByRole('textbox', { name: 'Nom du poste' }), 'beta');
    expect(screen.queryByRole('link', { name: 'Poste alpha' })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Poste beta' })).toBeInTheDocument();
    await user.clear(screen.getByRole('textbox', { name: 'Nom du poste' }));
    await user.type(screen.getByRole('textbox', { name: 'Nom du poste' }), 'inexistant');
    // The server filtered this response to zero rows but its `fleet` facet still counts
    // two machines: this is "no match", never the first-installation screen.
    expect(await screen.findByText('Aucun poste ne correspond')).toBeInTheDocument();
    expect(screen.queryByText('Votre premier poste vous attend')).not.toBeInTheDocument();
    await user.clear(screen.getByRole('textbox', { name: 'Nom du poste' }));
    await user.click(await screen.findByRole('link', { name: 'Poste alpha' }));
    window.location.hash = `#devices?id=${alpha.id}`;
    fireEvent(window, new HashChangeEvent('hashchange'));
    expect(await screen.findByRole('heading', { level: 1, name: 'Poste alpha' })).toBeInTheDocument();
    expect(screen.getByText('Utilisateur connecté')).toBeInTheDocument();
    expect(screen.getByText('utilisateur-un')).toBeInTheDocument();
    expect(screen.getByText('Mise à jour')).toBeInTheDocument();
    expect(screen.getByText('À mettre à jour')).toBeInTheDocument();
    // Browser policy is served in both editions; only the local tools are Enterprise.
    expect(screen.getByRole('button', { name: 'Politique du poste' })).toBeInTheDocument();
    expect(screen.queryByText('Outils locaux')).not.toBeInTheDocument();
    expect(screen.queryByText('Outils locaux détectés')).not.toBeInTheDocument();
  });
  it('switches organization from the hierarchical right-hand drawer', async () => {
    window.location.hash = '#devices';
    let current = 'root-1';
    const organizations = [
      { id: 'root-1', name: 'Organisation racine', role: 'owner', parent_id: null },
      { id: 'child-1', name: 'Organisation enfant', role: 'owner', parent_id: 'root-1' },
      { id: 'grandchild-1', name: 'Organisation petite-fille', role: 'admin', parent_id: 'child-1' },
      { id: 'orphan-1', name: 'Organisation isolée', role: 'viewer', parent_id: 'inaccessible-parent' },
    ];
    const fetchMock = serve({ '/api/devices': devices([]), '/api/tools': { items: [] } }, (url, init) => {
      if (url === '/api/session') { const org = organizations.find(o => o.id === current)!; return reply({ ...session, edition: 'commercial', organization: { id: org.id, name: org.name, role: org.role }, organizations }); }
      if (url === '/api/session/organization' && init?.method === 'POST') { current = JSON.parse(String(init.body)).organization_id; return reply({ ok: true }); }
    });
    render(<App />); const user = userEvent.setup();
    const trigger = await screen.findByRole('button', { name: 'Organisation Organisation racine' });
    expect(trigger).toHaveAttribute('aria-expanded', 'false');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    await user.click(trigger);
    const drawer = screen.getByRole('dialog', { name: 'Choisir une organisation' });
    expect(drawer).toHaveClass('drawer');
    expect(trigger).toHaveAttribute('aria-expanded', 'true');
    const root = within(drawer).getByRole('button', { name: /Organisation racine/ });
    expect(root).toHaveAttribute('aria-current', 'true');
    expect(root).toHaveFocus();
    const child = within(drawer).getByRole('button', { name: /Organisation enfant/ });
    expect(child).not.toHaveAttribute('aria-current');
    expect(root.closest('li')).toContainElement(child);
    expect(within(child.closest('li')!).getByRole('button', { name: /Organisation petite-fille/ })).toBeInTheDocument();
    expect(within(drawer).getByRole('button', { name: /Organisation isolée/ }).closest('li')!.parentElement).toBe(root.closest('li')!.parentElement);
    await user.click(within(drawer).getByRole('button', { name: 'Fermer' }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
    await user.click(trigger);
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: /Organisation petite-fille/ }));
    expect(fetchMock).toHaveBeenCalledWith('/api/session/organization', expect.objectContaining({ method: 'POST', body: JSON.stringify({ organization_id: 'grandchild-1' }), headers: expect.objectContaining({ 'X-CSRF-Token': 'session-csrf' }) }));
    expect(await screen.findByRole('button', { name: 'Organisation Organisation petite-fille' })).toBeInTheDocument();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
  it('requires an owned parent for organization creation, marks the root, and submits the selected parent', async () => {
    window.location.hash = '#organizations';
    const commercial = { ...session, edition: 'commercial' as const, permissions: [...adminPermissions, 'organizations.manage'], organization: { ...session.organization, id: 'root-1', role: 'owner' }, organizations: [{ id: 'root-1', name: 'Organisation racine', role: 'owner' }] };
    const organizations = { items: [{ id: 'root-1', name: 'Organisation racine', role: 'owner', parent_id: null, is_root: true }, { id: 'child-1', name: 'Organisation enfant', role: 'admin', parent_id: 'root-1', is_root: false }, { id: 'external-child', name: 'Organisation isolée', role: 'viewer', parent_id: 'inaccessible-parent', is_root: false }] };
    const fetchMock = serve({ '/api/members': { items: [] }, '/api/organizations': organizations }, (url, init) => {
      if (url === '/api/session') return reply(commercial);
      if (url === '/api/organizations' && init?.method === 'POST') return reply({ id: 'child-2' });
    });
    render(<App />); const user = userEvent.setup();
    expect(await screen.findByText('Racine')).toBeInTheDocument();
    expect(screen.getByText('inaccessible-parent')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Nouvelle organisation' }));
    expect(screen.getByText('Les membres de l’organisation parente accèdent aux données des organisations filles selon leurs permissions.')).toBeInTheDocument();
    const parent = screen.getByRole('combobox', { name: 'Organisation parente' });
    expect(parent).toHaveValue('root-1');
    expect(screen.queryByRole('option', { name: 'Aucune' })).not.toBeInTheDocument();
    expect(screen.queryByRole('option', { name: 'Organisation enfant' })).not.toBeInTheDocument();
    await user.type(screen.getByRole('textbox', { name: 'Nom' }), 'Nouvelle organisation');
    await user.click(screen.getByRole('checkbox', { name: /multifacteur/ }));
    await user.click(screen.getByRole('button', { name: 'Créer' }));
    expect(fetchMock).toHaveBeenCalledWith('/api/organizations', expect.objectContaining({ method: 'POST', body: JSON.stringify({ name: 'Nouvelle organisation', parent_id: 'root-1', require_mfa: true }), headers: expect.objectContaining({ 'X-CSRF-Token': 'session-csrf' }) }));
    expect(await screen.findByText('Organisation créée.')).toBeInTheDocument();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
  it('keeps an invitation open and displays the SMTP failure instead of claiming delivery', async () => {
    window.location.hash = '#members';
    serve({ '/api/members': { items: [] } }, (url, init) => url === '/api/members/invitations' && init?.method === 'POST' ? reply({ error: 'mail_failed', message: 'SMTP indisponible.' }, 502) : undefined);
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Inviter un membre' }));
    await user.type(screen.getByRole('textbox', { name: 'Adresse e-mail' }), 'member@example.org');
    await user.click(screen.getByRole('button', { name: 'Envoyer l’invitation' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('SMTP indisponible.');
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(screen.queryByText(/Le serveur a confirmé/)).not.toBeInTheDocument();
    expect(screen.queryByRole('option', { name: 'Propriétaire' })).not.toBeInTheDocument();
  });
  it('lists the members holding a role when its deletion is refused, then deletes it once freed', async () => {
    window.location.hash = '#roles';
    const owner: Session = { ...session, organization: { ...session.organization, role: 'owner' }, permissions: [...adminPermissions, 'roles.manage'] };
    let holders: { items: { id: string; email: string; display_name: string }[]; total: number } = { items: [{ id: 'member-2', email: 'member@example.org', display_name: 'Membre de test' }], total: 1 };
    const fetchMock = serve({}, (url, init) => {
      if (url === '/api/session') return reply(owner);
      if (url === '/api/roles/support/members') return reply(holders);
      if (url === '/api/roles/support' && init?.method === 'DELETE')
        return holders.total > 0 ? reply({ error: 'role_in_use', message: 'Reassign the members that hold this role before deleting it.' }, 409) : reply({ ok: true });
      if (url === '/api/members/member-2/role' && init?.method === 'PUT') { holders = { items: [], total: 0 }; return reply({ id: 'member-2', role: 'viewer' }); }
      if (url === '/api/roles') return reply({ items: [{ name: 'viewer', permissions: ['overview.read'], builtin: true }, { name: 'support', permissions: ['overview.read'], builtin: false }], catalog: ['overview.read'] });
    });
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Supprimer' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByRole('heading', { name: 'Rôle utilisé par des membres' })).toBeInTheDocument();
    expect(await within(dialog).findByText('member@example.org')).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: /Supprimer le rôle/ })).toBeDisabled();
    await user.click(within(dialog).getByRole('button', { name: /Réattribuer/ }));
    expect(fetchMock).toHaveBeenCalledWith('/api/members/member-2/role', expect.objectContaining({ method: 'PUT', body: JSON.stringify({ role: 'viewer' }) }));
    await waitFor(() => expect(within(dialog).getByRole('button', { name: /Supprimer le rôle/ })).toBeEnabled());
    await user.click(within(dialog).getByRole('button', { name: /Supprimer le rôle/ }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(await screen.findByText('Rôle supprimé.')).toBeInTheDocument();
  });
});
