import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { Profile, Session } from './api';

const basePermissions = ['overview.read', 'events.read', 'devices.read', 'devices.manage', 'members.read', 'members.manage', 'settings.manage', 'policy.manage', 'installers.manage'];
const session: Session = { user: { id: 'user-1', email: 'admin@example.org', display_name: 'Administrateur' }, organization: { id: 'org-1', name: 'Organisation de test', role: 'admin' }, organizations: [{ id: 'org-1', name: 'Organisation de test', role: 'admin' }], permissions: basePermissions, csrf_token: 'session-csrf', edition: 'community' };
const settingsBase = { name: 'Organisation de test', event_retention_days: 30, public_url: 'https://console.example.org', public_url_confirmed: true, public_url_editable: true };
// The profile page mounts the API keys panel, and serve() matches by prefix, so
// '/api/profile' would otherwise answer for '/api/profile/api-keys' with a Profile
// object and the panel would read items off it. Listed first so the longer key wins.
const noApiKeys = { items: [], content_access_available: false };
const overviewEmpty = { period_hours: 24, events: 0, blocked: 0, devices: 0, active_devices: 0, providers: [], timeline: [] };

function reply(body: unknown, status = 200) { return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }); }
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

describe('Identity: profile, member account types and LDAP directory', () => {
  it('opens the profile from the sidebar user block', async () => {
    const profile: Profile = { email: 'admin@example.org', display_name: 'Administrateur Local', first_name: 'Administrateur', last_name: 'Local', language: '', identity_type: 'local', mfa_configured: false, editable: { profile: true, email: true, password: true, mfa: true } };
    serve({ '/api/overview': overviewEmpty, '/api/devices': { items: [] }, '/api/profile/api-keys': noApiKeys, '/api/profile': profile });
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('link', { name: /Administrateur/ }));
    window.location.hash = '#profile';
    fireEvent(window, new HashChangeEvent('hashchange'));
    expect(await screen.findByRole('heading', { level: 1, name: 'Mon profil' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Changer mon mot de passe' })).toHaveAttribute('href', '/auth/login?action=update_password&lang=fr');
    expect(screen.getByRole('link', { name: 'Configurer mon second facteur' })).toHaveAttribute('href', '/auth/login?action=configure_totp&lang=fr');
    expect(screen.getByRole('link', { name: 'Modifier mon adresse e-mail' })).toHaveAttribute('href', '/auth/login?action=update_email&lang=fr');
    // The name is edited in place, not through an identity-provider round trip.
    expect(screen.queryByRole('link', { name: 'Modifier mon nom' })).not.toBeInTheDocument();
    expect(screen.getByRole('textbox', { name: 'Prénom' })).toBeEnabled();
    expect(screen.getByRole('textbox', { name: 'Nom' })).toHaveValue('Local');
  });

  it('saves the name and console language from the profile form', async () => {
    window.location.hash = '#profile';
    const profile: Profile = { email: 'admin@example.org', display_name: 'Administrateur Local', first_name: 'Administrateur', last_name: 'Local', language: '', identity_type: 'local', mfa_configured: false, editable: { profile: true, email: true, password: true, mfa: true } };
    const fetchMock = serve({ '/api/profile/api-keys': noApiKeys, '/api/profile': profile }, (url, init) => url === '/api/profile' && init?.method === 'PUT' ? reply({ display_name: 'Responsable Sécurité', first_name: 'Responsable', last_name: 'Sécurité', language: 'en' }) : undefined);
    render(<App />); const user = userEvent.setup();
    const first = await screen.findByRole('textbox', { name: 'Prénom' });
    await user.clear(first); await user.type(first, 'Responsable');
    const last = screen.getByRole('textbox', { name: 'Nom' });
    await user.clear(last); await user.type(last, 'Sécurité');
    await user.selectOptions(screen.getByRole('combobox', { name: 'Langue de la console' }), 'en');
    await user.click(screen.getByRole('button', { name: 'Enregistrer mon profil' }));
    await waitFor(() => {
      const put = fetchMock.mock.calls.find(([url, init]) => url === '/api/profile' && (init as RequestInit | undefined)?.method === 'PUT');
      expect(put).toBeDefined();
      expect(String((put?.[1] as RequestInit).body)).toBe(JSON.stringify({ language: 'en', first_name: 'Responsable', last_name: 'Sécurité' }));
    });
  });

  it('hides identity-provider-managed actions for an SSO profile', async () => {
    window.location.hash = '#profile';
    const profile: Profile = { email: 'sso@example.org', display_name: 'Compte SSO', first_name: 'Compte', last_name: 'SSO', language: 'fr', identity_type: 'sso', mfa_configured: null, editable: { profile: false, email: false, password: false, mfa: false } };
    serve({ '/api/profile/api-keys': noApiKeys, '/api/profile': profile });
    render(<App />);
    await screen.findByRole('heading', { level: 1, name: 'Mon profil' });
    // The heading renders before the profile arrives: wait for the form, not the heading.
    expect(await screen.findByRole('textbox', { name: 'Prénom' })).toBeDisabled();
    expect(screen.getByRole('textbox', { name: 'Nom' })).toBeDisabled();
    expect(screen.queryByRole('link', { name: 'Modifier mon adresse e-mail' })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Changer mon mot de passe' })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: /Configurer mon second facteur|Gérer mes seconds facteurs/ })).not.toBeInTheDocument();
    expect(screen.getByText(/fournisseur d'identité \(SSO\)/)).toBeInTheDocument();
  });

  it('shows only the second-factor action for an LDAP profile', async () => {
    window.location.hash = '#profile';
    const profile: Profile = { email: 'ldap@example.org', display_name: 'Compte LDAP', first_name: 'Compte', last_name: 'LDAP', language: '', identity_type: 'ldap', mfa_configured: true, editable: { profile: false, email: false, password: false, mfa: true } };
    serve({ '/api/profile/api-keys': noApiKeys, '/api/profile': profile });
    render(<App />);
    await screen.findByRole('heading', { level: 1, name: 'Mon profil' });
    expect(await screen.findByRole('textbox', { name: 'Prénom' })).toBeDisabled();
    expect(screen.queryByRole('link', { name: 'Modifier mon adresse e-mail' })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Changer mon mot de passe' })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Gérer mes seconds facteurs' })).toHaveAttribute('href', '/auth/login?action=manage_mfa&lang=fr');
  });

  it.each([true, null])('opens security management when MFA status is %s and refreshes it on return', async (configured) => {
    window.location.hash = '#profile';
    const profile: Profile = { email: 'admin@example.org', display_name: 'Compte Local', first_name: 'Compte', last_name: 'Local', language: '', identity_type: 'local', mfa_configured: configured, editable: { profile: true, email: true, password: true, mfa: true } };
    let afterManagement = false;
    serve({ '/api/profile/api-keys': noApiKeys }, (url) => url === '/api/profile' ? reply({ ...profile, mfa_configured: afterManagement ? false : configured }) : undefined);
    render(<App />);
    const link = await screen.findByRole('link', { name: 'Gérer mes seconds facteurs' });
    expect(link).toHaveAttribute('href', '/auth/login?action=manage_mfa&lang=fr');
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');
    const firstName = screen.getByRole('textbox', { name: 'Prénom' });
    fireEvent.change(firstName, { target: { value: 'Brouillon' } });
    fireEvent.click(link);
    afterManagement = true;
    fireEvent(window, new Event('focus'));
    const enroll = await screen.findByRole('link', { name: 'Configurer mon second facteur' });
    expect(enroll).toHaveAttribute('href', '/auth/login?action=configure_totp&lang=fr');
    expect(enroll).not.toHaveAttribute('target');
    expect(firstName).toHaveValue('Brouillon');
    expect(screen.getByText('non configuré')).toBeInTheDocument();
    // The security tab can stay open for several changes and return visits.
    afterManagement = false;
    fireEvent(window, new Event('focus'));
    expect(await screen.findByRole('link', { name: 'Gérer mes seconds facteurs' })).toBeInTheDocument();
    expect(firstName).toHaveValue('Brouillon');
  });

  it('shows member account types', async () => {
    window.location.hash = '#members';
    const items = [
      { id: 'm-1', email: 'a@example.org', display_name: 'Membre LDAP', role: 'viewer', organization_id: 'org-1', organization_name: 'Organisation de test', identity_type: 'ldap' },
      { id: 'm-2', email: 'b@example.org', display_name: 'Membre SSO', role: 'viewer', organization_id: 'org-1', organization_name: 'Organisation de test', identity_type: 'sso' },
      { id: 'm-3', email: 'c@example.org', display_name: 'Membre local', role: 'viewer', organization_id: 'org-1', organization_name: 'Organisation de test' },
    ];
    serve({ '/api/members': { items } });
    render(<App />);
    await screen.findByText('Membre LDAP');
    expect(screen.getByText('LDAP')).toBeInTheDocument();
    expect(screen.getByText('SSO')).toBeInTheDocument();
    expect(screen.getByText('Local')).toBeInTheDocument();
  });

  it('imports a directory member', async () => {
    window.location.hash = '#members';
    const fetchMock = serve({ '/api/members': { items: [], directory_configured: true } }, (url, init) => {
      if (url === '/api/members/directory?query=dire') return reply({ items: [{ subject: 'ldap-1', username: 'duser', email: 'directory.user@example.org', display_name: 'Directory User' }] });
      if (url === '/api/members/directory' && init?.method === 'POST') return reply({ id: 'member-x', role: 'viewer' }, 201);
    });
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: "Importer depuis l'annuaire" }));
    await user.type(screen.getByRole('textbox', { name: "Rechercher dans l'annuaire" }), 'dire');
    await user.click(screen.getByRole('button', { name: 'Rechercher' }));
    const radio = await screen.findByRole('radio', { name: /Directory User/ });
    await user.click(radio);
    await user.click(screen.getByRole('button', { name: 'Importer le membre' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/members/directory', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ subject: 'ldap-1', role: 'viewer' }),
      headers: expect.objectContaining({ 'X-CSRF-Token': 'session-csrf' }),
    })));
  });

  it('hides directory import without a configured directory', async () => {
    window.location.hash = '#members';
    serve({ '/api/members': { items: [] } });
    render(<App />);
    await screen.findByText('Aucun membre visible');
    expect(screen.queryByRole('button', { name: "Importer depuis l'annuaire" })).not.toBeInTheDocument();
  });

  it('configures the LDAP directory', async () => {
    window.location.hash = '#settings';
    const directorySession: Session = { ...session, permissions: [...basePermissions, 'directory.manage'] };
    const fetchMock = serve({ '/api/settings': settingsBase, '/api/settings/ldap': { configured: false } }, (url, init) => {
      if (url === '/api/session') return reply(directorySession);
      if (url === '/api/settings/ldap/test' && init?.method === 'POST') return reply({ ok: true, step: 'authentication' });
      if (url === '/api/settings/ldap' && init?.method === 'PUT') return reply({ ok: true });
    });
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: /Annuaire LDAP/ }));
    await user.type(await screen.findByRole('textbox', { name: 'URL de connexion' }), 'ldap://ldap-test:389');
    await user.type(screen.getByRole('textbox', { name: 'DN de connexion' }), 'cn=admin,dc=example,dc=org');
    await user.type(screen.getByLabelText('Mot de passe de connexion'), 'secret');
    await user.type(screen.getByRole('textbox', { name: 'DN des utilisateurs' }), 'ou=people,dc=example,dc=org');
    await user.type(screen.getByRole('textbox', { name: "Nom de l'annuaire" }), 'Annuaire de test');
    await user.click(screen.getByRole('button', { name: 'Tester la connexion' }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/settings/ldap/test', expect.objectContaining({ method: 'POST' })));
    await user.click(screen.getByRole('button', { name: "Enregistrer l'annuaire" }));
    await waitFor(() => {
      const putCall = fetchMock.mock.calls.find(([url, init]) => url === '/api/settings/ldap' && (init as RequestInit | undefined)?.method === 'PUT');
      expect(putCall).toBeDefined();
      const body = String((putCall?.[1] as RequestInit).body);
      expect(body).toContain('"connection_url":"ldap://ldap-test:389"');
      expect(body).toContain('"bind_credential"');
    });
  });

  it('realigns the schema fields on the selected directory vendor', async () => {
    window.location.hash = '#settings';
    const directorySession: Session = { ...session, permissions: [...basePermissions, 'directory.manage'] };
    serve({ '/api/settings': settingsBase, '/api/settings/ldap': { configured: false } }, url => url === '/api/session' ? reply(directorySession) : undefined);
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: /Annuaire LDAP/ }));
    expect(await screen.findByRole('textbox', { name: 'Attribut UUID' })).toHaveValue('entryUUID');
    await user.selectOptions(screen.getByRole('combobox', { name: "Type d'annuaire" }), 'ad');
    expect(screen.getByRole('textbox', { name: 'Attribut identifiant' })).toHaveValue('cn');
    expect(screen.getByRole('textbox', { name: 'Attribut RDN' })).toHaveValue('cn');
    expect(screen.getByRole('textbox', { name: 'Attribut UUID' })).toHaveValue('objectGUID');
    expect(screen.getByRole('textbox', { name: "Classes d'objet" })).toHaveValue('person, organizationalPerson, user');
    await user.selectOptions(screen.getByRole('combobox', { name: "Type d'annuaire" }), 'rhds');
    expect(screen.getByRole('textbox', { name: 'Attribut UUID' })).toHaveValue('nsuniqueid');
    expect(screen.getByRole('textbox', { name: "Classes d'objet" })).toHaveValue('inetOrgPerson, organizationalPerson');
  });

  it('hides the LDAP card without directory.manage', async () => {
    window.location.hash = '#settings';
    serve({ '/api/settings': settingsBase });
    render(<App />);
    await screen.findByRole('textbox', { name: 'Nom de l’organisation' });
    expect(screen.queryByRole('heading', { level: 2, name: 'Annuaire LDAP' })).not.toBeInTheDocument();
  });

  it('no longer shows the MFA link or checkbox on settings, and the PUT body omits require_mfa', async () => {
    window.location.hash = '#settings';
    const ownerSession: Session = { ...session, organization: { ...session.organization, role: 'owner' } };
    const fetchMock = serve({ '/api/settings': settingsBase }, (url, init) => {
      if (url === '/api/session') return reply(ownerSession);
      if (url === '/api/settings' && init?.method === 'PUT') return reply(settingsBase);
    });
    render(<App />); const user = userEvent.setup();
    const name = await screen.findByRole('textbox', { name: 'Nom de l’organisation' });
    expect(screen.queryByRole('link', { name: /Configurer mon second facteur|Gérer mes seconds facteurs/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('checkbox', { name: /authentification multifacteur/i })).not.toBeInTheDocument();
    await user.clear(name);
    await user.type(name, 'Organisation modifiée');
    await user.click(screen.getByRole('button', { name: 'Enregistrer les paramètres' }));
    await waitFor(() => {
      const putCall = fetchMock.mock.calls.find(([url, init]) => url === '/api/settings' && (init as RequestInit | undefined)?.method === 'PUT');
      expect(putCall).toBeDefined();
      expect(String((putCall?.[1] as RequestInit).body)).not.toContain('require_mfa');
    });
  });
});

describe('Identity: API keys on the profile page', () => {
  const profile: Profile = { email: 'admin@example.org', display_name: 'Administrateur Local', first_name: 'Administrateur', last_name: 'Local', language: '', identity_type: 'local', mfa_configured: true, editable: { profile: true, email: true, password: true, mfa: true } };
  const key = { id: '11111111-1111-4111-8111-111111111111', name: 'Export SIEM', permissions: ['events.read'], content_access: false, created_at: '2026-09-01T08:00:00Z', expires_at: '2099-01-01T08:00:00Z', last_used_at: null };

  it('lists keys, the permission summary and the never-used state', async () => {
    window.location.hash = '#profile';
    const wide = { ...key, id: '22222222-2222-4222-8222-222222222222', name: 'Large', permissions: ['events.read', 'devices.read', 'overview.read'] };
    const expired = { ...key, id: '33333333-3333-4333-8333-333333333333', name: 'Perimee', expires_at: '2020-01-01T08:00:00Z' };
    serve({ '/api/profile/api-keys': { items: [key, wide, expired], content_access_available: false }, '/api/profile': profile });
    render(<App />);
    // Wait on a row, not on the heading: the heading lives outside the
    // ResourceView and renders before the fetch resolves, so awaiting it races
    // the table into existence and fails intermittently.
    expect(await screen.findByText('Export SIEM')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Clés API' })).toBeInTheDocument();
    expect(screen.getAllByText('Jamais utilisée')).toHaveLength(3);
    // Beyond two permissions the cell collapses to a count that carries the detail.
    expect(screen.getByText('3 permissions')).toBeInTheDocument();
    expect(screen.getByText('Expirée')).toBeInTheDocument();
  });

  it('shows an empty state and offers only the caller own permissions', async () => {
    window.location.hash = '#profile';
    serve({ '/api/profile/api-keys': noApiKeys, '/api/profile': profile });
    render(<App />); const user = userEvent.setup();
    expect(await screen.findByRole('heading', { name: 'Aucune clé API' })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Nouvelle clé API' }));
    // No content flag when the caller cannot read prompt content themselves.
    expect(screen.queryByRole('checkbox', { name: /contenu des prompts/ })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Créer la clé' })).toBeDisabled();
  });

  it('reveals the secret once and hides it after closing', async () => {
    window.location.hash = '#profile';
    const created = { key: { ...key, name: 'Nouvelle' }, secret: 'mvk_TESTSECRETVALUE00000000000000000000000000' };
    let listed: unknown[] = [];
    const fetchMock = serve({ '/api/profile': profile }, (url, init) => {
      if (url === '/api/profile/api-keys' && init?.method === 'POST') { listed = [created.key]; return reply(created, 201); }
      if (url === '/api/profile/api-keys') return reply({ items: listed, content_access_available: false });
      return undefined;
    });
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Nouvelle clé API' }));
    await user.type(screen.getByRole('textbox', { name: 'Nom de la clé' }), 'Nouvelle');
    await user.click(screen.getByRole('radio', { name: '90 jours' }));
    await user.click(screen.getAllByRole('checkbox')[0]);
    await user.click(screen.getByRole('button', { name: 'Créer la clé' }));
    expect(await screen.findByText(created.secret)).toBeInTheDocument();
    const post = fetchMock.mock.calls.find(([url, init]) => url === '/api/profile/api-keys' && (init as RequestInit | undefined)?.method === 'POST');
    expect(JSON.parse(String((post?.[1] as RequestInit).body))).toMatchObject({ name: 'Nouvelle', expires_in_days: 90 });
    await user.click(screen.getByRole('button', { name: 'Terminer' }));
    // The secret is unrecoverable by design, so it must not survive the dialog.
    await waitFor(() => expect(screen.queryByText(created.secret)).not.toBeInTheDocument());
  });

  it('revokes a key after an inline confirmation', async () => {
    window.location.hash = '#profile';
    let items: unknown[] = [key];
    const fetchMock = serve({ '/api/profile': profile }, (url, init) => {
      if (url.startsWith('/api/profile/api-keys/') && init?.method === 'DELETE') { items = []; return reply({ ok: true }); }
      if (url === '/api/profile/api-keys') return reply({ items, content_access_available: false });
      return undefined;
    });
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Révoquer' }));
    await user.click(screen.getByRole('button', { name: 'Annuler' }));
    expect(fetchMock.mock.calls.some(([, init]) => (init as RequestInit | undefined)?.method === 'DELETE')).toBe(false);
    await user.click(screen.getByRole('button', { name: 'Révoquer' }));
    await user.click(screen.getByRole('button', { name: 'Confirmer la révocation' }));
    expect(await screen.findByText('Clé révoquée.')).toBeInTheDocument();
    const deleted = fetchMock.mock.calls.find(([, init]) => (init as RequestInit | undefined)?.method === 'DELETE');
    expect(String(deleted?.[0])).toBe('/api/profile/api-keys/' + key.id);
  });

  it('warns that the installer permission outlives the key, only when it is selected', async () => {
    window.location.hash = '#profile';
    serve({ '/api/profile/api-keys': noApiKeys, '/api/profile': profile });
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Nouvelle clé API' }));
    const warning = 'Cette permission dépasse la durée de vie de la clé';
    // Absent until the permission is actually chosen, so it reads as a
    // consequence of the choice rather than as page furniture.
    expect(screen.queryByText(warning)).not.toBeInTheDocument();
    await user.click(screen.getByRole('checkbox', { name: 'Gérer les installeurs' }));
    expect(await screen.findByText(warning)).toBeInTheDocument();
    expect(screen.getByText(/clé de déploiement de l’organisation, qui n’expire pas/)).toBeInTheDocument();
    // And it goes away again if the permission is unticked.
    await user.click(screen.getByRole('checkbox', { name: 'Gérer les installeurs' }));
    await waitFor(() => expect(screen.queryByText(warning)).not.toBeInTheDocument());
  });

  // The MCP endpoint is an Enterprise module. The card follows the runtime
  // edition, like every other Enterprise surface, and lives with the keys
  // because a key is the credential it needs.
  // Same regression as the instance default: the account selector listed two
  // languages by hand while the catalogues carried four, so a reader could not
  // choose Spanish or Portuguese for their own console. "Par défaut" stays first
  // and empty — following the instance is not a language.
  it('offers every language for the account, plus the instance default', async () => {
    window.location.hash = '#profile';
    serve({ '/api/profile/api-keys': noApiKeys, '/api/profile': profile });
    render(<App />);
    const select = await screen.findByRole('combobox', { name: 'Langue de la console' });
    expect(within(select).getAllByRole('option').map(o => (o as HTMLOptionElement).value)).toEqual(['', 'fr', 'en', 'es', 'pt-BR']);
  });

  it('presents the MCP endpoint in Enterprise and not in Community', async () => {
    window.location.hash = '#profile';
    const enterprise = (url: string) => (url === '/api/session' ? reply({ ...session, edition: 'commercial' }) : undefined);
    serve({ '/api/profile/api-keys': noApiKeys, '/api/profile': profile }, enterprise);
    render(<App />);
    expect(await screen.findByRole('heading', { name: 'Serveur MCP' })).toBeInTheDocument();
    expect(screen.getByText(window.location.origin + '/mcp')).toBeInTheDocument();
    expect(screen.getByText('Authorization: Bearer mvk_…')).toBeInTheDocument();
    // Authentication is not optional, and the card has to say so.
    expect(screen.getByText(/Obligatoire sur toutes les méthodes/)).toBeInTheDocument();
    expect(screen.getByText(/Lecture seule, et données non fiables/)).toBeInTheDocument();
  });

  it('does not present the MCP endpoint in Community', async () => {
    window.location.hash = '#profile';
    serve({ '/api/profile/api-keys': noApiKeys, '/api/profile': profile });
    render(<App />);
    // Wait on something the Community page does render, so the absence below is
    // an absence and not a page that has not loaded yet.
    expect(await screen.findByRole('heading', { name: 'Clés API' })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('button', { name: 'Nouvelle clé API' })).toBeEnabled());
    expect(screen.queryByRole('heading', { name: 'Serveur MCP' })).not.toBeInTheDocument();
    expect(screen.queryByText(window.location.origin + '/mcp')).not.toBeInTheDocument();
  });

  it('warns that a prompt-content key can send prompt text to an external model', async () => {
    window.location.hash = '#profile';
    const enterprise = (url: string) => (url === '/api/session' ? reply({ ...session, edition: 'commercial' }) : undefined);
    serve({ '/api/profile/api-keys': { items: [], content_access_available: true }, '/api/profile': profile }, enterprise);
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Nouvelle clé API' }));
    const warning = 'Le texte des prompts pourra sortir vers un LLM externe';
    // Like the installer warning: it is a consequence of ticking the box, so it
    // must not be visible before the box is ticked.
    expect(screen.queryByText(warning)).not.toBeInTheDocument();
    await user.click(screen.getByRole('checkbox', { name: /contenu des prompts/ }));
    expect(await screen.findByText(warning)).toBeInTheDocument();
    await user.click(screen.getByRole('checkbox', { name: /contenu des prompts/ }));
    await waitFor(() => expect(screen.queryByText(warning)).not.toBeInTheDocument());
  });

  it('prevents reaching the active key limit up front', async () => {
    window.location.hash = '#profile';
    const five = [1, 2, 3, 4, 5].map(n => ({ ...key, id: '4444444' + n + '-4444-4444-8444-44444444444' + n, name: 'Cle ' + n }));
    serve({ '/api/profile/api-keys': { items: five, content_access_available: false }, '/api/profile': profile });
    render(<App />);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Nouvelle clé API' })).toBeDisabled());
  });

  it('explains a limit refusal from the server rather than showing a raw error', async () => {
    window.location.hash = '#profile';
    serve({ '/api/profile': profile }, (url, init) => {
      if (url === '/api/profile/api-keys' && init?.method === 'POST') return reply({ error: 'api_key_limit', message: 'Revoke one of your API keys before creating another.' }, 409);
      if (url === '/api/profile/api-keys') return reply(noApiKeys);
      return undefined;
    });
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Nouvelle clé API' }));
    await user.type(screen.getByRole('textbox', { name: 'Nom de la clé' }), 'Sixieme');
    await user.click(screen.getAllByRole('checkbox')[0]);
    await user.click(screen.getByRole('button', { name: 'Créer la clé' }));
    expect(await screen.findByText('Limite de clés atteinte')).toBeInTheDocument();
    expect(screen.queryByText('La demande a échoué')).not.toBeInTheDocument();
  });
});
