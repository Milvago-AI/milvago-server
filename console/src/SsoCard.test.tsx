import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { Session, SsoSettings } from './api';

const basePermissions = ['overview.read', 'members.read', 'members.manage', 'settings.manage'];
const session: Session = { user: { id: 'user-1', email: 'owner@example.org', display_name: 'Propriétaire' }, organization: { id: 'org-1', name: 'Organisation de test', role: 'owner' }, organizations: [{ id: 'org-1', name: 'Organisation de test', role: 'owner' }], permissions: [...basePermissions, 'directory.manage'], csrf_token: 'session-csrf', edition: 'community' };
const settingsBase = { name: 'Organisation de test', event_retention_days: 30, public_url: 'https://console.example.org', public_url_confirmed: true, public_url_editable: true };
const redirect = (alias: string) => `https://console.example.org/realms/milvago/broker/${alias}/endpoint`;
const empty: SsoSettings = { editable: true, providers: { google: { configured: false, enabled: false, client_id: '', redirect_uri: redirect('google') }, microsoft: { configured: false, enabled: false, client_id: '', redirect_uri: redirect('microsoft') } } };

function reply(body: unknown, status = 200) { return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }); }
function serve(current: Session, sso: SsoSettings) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input);
    if (url === '/api/session') return reply(current);
    if (url === '/api/settings/sso') return reply(sso);
    if (url.startsWith('/api/settings/sso/') && init?.method === 'PUT') return reply(sso.providers.google);
    if (url === '/api/settings') return reply(settingsBase);
    return reply({ error: 'unexpected_request', message: url }, 404);
  });
}
beforeEach(() => {
  vi.restoreAllMocks(); localStorage.clear(); window.location.hash = '#settings';
});

describe('Settings > SSO', () => {
  it('configures Google with the redirect URI to register', async () => {
    const fetchMock = serve(session, empty);
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: /SSO/ }));
    const google = (await screen.findByRole('heading', { name: 'Google Workspace' })).closest('section') as HTMLElement;
    expect(within(google).getByRole('textbox', { name: 'URI de redirection' })).toHaveValue(redirect('google'));
    expect(within(google).getByLabelText('Secret client')).toBeRequired();
    await user.type(within(google).getByRole('textbox', { name: 'ID client OAuth' }), 'synthetic.apps.googleusercontent.com');
    await user.type(within(google).getByLabelText('Secret client'), 'synthetic-secret');
    await user.type(within(google).getByRole('textbox', { name: 'Domaine Google Workspace' }), 'example.org');
    await user.click(within(google).getByRole('button', { name: 'Enregistrer' }));
    await waitFor(() => {
      const put = fetchMock.mock.calls.find(([url, init]) => url === '/api/settings/sso/google' && (init as RequestInit | undefined)?.method === 'PUT');
      expect(put).toBeDefined();
      expect(JSON.parse(String((put?.[1] as RequestInit).body))).toEqual({ enabled: true, client_id: 'synthetic.apps.googleusercontent.com', client_secret: 'synthetic-secret', hosted_domain: 'example.org', tenant_id: '' });
    });
  });

  it('never prefills a stored secret and lets it be kept', async () => {
    const configured: SsoSettings = { ...empty, providers: { ...empty.providers, microsoft: { configured: true, enabled: true, client_id: '0000000a-0000-0000-0000-00000000000a', tenant_id: '0000000b-0000-0000-0000-00000000000b', redirect_uri: redirect('microsoft') } } };
    serve(session, configured);
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: /SSO/ }));
    const microsoft = (await screen.findByRole('heading', { name: 'Microsoft Entra ID' })).closest('section') as HTMLElement;
    expect(within(microsoft).getByRole('textbox', { name: 'ID de l’annuaire (locataire)' })).toHaveValue('0000000b-0000-0000-0000-00000000000b');
    expect(within(microsoft).getByLabelText('Secret client')).toHaveValue('');
    expect(within(microsoft).getByLabelText('Secret client')).not.toBeRequired();
    expect(within(microsoft).getByRole('button', { name: 'Supprimer le fournisseur' })).toBeInTheDocument();
  });

  it('explains who configures it when this owner cannot', async () => {
    serve(session, { ...empty, editable: false });
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: /SSO/ }));
    expect(await screen.findByText(/seul un propriétaire de l’organisation racine/)).toBeInTheDocument();
    expect(screen.queryByLabelText('Secret client')).not.toBeInTheDocument();
  });

  it('is hidden without directory.manage or without a licence', async () => {
    for (const current of [{ ...session, permissions: basePermissions }, { ...session, license: { restricted: true } } as Session]) {
      serve(current, empty);
      const { unmount } = render(<App />);
      await screen.findByRole('textbox', { name: 'Nom de l’organisation' });
      expect(screen.queryByRole('button', { name: /SSO/ })).not.toBeInTheDocument();
      unmount(); vi.restoreAllMocks();
    }
  });
});
