// First-run setup wizard: the whole path in memory, one request per server step, and
// nothing -- the password least of all -- left in browser storage.
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { SetupPage } from './SetupPage';
import type { SetupStatus } from './SetupPage';
import { Context } from './ui';
import type { Session } from './api';

const privacy = { pseudonymous: true, aggregate_only: false, k_anonymity: 5, identity_link_days: 90, lock_descendants: false, retention_justification: '', team_claim: '', discovery_enabled: false, ignored_domains: [], auto_catalog: false, share_health: false, share_fleet: false };
const ready: SetupStatus = { pending: true, ready: true, edition: 'community', privacy_defaults: privacy };
function reply(body: unknown, status = 200) { return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }); }

let assign: ReturnType<typeof vi.fn>;
beforeEach(() => {
  localStorage.clear(); sessionStorage.clear();
  assign = vi.fn();
  vi.stubGlobal('location', { ...window.location, origin: 'https://milvago.example.test', assign });
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

function show(status: SetupStatus = ready) {
  const chooseLanguage = vi.fn();
  render(<Context.Provider value={{ session: undefined as unknown as Session, language: 'en', refreshSession: async () => {} }}><SetupPage status={status} language="en" chooseLanguage={chooseLanguage} /></Context.Provider>);
  return { chooseLanguage };
}
const next = () => userEvent.click(screen.getByRole('button', { name: 'Next' }));
async function fillAdministrator(confirmation = 'a-long-enough-passphrase') {
  await userEvent.type(screen.getByLabelText('Email address'), 'owner@example.test');
  await userEvent.type(screen.getByLabelText('First name'), 'Alex');
  await userEvent.type(screen.getByLabelText('Last name'), 'Doe');
  await userEvent.type(screen.getByLabelText('Password'), 'a-long-enough-passphrase');
  await userEvent.type(screen.getByLabelText('Confirm the password'), confirmation);
}

it('stays closed until the server is ready', () => {
  show({ pending: true, ready: false, edition: 'community' });
  expect(screen.getByText('The setup wizard is closed')).toBeTruthy();
  expect(screen.queryByLabelText('Setup token')).toBeNull();
});

// Whole-wizard flows: under a loaded image build the default 5 s is not enough.
it('walks every step and sends the choices once', async () => {
  const calls: { url: string; init?: RequestInit }[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input); calls.push({ url, init });
    if (url === '/api/setup/session') return reply({ csrf: 'setup-csrf' });
    if (url === '/api/setup/complete') return reply({ login: '/auth/login' });
    return reply({ error: 'unexpected_request' }, 404);
  });
  const { chooseLanguage } = show();
  await userEvent.type(screen.getByLabelText('Setup token'), 'synthetic-token');
  await next();
  // Licence step: Community defaults to "continue without one", so the next step
  // needs no input here.
  await next();
  await screen.findByLabelText('Instance default language');
  await userEvent.selectOptions(screen.getByLabelText('Instance default language'), 'fr');
  expect(chooseLanguage).toHaveBeenCalledWith('fr');
  await next();
  await fillAdministrator('a-different-passphrase');
  await next();
  expect(await screen.findByText('The two passwords differ.')).toBeTruthy();
  await userEvent.clear(screen.getByLabelText('Confirm the password'));
  await userEvent.type(screen.getByLabelText('Confirm the password'), 'a-long-enough-passphrase');
  await next();
  // The previous step's inputs must not be reused for this one: a reused element keeps
  // the value attribute of the field it was (here the e-mail address).
  for (const box of screen.getAllByRole('checkbox')) expect(box.getAttribute('value')).toBeNull();
  expect(document.body.innerHTML).not.toContain('passphrase');
  await userEvent.click(screen.getByLabelText('Require multi-factor authentication for every member'));
  await next();
  await userEvent.type(screen.getByLabelText('Organization name'), 'Example organization');
  expect((screen.getByLabelText('Public agent URL') as HTMLInputElement).value).toBe('https://milvago.example.test');
  await next();
  await userEvent.click(screen.getByLabelText('Configure an e-mail server now'));
  expect(screen.getByText('Test recipient (administrator e-mail): owner@example.test')).toBeTruthy();
  await userEvent.click(screen.getByLabelText('Configure an e-mail server now'));
  await next();
  // Privacy step: the team claim is left to Administration > Privacy.
  expect(screen.queryByText('OIDC team claim')).toBeNull();
  await next();
  expect(await screen.findByText('Example organization')).toBeTruthy();
  await userEvent.click(screen.getByRole('button', { name: 'Create the administrator and finish' }));
  await waitFor(() => expect(assign).toHaveBeenCalledWith('/auth/login'));

  expect(calls.map(c => c.url)).toEqual(['/api/setup/session', '/api/setup/complete']);
  const complete = calls[1].init!;
  expect((complete.headers as Record<string, string>)['X-CSRF-Token']).toBe('setup-csrf');
  const body = JSON.parse(String(complete.body));
  expect(body).toMatchObject({ admin: { email: 'owner@example.test', first_name: 'Alex', last_name: 'Doe', password: 'a-long-enough-passphrase' }, organization: { name: 'Example organization', public_url: 'https://milvago.example.test', default_language: 'fr' }, admin_totp: true, require_mfa: true, smtp: null, license: '' });
  expect(body.privacy.k_anonymity).toBe(5);
  const stored = JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }) + document.cookie;
  expect(stored).not.toContain('passphrase');
  expect(stored).not.toContain('synthetic-token');
}, 20_000);

it('returns to the token when the setup session has expired', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
    const url = String(input);
    if (url === '/api/setup/session') return reply({ csrf: 'setup-csrf' });
    return reply({ error: 'setup_session_required', message: 'Enter the setup token again.' }, 401);
  });
  show();
  await userEvent.type(screen.getByLabelText('Setup token'), 'synthetic-token');
  await next();
  await next();
  await screen.findByLabelText('Instance default language');
  await next();
  await fillAdministrator();
  await next();
  await next();
  await userEvent.type(screen.getByLabelText('Organization name'), 'Example organization');
  await next();
  expect(screen.getByLabelText('Configure an e-mail server now').getAttribute('value')).toBeNull();
  await userEvent.click(screen.getByLabelText('Configure an e-mail server now'));
  await userEvent.type(screen.getByLabelText('Server'), 'mail.example.test');
  await userEvent.type(screen.getByLabelText('Sender address'), 'no-reply@example.test');
  await userEvent.click(screen.getByRole('button', { name: 'Send a test e-mail' }));
  expect(await screen.findByLabelText('Setup token')).toBeTruthy();
  expect(screen.getByText('Enter the setup token again.')).toBeTruthy();
}, 20_000);

it('cannot leave the Enterprise licence step with an empty licence', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
    const url = String(input);
    if (url === '/api/setup/session') return reply({ csrf: 'setup-csrf' });
    return reply({ error: 'unexpected_request' }, 404);
  });
  show({ pending: true, ready: true, edition: 'commercial', instance_id: 'i-0123456789abcdef0123456789abcdef01' });
  await userEvent.type(screen.getByLabelText('Setup token'), 'synthetic-token');
  await next();
  expect(await screen.findByText('i-0123456789abcdef0123456789abcdef01')).toBeTruthy();
  await next();
  expect(await screen.findByText('Enter a license to continue.')).toBeTruthy();
  // Still on the licence step: the language step never rendered.
  expect(screen.queryByLabelText('Instance default language')).toBeNull();
});

async function finishAfterLicenseStep(calls: { url: string; init?: RequestInit }[]) {
  await screen.findByLabelText('Instance default language');
  await next();
  await fillAdministrator();
  await next();
  await next();
  await userEvent.type(screen.getByLabelText('Organization name'), 'Example organization');
  await next();
  await next();
  await next();
  await userEvent.click(screen.getByRole('button', { name: 'Create the administrator and finish' }));
  await waitFor(() => expect(calls.some(c => c.url === '/api/setup/complete')).toBe(true));
  const complete = calls.find(c => c.url === '/api/setup/complete')!.init!;
  return JSON.parse(String(complete.body));
}

it('sends an empty licence when Community continues without one', async () => {
  const calls: { url: string; init?: RequestInit }[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input); calls.push({ url, init });
    if (url === '/api/setup/session') return reply({ csrf: 'setup-csrf' });
    if (url === '/api/setup/complete') return reply({ login: '/auth/login' });
    return reply({ error: 'unexpected_request' }, 404);
  });
  show();
  await userEvent.type(screen.getByLabelText('Setup token'), 'synthetic-token');
  await next();
  await userEvent.click(screen.getByLabelText('Continue without a license'));
  await next();
  const body = await finishAfterLicenseStep(calls);
  expect(body.license).toBe('');
}, 20_000);

it('shows an invalid licence at step two and stays there until corrected', async () => {
  const checks: string[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input);
    if (url === '/api/setup/session') return reply({ csrf: 'setup-csrf' });
    if (url === '/api/setup/license-check') {
      const license = JSON.parse(String(init?.body)).license as string;
      checks.push(license);
      return license === 'valid-test-license'
        ? reply({ valid: true })
        : reply({ error: 'license_invalid', message: 'This licence is not valid for this instance.' }, 400);
    }
    return reply({ error: 'unexpected_request' }, 404);
  });
  show();
  await userEvent.type(screen.getByLabelText('Setup token'), 'synthetic-token');
  await next();
  await userEvent.click(screen.getByLabelText('I have a license'));
  await userEvent.type(screen.getByLabelText('License'), 'bad-license');
  await next();
  expect(await screen.findByText('This license is not valid.')).toBeTruthy();
  expect(screen.queryByLabelText('Instance default language')).toBeNull();
  expect(checks).toEqual(['bad-license']);
  await userEvent.clear(screen.getByLabelText('License'));
  await userEvent.type(screen.getByLabelText('License'), 'valid-test-license');
  await next();
  expect(await screen.findByLabelText('Instance default language')).toBeTruthy();
  expect(checks).toEqual(['bad-license', 'valid-test-license']);
}, 20_000);

it('sends the pasted licence when Community has one', async () => {
  const calls: { url: string; init?: RequestInit }[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const url = String(input); calls.push({ url, init });
    if (url === '/api/setup/session') return reply({ csrf: 'setup-csrf' });
    if (url === '/api/setup/license-check') return reply({ valid: true });
    if (url === '/api/setup/complete') return reply({ login: '/auth/login' });
    return reply({ error: 'unexpected_request' }, 404);
  });
  show();
  await userEvent.type(screen.getByLabelText('Setup token'), 'synthetic-token');
  await next();
  await userEvent.click(screen.getByLabelText('I have a license'));
  await userEvent.type(screen.getByLabelText('License'), 'FAKE-LICENSE-TOKEN');
  await next();
  const body = await finishAfterLicenseStep(calls);
  expect(body.license).toBe('FAKE-LICENSE-TOKEN');
  const check = calls.find(c => c.url === '/api/setup/license-check')?.init;
  expect(JSON.parse(String(check?.body))).toEqual({ license: 'FAKE-LICENSE-TOKEN' });
  expect((check?.headers as Record<string, string>)['X-CSRF-Token']).toBe('setup-csrf');
}, 20_000);
