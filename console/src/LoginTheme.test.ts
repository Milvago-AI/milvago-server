import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

const script = readFileSync('../deploy/theme/milvago/login/resources/js/milvago.js', 'utf8');
const state = 's'.repeat(43);
const endpoint = '/auth/login/device-trust?state=' + state;
const response = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });

beforeEach(() => {
  const clientData = btoa(JSON.stringify({ st: state }));
  document.body.innerHTML = `<form action="http://localhost/realms/test/login-actions/authenticate?client_data=${clientData}">
    <input name="otp" data-auto-submit>
    <div data-login-trust hidden><input type="checkbox" data-trust-device><p data-trust-error hidden>Try again</p></div>
    <button type="submit">Verify</button></form>`;
  vi.spyOn(HTMLFormElement.prototype, 'requestSubmit').mockImplementation(function (this: HTMLFormElement, submitter) {
    this.dispatchEvent(new SubmitEvent('submit', { bubbles: true, cancelable: true, submitter }));
  });
});
afterEach(() => { document.body.innerHTML = ''; vi.restoreAllMocks(); });

function initialize() {
  new Function(script)();
  document.dispatchEvent(new Event('DOMContentLoaded'));
}
const group = () => document.querySelector<HTMLElement>('[data-login-trust]')!;
const checkbox = () => document.querySelector<HTMLInputElement>('[data-trust-device]')!;
const settle = async () => { await vi.waitFor(() => expect(group().hidden).toBe(false)); };

it('records the OTP-page choice before auto-submitting the six-digit code', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(response({ csrf_token: 'synthetic-csrf', remember: false }))
    .mockResolvedValueOnce(response({ remember: true }));
  initialize();
  await settle();
  expect(checkbox().checked).toBe(false);
  checkbox().checked = true;
  const input = document.querySelector<HTMLInputElement>('[name=otp]')!;
  input.value = '123456';
  input.dispatchEvent(new Event('input'));
  await vi.waitFor(() => expect(HTMLFormElement.prototype.requestSubmit).toHaveBeenCalledTimes(2));
  expect(fetcher).toHaveBeenLastCalledWith(endpoint, expect.objectContaining({
    method: 'POST', credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': 'synthetic-csrf' },
    body: JSON.stringify({ remember: true }),
  }));
  expect(input.value).toBe('123456');
});

it('restores a previous choice after a wrong OTP and records unchecking it', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(response({ csrf_token: 'synthetic-csrf', remember: true }))
    .mockResolvedValueOnce(response({ remember: false }));
  initialize(); await settle();
  expect(checkbox().checked).toBe(true);
  checkbox().checked = false;
  document.querySelector('form')!.requestSubmit();
  await vi.waitFor(() => expect(HTMLFormElement.prototype.requestSubmit).toHaveBeenCalledTimes(2));
  expect(fetcher).toHaveBeenLastCalledWith(endpoint, expect.objectContaining({ body: JSON.stringify({ remember: false }) }));
});

it('keeps trust hidden for a sensitive-action challenge while allowing normal OTP submission', async () => {
  const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({}, 403));
  initialize();
  await vi.waitFor(() => expect(fetcher).toHaveBeenCalledOnce());
  document.querySelector('form')!.requestSubmit();
  await vi.waitFor(() => expect(HTMLFormElement.prototype.requestSubmit).toHaveBeenCalledTimes(2));
  expect(group().hidden).toBe(true);
  expect(fetcher).toHaveBeenCalledOnce();
});

it('keeps the OTP on screen if saving the choice fails, then allows a retry', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(response({ csrf_token: 'synthetic-csrf', remember: false }))
    .mockResolvedValueOnce(response({}, 503)).mockResolvedValueOnce(response({ remember: true }));
  initialize(); await settle();
  checkbox().checked = true;
  document.querySelector('form')!.requestSubmit();
  const error = document.querySelector<HTMLElement>('[data-trust-error]')!;
  await vi.waitFor(() => expect(error.hidden).toBe(false));
  expect(HTMLFormElement.prototype.requestSubmit).toHaveBeenCalledOnce();
  document.querySelector('form')!.requestSubmit();
  await vi.waitFor(() => expect(HTMLFormElement.prototype.requestSubmit).toHaveBeenCalledTimes(3));
  expect(error.hidden).toBe(true);
});

it('offers no trust option when the Keycloak form has no bound OIDC state', () => {
  const fetcher = vi.spyOn(globalThis, 'fetch');
  document.querySelector('form')!.action = 'http://localhost/realms/test/login-actions/authenticate';
  initialize();
  expect(fetcher).not.toHaveBeenCalled();
  expect(group().hidden).toBe(true);
});
