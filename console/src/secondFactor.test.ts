import { afterEach, expect, it, vi } from 'vitest';
import { ApiError } from './api';
import { WINDOWS_PACKAGE_NAME, WINDOWS_PACKAGE_PATH } from './download';
import { browser, resumeSecondFactor, sameOriginTarget, verifySecondFactor } from './secondFactor';

const KEY = 'milvago.second-factor-retry';
const refused = new ApiError(403, 'fresh_mfa_required', 'Authenticate again.');

afterEach(() => { window.sessionStorage.clear(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

// sessionStorage outlives an abandoned verification: a directory bind password held
// there would stay readable for the life of the tab, although the server never returns it.
it('never holds a body that carries a secret, but still goes to the verification', () => {
  const navigate = vi.spyOn(browser, 'navigate').mockImplementation(() => {});
  expect(verifySecondFactor('/api/settings/ldap', 'PUT', { host: 'ldap.example.test', bind_credential: 'placeholder' }, refused, 'fr', scope)).toBe(true);
  expect(window.sessionStorage.getItem(KEY)).toBeNull();
  expect(navigate).toHaveBeenCalledWith(expect.stringContaining('/auth/login?mfa=1'));

  verifySecondFactor('/api/settings/ldap', 'PUT', { host: 'ldap.example.test', bind_credential: '' }, refused, 'fr', scope);
  expect(JSON.parse(window.sessionStorage.getItem(KEY)!).body.host).toBe('ldap.example.test');
  // A later change that cannot be held drops the older one rather than leave it to replay.
  verifySecondFactor('/api/settings/ldap', 'PUT', { bind_credential: 'placeholder' }, refused, 'fr', scope);
  expect(window.sessionStorage.getItem(KEY)).toBeNull();
  // Names outside the first list fail closed too; a lookalike ("keywords") is still held.
  for (const name of ['private_key', 'key', 'pin', 'passphrase', 'otp']) {
    verifySecondFactor('/api/settings/x', 'PUT', { nested: { [name]: 'placeholder' } }, refused, 'fr', scope);
    expect(window.sessionStorage.getItem(KEY)).toBeNull();
  }
  verifySecondFactor('/api/shadow/settings', 'PUT', { config: { keywords: ['alpha'] } }, refused, 'fr', scope);
  expect(JSON.parse(window.sessionStorage.getItem(KEY)!).body.config.keywords).toEqual(['alpha']);
});

const scope = { org: '11111111-1111-4111-8111-111111111111', user: '22222222-2222-4222-8222-222222222222' };

// Leaving the page is the one place a crafted destination could send the person elsewhere.
it('follows only a same-origin path', () => {
  const target = sameOriginTarget('/auth/login?mfa=1&lang=fr#top');
  expect(target && target.pathname + target.search + target.hash).toBe('/auth/login?mfa=1&lang=fr#top');
  for (const hostile of ['https://evil.example/x', '//evil.example/x', 'javascript:alert(1)', 'java\nscript:alert(1)', 'data:text/html,x', '']) {
    expect(sameOriginTarget(hostile)).toBeNull();
  }
});

// The verification signs in again and can land in another organization: a purge asked
// in a child organization must not run in the root one, nor for another person.
it('replays only for the same person in the same organization', async () => {
  vi.spyOn(browser, 'navigate').mockImplementation(() => {});
  const fetchMock = vi.fn(async () => new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }));
  vi.stubGlobal('fetch', fetchMock);
  for (const other of [{ ...scope, org: '33333333-3333-4333-8333-333333333333' }, { ...scope, user: '44444444-4444-4444-8444-444444444444' }]) {
    verifySecondFactor('/api/shadow/content/purge', 'POST', { before: '2026-09-24T00:00:00Z' }, refused, 'fr', scope);
    expect(await resumeSecondFactor('csrf', other)).toBe('none');
  }
  expect(fetchMock).not.toHaveBeenCalled();
  verifySecondFactor('/api/shadow/content/purge', 'POST', { before: '2026-09-24T00:00:00Z' }, refused, 'fr', scope);
  expect(await resumeSecondFactor('csrf', scope)).toBe('resumed');
  expect(fetchMock).toHaveBeenCalledTimes(1);
  vi.unstubAllGlobals();
});

it('downloads the protected Windows ZIP after verification and never replays it for another account', async () => {
  const navigate = vi.spyOn(browser, 'navigate').mockImplementation(() => {});
  const createObjectURL = vi.fn().mockReturnValue('blob:windows-package');
  Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: createObjectURL });
  Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: vi.fn() });
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
    expect(this.download).toBe(WINDOWS_PACKAGE_NAME);
  });
  const fetchMock = vi.fn(async () => new Response('PK-package', { status: 200, headers: { 'Content-Type': 'application/zip' } }));
  vi.stubGlobal('fetch', fetchMock);
  expect(verifySecondFactor(WINDOWS_PACKAGE_PATH, 'POST', undefined, refused, 'fr', scope, 'windows-package')).toBe(true);
  expect(navigate).toHaveBeenCalledWith('/auth/login?mfa=1&lang=fr');
  expect(await resumeSecondFactor('csrf', { ...scope, user: '33333333-3333-4333-8333-333333333333' })).toBe('none');
  expect(fetchMock).not.toHaveBeenCalled();
  verifySecondFactor(WINDOWS_PACKAGE_PATH, 'POST', undefined, refused, 'fr', scope, 'windows-package');
  expect(await resumeSecondFactor('csrf', scope)).toBe('downloaded');
  expect(fetchMock).toHaveBeenCalledWith(WINDOWS_PACKAGE_PATH, expect.objectContaining({ method: 'POST', headers: expect.objectContaining({ Accept: 'application/zip', 'X-CSRF-Token': 'csrf' }) }));
  expect(click).toHaveBeenCalledOnce();
  expect(await resumeSecondFactor('csrf', scope)).toBe('none');
});
