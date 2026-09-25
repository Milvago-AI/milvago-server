import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, request } from './api';

// A proxy or gateway answering for the server may send a JSON body that is not an
// object: `null`, a bare string, a number. Those parse successfully, so the error path
// must still produce an ApiError carrying the status -- the `instanceof ApiError`
// branches in ErrorNotice and InstallerDialog depend on it -- and not a TypeError
// from dereferencing `error.error` on null.
describe('request errors', () => {
  afterEach(() => vi.restoreAllMocks());
  for (const body of ['null', '"bad gateway"', '42']) {
    it(`turns a ${body} error body into an ApiError with the status and the fallback code`, async () => {
      vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(body, { status: 502, headers: { 'Content-Type': 'application/json' } }));
      const failure = await request('/api/anything').catch((e: unknown) => e);
      expect(failure).toBeInstanceOf(ApiError);
      expect(failure).toMatchObject({ status: 502, code: 'request_failed', message: 'HTTP 502' });
    });
  }
  it('keeps the server code and message when the body carries them', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ error: 'fresh_mfa_required', message: 'Verify again.' }), { status: 403, headers: { 'Content-Type': 'application/json' } }));
    const failure = await request('/api/anything').catch((e: unknown) => e);
    expect(failure).toMatchObject({ status: 403, code: 'fresh_mfa_required', message: 'Verify again.' });
  });
  it('ignores a code or message that is not a string', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ error: 7, message: ['x'] }), { status: 500, headers: { 'Content-Type': 'application/json' } }));
    const failure = await request('/api/anything').catch((e: unknown) => e);
    expect(failure).toMatchObject({ status: 500, code: 'request_failed', message: 'HTTP 500' });
  });
});
