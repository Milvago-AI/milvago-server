import { afterEach, expect, it, vi } from 'vitest';
import { ApiError, request, requestRaw } from './api';

afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

it('ends a stalled metadata read and releases the deadline timer', async () => {
  vi.useFakeTimers();
  vi.spyOn(globalThis, 'fetch').mockImplementation((_path, options) => new Promise((_resolve, reject) => {
    options?.signal?.addEventListener('abort', () => reject(options.signal?.reason), { once: true });
  }));
  const result = request('/api/devices').catch((error: unknown) => error);
  await vi.advanceTimersByTimeAsync(18_000);
  expect(await result).toMatchObject({ status: 504, code: 'read_timeout' });
  expect(vi.getTimerCount()).toBe(0);
});

it('bounds a stalled body after headers and cancels its stream', async () => {
  vi.useFakeTimers();
  const cancel = vi.fn();
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(new ReadableStream({ cancel }), { status: 200 }));
  const result = request('/api/shadow/cartography').catch((error: unknown) => error);
  await vi.advanceTimersByTimeAsync(18_000);
  expect(await result).toMatchObject({ status: 504, code: 'read_timeout' });
  expect(cancel).toHaveBeenCalledTimes(1);
  expect(vi.getTimerCount()).toBe(0);
});

it('keeps navigation cancellation distinct from a timeout', async () => {
  vi.useFakeTimers();
  const controller = new AbortController();
  vi.spyOn(globalThis, 'fetch').mockImplementation((_path, options) => new Promise((_resolve, reject) => {
    options?.signal?.addEventListener('abort', () => reject(options.signal?.reason), { once: true });
  }));
  const result = request('/api/discovery/environments', { signal: controller.signal }).catch((error: unknown) => error);
  controller.abort();
  expect(await result).toMatchObject({ name: 'AbortError' });
  expect(vi.getTimerCount()).toBe(0);
});

it('bounds bytes even when Content-Length understates an oversized response', async () => {
  const cancel = vi.fn();
  const body = new ReadableStream<Uint8Array>({ start(stream) { stream.enqueue(new Uint8Array(16 * 1024 * 1024 + 1)); }, cancel });
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(body, { headers: { 'Content-Length': '1' } }));
  await expect(request('/api/shadow/cartography')).rejects.toMatchObject({ status: 413, code: 'response_too_large' });
  expect(cancel).toHaveBeenCalledTimes(1);
});

it('retains UTF-8 characters split between response chunks', async () => {
  const bytes = new TextEncoder().encode('{"value":"é🙂"}');
  const body = new ReadableStream<Uint8Array>({ start(stream) { for (const byte of bytes) stream.enqueue(new Uint8Array([byte])); stream.close(); } });
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(body));
  await expect(request('/api/data')).resolves.toEqual({ value: 'é🙂' });
});

it('announces 401 before refusing an oversized gateway error body', async () => {
  const unauthorized = vi.fn();
  window.addEventListener('milvago:unauthorized', unauthorized);
  try {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('x'.repeat(64 * 1024 + 1), { status: 401 }));
    await expect(requestRaw('/api/data')).rejects.toBeInstanceOf(ApiError);
    expect(unauthorized).toHaveBeenCalledTimes(1);
  } finally { window.removeEventListener('milvago:unauthorized', unauthorized); }
});

it('preserves 204 and the credentials, no-store, body and CSRF policy of mutations', async () => {
  vi.useFakeTimers();
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(null, { status: 204 }));
  await expect(request('/api/settings', { method: 'PUT', body: { name: 'Synthetic' }, csrf: 'synthetic-csrf' })).resolves.toBeUndefined();
  expect(fetch).toHaveBeenCalledWith('/api/settings', expect.objectContaining({ method: 'PUT', credentials: 'same-origin', cache: 'no-store', body: '{"name":"Synthetic"}', headers: expect.objectContaining({ 'X-CSRF-Token': 'synthetic-csrf' }) }));
  expect(vi.getTimerCount()).toBe(0);
});
