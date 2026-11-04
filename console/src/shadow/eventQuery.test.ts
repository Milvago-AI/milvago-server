import { expect, it } from 'vitest';
import { eventQueryOperators, formatEventQuery, parseEventQuery } from './eventQuery';
import type { Criteria } from './types';
const period = { from: '2026-10-30T12:00:00Z', to: '2026-10-31T12:00:00Z' };
it('maps the user-facing operators to existing API criteria and retains context', () => {
  expect(parseEventQuery('service:chatgpt.com model:gpt-5.6 device:synthetic-id', { ...period, provider: 'old.example', action: 'blocked' })).toEqual({ ok: true, criteria: { ...period, provider: 'chatgpt.com', model: 'gpt-5.6', device_name: 'synthetic-id', regex: ['provider', 'model', 'device_name'] } });
  expect(parseEventQuery('', { ...period, provider: 'old.example' })).toEqual({ ok: true, criteria: period });
});
it('keeps repeated values separate, deduplicates and round-trips quoted Unicode and technical values', () => {
  const criteria: Criteria = { ...period, provider: ['first.example', 'second.example'], model: 'Modèle "A" \\ local', actor_id: 'os:'+'a'.repeat(64), tool: 'C:\\Program Files\\Synthetic', query: 'metadata, text' };
  const query = formatEventQuery(criteria);
  expect(query).toContain('service:=first.example service:=second.example');
  expect(parseEventQuery(query, period)).toEqual({ ok: true, criteria });
  expect(parseEventQuery('service:first.example service:first.example', period)).toEqual({ ok: true, criteria: { ...period, provider: 'first.example', regex: ['provider'] } });
});
it('formats every supported criterion without exposing context-only keys', () => {
  const criteria = Object.fromEntries(Object.entries(eventQueryOperators).map(([operator, key]) => [key, operator + '-value']));
  const query = formatEventQuery(criteria);
  expect(parseEventQuery(query, period)).toEqual({ ok: true, criteria: { ...period, ...criteria } });
});
it('keeps plain words, phrases and URLs in the existing metadata query', () => {
  expect(parseEventQuery('"alpha beta" gamma https://example.invalid/path', period)).toEqual({ ok: true, criteria: { ...period, query: 'alpha beta gamma https://example.invalid/path', regex: ['query'] } });
  expect(parseEventQuery('text:"service:literal"', period)).toEqual({ ok: true, criteria: { ...period, query: 'service:literal', regex: ['query'] } });
  expect(parseEventQuery('alpha and beta', period)).toEqual({ ok: true, criteria: { ...period, query: 'alpha and beta', regex: ['query'] } });
});
it.each([
  ['service:', 'value'], ['service: next', 'value'], ['service:""', 'value'], ['service:"   "', 'value'],
  ['model:"unfinished', 'quote'], ['model:"a"suffix', 'syntax'], ['model:a"b', 'quote'],
  ['service:x OR service:y', 'boolean'], ['unknown:value', 'operator'],
  ['constructor:value', 'operator'], ['__proto__:value', 'operator'],
  ['attachment:yes attachment:no', 'single'], ['text:a text:b', 'single'],
  ['service:"a\\nb"', 'value'], ['service:"a\\rb"', 'value'], ['service:"a\\u0000b"', 'value'],
  ['service:'+'a'.repeat(201), 'limit'], ['text:'+'é'.repeat(51), 'limit'],
  [Array.from({ length: 21 }, (_, i) => 'service:s'+i).join(' '), 'limit'],
  ['x'.repeat(2049), 'limit'],
])('rejects %s atomically (%s)', (query, kind) => {
  const base = { ...period, provider: 'keep.example' };
  expect(parseEventQuery(query, base)).toMatchObject({ ok: false, error: { kind } });
  expect(base.provider).toBe('keep.example');
});
it('rejects edition-unavailable operators without dropping the existing criteria', () => {
  expect(parseEventQuery('sensitivity:sensitive', period, new Set(['provider', 'query']))).toMatchObject({ ok: false, error: { kind: 'unavailable', value: 'sensitivity' } });
});
