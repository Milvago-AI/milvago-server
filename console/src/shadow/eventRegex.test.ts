import { expect, it } from 'vitest';
import { formatEventQuery, parseEventQuery, splitRegexSelections, validSearchRegex } from './eventQuery';
import { conversationsLink, criteriaFromHash, reportLink } from './filters';

it('searches partial and alternative service names and model prefixes as regex', () => {
  expect(parseEventQuery('service:chatgpt model:^gpt', {})).toEqual({ ok: true, criteria: { provider: 'chatgpt', model: '^gpt', regex: ['provider', 'model'] } });
  expect(parseEventQuery('service:(chatgpt|claude) device:^LT-COM app:chrome', {})).toEqual({ ok: true, criteria: { provider: '(chatgpt|claude)', device_name: '^LT-COM', tool: 'chrome', regex: ['provider', 'device_name', 'tool'] } });
});
it('retains the exact scope of existing links and views when formatting and parsing', () => {
  const scope = { provider: 'chatgpt.com', model: 'C:\\models\\literal', query: '[literal]', device_id: '11111111-1111-4111-8111-111111111111' };
  const text = formatEventQuery(scope);
  expect(text).toContain('service:=chatgpt.com');
  expect(parseEventQuery(text, {})).toEqual({ ok: true, criteria: scope });
});
it('round-trips escaped expressions and keeps inherited literal decisions stable', () => {
  const scope = { provider: ['chatgpt', 'claude'], model: '^gpt-5\\.[0-9]+$', action: 'blocked', regex: ['provider', 'model'] };
  expect(parseEventQuery(formatEventQuery(scope), {})).toEqual({ ok: true, criteria: scope });
  expect(parseEventQuery('service:=chatgpt.com action:blocked', {})).toEqual({ ok: true, criteria: { provider: 'chatgpt.com', action: 'blocked', regex: ['action'] } });
});
it.each(['[', '(a', '(?=a)', '(a)\\1', '(?i)chatgpt', 'a{256}', 'a+?', 'a\n', 'a\u0000', 'a\u0085'])('refuses malformed or unsupported regex %s before applying it', pattern => {
  const base = { provider: 'keep.example' };
  expect(parseEventQuery('service:' + JSON.stringify(pattern), base)).toMatchObject({ ok: false });
  expect(base).toEqual({ provider: 'keep.example' });
});
it('does not split a counted repetition, character class, group or escaped comma in the visual editor', () => {
  expect(splitRegexSelections('gpt-[0-9]{2,3}, (chatgpt,chatgpt), [a,b], x\\,y')).toEqual(['gpt-[0-9]{2,3}', '(chatgpt,chatgpt)', '[a,b]', 'x\\,y']);
  expect(validSearchRegex('gpt-[0-9]{2,3}')).toBe(true);
});
it('refuses non-text input and a mix of exact and pattern selections for one field atomically', () => {
  expect(parseEventQuery({ image: 'synthetic' } as unknown as string, {})).toMatchObject({ ok: false });
  expect(parseEventQuery('service:=literal service:pattern', {})).toMatchObject({ ok: false });
});

it('retains regex semantics in journal/report links and on reload', () => {
  const scope = { provider: 'chatgpt', model: '^gpt', regex: ['provider', 'model'] };
  const link = conversationsLink(scope);
  expect(new URLSearchParams(link.split('?')[1]).getAll('regex')).toEqual(['provider', 'model']);
  location.hash = link;
  expect(criteriaFromHash()).toMatchObject(scope);
  const report = reportLink(scope);
  expect(new URLSearchParams(report.split('?')[1]).getAll('regex')).toEqual(['provider', 'model']);
  location.hash = '';
});
