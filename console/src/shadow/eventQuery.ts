import type { Criteria } from './types';

// These names are query syntax, stable across console languages; they never become SQL.
export const eventQueryOperators = {
  service: 'provider', model: 'model', device: 'device_name', device_id: 'device_id', person: 'actor_id', app: 'tool',
  action: 'action', kind: 'kind', attachment: 'attachment', sensitivity: 'sensitivity',
  rule: 'dlp_rule', mode: 'dlp_mode', consequence: 'dlp_consequence', outcome: 'dlp_outcome', text: 'query',
} as const;
export type QueryOperators = Readonly<Record<string, string>>;
export type EventQueryError = { kind: 'syntax' | 'operator' | 'quote' | 'value' | 'limit' | 'single' | 'boolean' | 'unavailable' | 'invalid' | 'regex'; value?: string };
export type EventQueryResult = { ok: true; criteria: Criteria } | { ok: false; error: EventQueryError };
const singles = new Set(['attachment', 'query', 'dlp_rule', 'dlp_mode', 'dlp_consequence', 'dlp_outcome']);
const bytes = (value: string) => new TextEncoder().encode(value).length;
export const criterionValues = (criteria: Criteria, key: string): string[] => {
  const value = criteria[key]; return (Array.isArray(value) ? value : value ? [value] : []).filter(Boolean);
};
const quote = (value: string) => /[\s"\\]/u.test(value) || !value ? JSON.stringify(value) : value;
const quoteGlobal = (value: string) => /^[a-z_][a-z0-9_]*:/i.test(value) || /^(AND|OR|NOT)$/.test(value) ? JSON.stringify(value) : quote(value);
export const regexFields: ReadonlySet<string> = new Set(Object.values(eventQueryOperators));
export const usesRegex = (criteria: Criteria, key: string) => criterionValues(criteria, 'regex').includes(key);

// Compile only for syntax; never execute a user expression in the browser.
// The API applies the shared bounded POSIX ERE subset and is authoritative.
export function validSearchRegex(value: string): boolean {
  if (!value || bytes(value) > 200 || /[\u0000-\u001f\u007f-\u009f]/u.test(value) || value.includes('(?') || value.includes('[[.') || value.includes('[[=')) return false;
  let inClass = false;
  for (let i = 0; i < value.length; i++) {
    if (value[i] === '\\') { if (++i === value.length || /[a-z0-9]/i.test(value[i])) return false; continue; }
    if (value[i] === '[') inClass = true;
    else if (value[i] === ']') inClass = false;
    else if (!inClass && '*+?}'.includes(value[i]) && value[i + 1] === '?') return false;
  }
  for (const count of value.matchAll(/(?<!\\)\{(\d+)(?:,(\d*))?\}/g)) {
    if (Number(count[1]) > 255 || (count[2] && Number(count[2]) > 255)) return false;
  }
  try { new RegExp(value, 'i'); return true; } catch { return false; }
}

/** Preserve commas in character classes, groups and counted repetitions. */
export function splitRegexSelections(input: string): string[] {
  const values: string[] = []; let start = 0, depth = 0, inClass = false, inRepeat = false;
  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    if (ch === '\\') { i++; continue; }
    if (ch === '[') inClass = true;
    else if (ch === ']') inClass = false;
    else if (!inClass) {
      if (ch === '(') depth++;
      else if (ch === ')') depth = Math.max(0, depth - 1);
      else if (ch === '{') inRepeat = true;
      else if (ch === '}') inRepeat = false;
      else if (ch === ',' && !depth && !inRepeat) { values.push(input.slice(start, i).trim()); start = i + 1; }
    }
  }
  values.push(input.slice(start).trim()); return values.filter(Boolean);
}

export function formatEventQuery(criteria: Criteria, operators: QueryOperators = eventQueryOperators): string {
  const regexFields = new Set(Object.values(operators));
  return Object.entries(operators).flatMap(([operator, key]) => criterionValues(criteria, key).map(value => key === 'query' && usesRegex(criteria, key) ? quoteGlobal(value) : operator + ':' + quote((regexFields.has(key) && !usesRegex(criteria, key) ? '=' : '') + value))).join(' ');
}

/** Parse the whole draft before replacing any criterion. Context such as period is retained. */
export function parseEventQuery(input: string, base: Criteria, allowedKeys?: ReadonlySet<string>, operators: QueryOperators = eventQueryOperators): EventQueryResult {
  const regexFields = new Set(Object.values(operators));
  const fail = (kind: EventQueryError['kind'], value?: string): EventQueryResult => ({ ok: false, error: { kind, value } });
  if (typeof input !== 'string') return fail('syntax');
  if (input.length > 2048) return fail('limit');
  const parsed: Criteria = {};
  const patterns = new Set<string>(); const literals = new Set<string>();
  let index = 0, terms = 0; const text: string[] = [];
  while (index < input.length) {
    while (/\s/u.test(input[index] ?? '') && index < input.length) index++;
    if (index === input.length) break;
    if (++terms > 64) return fail('limit');
    let operator: string | undefined;
    const prefix = /^([a-z_][a-z0-9_]*):/i.exec(input.slice(index));
    // A pasted URL remains literal metadata; an unknown field name is an error.
    if (prefix && !/^https?:\/\//i.test(input.slice(index))) {
      operator = prefix[1].toLowerCase(); index += prefix[0].length;
      if (!Object.prototype.hasOwnProperty.call(operators, operator)) return fail('operator', operator);
    }
    if (index === input.length || /\s/u.test(input[index])) return fail('value', operator);
    let value: string; const quoted = input[index] === '"';
    if (quoted) {
      const start = index++; let closed = false;
      while (index < input.length) {
        if (input[index] === '\\') { index += 2; continue; }
        if (input[index++] === '"') { closed = true; break; }
      }
      if (!closed) return fail('quote');
      try { value = JSON.parse(input.slice(start, index)); } catch { return fail('quote'); }
      if (index < input.length && !/\s/u.test(input[index])) return fail('syntax');
    } else {
      const start = index; while (index < input.length && !/\s/u.test(input[index])) index++;
      value = input.slice(start, index); if (value.includes('"')) return fail('quote');
    }
    if (!value.trim() || /[\r\n\u0000]/u.test(value)) return fail('value', operator);
    if (!operator) {
      if (!quoted && (/^(AND|OR|NOT)$/.test(value))) return fail('boolean');
      text.push(value); continue;
    }
    const key = operators[operator];
    if (allowedKeys && !allowedKeys.has(key)) return fail('unavailable', operator);
    if (regexFields.has(key)) {
      const exact = value.startsWith('=');
      if (exact) value = value.slice(1);
      if (!value.trim()) return fail('value', operator);
      if (exact ? patterns.has(key) : literals.has(key)) return fail('regex', operator);
      if (exact) literals.add(key);
      else patterns.add(key);
    }
    const limit = key === 'query' || key.startsWith('dlp_') ? 100 : 200;
    if (bytes(value) > limit) return fail('limit', operator);
    if (patterns.has(key) && !validSearchRegex(value)) return fail('regex', operator);
    const previous = criterionValues(parsed, key);
    if (previous.includes(value)) continue;
    if (singles.has(key) && previous.length) return fail('single', operator);
    if (previous.length >= 20) return fail('limit', operator);
    parsed[key] = previous.length ? [...previous, value] : value;
  }
  if (text.length) {
    if (literals.has('query')) return fail('single', 'text');
    const value = [...criterionValues(parsed, 'query'), ...text].join(' ');
    if (bytes(value) > 100) return fail('limit', 'text');
    if (!validSearchRegex(value)) return fail('regex', 'text'); parsed.query = value; patterns.add('query');
  }
  const criteria = { ...base };
  for (const key of Object.values(operators)) delete criteria[key];
  delete criteria.regex;
  Object.assign(criteria, parsed);
  if (patterns.size) criteria.regex = [...regexFields].filter(key => patterns.has(key));
  return { ok: true, criteria };
}
