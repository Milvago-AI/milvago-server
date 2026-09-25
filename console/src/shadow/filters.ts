import type { Criteria } from './types';

export const filterKeys = ['from', 'to', 'actor_id', 'device_id', 'tool', 'provider', 'model', 'sensitivity', 'action', 'attachment', 'query', 'kind'] as const;
export function serializeCriteria(criteria: Criteria) {
  const params = new URLSearchParams();
  for (const key of filterKeys) for (const value of Array.isArray(criteria[key]) ? criteria[key] : [criteria[key]]) if (value) params.append(key, value);
  return params.toString();
}
export function criteriaFromHash(): Criteria {
  const params = new URLSearchParams(location.hash.split('?')[1] ?? ''); const result: Criteria = {};
  for (const key of filterKeys) { const values = params.getAll(key); if (values.length) result[key] = values.length === 1 ? values[0] : values; }
  return Object.keys(result).length ? result : periodCriteria(24);
}
export function periodCriteria(hours: number): Criteria { const to = new Date(); return { from: new Date(to.getTime() - hours * 3600000).toISOString(), to: to.toISOString() }; }
export function conversationsLink(criteria: Criteria) { return `#events?shadow=1&${serializeCriteria(criteria)}`; }
/** The printable report over one scope; `criteriaFromHash` reads it back on the other side. */
export function reportLink(criteria: Criteria) { return `#report?${serializeCriteria(criteria)}`; }
export function valueOf(criteria: Criteria, key: string) { const value = criteria[key]; return Array.isArray(value) ? value.join(', ') : value ?? ''; }
