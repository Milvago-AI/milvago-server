import { useState } from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { expect, it, vi } from 'vitest';
import { Context } from '../ui';
import type { Session } from '../api';
import type { Criteria } from './types';
import { EventFilters } from './EventFilters';
import { eventQueryOperators, formatEventQuery, parseEventQuery, usesRegex } from './eventQuery';

it('searches the displayed machine name rather than requiring its UUID', () => {
  expect(parseEventQuery('device:^LT-COM', {})).toEqual({ ok: true, criteria: { device_name: '^LT-COM', regex: ['device_name'] } });
  const legacy = { device_id: '11111111-1111-4111-8111-111111111111' };
  expect(formatEventQuery(legacy)).toBe('device_id:=11111111-1111-4111-8111-111111111111');
  expect(parseEventQuery(formatEventQuery(legacy), {})).toEqual({ ok: true, criteria: legacy });
});

it('applies regex semantics to every user-facing filter including enums and decisions', () => {
  for (const [operator, field] of Object.entries(eventQueryOperators)) {
    const result = parseEventQuery(operator + ':(alpha|beta)', {});
    expect(result.ok, operator).toBe(true);
    if (result.ok) {
      expect(usesRegex(result.criteria, field), operator).toBe(true);
      expect(result.criteria[field]).toBe('(alpha|beta)');
    }
  }
});

it('keeps an unqualified search unqualified when synchronizing filters and preserves scope', () => {
  const context = { view: 'agentic', environment_id: 'synthetic-environment', from: '2026-10-30T00:00:00Z' };
  const result = parseEventQuery('(LT-COM|chatgpt) action:block', context);
  expect(result).toEqual({ ok: true, criteria: { ...context, action: 'block', query: '(LT-COM|chatgpt)', regex: ['action', 'query'] } });
  if (result.ok) expect(formatEventQuery(result.criteria)).toBe('action:block (LT-COM|chatgpt)');
});

it('does not reinterpret a global value as an operator while synchronizing the search', () => {
  for (const query of ['service:literal', 'unknown:value', 'AND', 'https://example.invalid/path']) {
    const criteria = { query, regex: ['query'] };
    expect(parseEventQuery(formatEventQuery(criteria), {})).toEqual({ ok: true, criteria });
  }
});

const session = { user: { id: 'synthetic-reader' }, organization: { id: 'synthetic-org', role: 'viewer' }, permissions: ['events.read'], edition: 'community' } as Session;
function Harness({ changed }: { changed: (criteria: Criteria) => void }) {
  const [criteria, set] = useState<Criteria>({ view: 'agentic', environment_id: 'synthetic-environment' });
  return <Context.Provider value={{ session, language: 'en', refreshSession: async () => undefined }}>
    <EventFilters criteria={criteria} change={next => { set(next); changed(next); }} />
  </Context.Provider>;
}
it('synchronizes a regex entered in a formerly fixed-choice visual filter with the global draft', async () => {
  const user = userEvent.setup(), changed = vi.fn();
  render(<Harness changed={changed} />);
  await user.type(screen.getByRole('searchbox'), 'LT-COM');
  await user.click(screen.getByRole('button', { name: 'Add filter' }));
  await user.click(screen.getByRole('button', { name: 'Action' }));
  await user.type(screen.getByLabelText('Action'), 'block|redirect{Enter}');
  expect(changed).toHaveBeenLastCalledWith({ view: 'agentic', environment_id: 'synthetic-environment', query: 'LT-COM', action: 'block|redirect', regex: ['action', 'query'] });
  expect(screen.getByRole('searchbox')).toHaveValue('action:block|redirect LT-COM');
  await user.clear(screen.getByRole('searchbox'));
  expect(changed).toHaveBeenLastCalledWith({ view: 'agentic', environment_id: 'synthetic-environment' });
});
