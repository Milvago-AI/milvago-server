import { useState } from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { expect, it, vi } from 'vitest';
import type { Session } from '../api';
import { Context } from '../ui';
import { EventFilters } from './EventFilters';
import type { Criteria } from './types';
const session: Session = { user: { id: 'synthetic-reader', email: 'reader@example.invalid', display_name: 'Synthetic reader' }, organization: { id: 'synthetic-org', name: 'Synthetic organization', role: 'viewer' }, organizations: [], permissions: ['events.read'], csrf_token: 'fixture', edition: 'community' };
const period = { from: '2026-10-30T12:00:00Z', to: '2026-10-31T12:00:00Z' };
function Harness({ initial = period, changed }: { initial?: Criteria; changed: (value: Criteria) => void }) {
  const [criteria, set] = useState(initial);
  return <Context.Provider value={{ session, language: 'en', refreshSession: async () => undefined }}><EventFilters criteria={criteria} change={next => { set(next); changed(next); }}
    views={apply => <button type="button" onClick={() => apply(initial)}>Restore synthetic view</button>}/></Context.Provider>;
}
async function replaceSearch(user: ReturnType<typeof userEvent.setup>, value: string) {
  await user.click(screen.getByRole('searchbox')); await user.keyboard('{Control>}a{/Control}'); await user.paste(value);
}
it('converts the structured query to filters and never sends its operators as metadata text', async () => {
  const changed = vi.fn(), user = userEvent.setup(), device = '11111111-1111-4111-8111-111111111111';
  render(<Harness changed={changed}/>);
  await user.type(screen.getByRole('searchbox'), 'service:chatgpt.com model:gpt-5.6 device:'+device+'{Enter}');
  expect(changed).toHaveBeenLastCalledWith({ ...period, provider: 'chatgpt.com', model: 'gpt-5.6', device_name: device, regex: ['provider', 'model', 'device_name'] });
  expect(screen.getByRole('button', { name: 'Service: chatgpt.com' })).toBeVisible();
  expect(screen.getByRole('searchbox')).toHaveValue('service:chatgpt.com model:gpt-5.6 device:'+device);
});
it('merges a valid unsubmitted query with an added filter and updates text after editing or removing chips', async () => {
  const changed = vi.fn(), user = userEvent.setup(); render(<Harness changed={changed}/>);
  await user.type(screen.getByRole('searchbox'), 'service:chatgpt.com');
  expect(changed).not.toHaveBeenCalled();
  await user.click(screen.getByRole('button', { name: 'Add filter' }));
  await user.click(screen.getByRole('button', { name: 'Model' }));
  await user.type(screen.getByRole('textbox', { name: 'Model' }), 'gpt-5.6{Enter}');
  expect(screen.getByRole('searchbox')).toHaveValue('service:chatgpt.com model:gpt-5.6');
  expect(changed).toHaveBeenLastCalledWith({ ...period, provider: 'chatgpt.com', model: 'gpt-5.6', regex: ['provider', 'model'] });
  await user.click(screen.getByRole('button', { name: 'Service: chatgpt.com' }));
  await user.clear(screen.getByRole('textbox', { name: 'Service' }));
  await user.type(screen.getByRole('textbox', { name: 'Service' }), 'first.example, second.example{Enter}');
  expect(screen.getByRole('searchbox')).toHaveValue('service:first.example service:second.example model:gpt-5.6');
  await user.click(screen.getByRole('button', { name: 'Remove Service: first.example' }));
  expect(screen.getByRole('searchbox')).toHaveValue('service:second.example model:gpt-5.6');
  await user.clear(screen.getByRole('searchbox'));
  expect(changed).toHaveBeenLastCalledWith(period);
});
it('keeps results unchanged for an incomplete draft, including when Add filter is used, and can reset explicitly', async () => {
  const changed = vi.fn(), user = userEvent.setup(); render(<Harness initial={{ ...period, provider: 'keep.example' }} changed={changed}/>);
  await replaceSearch(user, 'model:"unfinished'); await user.keyboard('{Enter}');
  expect(screen.getByRole('alert')).toHaveTextContent('Close the double quotes'); expect(changed).not.toHaveBeenCalled();
  expect(screen.getByRole('button', { name: 'Service: keep.example' })).toBeVisible();
  await user.click(screen.getByRole('button', { name: 'Add filter (1)' }));
  await user.click(screen.getByRole('button', { name: 'Service' }));
  expect(changed).not.toHaveBeenCalled();
  await user.click(screen.getByRole('button', { name: 'Reset' }));
  expect(screen.getByRole('searchbox')).toHaveValue('');
  expect(Object.keys(changed.mock.lastCall![0]).sort()).toEqual(['from', 'to']);
});
it.each(['unknown:value', 'action:[', 'device_id:=invalid-id', 'sensitivity:sensitive', 'attachment:yes attachment:no'])(
  'does not broaden or partially apply invalid input %s', async query => {
    const changed = vi.fn(), user = userEvent.setup(); render(<Harness initial={{ ...period, provider: 'keep.example' }} changed={changed}/>);
    await replaceSearch(user, query); await user.keyboard('{Enter}');
    expect(screen.getByRole('alert')).toBeVisible(); expect(changed).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Service: keep.example' })).toBeVisible();
  },
);
it('quotes hostile metadata without interpreting it and keeps saved-view restoration authoritative', async () => {
  const changed = vi.fn(), user = userEvent.setup(); render(<Harness changed={changed}/>);
  const hostile='<img src=x onerror=alert(1)>';
  await user.type(screen.getByRole('searchbox'), 'service:'+JSON.stringify(hostile)+'{Enter}');
  expect(changed).toHaveBeenLastCalledWith({ ...period, provider: hostile, regex: ['provider'] }); expect(document.querySelector('img')).toBeNull();
  await user.clear(screen.getByRole('searchbox')); await user.type(screen.getByRole('searchbox'), 'service:pending.example');
  await user.click(screen.getByRole('button', { name: 'Restore synthetic view' }));
  expect(screen.getByRole('searchbox')).toHaveValue(''); expect(changed).toHaveBeenLastCalledWith(period);
  await user.type(screen.getByRole('searchbox'), 'service:another-draft.example');
  await user.click(screen.getByRole('button', { name: 'Restore synthetic view' }));
  expect(screen.getByRole('searchbox')).toHaveValue('');
});
it('allows removing an inherited unavailable criterion without making it available for new queries', async () => {
  const changed = vi.fn(), user = userEvent.setup(); render(<Harness initial={{ ...period, provider: 'keep.example', sensitivity: 'sensitive' }} changed={changed}/>);
  await user.click(screen.getByRole('button', { name: 'Remove Sensitivity: sensitive' }));
  expect(changed).toHaveBeenLastCalledWith({ ...period, provider: 'keep.example' });
  await replaceSearch(user, 'sensitivity:normal'); await user.keyboard('{Enter}');
  expect(screen.getByRole('alert')).toBeVisible(); expect(changed).toHaveBeenCalledTimes(1);
});

it('accepts partial device names and regex services without broadening an invalid draft', async () => {
  const changed = vi.fn(), user = userEvent.setup(); render(<Harness changed={changed}/>);
  await user.type(screen.getByRole('searchbox'), 'service:chatgpt device:^LT-COM{Enter}');
  expect(changed).toHaveBeenLastCalledWith({ ...period, provider: 'chatgpt', device_name: '^LT-COM', regex: ['provider', 'device_name'] });
  await replaceSearch(user, 'service:['); await user.keyboard('{Enter}');
  expect(screen.getByRole('alert')).toHaveTextContent('regular expression');
  expect(changed).toHaveBeenCalledTimes(1);
  expect(screen.getByRole('button', { name: 'Service: chatgpt' })).toBeVisible();
});

it('keeps counted repetitions intact when a pattern is added from the visual filter editor', async () => {
  const changed = vi.fn(), user = userEvent.setup(); render(<Harness changed={changed}/>);
  await user.type(screen.getByRole('searchbox'), 'service:chatgpt');
  await user.click(screen.getByRole('button', { name: 'Add filter' }));
  await user.click(screen.getByRole('button', { name: 'Model' }));
  await user.click(screen.getByRole('textbox', { name: 'Model' }));
  await user.paste('gpt-[0-9]{2,3}'); await user.keyboard('{Enter}');
  expect(changed).toHaveBeenLastCalledWith({ ...period, provider: 'chatgpt', model: 'gpt-[0-9]{2,3}', regex: ['provider', 'model'] });
  expect(screen.getByRole('searchbox')).toHaveValue('service:chatgpt model:gpt-[0-9]{2,3}');
});

it('applies an empty search immediately while retaining the selected period', async () => {
  const changed = vi.fn(), user = userEvent.setup();
  render(<Harness initial={{ ...period, provider: 'chatgpt', model: '^gpt', action: 'blocked', regex: ['provider', 'model'] }} changed={changed}/>);
  await user.clear(screen.getByRole('searchbox'));
  expect(changed).toHaveBeenCalledExactlyOnceWith(period);
  expect(screen.getByRole('searchbox')).toHaveValue('');
  expect(screen.queryByRole('button', { name: 'Service: chatgpt' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Model: ^gpt' })).not.toBeInTheDocument();
});

it('immediately clears an invalid draft and its applied filters without requiring Enter', async () => {
  const changed = vi.fn(), user = userEvent.setup();
  render(<Harness initial={{ ...period, provider: 'chatgpt', regex: ['provider'] }} changed={changed}/>);
  await replaceSearch(user, 'service:['); await user.keyboard('{Enter}');
  expect(screen.getByRole('alert')).toBeVisible(); expect(changed).not.toHaveBeenCalled();
  await user.clear(screen.getByRole('searchbox'));
  expect(changed).toHaveBeenCalledExactlyOnceWith(period);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});
