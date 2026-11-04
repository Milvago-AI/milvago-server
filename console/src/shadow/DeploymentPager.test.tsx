import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { Context, ResourceView, useResource } from '../ui';
import type { Session } from '../api';
import { useDeploymentPage } from './DeploymentPager';

const session: Session = { user: { id: 'user-1', email: 'admin@example.test', display_name: 'Synthetic admin' }, organization: { id: 'org-1', name: 'Synthetic organization', role: 'owner' }, organizations: [], permissions: [], csrf_token: 'synthetic', edition: 'community' };
function Deployment({ scope }: Readonly<{ scope: string }>) {
  const { after, pager } = useDeploymentPage(scope);
  const resource = useResource<{ items: string[]; next?: string }>(`/api/deployment-test?scope=${scope}${after ? '&after=' + encodeURIComponent(after) : ''}`);
  return <ResourceView resource={resource}>{data => <>{data.items.map(item => <p key={item}>{item}</p>)}{pager(data.next)}</>}</ResourceView>;
}
function view(scope: string) { return <Context.Provider value={{ session, language: 'fr', refreshSession: async () => {} }}><Deployment scope={scope} /></Context.Provider>; }

it('fetches only the visible page and follows a continuation even after an empty page', async () => {
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async input => new Response(JSON.stringify(String(input).includes('after=') ? { items: ['Last device'] } : { items: [], next: 'next-device' })));
  render(view('fleet'));
  await screen.findByRole('button', { name: 'Suivant' });
  expect(fetch).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole('button', { name: 'Suivant' }));
  await screen.findByText('Last device');
  expect(fetch).toHaveBeenCalledTimes(2);
  expect(fetch.mock.calls[1][0]).toBe('/api/deployment-test?scope=fleet&after=next-device');
  expect(screen.getByRole('button', { name: 'Suivant' })).toBeDisabled();
  fireEvent.click(screen.getByRole('button', { name: 'Précédent' }));
  await waitFor(() => expect(fetch).toHaveBeenCalledTimes(3));
  expect(fetch.mock.calls[2][0]).toBe('/api/deployment-test?scope=fleet');
});

it('resets continuations after scope or privacy changes', async () => {
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async input => new Response(JSON.stringify({ items: [String(input)], next: 'next-device' })));
  const page = render(view('first'));
  fireEvent.click(await screen.findByRole('button', { name: 'Suivant' }));
  await screen.findByText('/api/deployment-test?scope=first&after=next-device');
  page.rerender(view('second'));
  await screen.findByText('/api/deployment-test?scope=second');
  page.rerender(view('first'));
  await screen.findByText('/api/deployment-test?scope=first');
  fireEvent.click(screen.getByRole('button', { name: 'Suivant' }));
  await screen.findByText('/api/deployment-test?scope=first&after=next-device');
  window.dispatchEvent(new Event('milvago:privacy-changed'));
  await screen.findByText('/api/deployment-test?scope=first');
  expect(fetch.mock.calls.at(-1)?.[0]).toBe('/api/deployment-test?scope=first');
});
