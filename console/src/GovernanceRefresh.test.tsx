import { useLayoutEffect, useRef } from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { useGovernanceRefresh } from './AIGovernance';
import { useResource } from './ui';

function Assessment() {
  const resource = useResource<{ status: string }>('/api/ai-governance/effective');
  useGovernanceRefresh(resource.data, resource.reload);
  const focused = useRef(false);
  // A return-to-window event can arrive as the new data is painted, before
  // passive effects associated with that answer have been installed.
  useLayoutEffect(() => {
    if (resource.data && !focused.current) {
      focused.current = true;
      window.dispatchEvent(new Event('focus'));
    }
  }, [resource.data]);
  return <p>{resource.data?.status ?? 'loading'}</p>;
}

it('revalidates a focus arriving with the first answer and releases listeners on exit', async () => {
  vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
  let reads = 0;
  const fetch = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(JSON.stringify({ status: ++reads === 1 ? 'previous authorization' : 'expired authorization' })));
  const view = render(<Assessment />);
  await waitFor(() => expect(fetch).toHaveBeenCalledTimes(2));
  await screen.findByText('expired authorization');
  expect(fetch).toHaveBeenCalledTimes(2);
  view.unmount();
  fireEvent(window, new Event('focus'));
  expect(fetch).toHaveBeenCalledTimes(2);
});
