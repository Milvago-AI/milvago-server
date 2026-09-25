import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { Context } from '../ui';
import type { Session } from '../api';
import { CapturePanel } from './ConfigurationPanels';
import type { ShadowConfig } from './types';

const session = { user: { id: 'user-1', email: 'owner@example.org', display_name: 'Test owner' }, organization: { id: 'org-1', name: 'Test organization', role: 'owner' } } as unknown as Session;

function panel(enrollment: ShadowConfig['enrollment']) {
  const update = vi.fn();
  const config = { enrollment, collection: { enabled: true, store_content: false, store_file_names: true, content_retention_days: 7 } } as unknown as ShadowConfig;
  render(<Context.Provider value={{ language: 'en', session, refreshSession: async () => {} }}><CapturePanel config={config} update={update} device={false} /></Context.Provider>);
  return update;
}

describe('device approval rules', () => {
  it('shows older networks as domainless rules and saves everything as rules', () => {
    const update = panel({ approval: 'network', cidrs: ['10.20.0.0/16'], rules: [{ cidr: '192.0.2.0/24', domain: 'corp.example.com' }] });
    const networks = screen.getAllByLabelText('Network (CIDR)') as HTMLInputElement[];
    expect(networks.map(input => input.value)).toEqual(['10.20.0.0/16', '192.0.2.0/24']);
    expect((screen.getAllByLabelText('Machine domain (optional)') as HTMLInputElement[]).map(input => input.value)).toEqual(['', 'corp.example.com']);
    // The warning that a domain proves nothing is always in view.
    expect(screen.getByText(/declared by the machine/)).toBeTruthy();
    fireEvent.change(screen.getAllByLabelText('Machine domain (optional)')[0], { target: { value: 'lab.example.com' } });
    expect(update).toHaveBeenLastCalledWith('enrollment', { approval: 'network', cidrs: [], rules: [{ cidr: '10.20.0.0/16', domain: 'lab.example.com' }, { cidr: '192.0.2.0/24', domain: 'corp.example.com' }] });
  });

  it('adds and deletes rules, and a rule cannot be left without its network', () => {
    const update = panel({ approval: 'network', cidrs: [], rules: [{ cidr: '192.0.2.0/24', domain: '' }] });
    fireEvent.click(screen.getByRole('button', { name: /Add rule/ }));
    expect(update).toHaveBeenLastCalledWith('enrollment', { approval: 'network', cidrs: [], rules: [{ cidr: '192.0.2.0/24', domain: '' }, { cidr: '', domain: '' }] });
    fireEvent.click(screen.getByRole('button', { name: 'Delete rule 1' }));
    expect(update).toHaveBeenLastCalledWith('enrollment', { approval: 'network', cidrs: [], rules: [] });
    expect((screen.getByLabelText('Network (CIDR)') as HTMLInputElement).required).toBe(true);
  });
});
