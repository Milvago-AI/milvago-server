import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { Context } from '../ui';
import type { Session } from '../api';
import { ClassificationPanel } from './ConfigurationPanels';
import type { ShadowConfig } from './types';

// Fourth review, M6: the engine always keeps the keyword label, so selecting "keyword" for a
// usage sensitivity changed nothing. It is no longer offered.
describe('ClassificationPanel', () => {
  it('does not offer keywords as a classification choice', () => {
    const config = { classification: { browser: ['iban'], coding: [], medical_terms: [] } } as unknown as ShadowConfig;
    render(<Context.Provider value={{ session: {} as Session, language: 'en', refreshSession: async () => {} }}><ClassificationPanel config={config} update={() => {}} /></Context.Provider>);
    expect(screen.getAllByText('IBAN').length).toBe(2);
    expect(screen.queryByText('Keywords')).toBeNull();
  });
});
