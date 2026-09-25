import '@testing-library/jest-dom/vitest';
import { afterEach, beforeEach } from 'vitest';
import { cleanup, configure } from '@testing-library/react';
afterEach(cleanup);
// findBy*/waitFor wait 1 s by default, too short when the image build loads the host.
configure({ asyncUtilTimeout: 5_000 });

/**
 * The languages this browser asks for, as a reader configured them.
 *
 * An account set to "Default" now follows the browser and then English (user
 * decision, 2026-09-17), so the language a test renders in is a property of its
 * simulated reader. jsdom asks for English, which would flip the French
 * expectations this suite is written in; the baseline reader below speaks
 * French, and the language tests call this to speak something else.
 */
export function speaks(...tags: string[]) {
  Object.defineProperty(navigator, 'languages', { configurable: true, value: tags });
  Object.defineProperty(navigator, 'language', { configurable: true, value: tags[0] ?? '' });
}
beforeEach(() => speaks('fr-FR', 'fr'));
