import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

const script = readFileSync('../deploy/theme/milvago/login/resources/js/milvago.js', 'utf8');
let media: EventTarget & { matches: boolean };
beforeEach(() => {
  localStorage.clear();
  document.cookie = 'milvago_theme=;Max-Age=0;Path=/';
  media = Object.assign(new EventTarget(), { matches: true });
  vi.stubGlobal('matchMedia', () => media);
  document.body.innerHTML = '<button data-theme-toggle data-label-dark="Dark" data-label-light="Light"></button>';
});
afterEach(() => { document.body.innerHTML = ''; vi.unstubAllGlobals(); });
function initialize() {
  new Function(script)();
  document.dispatchEvent(new Event('DOMContentLoaded'));
}

it('applies and follows the identity page system theme without storing a choice', () => {
  initialize();
  expect(document.documentElement.dataset.theme).toBe('light');
  expect(localStorage.getItem('milvago.theme')).toBeNull();
  media.matches = false;
  media.dispatchEvent(new Event('change'));
  expect(document.documentElement.dataset.theme).toBe('dark');
  expect(document.querySelector('button')?.getAttribute('aria-label')).toBe('Light');
});

it('keeps an explicit identity-page choice when the system subsequently changes', () => {
  initialize();
  document.querySelector('button')!.click();
  expect(document.documentElement.dataset.theme).toBe('dark');
  expect(document.cookie).toContain('milvago_theme=dark');
  expect(localStorage.getItem('milvago.theme')).toBe('dark');
  media.dispatchEvent(new Event('change'));
  expect(document.documentElement.dataset.theme).toBe('dark');
});

it('ignores non-theme storage and prioritizes the validated shared cookie', () => {
  localStorage.setItem('milvago.theme', 'image/png');
  initialize();
  expect(document.documentElement.dataset.theme).toBe('light');
  document.cookie = 'milvago_theme=dark;Path=/';
  initialize();
  expect(document.documentElement.dataset.theme).toBe('dark');
});
