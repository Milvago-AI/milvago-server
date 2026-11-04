import { act, fireEvent, render, screen } from '@testing-library/react';
import { readFileSync } from 'node:fs';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { useTheme } from './useTheme';

afterEach(() => vi.unstubAllGlobals());

function Reader() {
  const [theme, choose] = useTheme();
  return <button onClick={() => choose(theme === 'light' ? 'dark' : 'light')}>{theme}</button>;
}
let media: EventTarget & { matches: boolean };
beforeEach(() => {
  localStorage.clear();
  document.cookie = 'milvago_theme=;Max-Age=0;Path=/';
  delete document.documentElement.dataset.theme;
  media = Object.assign(new EventTarget(), { matches: true });
  vi.stubGlobal('matchMedia', vi.fn(() => media));
});

it('follows live system changes without turning them into a stored choice', () => {
  const reader = render(<Reader />);
  expect(screen.getByRole('button')).toHaveTextContent('light');
  expect(document.documentElement.dataset.theme).toBe('light');
  expect(localStorage.getItem('milvago.theme')).toBeNull();
  expect(document.cookie).not.toContain('milvago_theme=');
  media.matches = false;
  act(() => { media.dispatchEvent(new Event('change')); });
  expect(screen.getByRole('button')).toHaveTextContent('dark');
  fireEvent.click(screen.getByRole('button'));
  expect(localStorage.getItem('milvago.theme')).toBe('light');
  expect(document.cookie).toContain('milvago_theme=light');
  act(() => { media.dispatchEvent(new Event('change')); });
  expect(screen.getByRole('button')).toHaveTextContent('light');
  reader.unmount();
  expect(() => media.dispatchEvent(new Event('change'))).not.toThrow();
});

it('prioritizes the shared identity cookie and rejects malformed storage values', () => {
  localStorage.setItem('milvago.theme', '<img src=x onerror=alert(1)>');
  document.cookie = 'milvago_theme=dark;Path=/';
  render(<Reader />);
  expect(document.documentElement.dataset.theme).toBe('dark');
  act(() => { media.dispatchEvent(new Event('change')); });
  expect(screen.getByRole('button')).toHaveTextContent('dark');
});

it('works with denied storage and remembers the choice for this screen', () => {
  vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new DOMException('Denied', 'SecurityError'); });
  vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new DOMException('Denied', 'SecurityError'); });
  render(<Reader />);
  fireEvent.click(screen.getByRole('button'));
  expect(document.documentElement.dataset.theme).toBe('dark');
  act(() => { media.dispatchEvent(new Event('change')); });
  expect(screen.getByRole('button')).toHaveTextContent('dark');
});

it('applies the same validated choice in the blocking head script before React', () => {
  const bootstrap = readFileSync('public/theme.js', 'utf8');
  const html = readFileSync('index.html', 'utf8');
  expect(html.indexOf('<script src="/theme.js"></script>')).toBeLessThan(html.indexOf('</head>'));
  for (const [cookie, stored, expected] of [
    ['', '', 'light'], ['', 'dark', 'dark'], ['light', 'dark', 'light'], ['', 'image/png', 'light'],
  ]) {
    document.cookie = 'milvago_theme=;Max-Age=0;Path=/';
    if (cookie) document.cookie = `milvago_theme=${cookie};Path=/`;
    localStorage.setItem('milvago.theme', stored);
    new Function(bootstrap)();
    expect(document.documentElement.dataset.theme).toBe(expected);
  }
  vi.stubGlobal('matchMedia', undefined);
  document.cookie = 'milvago_theme=;Max-Age=0;Path=/';
  localStorage.clear();
  new Function(bootstrap)();
  expect(document.documentElement.dataset.theme).toBe('dark');
});
