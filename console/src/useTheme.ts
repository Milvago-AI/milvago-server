import { useLayoutEffect, useRef, useState } from 'react';

type Theme = 'light' | 'dark';
const valid = (value: string | null | undefined): value is Theme => value === 'light' || value === 'dark';

function preference(): Theme | undefined {
  try {
    const cookie = document.cookie.split(';').map(value => value.trim()).find(value => /^milvago_theme=(light|dark)$/.test(value));
    if (cookie) return cookie.split('=')[1] as Theme;
  } catch { /* Storage is optional in restricted browsers. */ }
  try {
    const value = localStorage.getItem('milvago.theme');
    if (valid(value)) return value;
  } catch { /* Follow the system until the reader chooses. */ }
  return undefined;
}

function systemTheme(): Theme {
  return typeof window.matchMedia === 'function' && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

function apply(theme: Theme) {
  document.documentElement.dataset.theme = theme;
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', theme === 'light' ? '#F3F6FA' : '#111722');
}

export function useTheme(): readonly [Theme, (theme: Theme) => void] {
  const choice = useRef(preference());
  const [theme, setTheme] = useState<Theme>(() => choice.current ?? systemTheme());
  useLayoutEffect(() => { apply(theme); }, [theme]);
  useLayoutEffect(() => {
    const media = typeof window.matchMedia === 'function' ? window.matchMedia('(prefers-color-scheme: light)') : undefined;
    const sync = () => { if (!choice.current) setTheme(media?.matches ? 'light' : 'dark'); };
    const storage = (event: StorageEvent) => {
      if (event.key !== 'milvago.theme' && event.key !== null) return;
      choice.current = preference();
      setTheme(choice.current ?? systemTheme());
    };
    media?.addEventListener?.('change', sync);
    window.addEventListener('storage', storage);
    sync();
    return () => {
      media?.removeEventListener?.('change', sync);
      window.removeEventListener('storage', storage);
    };
  }, []);
  function choose(next: Theme) {
    if (!valid(next)) return;
    choice.current = next;
    apply(next);
    setTheme(next);
    try { localStorage.setItem('milvago.theme', next); } catch { /* Keep the in-memory choice. */ }
    try { document.cookie = `milvago_theme=${next};Path=/;SameSite=Lax${location.protocol === 'https:' ? ';Secure' : ''}`; } catch { /* Keep the in-memory choice. */ }
  }
  return [theme, choose];
}
