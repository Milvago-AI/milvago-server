import { useEffect, useState } from 'react';

function requestedArea<T extends string>(allowed: readonly string[], fallback: T, enabled: boolean): T {
  const [page, query] = window.location.hash.split('?');
  const value = new URLSearchParams(query ?? '').get('area');
  if(enabled&&page==='#shadow'&&['protection','privacy','classification'].includes(value||'')) {queueMicrotask(()=>{window.location.hash='#dlp';});return fallback;}
  return enabled && page === '#shadow' && value && allowed.includes(value) ? value as T : fallback;
}

export function useShadowArea<T extends string>(areas: readonly T[], fallback: T, enabled: boolean) {
  const [area, setArea] = useState<T>(() => requestedArea(areas, fallback, enabled));
  // Capabilities rebuild the array on each render; only changes to its values matter.
  const allowed = areas.join(',');
  useEffect(() => {
    const changed = (event?: HashChangeEvent) => {
      if (event && (window.location.hash.split('?')[0] !== '#shadow' || (event.newURL && event.newURL !== window.location.href))) return;
      setArea(requestedArea(allowed.split(','), fallback, enabled));
    };
    setArea(current => allowed.split(',').includes(current) ? current : fallback);
    window.addEventListener('hashchange', changed);
    return () => window.removeEventListener('hashchange', changed);
  }, [allowed, fallback, enabled]);
  return [area, setArea] as const;
}
