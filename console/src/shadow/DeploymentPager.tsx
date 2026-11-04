import { useEffect, useState } from 'react';
import { useText } from '../ui';

// Only the visible page is fetched. A scope change starts from its first page.
export function useDeploymentPage(scope = '') {
  const t = useText();
  const [state, setState] = useState({ scope, cursors: [''] });
  useEffect(() => {
    const reset = () => setState({ scope, cursors: [''] });
    reset();
    window.addEventListener('milvago:privacy-changed', reset);
    return () => window.removeEventListener('milvago:privacy-changed', reset);
  }, [scope]);
  const cursors = state.scope === scope ? state.cursors : [''];
  const after = cursors[cursors.length - 1];
  function pager(next?: string) {
    if (cursors.length === 1 && !next) return null;
    return <nav className="pagination" aria-label={t('page')}>
      <button type="button" className="button secondary small" disabled={cursors.length === 1} onClick={() => setState({ scope, cursors: cursors.slice(0, -1) })}>{t('previous')}</button>
      <span>{t('page')} {cursors.length}</span>
      <button type="button" className="button secondary small" disabled={!next} onClick={() => next && setState({ scope, cursors: [...cursors, next] })}>{t('next')}</button>
    </nav>;
  }
  return { after, pager };
}
