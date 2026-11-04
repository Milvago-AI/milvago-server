import './ObjectDrawer.css';
import { createContext, useContext, useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { Dialog, useText } from './ui';

const CloseContext=createContext<(()=>void)|null>(null);
export function ObjectDrawerClose(){const close=useContext(CloseContext);const t=useText();return <button className="button secondary" type="button" onClick={()=>close?.()}>{t('close')}</button>;}

/** Object creation/editing uses the same drawer, focus handling and discard flow. */
export function ObjectDrawer({ title, children, dirty, close }: Readonly<{ title: string; children: ReactNode; dirty: boolean; close: () => void }>) {
  const t = useText();
  const [ready, setReady] = useState(false);
  const [discard, setDiscard] = useState(false);
  useEffect(() => {
    const frame = requestAnimationFrame(() => setReady(true));
    return () => cancelAnimationFrame(frame);
  }, []);
  const requestClose = () => dirty ? setDiscard(true) : close();
  return <>
    <Dialog side="right" title={title} close={requestClose}>
      <div className="object-drawer" aria-busy={!ready}>
        {ready ? <CloseContext.Provider value={requestClose}>{children}</CloseContext.Provider> : <div className="object-drawer-skeleton" role="status" aria-label={t('objectLoading')}><span /><span /><span /><span /></div>}
      </div>
    </Dialog>
    {discard && <Dialog title={t('objectDiscardChanges')} close={() => setDiscard(false)}><div className="dialog-body"><p>{t('objectUnsaved')}</p><div className="dialog-actions"><button className="button secondary" type="button" onClick={() => setDiscard(false)}>{t('objectKeepEditing')}</button><button className="button danger" type="button" onClick={close}>{t('objectDiscardAndClose')}</button></div></div></Dialog>}
  </>;
}
