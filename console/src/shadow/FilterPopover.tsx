import { useEffect, useId, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Icon } from '../ui';

/** Non-modal controls keep the results available while closing on focus departure. */
export function FilterPopover({ label, children, align = 'start', onOpen, requestOpen = 0 }: Readonly<{
  label: string; children: (close: () => void) => ReactNode; align?: 'start' | 'end'; onOpen?: () => void; requestOpen?: number;
}>) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null), trigger = useRef<HTMLButtonElement>(null), id = useId();
  const restore = useRef<HTMLElement | null>(null);
  function close() { setOpen(false); (restore.current?.isConnected ? restore.current : trigger.current)?.focus(); }
  useEffect(() => {
    if (requestOpen > 0) { restore.current = document.activeElement instanceof HTMLElement ? document.activeElement : null; setOpen(true); }
  }, [requestOpen]);
  useEffect(() => {
    if (!open) return;
    const outside = (event: Event) => { if (event.target instanceof Node && !ref.current?.contains(event.target)) setOpen(false); };
    const escape = (event: KeyboardEvent) => { if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); close(); } };
    document.addEventListener('pointerdown', outside); document.addEventListener('focusin', outside); document.addEventListener('keydown', escape);
    return () => { document.removeEventListener('pointerdown', outside); document.removeEventListener('focusin', outside); document.removeEventListener('keydown', escape); };
  }, [open]);
  return <div className={'event-popover align-' + align} ref={ref}>
    <button ref={trigger} type="button" className="button secondary" aria-expanded={open} aria-controls={open ? id : undefined}
      onClick={() => { restore.current = trigger.current; if (!open) onOpen?.(); setOpen(!open); }}>{label}<Icon name="chevron" size={13}/></button>
    {open && <section id={id} className="event-popover-panel" role="region" aria-label={label}>{children(close)}</section>}
  </div>;
}
