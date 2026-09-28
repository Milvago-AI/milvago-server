import { Fragment, createContext, useContext, useEffect, useId, useRef, useState } from 'react';
import type { ButtonHTMLAttributes, ReactNode } from 'react';
import {
  Activity, AppWindow, ArrowRight, Building2, Check, ChevronDown, ChevronRight, Copy, CornerDownRight, Download, Eye, File, FileArchive, FileSpreadsheet, FileText, Filter, GitFork, Globe, Image, Info, LayoutDashboard, List, Lock, LogOut, Menu, Monitor, Moon, PanelLeftClose, PanelLeftOpen, Plus, RefreshCw, ScrollText, Search, Settings, ShieldCheck, Sun, Trash2, TriangleAlert, Users, X,
} from 'lucide-react';
import { ApiError, request } from './api';
import type { Session } from './api';
import { secondFactorRequired, requestSecondFactor } from './secondFactor';
import { languages as languageOptions } from './locales/languages';
import type { Language } from './locales/languages';
import { en } from './locales/en';
import type { TranslationKey } from './locales/en';
import { fr } from './locales/fr';
import { es } from './locales/es';
import { ptBR } from './locales/pt-BR';

export { languages, isLanguage, browserLanguage } from "./locales/languages";
export type { Language } from "./locales/languages";

const catalogs: Record<Language, Record<TranslationKey, string>> = { fr, en, es, 'pt-BR': ptBR };

export type Translate = (key: TranslationKey, params?: (string | number)[]) => string;

export const Context = createContext<{ language: Language; session: Session; refreshSession: () => Promise<void> }>(null!);

/**
 * Every visible string is a key into the catalogues in src/locales. English is
 * the source of truth for the key set and the last-resort fallback: the other
 * catalogues are typed as Record<TranslationKey, string>, so a missing key is a
 * compilation error rather than a blank in the interface, and the fallback only
 * ever fires for a catalogue loaded at runtime out of step with the build.
 *
 * Placeholders are {0}, {1}… so a translation may reorder the values it is given,
 * which several languages need and positional concatenation would forbid.
 */
export function translate(language: Language, key: TranslationKey, params?: (string | number)[]): string {
  const text = catalogs[language][key] ?? en[key];
  if (!params) return text;
  return text.replace(/\{(\d+)\}/g, (match, index) => { const value = params[Number(index)]; return value === undefined ? match : String(value); });
}

/** The same lookup bound to the language in context. App holds the language in
 * state before the provider exists, so it calls translate() directly. */
export function useText(): Translate {
  const { language } = useContext(Context);
  return (key, params) => translate(language, key, params);
}

/**
 * The language chooser of the signed-out page. Signed in, the language is an
 * account setting changed from the profile form, and the sidebar deliberately
 * offers no shortcut for it (product decision, 2026-09-11). A two-state toggle was
 * fine while there were two languages; with four, a control that only says what
 * it will switch *to* stops being readable, so this states the current choice
 * and offers the others by name.
 *
 * It calls translate() rather than useText(): the signed-out page renders this
 * control outside the Context provider, where the hook would have nothing to
 * read.
 */
export function LanguagePicker({ language, choose }: Readonly<{ language: Language; choose: (next: Language) => void }>) {
  return (
    <select
      className="language-picker"
      aria-label={translate(language, 'languageLabel')}
      value={language}
      onChange={event => choose(event.target.value as Language)}
    >
      {languageOptions.map(option => <option key={option.code} value={option.code}>{option.label}</option>)}
    </select>
  );
}

export function useResource<T>(path: string) {
  const [data, setData] = useState<T>(); const [error, setError] = useState<unknown>(); const [loading, setLoading] = useState(true); const [version, setVersion] = useState(0);
  useEffect(() => {
    const controller = new AbortController(); setLoading(true); setError(undefined); setData(undefined);
    request<T>(path, { signal: controller.signal }).then(value => { if (!controller.signal.aborted) setData(value); }).catch(e => { if (!controller.signal.aborted) setError(e); }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [path, version]);
  useEffect(() => {
    // Discard visible personal data before revalidation, including an expired
    // grant when a sleeping tab wakes. Never preserve it behind a loading state.
    const invalidate = () => { setData(undefined); setLoading(true); setVersion(v => v + 1); };
    const deadlines: number[] = [];
    const visit = (value: unknown) => {
      if (!value || typeof value !== 'object') return;
      const record = value as Record<string, unknown>;
      if (typeof record.identity_expires_at === 'string') {
        const deadline = Date.parse(record.identity_expires_at);
        if (Number.isFinite(deadline)) deadlines.push(deadline);
      }
      Object.values(record).forEach(visit);
    };
    visit(data);
    const timer = deadlines.length ? window.setTimeout(invalidate, Math.max(0, Math.min(2147483647, Math.min(...deadlines) - Date.now()))) : undefined;
    const poll = deadlines.length ? window.setInterval(invalidate, 30000) : undefined;
    const visible = () => { if (document.visibilityState === 'visible') invalidate(); };
    window.addEventListener('milvago:privacy-changed', invalidate);
    if (deadlines.length) { window.addEventListener('focus', invalidate); document.addEventListener('visibilitychange', visible); }
    return () => { clearTimeout(timer); clearInterval(poll); window.removeEventListener('milvago:privacy-changed', invalidate); window.removeEventListener('focus', invalidate); document.removeEventListener('visibilitychange', visible); };
  }, [data]);
  return { data, error, loading, reload: () => { setData(undefined); setLoading(true); setVersion(v => v + 1); } };
}
export function useMutation() {
  const { session, language } = useContext(Context); const [pending, setPending] = useState(false); const [error, setError] = useState<unknown>();
  async function run<T>(path: string, method: string, body?: unknown): Promise<T | undefined> {
    // Every write in this console goes through here, so a demonstration instance is
    // stopped once, at the only place that cannot be forgotten. The screens hide
    // their own save controls as well, but that is cosmetics: a control reached by
    // another route -- a keyboard submit, a stale render, a component added later --
    // still ends here. The server refuses the request anyway; refusing it locally
    // means the visitor gets a plain explanation instead of a raw 403.
    if (session.demo_read_only) {
      const refusal = new ApiError(403, 'demo_read_only', 'This demonstration instance is read-only.');
      setError(refusal);
      throw refusal;
    }
    setPending(true); setError(undefined);
    try { return await request<T>(path, { method, body, csrf: session.csrf_token }); }
    // Hold the refused action in memory until the person confirms the second-factor
    // dialog. Callers still receive the refusal so they keep their unsaved draft.
    catch (e) { setError(e); requestSecondFactor(path, method, body, e, language, { org: session.organization.id, user: session.user.id }); throw e; }
    finally { setPending(false); }
  }
  return { run, pending, error, clear: () => setError(undefined) };
}

/* ---------- Icons (lucide-react, bundled, no network) ---------- */
export type IconName = 'arrow' | 'refresh' | 'sun' | 'moon' | 'plus' | 'close' | 'check' | 'shield' | 'device' | 'activity' | 'dashboard' | 'map' | 'list' | 'apps' | 'settings' | 'users' | 'scroll' | 'building' | 'logout' | 'menu' | 'panel-close' | 'panel-open' | 'info' | 'alert' | 'search' | 'download' | 'trash' | 'lock' | 'eye' | 'filter' | 'globe' | 'chevron' | 'chevron-right' | 'corner' | 'copy' | 'file' | 'file-image' | 'file-text' | 'file-sheet' | 'file-archive';
const icons = { arrow: ArrowRight, refresh: RefreshCw, sun: Sun, moon: Moon, plus: Plus, close: X, check: Check, shield: ShieldCheck, device: Monitor, activity: Activity, dashboard: LayoutDashboard, map: GitFork, list: List, apps: AppWindow, settings: Settings, users: Users, scroll: ScrollText, building: Building2, logout: LogOut, menu: Menu, 'panel-close': PanelLeftClose, 'panel-open': PanelLeftOpen, info: Info, alert: TriangleAlert, search: Search, download: Download, trash: Trash2, lock: Lock, eye: Eye, filter: Filter, globe: Globe, chevron: ChevronDown, 'chevron-right': ChevronRight, corner: CornerDownRight, copy: Copy, file: File, 'file-image': Image, 'file-text': FileText, 'file-sheet': FileSpreadsheet, 'file-archive': FileArchive };
export function Icon({ name, size = 16 }: Readonly<{ name: IconName; size?: number }>) { const Component = icons[name]; return <Component size={size} strokeWidth={1.75} aria-hidden="true" />; }

/* ---------- Primitives ---------- */
type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'secondary' | 'ghost' | 'danger'; size?: 'default' | 'small'; icon?: IconName };
export function Button({ variant = 'secondary', size = 'default', icon, className = '', children, type = 'button', ...rest }: ButtonProps) {
  const classes = ['button', variant];
  if (size === 'small') classes.push('small');
  if (className) classes.push(className);
  return <button type={type} className={classes.join(' ')} {...rest}>{icon && <Icon name={icon} />}{children}</button>;
}
export function Card({ title, description, actions, footer, flush, className = '', children }: Readonly<{ title?: ReactNode; description?: ReactNode; actions?: ReactNode; footer?: ReactNode; flush?: boolean; className?: string; children?: ReactNode }>) {
  return <section className={className ? `card ${className}` : 'card'}>{(title || actions) && <div className="card-head"><div>{title && <h2 className="card-title">{title}</h2>}{description && <p className="card-desc">{description}</p>}</div>{actions && <div className="actions">{actions}</div>}</div>}{flush ? children : <div className="card-body">{children}</div>}{footer && <div className="card-foot">{footer}</div>}</section>;
}
export function Kpi({ label, value, hint, tone, icon }: Readonly<{ label: ReactNode; value: ReactNode; hint?: ReactNode; tone?: 'danger' | 'warning' | 'success'; icon?: IconName }>) {
  return <article className="kpi"><span className="kpi-label"><span>{label}</span>{icon && <Icon name={icon} />}</span><span className={tone ? `kpi-value tone-${tone}` : 'kpi-value'}>{value}</span>{hint && <span className="kpi-hint">{hint}</span>}</article>;
}
export function Badge({ tone = 'neutral', dot, children }: Readonly<{ tone?: 'neutral' | 'success' | 'warning' | 'danger'; dot?: boolean; children: ReactNode }>) { return <span className={`badge badge-${tone}${dot ? ' badge-dot' : ''}`}>{children}</span>; }
export function Tabs({ items, selected, onSelect, label }: Readonly<{ items: { id: string; name: ReactNode }[]; selected: string; onSelect: (id: string) => void; label: string }>) {
  return <fieldset className="tabs" aria-label={label}>{items.map(item => <button key={item.id} type="button" className={`tab${selected === item.id ? ' active' : ''}`} aria-pressed={selected === item.id} onClick={() => onSelect(item.id)}>{item.name}</button>)}</fieldset>;
}
/** How many rows a page holds. Offered above the table it governs. */
export const PAGE_SIZES = [10, 20, 50, 100, 200];
/** Keep a numbered page inside the range the result set actually exposes. */
export function clampPage(page: number, pages: number) { return Math.max(1, Math.min(page, pages)); }
export function PageSize({ value, change, label }: Readonly<{ value: number; change: (size: number) => void; label: string }>) {
  return <fieldset className="segment" aria-label={label}>{PAGE_SIZES.map(size => <button key={size} type="button" aria-pressed={value === size} onClick={() => change(size)}>{size}</button>)}</fieldset>;
}
/**
 * Numbered pages under a table. The first and the last are always reachable, with the
 * current page and its neighbours in between and an ellipsis over what is skipped, so a
 * long list stays one click from either end without printing a thousand buttons.
 */
export function PageNumbers({ page, pages, go, label }: Readonly<{ page: number; pages: number; go: (page: number) => void; label: string }>) {
  const t = useText();
  if (pages < 2) return null;
  const shown = [...new Set([1, 2, page - 1, page, page + 1, pages - 1, pages])].filter(value => value >= 1 && value <= pages).sort((a, b) => a - b);
  return <nav className="pager" aria-label={label}>
    <button type="button" className="button secondary small" disabled={page <= 1} onClick={() => go(page - 1)}>{t('previous')}</button>
    {shown.map((value, index) => <Fragment key={value}>
      {index > 0 && value - shown[index - 1]! > 1 && <span className="pager-gap" aria-hidden="true">…</span>}
      <button type="button" className={`pager-page${value === page ? ' active' : ''}`} aria-current={value === page ? 'page' : undefined} onClick={() => go(value)}>{value}</button>
    </Fragment>)}
    <button type="button" className="button secondary small" disabled={page >= pages} onClick={() => go(page + 1)}>{t('next')}</button>
  </nav>;
}
/** Bounds a server-paged `page` to the range a resource's `total` (or its
 * item count) actually supports, and pushes the clamped value back through
 * `setPage` when the caller is holding a page number the data no longer has —
 * a filter narrowing the result set, a reload landing on fewer rows. Before
 * `total` is known (the resource is still loading), `page` is returned as-is
 * and `pages` mirrors it, since there is nothing yet to clamp against. */
export function useBoundedPage(page: number, setPage: (page: number) => void, size: number, total?: number) {
  const pages = total === undefined ? Math.max(1, page) : Math.max(1, Math.ceil(total / size));
  const current = total === undefined ? page : clampPage(page, pages);
  useEffect(() => {
    if (total !== undefined && current !== page) setPage(current);
  }, [current, page, setPage, total]);
  return { current, pages };
}
export function Field({ label, help, children, className = '' }: Readonly<{ label: ReactNode; help?: ReactNode; children: ReactNode; className?: string }>) {
  return <div className={className ? `field ${className}` : 'field'}><label><span className="label">{label}</span>{children}</label>{help && <span className="help">{help}</span>}</div>;
}
const noticeIcons: Partial<Record<string, IconName>> = { success: 'check', neutral: 'info' };
export function Notice({ tone = 'neutral', title, action, role, children }: Readonly<{ tone?: 'neutral' | 'success' | 'warning' | 'danger'; title?: ReactNode; action?: ReactNode; role?: 'alert' | 'status'; children?: ReactNode }>) {
  const icon: IconName = noticeIcons[tone] ?? 'alert';
  return <div className={tone === 'neutral' ? 'notice' : `notice notice-${tone}`} role={role ?? (tone === 'danger' ? 'alert' : 'status')}><Icon name={icon} /><div>{title && <strong>{title}</strong>}{children && <p>{children}</p>}</div>{action}</div>;
}
export function PageBar({ title, actions, info }: Readonly<{ title: ReactNode; actions?: ReactNode; info?: ReactNode }>) {
  return <><div className="pagebar"><h1 className="page-title">{title}</h1>{actions && <div className="actions">{actions}</div>}</div>{info && <div className="info-line"><Icon name="info" /><span>{info}</span></div>}</>;
}
export function Empty({ title, action, children }: Readonly<{ title: string; action?: ReactNode; children?: ReactNode }>) { return <div className="empty"><span className="empty-symbol"><Icon name="activity" size={20} /></span><h3>{title}</h3>{children && <p>{children}</p>}{action}</div>; }
// The title of an error, guard by guard rather than nested ternaries.
// The cases are the same as before, in the same order: an access refusal, a
// revision or action conflict, and everything else.
function errorTitle(error: unknown, t: Translate) {
  if (!(error instanceof ApiError)) return t("requestFailed");
  if (error.status === 403) return t("accessDenied");
  if (error.status !== 409) return t("requestFailed");
  return error.code === 'revision_conflict' ? t("aNewerChangeExists") : t("actionUnavailable");
}
// Server error codes translated in place of the server's own English sentence.
// Licence codes can surface from many mutations (roles, invitations, directory,
// device enrollment, the licence forms themselves), always through this one
// component, so extending this map is enough to translate all of them at once.
const knownErrorMessages: Partial<Record<string, TranslationKey>> = {
  license_restricted: "licenseErrorRestricted",
  license_required: "licenseErrorRequired",
  license_invalid: "licenseErrorInvalid",
  license_community_on_enterprise: "licenseErrorCommunityOnEnterprise",
  license_request_failed: "licenseErrorRequestFailed",
  device_limit_reached: "licenseErrorDeviceLimitReached",
  smtp_recipient_unknown: "smtpRecipientUnknown",
};
export function ErrorNotice({ error, retry }: Readonly<{ error: unknown; retry?: () => void }>) {
  const t = useText(); if (!error) return null;
  // The shared dialog explains the verification step; never flash a second notice
  // underneath it or expose the server's raw refusal sentence.
  if (secondFactorRequired(error)) return null;
  const knownKey = error instanceof ApiError ? knownErrorMessages[error.code] : undefined;
  let text = t("cannotReachTheServerCheckYour");
  if (error instanceof ApiError) text = error.message;
  if (knownKey) text = t(knownKey);
  return <div className="notice error" role="alert"><Icon name="alert" /><div><strong>{errorTitle(error, t)}</strong><p>{text}</p></div>{retry && <button type="button" className="button secondary small" onClick={retry}>{t("retry")}</button>}</div>;
}
export function Loading() { const t = useText(); return <output className="loading"><span className="spinner" />{t("loading")}</output>; }
export function ResourceView<T>({ resource, children }: Readonly<{ resource: ReturnType<typeof useResource<T>>; children: (data: T) => ReactNode }>) {
  if (resource.loading) { return <Loading />; }
  if (resource.error) { return <ErrorNotice error={resource.error} retry={resource.reload} />; }
  if (resource.data !== undefined) { return children(resource.data); }
  return null;
}
export function DateValue({ value }: Readonly<{ value: string | null }>) {
  const { language } = useContext(Context);
  if (!value || Number.isNaN(Date.parse(value))) { return <span className="muted">—</span>; }
  return <time dateTime={value} title={value}>{new Intl.DateTimeFormat(language, { dateStyle: 'short', timeStyle: 'short' }).format(new Date(value))}</time>;
}
export function Status({ value }: Readonly<{ value: string }>) { const t = useText(); const labels: Record<string, string> = { pending: t("pending"), approved: t("approved"), active: t("active2"), revoked: t("revoked"), observed: t("observed3"), blocked: t("blocked4"), observe: t("observe"), block: t("block") }; return <span className={`status status-${value}`}><span />{labels[value] ?? value}</span>; }
/** The `?id=<uuid>` of a detail page; anything that is not a UUID reads as no id, so a hostile hash never reaches a fetch. */
export function idFromHash(): string {
  const raw = new URLSearchParams(window.location.hash.split('?')[1] ?? '').get('id') ?? '';
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(raw) ? raw : '';
}
export function can(session: Session, permission: string) { return session.permissions?.includes(permission) ?? false; }
// Whether this instance refuses every write. Deliberately not folded into `can()`:
// a permission answers "may this account do it", this answers "does this instance
// accept it at all", and the two must stay apart — a demonstration keeps its
// configuration screens open to look at, which is exactly what removing the
// permission would take away.
export function readOnly(session: Session) { return session.demo_read_only === true; }
export function canManage(session: Session) { return can(session, 'members.manage'); }
/** Approving, revoking and deleting devices: the server gates them on devices.manage. */
export function canManageDevices(session: Session) { return can(session, 'devices.manage'); }
export function canAnalyze(session: Session) { return !session.privacy?.aggregate_only && can(session, 'events.read'); }
export function RefreshButton({ onClick }: Readonly<{ onClick: () => void }>) { const t = useText(); return <button className="button secondary" onClick={onClick}><Icon name="refresh" />{t("refresh")}</button>; }

/**
 * Copies text, reporting whether it actually worked. The async clipboard exists
 * only in a secure context and can still be refused by permission policy, so the
 * legacy selection path is a real fallback and not decoration. Callers must not
 * claim success on `false` — for a secret shown once, a copy the user believes
 * happened and did not is worse than no button at all.
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  if (window.isSecureContext && navigator.clipboard) {
    try { await navigator.clipboard.writeText(text); return true; } catch { /* fall through */ }
  }
  const area = document.createElement('textarea');
  area.value = text;
  area.setAttribute('readonly', '');
  area.style.position = 'fixed';
  area.style.top = '0';
  area.style.opacity = '0';
  document.body.append(area);
  area.select();
  area.setSelectionRange(0, text.length);
  let copied = false;
  try { copied = document.execCommand('copy'); } catch { copied = false; }
  area.remove();
  return copied;
}

const dialogVariants = { right: 'drawer', wide: 'wide', list: 'list' } as const;
// Open dialogs, counted: the page scrolls again when the last one closes, whatever the
// order. Each dialog restoring the value it found left the page without a scrollbar
// when a conversation and its message detail closed in the other order.
let openDialogs = 0;
function lockPageScroll() {
  openDialogs++;
  document.documentElement.style.overflow = 'hidden';
  return () => {
    openDialogs = Math.max(0, openDialogs - 1);
    if (openDialogs === 0) document.documentElement.style.overflow = '';
  };
}
export function Dialog({ title, children, close, side }: Readonly<{ title: string; children: ReactNode; close: () => void; side?: 'right' | 'wide' | 'list' }>) {
  const ref = useRef<HTMLDialogElement>(null); const t = useText(); const closeRef = useRef(close); closeRef.current = close; const id = useId();
  // A modal <dialog> does not stop the document behind it from scrolling, so an
  // open dialog otherwise shows a second scrollbar next to its own — three of them
  // once a drawer is stacked over a full screen dialog. Locked through a count of
  // open dialogs (lockPageScroll), so nested dialogs unwind in any order.
  // A click on the backdrop closes, like the button and Escape. The backdrop belongs to
  // the `<dialog>` itself: what distinguishes the backdrop from the content is the
  // pointer position, not the event target, otherwise the inner margins would close
  // it too. The gesture must START and end outside, so that a text selection
  // released outside the dialog does not close it; `detail === 0` rules out
  // keyboard-originated clicks, which carry no position. A click inside a nested dialog (the
  // detail of a message, a drawer opened over the conversation) bubbles up here,
  // outside this one's box: it is not a click on its own backdrop, and "Close" on the
  // detail used to close the conversation as well.
  useEffect(() => { const dialog = ref.current!; const unlock = lockPageScroll(); const prior = document.activeElement as HTMLElement | null; dialog.showModal(); const cancel = (event: globalThis.Event) => { event.preventDefault(); closeRef.current(); }; const outside = (event: MouseEvent) => { const box = dialog.getBoundingClientRect(); return event.detail > 0 && (event.target as Element | null)?.closest('dialog') === dialog && (event.clientX < box.left || event.clientX > box.right || event.clientY < box.top || event.clientY > box.bottom); }; let startedOutside = false; const down = (event: MouseEvent) => { startedOutside = outside(event); }; const click = (event: MouseEvent) => { if (startedOutside && outside(event)) closeRef.current(); }; dialog.addEventListener('cancel', cancel); dialog.addEventListener('mousedown', down); dialog.addEventListener('click', click); return () => { dialog.removeEventListener('cancel', cancel); dialog.removeEventListener('mousedown', down); dialog.removeEventListener('click', click); dialog.close(); unlock(); prior?.focus(); }; }, []);
  const variant = side ? dialogVariants[side] : '';
  return <dialog ref={ref} className={variant ? `dialog ${variant}` : 'dialog'} aria-labelledby={id}><div className="dialog-heading"><h2 id={id}>{title}</h2><button type="button" className="icon-button" onClick={close} aria-label={t("close")}><Icon name="close" /></button></div>{children}</dialog>;
}
