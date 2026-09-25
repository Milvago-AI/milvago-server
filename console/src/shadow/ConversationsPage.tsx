import { IdentityReveal } from "../IdentityReveal";
import { useContext, useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Badge, Card, clampPage, Context, DateValue, Dialog, Empty, Icon, Loading, PageBar, PageNumbers, PageSize, RefreshButton, ResourceView, Status, useResource, useText } from '../ui';
import type { IconName, Translate } from '../ui';
import { ExportMenu, FilterBar, SavedFilters } from './FilterBar';
import { conversationsLink, criteriaFromHash, serializeCriteria } from './filters';
import type { Conversation, Criteria, EventDetail, ShadowEvent, Thread, ThreadMessage } from './types';

// A person is verified only through the OIDC association; the server names an
// unverified actor `unknown` and still sends a placeholder display name. Without a
// verified person, the OS account the record belongs to is shown, marked as such.
const verified = (event: ShadowEvent) => !!event.actor_name && event.actor_id !== 'unknown';
// Without a verified person the record is not anonymous: the OS account still
// designates someone, under a pseudonym. Saying "unattributed" there claimed the
// record pointed at nobody. That word is kept for the case it actually describes —
// neither a verified person nor an OS account.
// `user_known` is the server saying a person is there without saying who: under
// pseudonymity the account is withheld, so the account itself cannot be the test.
const unverifiedPerson = (event: ShadowEvent, t: Translate) => event.user || event.user_known ? t("pseudonymised") : t("unattributed");

/** Who a record belongs to, and by which attribution — one answer, stated the same
 * way in the list, in the thread header and in the event detail. A verified
 * association names the person; failing that the OS account or the collected
 * profile does, said as such; failing both, nothing does. The detail used to show
 * "verified person: unattributed" as one field and the account as another, which
 * read as a contradiction of the very line above it. */
function Person({ event }: Readonly<{ event: ShadowEvent }>) {
  const t = useText();
  if (verified(event)) return <>{event.actor_name}<span className="cell-detail">{t("verifiedPerson")}</span></>;
  if (event.user) return <>{event.user}<span className="cell-detail">{event.source === 'native' ? t("collectedProfile") : t("osUser")}</span></>;
  return <>{unverifiedPerson(event, t)}</>;
}

export function ConversationsPage() {
  // Usage sensitivity is an Enterprise capability; Community reports none.
  const t = useText(); const { session } = useContext(Context); const sensitivity = session.edition === 'commercial'; const [criteria, setCriteria] = useState(criteriaFromHash); const [open, setOpen] = useState<Conversation>();
  // Pages are asked for by number, not walked one cursor at a time: the reader wants to
  // reach the last page as directly as the second. The server answers with the matching
  // total, which is what turns a page size into a number of pages.
  const [page, setPage] = useState(1); const [size, setSize] = useState(50);
  useEffect(() => { const changed = () => { setCriteria(criteriaFromHash()); setPage(1); setOpen(undefined); }; window.addEventListener('hashchange', changed); return () => window.removeEventListener('hashchange', changed); }, []);
  const resource = useResource<{ items: Conversation[]; total?: number }>(`/api/shadow/conversations?${serializeCriteria(criteria)}&limit=${size}&offset=${(page - 1) * size}`);
	const total = resource.data?.total ?? resource.data?.items.length ?? 0;
	const pages = Math.max(1, Math.ceil(total / size));
	const currentPage = resource.data ? clampPage(page, pages) : page;
	const correctingPage = resource.data !== undefined && currentPage !== page;
	useEffect(() => { if (correctingPage) setPage(currentPage); }, [correctingPage, currentPage]);
  // The open dialog shows the list's copy of its row: follow the list, so that when a
  // reveal expires and the list comes back aliased, the dialog does not keep the name.
  useEffect(() => { setOpen(current => current && resource.data?.items.find(item => item.key === current.key)); }, [resource.data]);
  function change(next: Criteria) { setCriteria(next); setPage(1); location.hash = conversationsLink(next); }
  return <><PageBar title={t("conversations")} actions={<><ExportMenu criteria={criteria} /><RefreshButton onClick={resource.reload} /></>} info={t("aConversationGroupsTheRecordsOf")} /><Card><FilterBar criteria={criteria} change={change} /><SavedFilters criteria={criteria} apply={change} /></Card>{correctingPage ? <Loading /> : <ResourceView resource={resource}>{data => <section className="panel table-panel"><div className="section-heading"><h2>{t("conversations")}</h2><div className="heading-controls"><span className="muted">{t("resultsCount", [total])}</span><PageSize value={size} label={t("perPage")} change={value => { setSize(value); setPage(1); }} /></div></div>{data.items.length ? <div className="table-scroll"><table><thead><tr>{[t("toolService"), t("model"), t("device"), t("person"), t("lastActivity"), t("messages"), t("attachedFiles"), t("action"), ...(sensitivity ? [t("sensitivity")] : [])].map(label => <th key={label}>{label}</th>)}</tr></thead><tbody>{data.items.map(item => <ConversationRow key={item.key} item={item} sensitivity={sensitivity} open={() => setOpen(item)} />)}</tbody></table></div> : <Empty title={t("noConversationsMatchTheseFilters")}>{t("expandThePeriodOrRemoveA")}</Empty>}<PageNumbers page={currentPage} pages={pages} go={setPage} label={t("pagination")} /></section>}</ResourceView>}<p className="fine-print">{t("exportsContainMetadataMatchingTheExact")}</p>{open && <ConversationDialog conversation={open} close={() => setOpen(undefined)} />}</>;
}

// The whole row opens the conversation, which is what a reader expects of a list
// of conversations. The service cell still carries a real button: a click handler
// on the row alone would be unreachable by keyboard, and a table row cannot take
// a button role without losing its own.
function ConversationRow({ item, sensitivity, open }: Readonly<{ item: Conversation; sensitivity: boolean; open: () => void }>) {
  const t = useText(); const event = item.latest; const exchanged = item.prompts + item.responses;
  let action = <Status value="observed" />;
  if (item.redirected) action = <Badge tone="warning">{t("nRedirected", [String(item.redirected)])}</Badge>;
  if (item.blocked) action = <Badge tone="danger">{t("nBlocked", [String(item.blocked)])}</Badge>;
  return <tr className="conversation-row" onClick={open}><td><button type="button" className="row-open" onClick={click => { click.stopPropagation(); open(); }}>{event.provider}<span className="sr-only"> · {t("openTheConversation")} {item.key}</span></button><span className="cell-detail">{event.tool || t("unknown2")}</span></td>
    <td>{item.model || <span className="muted">{t("unknown2")}</span>}{item.effort ? <span className="cell-detail">{t("effort")} : {item.effort}</span> : null}</td>
    <td><strong>{event.hostname || t("machineNameUnavailable")}</strong><span className="cell-detail mono" title={event.device_id}>{event.device_id.slice(0, 8)}</span></td>
    <td><Person event={event} /></td>
    <td className="nowrap"><DateValue value={item.last_at} /><span className="cell-detail">{t("startedAt")} <DateValue value={item.started_at} /></span></td>
    <td className="nowrap">{exchanged === 1 ? t("oneMessage") : t("nMessages", [String(exchanged)])}</td>
    {/* Un document parti avec la conversation. L'icône porte un libellé accessible :
        une pastille muette ne se lit pas à la voix, et cette colonne se filtre. */}
    <td className="nowrap">{item.has_attachment
      ? <Badge tone="warning"><Icon name="file" />{t("withAttachment")}</Badge>
      : <span className="muted">—</span>}</td>
    <td>{action}</td>
    {sensitivity && <td>{event.sensitivity === 'sensitive' ? <Badge tone="warning">{t("sensitive")}</Badge> : <span className="muted">{event.sensitivity === 'normal' ? t("normal") : t("unknown")}</span>}</td>}
  </tr>;
}

// The refusal reason is the most useful field of a blocked event, so it is named
// rather than shown as its wire value.
function refusalReason(t: Translate, reason: NonNullable<ShadowEvent['decision_reason']>) {
  if (reason === 'model_denied') return t("modelDeniedByPolicy");
  if (reason === 'model_unknown') return t("modelCouldNotBeIdentified");
  if (reason === 'control_unavailable') return t("localControlUnavailable");
  return reason;
}

/**
 * The thread, as a full screen dialog over the list. Each page of messages is its
 * own `useResource`, rather than one accumulating buffer: that hook is what drops
 * revealed personal data when an identity grant expires, and a buffer of our own
 * would keep older pages readable past their deadline. Pages are rendered oldest
 * first, so reading runs down the screen the way the exchange happened.
 */
function ConversationDialog({ conversation, close }: Readonly<{ conversation: Conversation; close: () => void }>) {
  const t = useText(); const event = conversation.latest;
  const [cursors, setCursors] = useState(['']); const [earlier, setEarlier] = useState(''); const [detail, setDetail] = useState<ShadowEvent>();
  const scroll = useRef<HTMLDivElement>(null);
  const exchanged = conversation.prompts + conversation.responses;
  return <Dialog title={`${event.provider} · ${event.hostname || t("machineNameUnavailable")}`} close={close} side="wide">
    <div className="thread-shell">
      <header className="thread-summary">
        <dl className="dl">
          <dt>{t("person")}</dt><dd><Person event={event} /></dd>
          <dt>{t("toolService")}</dt><dd>{event.tool || t("unknown2")}</dd>
          <dt>{t("model")}</dt><dd>{conversation.model || <span className="muted">{t("unknown2")}</span>}</dd>
          {conversation.effort ? <><dt>{t("effort")}</dt><dd>{conversation.effort}</dd></> : null}
          <dt>{t("startedAt")}</dt><dd><DateValue value={conversation.started_at} /></dd>
          <dt>{t("lastActivity")}</dt><dd><DateValue value={conversation.last_at} /></dd>
          <dt>{t("messages")}</dt><dd>{exchanged === 1 ? t("oneMessage") : t("nMessages", [String(exchanged)])}</dd>
        </dl>
        <IdentityReveal subject={event.actor_id} expiresAt={event.identity_expires_at} />
      </header>
      <div className="thread-scroll" ref={scroll}>
        {earlier ? <div className="thread-earlier"><button type="button" className="button secondary small" onClick={() => { setCursors(values => [...values, earlier]); setEarlier(''); }}>{t("loadEarlierMessages")}</button></div> : null}
        {[...cursors].reverse().map((cursor, index) => <ThreadPage key={cursor || 'head'} conversation={conversation} cursor={cursor}
          oldest={index === 0} newest={index === cursors.length - 1} report={setEarlier}
          loaded={() => { const node = scroll.current; if (node) node.scrollTop = node.scrollHeight; }} detail={setDetail} />)}
      </div>
      <div className="dialog-actions"><button className="button primary" onClick={close}>{t("close")}</button></div>
    </div>
    {detail && <EventDialog event={detail} close={() => setDetail(undefined)} />}
  </Dialog>;
}

function ThreadPage({ conversation, cursor, oldest, newest, report, loaded, detail }: Readonly<{ conversation: Conversation; cursor: string; oldest: boolean; newest: boolean; report: (value: string) => void; loaded: () => void; detail: (event: ShadowEvent) => void }>) {
  const t = useText();
  const cursorParameter = cursor ? `&cursor=${encodeURIComponent(cursor)}` : '';
  const resource = useResource<Thread>(`/api/shadow/conversation?key=${encodeURIComponent(conversation.key)}&device_id=${encodeURIComponent(conversation.latest.device_id)}${cursorParameter}`);
  const data = resource.data;
  useEffect(() => { if (!data) { return; } if (oldest) { report(data.older_cursor); } if (newest) { loaded(); } }, [data, oldest, newest]);
  return <ResourceView resource={resource}>{page => <>{page.items.length ? fold(page.items).map(message => <Message key={`${message.device_id}:${message.id}`} message={message} open={() => detail(message)} />) : <p className="muted">{t("noEventsMatchTheseFilters")}</p>}</>}</ResourceView>;
}

/**
 * Un envoi accompagné d'un fichier produit DEUX enregistrements : le fichier part chez
 * le fournisseur dès qu'il est attaché, donc il est enregistré avant le texte, sous la
 * même corrélation. Affichés tels quels, ils donnaient deux bulles dont une vide, pour
 * un seul envoi. La pièce jointe rejoint donc la bulle de son message.
 *
 * Fusion à l'AFFICHAGE seulement : les deux enregistrements restent distincts, chacun
 * avec son horodatage et son détail, et rien n'est réécrit. Un fichier attaché sans
 * envoi qui suit garde sa propre bulle — il décrit alors bien ce qui s'est passé.
 */
export function fold(items: ThreadMessage[]): ThreadMessage[] {
  const attached = new Map<string, string[]>(), hosts = new Set<string>();
  for (const message of items) {
    if (message.kind !== 'prompt' || !message.correlation_id) continue;
    if (!message.characters && message.files?.length) attached.set(message.correlation_id, [...(attached.get(message.correlation_id) ?? []), ...message.files]);
    else if (message.characters) hosts.add(message.correlation_id);
  }
  return items.flatMap(message => {
    const carried = message.correlation_id ? attached.get(message.correlation_id) : undefined;
    if (!carried || message.kind !== 'prompt' || !hosts.has(message.correlation_id!)) return [message];
    if (!message.characters) return [];
    return [{ ...message, files: [...new Set([...(message.files ?? []), ...carried])] }];
  });
}

// Le type du fichier se lit dans son extension : c'est la seule chose dont on dispose,
// aucun octet n'étant jamais lu. Une extension inconnue reste un fichier, pas une
// devinette.
const FILE_ICONS: [RegExp, IconName][] = [
  [/\.(png|jpe?g|gif|webp|bmp|svg|heic|heif|avif|tiff?)$/i, 'file-image'],
  [/\.(pdf|docx?|odt|rtf|txt|md|pages)$/i, 'file-text'],
  [/\.(xlsx?|csv|tsv|ods|numbers)$/i, 'file-sheet'],
  [/\.(zip|rar|7z|tar|gz|bz2|xz)$/i, 'file-archive'],
];
export const fileIcon = (name: string): IconName => FILE_ICONS.find(([pattern]) => pattern.test(name))?.[1] ?? 'file';

/**
 * One bubble. A readable text stays a plain `div` so it can be selected and
 * copied; only the small detail control and the tag are buttons. The text itself
 * is a React text node, never markup: content is written by whoever used the AI
 * service, and it is rendered here exactly as it was captured.
 *
 * Un clic sur la bulle ouvre son détail, **sauf** si du texte est sélectionné : sans
 * cette garde, relire un message en le surlignant ouvrirait un dialogue au relâchement.
 * La bulle et sa petite icône ouvrent toutes deux le détail au clavier. La bulle
 * reste un conteneur car son texte doit pouvoir être sélectionné et elle contient
 * des contrôles qui ne peuvent pas être imbriqués dans un bouton natif.
 */
function Message({ message, open }: Readonly<{ message: ThreadMessage; open: () => void }>) {
  const t = useText();
  if (message.kind === 'navigation') return <p className="thread-nav"><button type="button" onClick={open}>{t("navigation")} · <DateValue value={message.occurred_at} /></button></p>;
  const prompt = message.kind === 'prompt';
  const text = prompt ? message.content?.prompt : message.content?.response;
  function hiddenCause() {
    if (message.content_state === 'denied') return t("readingNotAuthorized");
    if (message.content_state === 'not_retained') return t("textNotRetained");
    if (message.content_state === 'identity') return t("identityNotRevealed");
    return '';
  }
  const cause = hiddenCause();
  const files = message.files ?? [];
  const selecting = () => !!window.getSelection && !window.getSelection()?.isCollapsed;
  function renderContent(): ReactNode {
    if (text !== undefined && text !== null) return <pre>{text}</pre>;
    // A message made only of files has no text to conceal.
    if (files.length && !message.characters) return null;
    return <button type="button" className="bubble-tag" onClick={open}>{prompt ? t("hiddenPrompt") : t("hiddenResponse")}{cause ? ' · ' + cause : ''}</button>;
  }
  const bubbleContent = renderContent();
  return <div className={`thread-row ${prompt ? 'prompt' : 'response'}`}>
    <div className={`bubble${message.action === 'blocked' ? ' blocked' : ''}`} role="button" tabIndex={0} onClick={() => { if (!selecting()) open(); }} onKeyDown={event => { if (event.target === event.currentTarget && (event.key === 'Enter' || event.key === ' ') && !selecting()) { event.preventDefault(); open(); } }}>
      {bubbleContent}
      {files.length ? <ul className="bubble-files" aria-label={t("attachedFiles")}>{files.map(name => <li key={name} className="bubble-file" title={name}><Icon name={fileIcon(name)} /><span>{name}</span></li>)}</ul> : null}
      {message.action === 'blocked' && message.decision_reason ? <p className="bubble-refusal">{refusalReason(t, message.decision_reason)}</p> : null}
      <p className="bubble-meta">
        <DateValue value={message.occurred_at} />
        {message.model ? <span>{message.model}</span> : null}
        {message.action !== 'observed' ? <Status value={message.action} /> : null}
        <button type="button" className="icon-button" onClick={open} aria-label={`${t("messageDetail")} ${message.id}`}><Icon name="chevron-right" /></button>
      </p>
    </div>
  </div>;
}

/**
 * Le détail d'un enregistrement ne concerne qu'un sens : un envoi OU une réponse. Les
 * deux sections étaient affichées côte à côte sous « Requête conservée » / « Réponse
 * conservée », si bien qu'un détail de requête montrait un cadre de réponse vide.
 * C'est le genre de l'enregistrement qui décide, et son titre le nomme simplement.
 */
function RetainedText({ event, content }: Readonly<{ event: ShadowEvent; content?: { prompt?: string; response?: string } }>) {
  const t = useText();
  const prompt = event.kind === 'prompt';
  const text = prompt ? content?.prompt : content?.response;
  if (text === undefined || text === null) return <div className="notice"><p>{t("noTextIsRetainedForThis")}</p></div>;
  return <div className="event-content"><p className="fine-print">{t("thisContentReadHasBeenAudited")}</p><section><h3>{prompt ? t("request") : t("response")}</h3><pre>{text}</pre></section></div>;
}

function EventDialog({ event, close }: Readonly<{ event: ShadowEvent; close: () => void }>) {
  const t = useText(); const resource = useResource<EventDetail>(`/api/shadow/events/${encodeURIComponent(event.id)}?device_id=${encodeURIComponent(event.device_id)}`);
  return <Dialog title={t("eventDetail")} close={close} side="right"><ResourceView resource={resource}>{data => <div className="dialog-body"><dl className="dl"><dt>{t("timestamp")}</dt><dd><DateValue value={data.event.occurred_at} /></dd><dt>{t("person")}</dt><dd><Person event={data.event} /></dd><dt>{t("device")}</dt><dd>{data.event.hostname || t("machineNameUnavailable")}<span className="cell-detail mono">{data.event.device_id}</span></dd><dt>{t("source")}</dt><dd>{data.event.source === 'native' ? t("localApplication") : t("browser")} · {data.event.tool}</dd><dt>{t("serviceModel")}</dt><dd>{data.event.provider} / {data.event.model || t("unknown2")}</dd><dt>{t("action")}</dt><dd><Status value={data.event.action} /></dd>{data.event.decision_reason && <><dt>{t("refusalReason")}</dt><dd>{refusalReason(t, data.event.decision_reason)}</dd></>}{data.event.platform_id && <><dt>{t("platform")}</dt><dd><code>{data.event.platform_id}</code></dd></>}<dt>{t("characters")}</dt><dd>{data.event.characters}</dd><dt>{t("categories")}</dt><dd>{data.event.labels.length ? data.event.labels.join(', ') : '—'}</dd>{data.event.files?.length ? <><dt>{t("attachedFiles")}</dt><dd>{data.event.files.map(name => <span key={name} className="cell-detail">{name}</span>)}</dd></> : null}<dt>{t("appliedRevision")}</dt><dd>{data.event.policy_revision}</dd>{data.event.url && <><dt>URL</dt><dd><code>{data.event.url}</code></dd></>}{data.event.conversation_id && <><dt>{t("conversation")}</dt><dd><code>{data.event.conversation_id}</code></dd></>}{data.event.correlation_id && <><dt>{t("correlation")}</dt><dd><code>{data.event.correlation_id}</code></dd></>}</dl><IdentityReveal subject={data.event.actor_id} expiresAt={data.event.identity_expires_at}/>{!data.can_read_content ? <div className="notice"><Icon name="shield" /><p>{t("rawContentRequiresExplicitPermissionNo")}</p></div> : <RetainedText event={data.event} content={data.content} />}<div className="dialog-actions"><button className="button primary" onClick={close}>{t("close")}</button></div></div>}</ResourceView></Dialog>;
}
