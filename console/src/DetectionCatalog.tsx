import { ApiError } from './api';
import { useContext, useMemo, useRef, useState } from 'react';
import { Badge, Button, Context, Dialog, Empty, ErrorNotice, Icon, Notice, ResourceView, Tabs, useMutation, useResource, useText } from './ui';
import type { TranslationKey } from './locales/en';

type NetworkRule = { method: string; host: string; path: string; text_path: string; text_paths: string[]; model_path: string; effort_path: string; conversation_path: string };
// `asset_hosts` : hôtes que la page peut charger sous contrôle de contenu (mesurés, jamais couverts).
// Pas encore éditable ici ; les dialogues étalent le fournisseur existant, donc la valeur servie survit à une modification.
type Provider = { id: string; label: string; domains: string[]; aliases: string[]; conversation_path: string; conversation_segment: number; qualified_at: string; dom: { editor: string; send: string; response: string }; network: NetworkRule[]; asset_hosts?: string[] };
type NativeTool = { id: string; platform: string; qualified_versions: string[]; parser: string; telemetry_text_qualified_versions: string[] };
type Content = { providers: Provider[]; native_tools: NativeTool[]; heuristics: { keys: string[]; mime_types: string[] } };
type Catalog = { revision: number; content: Content; can_publish: boolean };
type Envelope = { payload: string; signature: string };
type Kind = 'browser' | 'native';
type Editing = { kind: Kind; index?: number };
const list = (text: string) => text.split(/[\n,]/).map(value => value.trim()).filter(Boolean);
const domLabels = { editor: 'catalogEditor', send: 'catalogSend', response: 'catalogResponse' } as const;
const networkLabels = { host: 'domain', path: 'catalogRequestPath', text_path: 'catalogTextPath', model_path: 'catalogModelPath', effort_path: 'catalogEffortPath', conversation_path: 'catalogConversationPath' } as const;
const emptyProvider = (): Provider => ({ id: '', label: '', domains: [], aliases: [], conversation_path: '', conversation_segment: 0, qualified_at: '', dom: { editor: '', send: '', response: '' }, network: [] });
const emptyNative = (): NativeTool => ({ id: '', platform: '', qualified_versions: [], parser: '', telemetry_text_qualified_versions: [] });

export function DetectionCatalog() {
  const r = useResource<Catalog>('/api/detection/catalog'), t = useText();
  // Publication feedback survives ResourceView unmounting its editor on reload.
  const [published, setPublished] = useState(false);
  // The published domains used to be reported upwards so the candidates table could
  // offer "promote". That made the offer depend on having published in this very
  // browsing session, which no customer ever does: the discovery page now reads the
  // catalogue itself, and the server stays the authority either way.
  return <>{published && <Notice tone="success">{t('catalogPublished')}</Notice>}<ResourceView resource={r}>{value => <Editor key={value.revision} initial={value} onPublished={() => {
    setPublished(true); r.reload();
  }} />}</ResourceView></>;
}

function Editor({ initial, onPublished }: Readonly<{ initial: Catalog; onPublished: (value: Catalog) => void }>) {
  const t = useText(), mutation = useMutation(), { session } = useContext(Context);
  const [content, setContent] = useState(initial.content), [kind, setKind] = useState<Kind>('browser');
  const [query, setQuery] = useState(''), [selected, setSelected] = useState<Set<number>>(new Set());
  const [editing, setEditing] = useState<Editing>(), [bulk, setBulk] = useState(false), [deleting, setDeleting] = useState<number[]>();
  const [heuristics, setHeuristics] = useState(false), [importing, setImporting] = useState(false), [preview, setPreview] = useState(false), [discard, setDiscard] = useState(false);
  const [saved, setSaved] = useState(false);
  // One memo for every diff against the published document: a keystroke in the
  // search field re-renders, and none of these serialisations depend on it.
  const { changed, removed, nativeChanged, heuristicsChanged } = useMemo(() => {
    const initialById = new Map(initial.content.providers.map(old => [old.id, old]));
    return {
      changed: content.providers.filter(provider => JSON.stringify(provider) !== JSON.stringify(initialById.get(provider.id))),
      removed: initial.content.providers.filter(provider => !content.providers.some(next => next.id === provider.id)),
      nativeChanged: JSON.stringify(content.native_tools) !== JSON.stringify(initial.content.native_tools),
      heuristicsChanged: JSON.stringify(content.heuristics) !== JSON.stringify(initial.content.heuristics),
    };
  }, [content, initial]);
  const hasChanges = changed.length > 0 || removed.length > 0 || nativeChanged || heuristicsChanged;
  const update = (next: Content) => { setContent(next); setPreview(false); setSaved(true); };
  const search = query.trim().toLocaleLowerCase();
  const rows = kind === 'browser'
    ? content.providers.map((provider, index) => ({ index, name: provider.label || provider.id, id: provider.id, summary: [...provider.domains, ...provider.aliases].join(', '), provider }))
    : content.native_tools.map((native, index) => ({ index, name: native.id, id: native.id, summary: native.platform, native }));
  const visible = rows.filter(row => (row.name + ' ' + row.id + ' ' + row.summary).toLocaleLowerCase().includes(search));
  const allSelected = visible.length > 0 && visible.every(row => selected.has(row.index));
  const canDelete = (indices: number[]) => kind === 'native' || content.providers.length > indices.length;
  function selectVisible(checked: boolean) {
    setSelected(current => { const next = new Set(current); visible.forEach(row => checked ? next.add(row.index) : next.delete(row.index)); return next; });
  }
  async function publish() {
    try {
      const result = await mutation.run<Catalog>('/api/detection/catalog', 'PUT', { revision: initial.revision, content });
      if (result?.revision && result.content) onPublished(result);
    } catch { /* The error and the current draft remain visible in the preview. */ }
  }
  const closePreview = () => { if (!mutation.pending) setPreview(false); };
  return <>
    <section className="panel table-panel catalog-panel">
      <div className="section-heading">
        <div><h2>{t('detectionCatalog')}</h2><p>{t('revision')} {initial.revision}{hasChanges && <> · {t('catalogDraft')}</>}</p></div>
        <div className="row-actions">
          {initial.can_publish && <><Button icon="settings" onClick={() => setHeuristics(true)}>{t('catalogHeuristics')}</Button><Button icon="download" onClick={() => setImporting(true)}>{t('catalogSignedImport')}</Button>
            <Button variant="primary" icon="plus" disabled={kind === 'browser' ? content.providers.length >= 128 : content.native_tools.length >= 32} onClick={() => setEditing({ kind })}>{t(kind === 'browser' ? 'catalogAddCoverage' : 'catalogAddNativeTool')}</Button></>}
        </div>
      </div>
      {!initial.can_publish && <Notice>{t('catalogRootOwner')}</Notice>}
      <div className="catalog-toolbar">
        <Tabs label={t('coverage')} selected={kind} onSelect={value => { setKind(value as Kind); setSelected(new Set()); setQuery(''); }} items={[
          { id: 'browser', name: <>{t('catalogBrowser')} <span className="count-badge">{content.providers.length}</span></> },
          ...(session.edition === 'commercial' ? [{ id: 'native', name: <>{t('catalogNativeTools')} <span className="count-badge">{content.native_tools.length}</span></> }] : []),
        ]} />
        <label className="catalog-search"><Icon name="search" /><input type="search" aria-label={t('catalogSearch')} placeholder={t('catalogSearch')} value={query} onChange={event => setQuery(event.target.value)} /></label>
      </div>
      {selected.size > 0 && <section className="catalog-selection" aria-label={t('catalogSelection', [selected.size])}>
        <strong>{t('catalogSelection', [selected.size])}</strong><div className="row-actions">
          <Button size="small" icon="settings" onClick={() => setBulk(true)}>{t('catalogEditSelected')}</Button>
          <Button size="small" variant="danger" icon="trash" disabled={!canDelete([...selected])} title={!canDelete([...selected]) ? t('catalogAtLeastOne') : undefined} onClick={() => setDeleting([...selected])}>{t('deleteSelected')}</Button>
          <Button size="small" variant="ghost" onClick={() => setSelected(new Set())}>{t('catalogClearSelection')}</Button>
        </div>
      </section>}
      {visible.length ? <div className="table-scroll"><table className="catalog-table"><thead><tr>
        {initial.can_publish && <th className="select-cell"><input type="checkbox" aria-label={t('catalogSelectVisible')} checked={allSelected} ref={element => { if (element) element.indeterminate = !allSelected && visible.some(row => selected.has(row.index)); }} onChange={event => selectVisible(event.target.checked)} /></th>}
        <th>{t('name')}</th><th>{t(kind === 'browser' ? 'catalogDomainsSummary' : 'catalogPlatform')}</th>
        <th>{t(kind === 'browser' ? 'catalogDOM' : 'catalogParser')}</th><th>{t(kind === 'browser' ? 'catalogNetwork' : 'catalogNativeVersions')}</th><th>{t('actions')}</th>
      </tr></thead><tbody>{visible.map(row => <tr key={row.index} className={'catalog-row' + (selected.has(row.index) ? ' is-selected' : '')} onClick={() => setEditing({ kind, index: row.index })}>
        {initial.can_publish && <td className="select-cell" onClick={event => event.stopPropagation()}><input type="checkbox" aria-label={t('select') + ' ' + row.name} checked={selected.has(row.index)} onChange={event => { const checked = event.target.checked; setSelected(current => { const next = new Set(current); if (checked) { next.add(row.index); } else { next.delete(row.index); } return next; }); }} /></td>}
        <td className="nowrap"><button className="text-link catalog-name" onClick={event => { event.stopPropagation(); setEditing({ kind, index: row.index }); }}><strong>{row.name || t('catalogAddCoverage')}</strong></button>{row.name !== row.id && <span className="catalog-identifier mono">{row.id}</span>}</td>
        <td className="keep-words">{row.summary || '—'}</td>
        <td className="keep-words">{'provider' in row ? <Badge>{t(Object.values(row.provider.dom).some(Boolean) ? 'catalogConfigured' : 'catalogNotConfigured')}</Badge> : row.native.parser || '—'}</td>
        <td>{'provider' in row ? <span className="count-badge">{row.provider.network.length}</span> : row.native.qualified_versions.join(', ') || '—'}</td>
        <td onClick={event => event.stopPropagation()}><div className="row-actions"><button className="icon-button" aria-label={t('catalogCoverageDetails') + ' ' + row.name} title={t('catalogCoverageDetails')} onClick={() => setEditing({ kind, index: row.index })}><Icon name={initial.can_publish ? 'settings' : 'eye'} /></button>
          {initial.can_publish && <button className="icon-button danger" disabled={!canDelete([row.index])} aria-label={t('delete') + ' ' + row.name} title={canDelete([row.index]) ? t('delete') : t('catalogAtLeastOne')} onClick={() => setDeleting([row.index])}><Icon name="trash" /></button>}</div></td>
      </tr>)}</tbody></table></div> : <Empty title={t('catalogNoResults')} />}
      {initial.can_publish && <div className="catalog-footer"><p className="fine-print">{t('catalogDraftHint')}</p>{hasChanges && <div className="row-actions"><Button onClick={() => setDiscard(true)}>{t('discardDraft')}</Button><Button variant="primary" icon="check" onClick={() => { mutation.clear(); setPreview(true); }}>{t('catalogPreview')}</Button></div>}</div>}
    </section>
    {saved && hasChanges && <Notice tone="success">{t('catalogDraftSaved')}</Notice>}
    {editing?.kind === 'browser' && <ProviderDialog initial={editing.index === undefined ? emptyProvider() : content.providers[editing.index]} creating={editing.index === undefined} readOnly={!initial.can_publish} close={() => setEditing(undefined)} save={provider => {
      update({ ...content, providers: editing.index === undefined ? [...content.providers, provider] : content.providers.map((old, index) => index === editing.index ? provider : old) }); setEditing(undefined);
    }} />}
    {editing?.kind === 'native' && <NativeDialog initial={editing.index === undefined ? emptyNative() : content.native_tools[editing.index]} creating={editing.index === undefined} readOnly={!initial.can_publish} close={() => setEditing(undefined)} save={native => {
      update({ ...content, native_tools: editing.index === undefined ? [...content.native_tools, native] : content.native_tools.map((old, index) => index === editing.index ? native : old) }); setEditing(undefined);
    }} />}
    {bulk && <BulkDialog kind={kind} count={selected.size} close={() => setBulk(false)} save={(field, value) => {
      if (kind === 'browser') update({ ...content, providers: content.providers.map((provider, index) => {
        if (!selected.has(index)) return provider;
        if (field in domLabels) return { ...provider, dom: { ...provider.dom, [field]: value } };
        return { ...provider, [field]: field === 'conversation_segment' ? Number(value) : value };
      }) });
      else update({ ...content, native_tools: content.native_tools.map((native, index) => !selected.has(index) ? native : { ...native, [field]: field.endsWith('versions') ? list(value) : value }) });
      setBulk(false);
    }} />}
    {deleting && <Dialog title={t('catalogDeleteTitle')} close={() => setDeleting(undefined)}><div className="dialog-body"><p>{t('catalogDeleteConfirm', [deleting.length])}</p><ul>{rows.filter(row => deleting.includes(row.index)).map(row => <li key={row.index}>{row.name}</li>)}</ul><div className="dialog-actions"><Button onClick={() => setDeleting(undefined)}>{t('cancel')}</Button><Button variant="danger" disabled={!canDelete(deleting)} icon="trash" onClick={() => {
      update(kind === 'browser' ? { ...content, providers: content.providers.filter((_, index) => !deleting.includes(index)) } : { ...content, native_tools: content.native_tools.filter((_, index) => !deleting.includes(index)) }); setSelected(new Set()); setDeleting(undefined);
    }}>{t('delete')}</Button></div></div></Dialog>}
    {discard && <Dialog title={t('catalogDiscardTitle')} close={() => setDiscard(false)}><div className="dialog-body"><p>{t('catalogDiscardConfirm')}</p><div className="dialog-actions"><Button onClick={() => setDiscard(false)}>{t('cancel')}</Button><Button variant="danger" onClick={() => { setContent(initial.content); setSelected(new Set()); setSaved(false); setDiscard(false); setPreview(false); }}>{t('discardDraft')}</Button></div></div></Dialog>}
    {heuristics && <HeuristicsDialog initial={content.heuristics} close={() => setHeuristics(false)} save={value => { update({ ...content, heuristics: value }); setHeuristics(false); }} />}
    {preview && <Dialog title={t('catalogChanges')} close={closePreview} side="right"><div className="dialog-body"><ErrorNotice error={mutation.error} />
      <ul>{changed.map(provider => <li key={provider.id}>{t('catalogChanged', [provider.id])}</li>)}{removed.map(provider => <li key={provider.id}>{t('catalogRemoved', [provider.id])}</li>)}{nativeChanged && <li>{t('catalogNativeToolsChanged')}</li>}{heuristicsChanged && <li>{t('catalogHeuristicsChanged')}</li>}</ul>
      <details><summary>{t('catalogRawChanges')}</summary><pre className="catalog-preview">{JSON.stringify({ before: initial.content, after: content }, null, 2)}</pre></details>
      <div className="dialog-actions"><Button disabled={mutation.pending} onClick={closePreview}>{t('cancel')}</Button><Button variant="primary" disabled={mutation.pending || !hasChanges} onClick={() => void publish()}>{t('catalogPublish')}</Button></div>
    </div></Dialog>}
    {importing && <ImportDialog initial={initial} content={content} close={() => setImporting(false)} onPublished={onPublished} />}
  </>;
}

function ProviderDialog({ initial, creating, readOnly, close, save }: Readonly<{ initial: Provider; creating: boolean; readOnly: boolean; close: () => void; save: (value: Provider) => void }>) {
  const t = useText(), [draft, setDraft] = useState(initial), [domains, setDomains] = useState(initial.domains.join('\n')), [aliases, setAliases] = useState(initial.aliases.join('\n'));
  const [ruleKeys, setRuleKeys] = useState(() => initial.network.map((_, index) => index));
  const nextRuleKey = useRef(initial.network.length);
  function removeNetworkRule(index: number) {
    setDraft(current => ({ ...current, network: current.network.filter((_, position) => position !== index) }));
    setRuleKeys(current => current.filter((_, position) => position !== index));
  }
  function addNetworkRule() {
    setDraft(current => ({ ...current, network: [...current.network, { method: 'POST', host: list(domains)[0] || '', path: '/', text_path: '', text_paths: [], model_path: '', effort_path: '', conversation_path: '' }] }));
    setRuleKeys(current => [...current, nextRuleKey.current++]);
  }
  const field = (key: 'id' | 'label' | 'conversation_path' | 'qualified_at', label: TranslationKey) => <label>{t(label)}<input required={key === 'id' || key === 'label' || key === 'qualified_at'} maxLength={key === 'label' ? 100 : 256} value={draft[key]} onChange={event => setDraft({ ...draft, [key]: event.target.value })} /></label>;
  return <Dialog title={creating ? t('catalogAddCoverage') : initial.label || t('catalogCoverageDetails')} close={close} side="right"><form className="form-grid catalog-editor" onSubmit={event => { event.preventDefault(); save({ ...draft, domains: list(domains), aliases: list(aliases) }); }}>
    <fieldset disabled={readOnly}><legend>{t('catalogGeneral')}</legend>{field('id', 'identifier')}{field('label', 'name')}
      <label>{t('catalogDomains')}<textarea required maxLength={8096} value={domains} onChange={event => setDomains(event.target.value)} /></label>
      <label>{t('catalogDomainAliases')}<textarea maxLength={8096} value={aliases} onChange={event => setAliases(event.target.value)} /></label>
      {field('qualified_at', 'catalogQualifiedAt')}{field('conversation_path', 'catalogConversationPath')}
      <label>{t('catalogConversationSegment')}<input type="number" required min={0} max={16} value={draft.conversation_segment} onChange={event => setDraft({ ...draft, conversation_segment: Number(event.target.value) })} /></label>
    </fieldset>
    <fieldset disabled={readOnly}><legend>{t('catalogDOM')}</legend>{(Object.keys(domLabels) as (keyof typeof domLabels)[]).map(key => <label key={key}>{t(domLabels[key])}<input maxLength={512} value={draft.dom[key]} onChange={event => setDraft({ ...draft, dom: { ...draft.dom, [key]: event.target.value } })} /></label>)}</fieldset>
    <fieldset disabled={readOnly}><legend>{t('catalogNetwork')}</legend>{draft.network.map((rule, index) => <fieldset key={ruleKeys[index]}><legend>{t('catalogNetworkRule')} {index + 1}</legend>
      <label>{t('catalogMethod')}<select value={rule.method} onChange={event => setDraft({ ...draft, network: draft.network.map((old, n) => n === index ? { ...old, method: event.target.value } : old) })}><option>POST</option><option>PUT</option></select></label>
      <label>{t('catalogTextPaths')}<textarea maxLength={1200} value={(rule.text_paths ?? []).join('\n')} onChange={event => setDraft({ ...draft, network: draft.network.map((old, n) => n === index ? { ...old, text_paths: list(event.target.value) } : old) })} /></label>
      {(Object.keys(networkLabels) as (keyof typeof networkLabels)[]).map(key => <label key={key}>{t(networkLabels[key])}<input required={key === 'host' || key === 'path'} maxLength={256} value={rule[key]} onChange={event => setDraft({ ...draft, network: draft.network.map((old, n) => n === index ? { ...old, [key]: event.target.value } : old) })} /></label>)}
      {!readOnly && <Button variant="danger" size="small" icon="trash" onClick={() => removeNetworkRule(index)}>{t('catalogRemoveRule')}</Button>}
    </fieldset>)}{!readOnly && <Button icon="plus" disabled={draft.network.length >= 32} onClick={addNetworkRule}>{t('catalogAddRule')}</Button>}</fieldset>
    <div className="dialog-actions"><Button onClick={close}>{t(readOnly ? 'close' : 'cancel')}</Button>{!readOnly && <Button variant="primary" type="submit">{t('saveChanges')}</Button>}</div>
  </form></Dialog>;
}

function NativeDialog({ initial, creating, readOnly, close, save }: Readonly<{ initial: NativeTool; creating: boolean; readOnly: boolean; close: () => void; save: (value: NativeTool) => void }>) {
  const t = useText(), [draft, setDraft] = useState(initial), [versions, setVersions] = useState(initial.qualified_versions.join('\n')), [textVersions, setTextVersions] = useState(initial.telemetry_text_qualified_versions.join('\n'));
  return <Dialog title={creating ? t('catalogAddNativeTool') : initial.id} close={close} side="right"><form className="form-grid catalog-editor" onSubmit={event => { event.preventDefault(); save({ ...draft, qualified_versions: list(versions), telemetry_text_qualified_versions: list(textVersions) }); }}><fieldset disabled={readOnly}>
    <label>{t('identifier')}<select required value={draft.id} onChange={event => setDraft({ ...draft, id: event.target.value })}><option value="">{t('select')}</option><option value="claude-code">claude-code</option><option value="codex">codex</option><option value="claude-desktop">claude-desktop</option></select></label>
    <label>{t('catalogPlatform')}<select required value={draft.platform} onChange={event => setDraft({ ...draft, platform: event.target.value })}><option value="">{t('select')}</option><option value="windows">Windows</option><option value="linux">Linux</option></select></label>
    <label>{t('catalogParser')}<select required value={draft.parser} onChange={event => setDraft({ ...draft, parser: event.target.value })}><option value="">{t('select')}</option><option value="otlp-v1">otlp-v1</option><option value="claude-desktop-v1">claude-desktop-v1</option></select></label>
    <label>{t('catalogQualifiedVersions')}<textarea maxLength={8320} value={versions} onChange={event => setVersions(event.target.value)} /></label>
    <label>{t('catalogTextQualifiedVersions')}<textarea maxLength={8320} value={textVersions} onChange={event => setTextVersions(event.target.value)} /></label>
  </fieldset><div className="dialog-actions"><Button onClick={close}>{t(readOnly ? 'close' : 'cancel')}</Button>{!readOnly && <Button variant="primary" type="submit">{t('saveChanges')}</Button>}</div></form></Dialog>;
}

function BulkDialog({ kind, count, close, save }: Readonly<{ kind: Kind; count: number; close: () => void; save: (field: string, value: string) => void }>) {
  const t = useText();
  const fields: Record<string, TranslationKey> = kind === 'browser'
    ? { qualified_at: 'catalogQualifiedAt', conversation_path: 'catalogConversationPath', conversation_segment: 'catalogConversationSegment', ...domLabels }
    : { platform: 'catalogPlatform', parser: 'catalogParser', qualified_versions: 'catalogQualifiedVersions', telemetry_text_qualified_versions: 'catalogTextQualifiedVersions' };
  const [field, setField] = useState(Object.keys(fields)[0]), [value, setValue] = useState('');
  let valueControl = <input type={field === 'conversation_segment' ? 'number' : 'text'} required={field === 'qualified_at' || field === 'conversation_segment'} min={0} max={16} maxLength={field in domLabels ? 512 : 256} value={value} onChange={event => setValue(event.target.value)} />;
  if (field.endsWith('versions')) valueControl = <textarea maxLength={8320} value={value} onChange={event => setValue(event.target.value)} />;
  if (field === 'platform' || field === 'parser') valueControl = <select required value={value} onChange={event => setValue(event.target.value)}><option value="">{t('select')}</option>{(field === 'platform' ? ['windows', 'linux'] : ['otlp-v1', 'claude-desktop-v1']).map(option => <option key={option}>{option}</option>)}</select>;
  return <Dialog title={t('catalogEditSelected')} close={close}><form className="form-grid" onSubmit={event => { event.preventDefault(); save(field, value); }}>
    <p>{t('catalogSelection', [count])}. {t('catalogBulkHint')}</p>
    <label>{t('catalogBulkField')}<select value={field} onChange={event => { setField(event.target.value); setValue(''); }}>{Object.entries(fields).map(([key, label]) => <option key={key} value={key}>{t(label)}</option>)}</select></label>
    <label>{t('catalogBulkValue')}{valueControl}</label>
    <div className="dialog-actions"><Button onClick={close}>{t('cancel')}</Button><Button variant="primary" type="submit">{t('apply')}</Button></div>
  </form></Dialog>;
}

function HeuristicsDialog({ initial, close, save }: Readonly<{ initial: Content['heuristics']; close: () => void; save: (value: Content['heuristics']) => void }>) {
  const t = useText(), [keys, setKeys] = useState(initial.keys.join('\n')), [types, setTypes] = useState(initial.mime_types.join('\n'));
  return <Dialog title={t('catalogHeuristics')} close={close} side="right"><form className="form-grid" onSubmit={event => { event.preventDefault(); save({ keys: list(keys), mime_types: list(types) }); }}>
    <label>{t('catalogHeuristicKeys')}<textarea maxLength={1040} value={keys} onChange={event => setKeys(event.target.value)} /></label>
    <label>{t('catalogMimeTypes')}<textarea maxLength={272} value={types} onChange={event => setTypes(event.target.value)} /></label>
    <div className="dialog-actions"><Button onClick={close}>{t('cancel')}</Button><Button variant="primary" type="submit">{t('saveChanges')}</Button></div>
  </form></Dialog>;
}

function parseEnvelope(input: string, invalidMessage: string): Envelope {
  if (input.length > 1500000) throw new ApiError(400, 'invalid_catalog', invalidMessage);
  const value = JSON.parse(input) as Envelope;
  if (!value || typeof value.payload !== 'string' || typeof value.signature !== 'string' || Object.keys(value).some(key => !['payload', 'signature'].includes(key))) {
    throw new ApiError(400, 'invalid_catalog', invalidMessage);
  }
  return value;
}

function ImportDialog({ initial, content, close, onPublished }: Readonly<{ initial: Catalog; content: Content; close: () => void; onPublished: (value: Catalog) => void }>) {
  const t = useText(), mutation = useMutation(), inputRevision = useRef(0);
  const [input, setInput] = useState(''), [envelope, setEnvelope] = useState<Envelope>(), [imported, setImported] = useState<Content>(), [error, setError] = useState<unknown>();
  async function importCatalog(publish: boolean) {
    const revision = inputRevision.current; setError(undefined);
    try {
      const value = publish ? envelope : parseEnvelope(input, t('catalogInvalidEnvelope'));
      if (!value) return;
      const result = await mutation.run<Catalog & { published: boolean }>('/api/detection/catalog/import', 'POST', { expected_revision: initial.revision, envelope: value, publish });
      if (!result?.content || (!publish && revision !== inputRevision.current)) return;
      if (publish) {
        if (!result.published) throw new ApiError(400, 'invalid_catalog', t('catalogInvalidEnvelope'));
        onPublished(result);
      } else { setEnvelope(value); setImported(result.content); }
    } catch (error_) { if (publish || revision === inputRevision.current) setError(error_ instanceof SyntaxError ? new ApiError(400, 'invalid_catalog', t('catalogInvalidEnvelope')) : error_); }
  }
  return <Dialog title={t('catalogSignedImport')} close={() => { if (!mutation.pending) close(); }} side="right"><div className="dialog-body">
    <ErrorNotice error={mutation.error} /><ErrorNotice error={error} />
    {JSON.stringify(content) !== JSON.stringify(initial.content) && <Notice tone="warning">{t('catalogImportReplace')}</Notice>}
    <label>{t('catalogSignedEnvelope')}<textarea maxLength={1500000} value={input} onChange={event => { inputRevision.current++; setInput(event.target.value); setEnvelope(undefined); setImported(undefined); }} /></label>
    <Button disabled={mutation.pending || !input.trim()} onClick={() => void importCatalog(false)}>{t('catalogVerifyImport')}</Button>
    {imported && <><h3>{t('catalogChanges')}</h3><ul>{imported.providers.map(provider => <li key={provider.id}>{provider.label} ({provider.domains.join(', ')})</li>)}</ul><details><summary>{t('catalogRawChanges')}</summary><pre className="catalog-preview">{JSON.stringify({ before: initial.content, after: imported }, null, 2)}</pre></details></>}
    <div className="dialog-actions"><Button disabled={mutation.pending} onClick={close}>{t('cancel')}</Button>{imported && <Button variant="primary" disabled={mutation.pending} onClick={() => void importCatalog(true)}>{t('catalogPublish')}</Button>}</div>
  </div></Dialog>;
}
