import { useContext, useMemo, useState } from 'react';
import { Context, Empty, ErrorNotice, Notice, ResourceView, can, readOnly, useMutation, useResource, useText } from '../ui';
import type { Privacy } from '../PrivacyDetectionPage';
import { CATEGORY_LABELS, PLATFORM_CATEGORIES, PLATFORM_CATEGORY, type PlatformCategory } from './platformCategories';

// The server sends what this edition does NOT capture in full: a platform it covers can
// never reach Discovery, so a switch for it would decide nothing.
type Platform = { id: string; label: string; domains: string[]; paths?: string[]; muted: boolean };

/** Which platforms Discovery is allowed to name, and whether Discovery runs at all.
 *
 * Hiding a platform is a reading choice, not a change to detection: the visit is still
 * recorded, so bringing it back shows its history rather than starting a new one. That is
 * also why the mute does not travel through the signed catalogue -- a toggle there would
 * mean a new revision redistributed to every machine each time an administrator changes
 * their mind about one row.
 */
export function KnownPlatformsPanel() {
  const t = useText();
  // `busy` also carries the freeze of a demo instance: the list of
  // platforms stays fully readable, only the checkbox that mutes becomes
  // inert.
  const { session } = useContext(Context);
  const resource = useResource<{ platforms: Platform[] }>('/api/detection/platforms');
  const mutation = useMutation();
  const [query, setQuery] = useState('');
  // The server is the authority; this only keeps the checkbox from lagging a round trip
  // behind the click on a list this long.
  const [pending, setPending] = useState<Record<string, boolean>>({});

  async function toggle(platform: Platform, muted: boolean) {
    setPending(current => ({ ...current, [platform.id]: muted }));
    try { await mutation.run('/api/detection/platforms', 'PATCH', { id: platform.id, muted }); resource.reload(); }
    catch { setPending(current => { const next = { ...current }; delete next[platform.id]; return next; }); }
  }

  return <div className="platform-admin">
    <DiscoverySwitch />
    <Notice>{t('platformsNotice')}</Notice>
    {session.edition === 'community' && <p className="field-help">{t('platformsEnterpriseBlocking')}</p>}
    <ErrorNotice error={mutation.error} />
    <ResourceView resource={resource}>{data => <PlatformList
      platforms={data.platforms} query={query} setQuery={setQuery}
      pending={pending} busy={mutation.pending || readOnly(session)} toggle={toggle} t={t} />}</ResourceView>
  </div>;
}

/** Candidate discovery, moved here from Privacy on 2026-09-16 so the switch is read next
 *  to the platforms it feeds. It still writes through PUT /api/privacy, which is what
 *  demands `settings.manage`, a fresh second factor and a written reason -- so the whole
 *  flow moved, not just the checkbox. Someone with policy.manage alone would only get a
 *  403 on save, so they are shown the state and not the control. */
function DiscoverySwitch() {
  const t = useText();
  const { session, refreshSession } = useContext(Context);
  const resource = useResource<Privacy>('/api/privacy');
  const mutation = useMutation();
  const [reason, setReason] = useState('');
  const editable = can(session, 'settings.manage');

  async function save(privacy: Privacy, enabled: boolean) {
    // The whole document is sent back, as Privacy does: a partial write would reset the
    // settings this screen never shows. `revision` is the one read here, so a change made
    // elsewhere meanwhile is refused rather than overwritten.
    try {
      await mutation.run('/api/privacy', 'PUT', { config: { ...privacy.config, discovery_enabled: enabled }, revision: privacy.revision, reason: reason.trim() });
      window.dispatchEvent(new Event('milvago:privacy-changed'));
      await refreshSession();
      setReason('');
      resource.reload();
    } catch { /* Visible server error. */ }
  }

  return <ResourceView resource={resource}>{privacy => <section className="platform-discovery">
    <ErrorNotice error={mutation.error} />
    {privacy.locked_by && <Notice tone="warning" title={t('configurationLocked')} />}
    <label className="checkbox-label">
      <input type="checkbox" checked={privacy.config.discovery_enabled} disabled={!editable || mutation.pending || !!privacy.locked_by || reason.trim().length < 8}
        onChange={event => void save(privacy, event.target.checked)} />
      <span>{t('discoveryEnabled')}</span>
    </label>
    <Notice>{t('privacyDiscoveryNotice')}</Notice>
    {/* The help sits outside the label, as it does on the Privacy form: inside, it would
        be read as part of the field's accessible name. */}
    {editable && !privacy.locked_by && <><label>{t('privacyChangeReason')}
      <textarea required minLength={8} maxLength={1000} value={reason} onChange={event => setReason(event.target.value)} />
    </label><small className="field-help">{t('privacyChangeReasonHelp')}</small></>}
  </section>}</ResourceView>;
}

function PlatformList({ platforms, query, setQuery, pending, busy, toggle, t }: Readonly<{
  platforms: Platform[]; query: string; setQuery: (value: string) => void;
  pending: Record<string, boolean>; busy: boolean;
  toggle: (platform: Platform, muted: boolean) => void; t: ReturnType<typeof useText>;
}>) {
  const term = query.trim().toLowerCase();
  const groups = useMemo(() => {
    const matching = term
      ? platforms.filter(p => p.label.toLowerCase().includes(term) || p.domains.some(d => d.includes(term)))
      : platforms;
    // A catalogue may name a platform this build predates, so an unmapped id is grouped
    // rather than dropped -- silently losing a row from a list of choices would leave a
    // platform impossible to hide with no way to tell.
    const byCategory = new Map<PlatformCategory | 'other', Platform[]>();
    for (const platform of matching) {
      const category = PLATFORM_CATEGORY[platform.id] ?? 'other';
      const bucket = byCategory.get(category);
      if (bucket) bucket.push(platform); else byCategory.set(category, [platform]);
    }
    return [...PLATFORM_CATEGORIES, 'other' as const]
      .map(category => ({ category, items: byCategory.get(category) ?? [] }))
      .filter(group => group.items.length > 0);
  }, [platforms, term]);

  const hidden = platforms.filter(p => (pending[p.id] ?? p.muted)).length;
  if (!platforms.length) return <Empty title={t('platformsNone')}>{t('platformsNoneHint')}</Empty>;

  return <>
    <div className="platform-toolbar">
      <label className="platform-search">{t('platformsSearch')}
        <input type="search" value={query} onChange={event => setQuery(event.target.value)} placeholder={t('platformsSearchPlaceholder')} />
      </label>
      <p className="muted">{t('platformsSummary', [platforms.length, hidden])}</p>
    </div>
    {groups.length
      ? groups.map(group => <section className="platform-group" key={group.category}>
        <h3>{group.category === 'other' ? t('platformCategoryOther') : t(CATEGORY_LABELS[group.category])}<span className="platform-count">{group.items.length}</span></h3>
        <ul>{group.items.map(platform => {
          const muted = pending[platform.id] ?? platform.muted;
          return <li key={platform.id} className={muted ? 'platform-row muted-platform' : 'platform-row'}>
            <label className="checkbox-label">
              <input type="checkbox" aria-label={platform.label} checked={!muted} disabled={busy} onChange={event => toggle(platform, !event.target.checked)} />
              <span>
                <strong>{platform.label}</strong>
                <small>{platform.domains.join(', ')}{platform.paths?.length ? ' ' + platform.paths.join(' ') : ''}</small>
              </span>
            </label>
          </li>;
        })}</ul>
      </section>)
      : <Empty title={t('platformsNoMatch')} />}
  </>;
}
