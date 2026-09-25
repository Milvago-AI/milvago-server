import { useEffect, useId, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import type { Session } from './api';
import { Dialog, Icon, can, canAnalyze } from './ui';
import type { IconName, Translate } from './ui';

// `report` is the printable synthesis. It has no navigation entry on purpose: it is
// reached from the export control of the map and of the conversations, always with a
// scope in the hash, and it renders outside this shell so it prints clean.
export type Page = 'overview' | 'map' | 'events' | 'devices' | 'groups' | 'applications' | 'settings' | 'members' | 'roles' | 'audit' | 'shadow' | 'organizations' | 'observability' | 'profile' | 'privacy' | 'reports' | 'discovery' | 'detection' | 'report';

/** Product name of an edition. The API keeps the internal id "commercial". */
export function editionName(edition: Session['edition']): string {
  return edition === 'community' ? 'Community' : 'Enterprise';
}

function initials(session: Session) {
  const source = session.user.display_name || session.user.email;
  const parts = source.split(/[\s@._-]+/).filter(Boolean);
  return ((parts[0]?.[0] ?? '') + (parts[1]?.[0] ?? '')).toUpperCase() || '·';
}

type Organization = Session['organizations'][number];
type OrganizationNode = { organization: Organization; children: OrganizationNode[] };

/** Nests accessible organizations under their parent; an organization whose parent is not accessible is listed at the root. */
function organizationTree(organizations: Organization[]): OrganizationNode[] {
  const nodes = new Map(organizations.map(organization => [organization.id, { organization, children: [] as OrganizationNode[] }]));
  const roots: OrganizationNode[] = [];
  for (const node of nodes.values()) {
    const parent = node.organization.parent_id ? nodes.get(node.organization.parent_id) : undefined;
    (parent && parent !== node ? parent.children : roots).push(node);
  }
  const sort = (list: OrganizationNode[]): OrganizationNode[] => {
    list.sort((a, b) => a.organization.name.localeCompare(b.organization.name));
    list.forEach(node => sort(node.children));
    return list;
  };
  return sort(roots);
}

/** Enterprise only: current organization as a button; the hierarchical picker opens in a right-hand drawer. */
function OrganizationSwitcher({ session, switching, switchOrganization, t }: Readonly<{ session: Session; switching: boolean; switchOrganization: (id: string) => void; t: Translate }>) {
  const [open, setOpen] = useState(false);
  const list = useRef<HTMLDivElement>(null);
  const id = useId();
  const tree = useMemo(() => organizationTree(session.organizations), [session.organizations]);
  // Runs after the drawer's own effect (showModal), so the current organization ends up focused.
  useEffect(() => { if (open) list.current?.querySelector<HTMLElement>('[aria-current="true"]')?.focus(); }, [open]);
  function select(organization: Organization) {
    setOpen(false);
    if (organization.id !== session.organization.id) switchOrganization(organization.id);
  }
  const renderNodes = (nodes: OrganizationNode[], depth: number): ReactNode => nodes.map(({ organization, children }) => {
    const current = organization.id === session.organization.id;
    return (
      <li key={organization.id}>
        <button type="button" className="org-tree-item" aria-current={current ? 'true' : undefined} title={organization.name} onClick={() => select(organization)}>
          <Icon name={depth === 0 ? 'building' : 'corner'} />
          <span className="org-name">{organization.name}</span>
          <span className="org-role">{organization.role}</span>
          {current && <Icon name="check" />}
        </button>
        {children.length > 0 && <ul className="org-tree-group">{renderNodes(children, depth + 1)}</ul>}
      </li>
    );
  });
  return (
    <div className="org">
      <span className="org-label" id={`${id}-label`}>{t("organization")}</span>
      <button type="button" className="org-button" aria-haspopup="dialog" aria-expanded={open} aria-labelledby={`${id}-label ${id}-name`} disabled={switching} onClick={() => setOpen(true)}>
        <Icon name="building" />
        <span className="org-name" id={`${id}-name`}>{session.organization.name}</span>
        <Icon name="chevron-right" />
      </button>
      {open && (
        <Dialog title={t("chooseAnOrganization")} close={() => setOpen(false)} side="right">
          <div ref={list} className="dialog-body org-tree">
            <p>{t("childOrganizationsAreGroupedUnderTheir")}</p>
            <ul>{renderNodes(tree, 0)}</ul>
          </div>
        </Dialog>
      )}
    </div>
  );
}

type NavItem = { page: Page; icon: IconName; href: string };
function administrationItems(session: Session): NavItem[] {
  // Administration entries retain their individual access controls.
  const administration: NavItem[] = [];
  if (can(session, 'members.read')) administration.push({ page: 'members', icon: 'users', href: '#members' });
  // A restricted Community instance has no rights management: the server itself
  // refuses role writes with license_restricted, so the entry would only lead to a refusal.
  if (can(session, 'roles.manage') && !session.license?.restricted) administration.push({ page: 'roles', icon: 'lock', href: '#roles' });
  if (can(session, 'policy.manage')) administration.push({ page: 'shadow', icon: 'eye', href: '#shadow' });
  // The catalogue editor publishes for the whole instance, so only the root owner can
  // use it and only an operator ever needs it. It appears when the instance runs with
  // MILVAGO_DEBUG; the server closes the routes that write a catalogue on the same
  // flag, so this is decluttering, not the access control.
  if (can(session, 'policy.manage') && session.console_debug) administration.push({ page: 'detection', icon: 'activity', href: '#detection' });
  if (can(session, 'settings.manage') || can(session, 'identity.erase')) administration.push({ page: 'privacy', icon: 'shield', href: '#privacy' });
  if (session.edition === 'commercial') administration.push({ page: 'organizations', icon: 'building', href: '#organizations' });
  if (can(session, 'audit.read')) administration.push({ page: 'audit', icon: 'scroll', href: '#audit' });
  if (session.edition === 'commercial' && can(session, 'observability.manage')) administration.push({ page: 'observability', icon: 'activity', href: '#observability' });
  administration.push({ page: 'settings', icon: 'settings', href: '#settings' });
  return administration;
}

export function Shell({ session, page, pageNames, theme, toggleTheme, logout, switching, switchOrganization, t, children }: Readonly<{
  session: Session; page: Page; pageNames: Record<Page, string>; theme: 'light' | 'dark'; toggleTheme: () => void;
  logout: () => void; switching: boolean; switchOrganization: (id: string) => void; t: Translate; children: ReactNode;
}>) {
  const [open, setOpen] = useState(false);
  // Desktop only: the sidebar folds into an icon rail. A per-browser convenience, so a
  // storage failure simply means it starts unfolded.
  const [collapsed, setCollapsed] = useState(() => { try { return localStorage.getItem('milvago.sidebar') === 'collapsed'; } catch { return false; } });
  function toggleCollapsed() {
    const next = !collapsed;
    setCollapsed(next);
    try { localStorage.setItem('milvago.sidebar', next ? 'collapsed' : 'expanded'); } catch { /* optional */ }
  }
  useEffect(() => { setOpen(false); }, [page]);
  useEffect(() => {
    if (!open) return;
    const key = (event: KeyboardEvent) => { if (event.key === 'Escape') setOpen(false); };
    window.addEventListener('keydown', key);
    return () => window.removeEventListener('keydown', key);
  }, [open]);
  const administration = administrationItems(session);
  const groups: { label: string; items: { page: Page; icon: IconName; href: string }[] }[] = [
    // AI Applications moved from Fleet to Monitoring (product decision,
    // 2026-09-17): the screen answers "which AIs are running for me", not "what is
    // this device's state". It stays Enterprise only -- `/api/tools` does not exist
    // elsewhere -- and under the same analysis guard as before.
    //
    // Icon `apps` (application window) rather than `list`: the screen sat next to Conversations
    // with the same one, and two entries in the same section carrying the same icon
    // become indistinguishable. Not a grid either -- `layout-grid` is indistinguishable from
    // the `layout-dashboard` of Overview at 16px, which would only move the
    // collision from one neighbor to the other. Measured, not assumed: `scratchpad/icon-strip.mjs`
    // renders the rail's icons and the candidates at actual size.
    { label: t("monitoring"), items: [{ page: 'overview', icon: 'dashboard', href: '#overview' }, { page: 'map', icon: 'map', href: '#map' }, { page: 'events', icon: 'list', href: '#events' }, ...(session.edition === 'commercial' && canAnalyze(session) ? [{ page: 'applications' as Page, icon: 'apps' as IconName, href: '#applications' }] : []), ...(can(session, 'policy.manage') ? [{ page: 'discovery' as Page, icon: 'search' as IconName, href: '#discovery' }] : []), ...(can(session, 'reports.aggregate') ? [{ page: 'reports' as Page, icon: 'scroll' as IconName, href: '#reports' }] : [])] },
    { label: t("fleet"), items: [{ page: 'devices', icon: 'device', href: '#devices' }, { page: 'groups', icon: 'users', href: '#groups' }] },
    { label: t("administration"), items: administration },
  ];
  const analyst = canAnalyze(session);
  const edition = editionName(session.edition);
  // The logo never takes the accent: monochrome white on the dark rendering,
  // monochrome black on the light one (charte graphique v2.0, ch. 02).
  const brand = (
    <a className="brand" href="#overview" aria-label="Milvago">
      <img
        src={theme === 'light' ? '/milvago-symbol-mono-black.svg' : '/milvago-symbol-mono-white.svg'}
        alt=""
        width="28"
        height="28"
      />
      <span className="brand-name">Milvago</span>
    </a>
  );
  return (
    <div className={`shell${collapsed ? ' collapsed' : ''}`}>
      <div className={`overlay${open ? ' open' : ''}`} onClick={() => setOpen(false)} aria-hidden="true" />
      <aside className={`sidebar${open ? ' open' : ''}`} id="sidebar">
        <div className="brand-row">
          {brand}
          <span className="edition">{edition}</span>
          <button className="icon-button brand-close" onClick={() => setOpen(false)} aria-label={t("closeMenu")}><Icon name="close" /></button>
        </div>
        {session.edition === 'commercial' && (
          <OrganizationSwitcher session={session} switching={switching} switchOrganization={switchOrganization} t={t} />
        )}
        <nav className="nav" aria-label={t("mainNavigation")}>
          {groups.map(group => {
            const items = group.items.filter(item => (!['events', 'map'].includes(item.page) || analyst) && (!['devices', 'groups'].includes(item.page) || (!session.privacy?.aggregate_only && can(session, 'devices.read'))) && (item.page !== 'overview' || can(session, 'overview.read')));
            if (!items.length) return null;
            return (
              <div className="nav-group" key={group.label}>
                <span className="nav-label">{group.label}</span>
                {items.map(item => (
                  <a key={item.page} className="nav-item" href={item.href} aria-current={page === item.page ? 'page' : undefined} title={collapsed ? pageNames[item.page] : undefined}>
                    <Icon name={item.icon} />
                    <span>{pageNames[item.page]}</span>
                  </a>
                ))}
              </div>
            );
          })}
        </nav>
        <div className="sidebar-footer">
          <a className="user" href="#profile" aria-current={page === 'profile' ? 'page' : undefined}>
            <span className="avatar" aria-hidden="true">{initials(session)}</span>
            <div className="user-meta">
              <span className="user-name">{session.user.display_name || session.user.email}</span>
              <span className="user-role">{session.organization.role}</span>
            </div>
          </a>
          {/* The console language is an account setting, changed from the profile
              form reached through the user block above (product decision, 2026-09-11). */}
          <div className="sidebar-tools">
            <button className="icon-button" onClick={toggleTheme} aria-label={theme === 'light' ? t("switchToDarkTheme") : t("switchToLightTheme")}>
              <Icon name={theme === 'light' ? 'moon' : 'sun'} />
            </button>
            <button className="icon-button sidebar-toggle" onClick={toggleCollapsed} aria-expanded={!collapsed} aria-controls="sidebar" aria-label={collapsed ? t("expandSidebar") : t("collapseSidebar")} title={collapsed ? t("expandSidebar") : t("collapseSidebar")}>
              <Icon name={collapsed ? 'panel-open' : 'panel-close'} />
            </button>
            <span className="spacer" />
            <button className="icon-button" onClick={logout} disabled={switching} aria-label={t("signOut")} title={t("signOut")}>
              <Icon name="logout" />
            </button>
          </div>
        </div>
      </aside>
      <div className="main-column">
        <div className="mobile-bar">
          <button className="icon-button" onClick={() => setOpen(true)} aria-label={t("menu")} aria-expanded={open} aria-controls="sidebar"><Icon name="menu" /></button>
          {brand}
          <span className="edition">{edition}</span>
        </div>
        <main id="content" className="main" tabIndex={-1}>{children}</main>
      </div>
    </div>
  );
}
