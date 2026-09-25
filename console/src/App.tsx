import { AliasRotation } from "./AliasRotation";
import { ObservabilityPage } from "./ObservabilityPage";
import { PrivacyPanel, ReportsPanel, DetectionPanel, CoverageNotice } from "./PrivacyDetectionPage";
import { DiscoveryPage } from "./DiscoveryPage";
import { SetupWizard } from "./SetupWizard";
import { SetupPage } from "./SetupPage";
import type { SetupStatus } from "./SetupPage";
import { CartographyPage } from "./shadow/CartographyPage";
import { ReportPage } from "./shadow/ReportPage";
import { ConversationsPage } from "./shadow/ConversationsPage";
import { ShadowAdministration, ScopedSettings } from "./shadow/ShadowAdministration";
import { DeviceUpdateStatus } from "./shadow/UpdateStatus";
import { ConnectorRegistrationPanel } from "./ConnectorRegistrationPanel";
import { DeploymentKeyPanel, InstallerDialog } from "./InstallerDialog";
import { RolesPanel } from "./RolesPanel";
import { ProfilePage } from "./ProfilePage";
import { DirectoryCard } from "./DirectoryCard";
import { DirectoryImportDialog } from "./DirectoryImportDialog";
import "./shadow/shadow.css";
import { useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import type { SubmitEvent, ReactNode } from "react";
import { ApiError, request } from "./api";
import { navigate } from "./navigation";
import { Shell, editionName } from "./Shell";
import type { Page } from "./Shell";
import { GroupsPage } from "./GroupsPage";
import type {
  Audit,
  Device,
  DeviceGroup,
  LicenseStatus,
  Member,
  MembersResponse,
  Overview,
  Session,
  Settings,
} from "./api";

import {
  Context,
  useText,
  useResource,
  useMutation,
  Icon,
  Empty,
  ErrorNotice,
  Notice,
  ResourceView,
  DateValue,
  Status,
  can,
  canManage,
  canAnalyze,
  idFromHash,
  useBoundedPage,
  PageBar,
  PageNumbers,
  PageSize,
  RefreshButton,
  Dialog,
  Card,
  Kpi,
  Badge,
  Button,
  Tabs,
  translate,
  isLanguage,
  browserLanguage,
  languages,
  LanguagePicker,
  copyToClipboard,
} from "./ui";
import type { Language, Translate } from "./ui";
import { resumeSecondFactor } from "./secondFactor";
import type { TranslationKey } from "./locales/en";
// A set rather than an array: the only question asked is membership,
// and it is asked on every change of URL fragment.
const pages = new Set<Page>([
  "overview",
  "map",
  "events",
  "devices",
  "groups",
  "applications",
  "settings",
  "members",
  "roles",
  "audit",
  "shadow",
  "organizations",
  "observability",
  "profile",
  "privacy",
  "reports",
  "discovery",
  "detection",
  "report",
]);
function stored(key: string, fallback: string) {
  try {
    return localStorage.getItem(key) ?? fallback;
  } catch {
    return fallback;
  }
}
function persist(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* Preference persistence is optional. */
  }
}
function preferredTheme() {
  const cookie = document.cookie
    .split(";")
    .map((value) => value.trim())
    .find((value) => /^milvago_theme=(light|dark)$/.test(value));
  return cookie?.split("=")[1] ?? stored("milvago.theme", "");
}
function pageFromHash(): Page {
  const value = window.location.hash.slice(1).split("?")[0] as Page;
  return pages.has(value) ? value : "overview";
}

// What each navigation entry renders, and under what condition.
//
// Previously a single chain of nested ternaries carried the eighteen pages
// and their guards: cognitive complexity 368, and a page's guard was only
// readable by counting the parentheses of the ones before it. One entry per page,
// with early returns, says the same thing -- the guard first, the page after --
// and reads back in isolation. No condition changed meaning.
type PageContext = {
  session: Session;
  t: Translate;
  refreshSession: () => Promise<void>;
};

const pageViews: Partial<Record<Page, (context: PageContext) => ReactNode>> = {
  // An organization in aggregate-only mode, or a profile that aggregates without reading
  // devices, has no overview to show: its figures are the report.
  // Without `events.read`, the server itself answers the aggregate report at GET /api/overview
  // (console.go): rendering the overview on that body left the page without its
  // counters and without the reminder of pending devices, silently.
  overview: ({ session, t }) => {
    const aggregateOnly =
      session.privacy?.aggregate_only ||
      !can(session, "events.read") ||
      (can(session, "reports.aggregate") && !can(session, "devices.read"));
    if (!aggregateOnly) return <OverviewPage />;
    if (!can(session, "reports.aggregate"))
      return <Empty title={t("accessRestricted")} />;
    return (
      <>
        <PageBar title={t("reports")} />
        <ReportsPanel />
      </>
    );
  },
  map: ({ session, t }) => {
    if (!canAnalyze(session)) return <Empty title={t("analystAccessRequired")} />;
    return <CartographyPage />;
  },
  events: ({ session, t }) => {
    if (!canAnalyze(session))
      return <Empty title={t("accessRequiresAnAnalystOrAdministrator")} />;
    return <ConversationsPage />;
  },
  devices: ({ session, t }) => {
    if (session.privacy?.aggregate_only || !can(session, "devices.read"))
      return <Empty title={t("accessRestricted")} />;
    return <DevicesPage />;
  },
  groups: ({ session, t }) => {
    if (session.privacy?.aggregate_only || !can(session, "devices.read"))
      return <Empty title={t("accessRestricted")} />;
    return <GroupsPage />;
  },
  applications: ({ session, t }) => {
    if (session.edition !== "commercial" || !canAnalyze(session))
      return <Empty title={t("accessRestricted")} />;
    return <ApplicationsPage />;
  },
  observability: ({ session, t }) => {
    if (session.edition !== "commercial" || !can(session, "observability.manage"))
      return <Empty title={t("accessRestricted")} />;
    return <ObservabilityPage />;
  },
  settings: ({ t }) => (
    <>
      <PageBar title={t("settings")} info={t("organizationAndInstanceSettings")} />
      <SettingsPanel />
    </>
  ),
  members: ({ session, t }) => {
    if (!can(session, "members.read")) return <Empty title={t("accessRestricted")} />;
    return (
      <>
        <PageBar title={t("members")} />
        <MembersPanel />
      </>
    );
  },
  roles: ({ session, t }) => {
    if (!can(session, "roles.manage")) return <Empty title={t("ownerAccessRequired")} />;
    return (
      <>
        <PageBar title={t("roles")} info={t("defineRolesAndTheirPermissions")} />
        <RolesPanel />
      </>
    );
  },
  audit: ({ session, t }) => {
    if (!can(session, "audit.read")) return <Empty title={t("ownerAccessRequired")} />;
    return (
      <>
        <PageBar title={t("auditLog")} />
        <AuditPanel />
      </>
    );
  },
  // Erasing an identity without being able to manage privacy gives alias
  // rotation alone: the page exists, its content follows the stronger right.
  privacy: ({ session, t, refreshSession }) => {
    const manages = can(session, "settings.manage");
    if (!manages && !can(session, "identity.erase"))
      return <Empty title={t("accessRestricted")} />;
    return (
      <>
        <PageBar title={t("privacy")} />
        {manages ? <PrivacyPanel /> : <AliasRotation done={() => void refreshSession()} />}
      </>
    );
  },
  reports: ({ session, t }) => {
    if (!can(session, "reports.aggregate")) return <Empty title={t("accessRestricted")} />;
    return (
      <>
        <PageBar title={t("reports")} />
        <ReportsPanel />
      </>
    );
  },
  discovery: ({ session, t }) => {
    if (!can(session, "policy.manage")) return <Empty title={t("accessRestricted")} />;
    return (
      <>
        <PageBar title={t("discovery")} />
        <DiscoveryPage />
      </>
    );
  },
  // The URL fragment is typed as easily as a link is followed: the flag is
  // checked here too, and not only where the navigation entry is built.
  detection: ({ session, t }) => {
    if (!can(session, "policy.manage") || !session.console_debug)
      return <Empty title={t("accessRestricted")} />;
    return (
      <>
        <PageBar title={t("detectionCatalog")} />
        <DetectionPanel />
      </>
    );
  },
  shadow: ({ session, t }) => {
    if (!can(session, "policy.manage")) return <Empty title={t("accessRestricted")} />;
    return <ShadowAdministration />;
  },
  organizations: ({ session, t }) => {
    if (session.edition !== "commercial") return <Empty title={t("enterpriseEditionOnly")} />;
    return (
      <>
        <PageBar title={t("organizations")} />
        <OrganizationsPanel />
      </>
    );
  },
  profile: () => <ProfilePage />,
};
export function App() {
  const [language, setLanguage] = useState<Language>(() => {
    const remembered = stored("milvago.language", "");
    return isLanguage(remembered) ? remembered : browserLanguage();
  });
  const explicitLanguage = useRef(stored("milvago.language", ""));
  // Signed-out page only: once signed in, the language is an account setting
  // changed from the profile form, and the sidebar offers no shortcut for it
  // (product decision, 2026-09-11).
  const chooseLanguage = (next: Language) => {
    explicitLanguage.current = next;
    persist("milvago.language", next);
    setLanguage(next);
  };
  // Dark is the brand's default rendering (charte graphique v2.0): the system
  // setting is not consulted, only an explicit choice by this reader.
  const [theme, setTheme] = useState(() =>
    preferredTheme() === "light" ? "light" : "dark",
  );
  const [session, setSession] = useState<Session>();
  // Edition of this instance as served publicly, for the signed-out entry page.
  const [publicEdition, setPublicEdition] = useState<Session["edition"]>();
  // An instance without any administrator shows the setup wizard instead of the entry page.
  const [setupStatus, setSetupStatus] = useState<SetupStatus>();
  const [sessionError, setSessionError] = useState<unknown>();
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState<Page>(pageFromHash);
  const [switching, setSwitching] = useState(false);
  const [actionError, setActionError] = useState<unknown>();
  const t: Translate = (key, params) => translate(language, key, params);
  const refreshSession = useCallback(async () => {
    setSessionError(undefined);
    try {
      const updated = await request<Session>("/api/session");
      // The language stored on the account wins; without one, this browser's
      // explicit choice on the signed-out page; without that, the language the
      // browser itself asks for, and English when it asks for none we serve
      // (product decision, 2026-09-17 — the instance default no longer takes part:
      // "Default" on an account now means "follow this reader's browser", which
      // is the only thing that can be right for every reader of one instance).
      // Every step is applied, not just guarded: the profile form is the only
      // signed-in way to change the language, so clearing the account language
      // ("Default") must fall back right away rather than leave the last saved
      // language on screen until the next load.
      //
      // Every test here goes through isLanguage(). Spelling the accepted values
      // out is what silently dropped Spanish and Brazilian Portuguese: a
      // remembered "es" was not in ["fr","en"], so the guard read as "no explicit
      // choice" and overwrote it. One predicate, fed by the language list itself.
      if (isLanguage(updated.user.language ?? ""))
        setLanguage(updated.user.language as Language);
      else if (isLanguage(explicitLanguage.current))
        setLanguage(explicitLanguage.current);
      else
        setLanguage(browserLanguage());
      setSession(updated);
    } catch (e) {
      if (!(e instanceof ApiError && e.status === 401)) setSessionError(e);
      setSession(undefined);
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    // Only the edition is read here now: the signed-out page renders this
    // browser's explicit choice, else its own language, both of which are known
    // before any request answers.
    request<{ edition: Session["edition"] }>("/api/bootstrap", { signal: controller.signal })
      .then(value => {
        if (controller.signal.aborted) return;
        setPublicEdition(value.edition);
      }).catch(() => { /* The resolved language already stands. */ });
    request<SetupStatus>("/api/setup", { signal: controller.signal })
      .then(value => { if (!controller.signal.aborted) setSetupStatus(value); })
      .catch(() => { /* Without an answer, the entry page stands. */ });
    return () => controller.abort();
  }, []);
  useEffect(() => {
    void refreshSession();
    const unauthorized = () => setSession(undefined);
    window.addEventListener("milvago:unauthorized", unauthorized);
    return () =>
      window.removeEventListener("milvago:unauthorized", unauthorized);
  }, [refreshSession]);
  useEffect(() => {
    const changed = () => setPage(pageFromHash());
    window.addEventListener("hashchange", changed);
    return () => window.removeEventListener("hashchange", changed);
  }, []);
  useEffect(() => {
    document.documentElement.lang = language;
  }, [language]);
  // Coming back from a second-factor verification: replay the one call it was demanded
  // for, then show the page as the server now has it. Attempted once, and only while a
  // session is loaded — the replay carries its CSRF token.
  const resumed = useRef(false);
  useEffect(() => {
    if (resumed.current || !session?.csrf_token) return;
    resumed.current = true;
    void resumeSecondFactor(session.csrf_token, { org: session.organization.id, user: session.user.id }).then(outcome => {
      if (outcome === 'resumed') window.location.reload();
    });
  }, [session]);
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    persist("milvago.theme", theme);
    document.cookie = `milvago_theme=${theme};Path=/;SameSite=Lax${window.location.protocol === "https:" ? ";Secure" : ""}`;
  }, [theme]);
  const pageNames = {
    map: t("cartography"),
    overview: t("overview"),
    events: t("conversations"),
    devices: t("devices"),
    groups: t("groups"),
    applications: t("aiApplications"),
    settings: t("settings"),
    members: t("members"),
    roles: t("roles"),
    audit: t("auditLog"),
    shadow: "Shadow AI",
    organizations: t("organizations"),
    observability: t("observability"),
    profile: t("myProfile"),
    privacy: t("privacy"),
    reports: t("reports"),
    discovery: t("discovery"),
    detection: t("detectionCatalog"),
    report: t("synthesisReport"),
  };
  useEffect(() => {
    document.title = `Milvago — ${pageNames[page]}`;
  }, [page, language]);
  // A fresh object on every render would re-render everything that reads the context, on
  // every keystroke in any screen. The memo has to sit here, before the
  // early returns: a hook cannot live after a conditional `return`.
  // `session` may still be absent at this point; the two providers that read
  // this value are both placed after the `return` that rules out that case.
  const contextValue = useMemo(
    () => ({ language, session: session as Session, refreshSession }),
    [language, session, refreshSession],
  );
  const controls = (
    <div className="preferences">
      <button
        className="icon-button"
        onClick={() => setTheme(theme === "light" ? "dark" : "light")}
        aria-label={
          theme === "light"
            ? t("switchToDarkTheme")
            : t("switchToLightTheme")
        }
      >
        <Icon name={theme === "light" ? "moon" : "sun"} />
      </button>
      <LanguagePicker language={language} choose={chooseLanguage} />
    </div>
  );
  // Entry page: the logo stays monochrome, never tinted with the accent.
  const brand = (
    <a className="brand" href="#overview" aria-label="Milvago">
      <img
        src={theme === "light" ? "/milvago-symbol-mono-black.svg" : "/milvago-symbol-mono-white.svg"}
        alt=""
        width="32"
        height="32"
      />
      <span className="brand-name">Milvago</span>
    </a>
  );
  // As long as the session is not known, assert neither "signed in" nor "signed out".
  // Rendering the landing page during the check made a "Sign in" screen
  // appear right AFTER a successful authentication, for as long as
  // /api/session took to answer: the user saw the opposite of what had just
  // happened, then the console. The header stays, so nothing jumps on screen.
  if (loading)
    return (
      <div className="entry">
        <header className="entry-header">
          {brand}
          {controls}
        </header>
      </div>
    );
  if (!session && setupStatus?.pending)
    return (
      <div className="entry">
        <header className="entry-header">
          {brand}
          {controls}
        </header>
        <Context.Provider value={contextValue}>
          <SetupPage status={setupStatus} language={language} chooseLanguage={chooseLanguage} />
        </Context.Provider>
        <footer className="entry-footer">
          <span>Milvago</span>
          <span>{editionName(setupStatus.edition)}</span>
        </footer>
      </div>
    );
  if (!session)
    return (
      <div className="entry">
        <header className="entry-header">
          {brand}
          {controls}
        </header>
        <main className="entry-main">
          <p className="eyebrow">
            {t("aiUsageInPerspective")}
          </p>
          <h1>
            {t("seeClearly")}
            <br />
            <span>{t("actWithConfidence")}</span>
          </h1>
          <p className="entry-description">
            {t("oneSpaceToUnderstandBrowserUsage")}
          </p>
          {/* `loading` is already false here: the loading render happened higher
              up and left the function. The "checking session" branch
              that used to sit here could therefore never display. */}
          {sessionError ? (
            <div className="notice error" role="alert">
              <p>
                {t("theServerIsUnavailableYourSession")}
              </p>
              <button
                type="button"
                className="button"
                onClick={() => {
                  setLoading(true);
                  void refreshSession();
                }}
              >
                {t("retry")}
              </button>
            </div>
          ) : (
            <div className="entry-cta">
              <a className="button primary login-button" href={t("authLoginLangEn")}>
                {t("signIn")}
                <Icon name="arrow" />
              </a>
              <span className="entry-footnote">
                <Icon name="lock" />
                {t("secureAuthenticationThroughYourIdentityProvi")}
              </span>
            </div>
          )}
        </main>
        <aside className="entry-aside">
          <div className="entry-value">
            <Icon name="eye" />
            <div>
              <strong>{t("observe")}</strong>
              <span>{t("browserAndToolUsageWithoutThe")}</span>
            </div>
          </div>
          <div className="entry-value">
            <Icon name="map" />
            <div>
              <strong>{t("understand")}</strong>
              <span>{t("whoUsesWhatFromPeopleTo")}</span>
            </div>
          </div>
          <div className="entry-value">
            <Icon name="shield" />
            <div>
              <strong>{t("decide")}</strong>
              <span>{t("explicitSignedAndEnforcedRules")}</span>
            </div>
          </div>
        </aside>
        <footer className="entry-footer">
          <span>Milvago</span>
          {publicEdition && <span>{editionName(publicEdition)}</span>}
        </footer>
      </div>
    );
  // Enterprise without a valid licence: every /api route but a short allow-list (this
  // session, switching organization, the licence itself, setup, auth) answers 402, so
  // no other page would render anything real. Shown outside the Shell -- its sidebar
  // links to pages that would all refuse -- with just enough to enter a licence.
  if (session.license?.locked)
    return (
      <Context.Provider value={contextValue}>
        <div className="entry">
          <header className="entry-header">
            {brand}
            {controls}
          </header>
          <main className="entry-main">
            <Notice tone="danger" title={t("licenseLockedTitle")}>{t("licenseLockedBody")}</Notice>
            <LicensePanel />
          </main>
          <footer className="entry-footer">
            <span>Milvago</span>
            <span>{editionName(session.edition)}</span>
          </footer>
        </div>
      </Context.Provider>
    );
  // The printable report renders on its own, outside the shell: a sidebar, a sticky
  // page bar and a mobile bar mean nothing on paper, and hiding them at print time
  // only works for a print the browser announces — `page.pdf()` announces nothing.
  // Same permission as the map it is opened from.
  if (page === "report")
    return (
      <Context.Provider value={contextValue}>
        {canAnalyze(session) ? <ReportPage /> : <Empty title={t("analystAccessRequired")} />}
      </Context.Provider>
    );
  async function switchOrganization(id: string) {
    if (!session) return;
    setSwitching(true);
    setActionError(undefined);
    try {
      await request("/api/session/organization", {
        method: "POST",
        body: { organization_id: id },
        csrf: session.csrf_token,
      });
      await refreshSession();
    } catch (e) {
      setActionError(e);
    } finally {
      setSwitching(false);
    }
  }
  async function logout() {
    if (!session) return;
    setSwitching(true);
    setActionError(undefined);
    try {
      const result = await request<{ ok: boolean; logout_url: string }>(
        "/auth/logout",
        { method: "POST", csrf: session.csrf_token },
      );
      navigate(result.logout_url);
      setSession(undefined);
    } catch (e) {
      setActionError(e);
    } finally {
      setSwitching(false);
    }
  }
  return (
    <Context.Provider value={contextValue}>
      <a className="skip-link" href="#content">
        {t("skipToContent")}
      </a>
      <Shell
        session={session}
        page={page}
        pageNames={pageNames}
        theme={theme as "light" | "dark"}
        toggleTheme={() => setTheme(theme === "light" ? "dark" : "light")}
        logout={() => void logout()}
        switching={switching}
        switchOrganization={(id) => void switchOrganization(id)}
        t={t}
      >
        <ErrorNotice error={actionError} />
        <FirstRunBanner />
        <LicenseBanner />
        {/* Only where figures are read. Elsewhere it would be noise, and on a page with
            no numbers it would warn about nothing the reader is looking at. */}
        {["overview", "map", "events"].includes(page) && can(session, "policy.manage") && <CoverageNotice />}
        <div className="page" key={session.organization.id + ":" + session.permissions.join(",") + ":" + Boolean(session.privacy?.aggregate_only)}>
          {pageViews[page]?.({ session, t, refreshSession }) ?? <OverviewPage />}
        </div>
      </Shell>
    </Context.Provider>
  );
}

function OverviewPage() {
  const t = useText();
  const { language, session } = useContext(Context);
  // One request: the to-do badge reads `pending_devices` from the overview itself. It
  // used to fetch the device listing for that single fleet-wide figure and throw the row
  // away, machine name decrypted and all.
  const resource = useResource<Overview>("/api/overview");
  const number = (n: number) => new Intl.NumberFormat(language).format(n);
  return (
    <>
      <PageBar
        title={t("overview")}
        actions={<RefreshButton onClick={resource.reload} />}
        info={t("aBrowserEventIsNotA")}
      />
      <ResourceView resource={resource}>
        {(data) => {
          const share = data.events
            ? new Intl.NumberFormat(language, { maximumFractionDigits: 1 }).format(
                (data.blocked / data.events) * 100,
              )
            : null;
          const inactive = Math.max(0, data.devices - data.active_devices);
          const pending = data.pending_devices;
          return (
            <>
              {pending > 0 && canManage(session) && (
                <section className="todo" aria-label={t("toDo")}>
                  <div className="todo-row">
                    <Icon name="alert" />
                    <span>
                      <strong>
                        {number(pending)}{" "}
                        {pending > 1
                          ? t("devicesAreWaitingFor")
                          : t("deviceIsWaitingFor")}
                      </strong>{" "}
                      {t("yourApproval")}
                    </span>
                    <span className="spacer" />
                    <a className="button secondary small" href="#devices">
                      {t("viewDevices")}
                      <Icon name="arrow" />
                    </a>
                  </div>
                </section>
              )}
              {data.devices === 0 && (
                <Card
                  title={t("getStarted")}
                  description={t("threeStepsToSeeYourFirst")}
                  flush
                >
                  <div className="steps">
                    <div className="step">
                      <span className="step-n">1</span>
                      <h3 className="step-title">
                        {t("downloadTheAgent")}
                      </h3>
                      <p className="step-desc">
                        {t("theMsiOrRpmPackageIs")}
                      </p>
                      <a className="button secondary small" href="#devices">
                        {t("openDevices")}
                      </a>
                    </div>
                    <div className="step">
                      <span className="step-n later">2</span>
                      <h3 className="step-title">
                        {t("approveTheFirstDevice")}
                      </h3>
                      <p className="step-desc">
                        {t("aDeviceAppearsAsPendingAfter")}
                      </p>
                      <a className="button secondary small" href="#devices">
                        {t("viewDevices")}
                      </a>
                    </div>
                    <div className="step">
                      <span className="step-n later">3</span>
                      <h3 className="step-title">
                        {t("configureServices")}
                      </h3>
                      <p className="step-desc">
                        {t("inShadowAiChooseTheServices")}
                      </p>
                      <a className="button secondary small" href="#shadow">
                        {t("openShadowAi")}
                      </a>
                    </div>
                  </div>
                </Card>
              )}
              <section className="kpis" aria-label={t("metrics")}>
                <Kpi
                  label={t("requests")}
                  icon="list"
                  value={number(data.events)}
                  hint={t("last0Hours1Navigations", [data.period_hours, number(data.navigations)])}
                />
                <Kpi
                  label={t("blocked")}
                  icon="shield"
                  value={number(data.blocked)}
                  tone={data.blocked > 0 ? "danger" : undefined}
                  hint={
                    share !== null
                      ? t("n0OfRequests", [share])
                      : t("accordingToAppliedRules")
                  }
                />
                <Kpi
                  label={t("activeDevices")}
                  icon="device"
                  value={
                    <>
                      {number(data.active_devices)}{" "}
                      <small>/ {number(data.devices)}</small>
                    </>
                  }
                  hint={t("n0InactivePendingOrRevoked", [number(inactive)])}
                />
                <Kpi
                  label={t("observedProviders")}
                  icon="globe"
                  value={number(data.providers.length)}
                  hint={t("overThePeriod")}
                />
              </section>
              <div className="overview-grid">
                <Card
                  title={t("usageRhythm")}
                  description={t("requestsReceivedPerHour")}
                  actions={
                    <div className="legend">
                      <span>
                        <i />
                        {t("observed")}
                      </span>
                      <span className="legend-blocked">
                        <i />
                        {t("blocked")}
                      </span>
                    </div>
                  }
                  footer={
                    <>
                      <span className="muted">
                        {t("observationWindowLast0Hours", [data.period_hours])}
                      </span>
                      <a className="button ghost small" href="#events">
                        {t("openConversations")}
                        <Icon name="arrow" />
                      </a>
                    </>
                  }
                >
                  {data.events === 0 || data.timeline.length === 0 ? (
                    <Empty title={t("noEventsReceived")}>
                      {t("eventsWillAppearAsSoonAs")}
                    </Empty>
                  ) : (
                    <TimelineChart
                      timeline={data.timeline}
                      label={t("n0EventsIncluding1BlockedOver", [data.events, data.blocked, data.period_hours])}
                    />
                  )}
                </Card>
                <Card
                  title={t("observedProviders")}
                  description={t("distributionOfReceivedEvents")}
                  footer={
                    canAnalyze(session) ? (
                      <>
                        <span className="muted">
                          {t("peopleToolsServicesModels")}
                        </span>
                        <a className="button ghost small" href="#map">
                          {t("openCartography")}
                          <Icon name="arrow" />
                        </a>
                      </>
                    ) : undefined
                  }
                >
                  {data.providers.length === 0 ? (
                    <Empty title={t("noProvidersObserved")}>
                      {t("thisListReflectsOnlyEventsActually")}
                    </Empty>
                  ) : (
                    <div className="providers">
                      {data.providers.map((provider) => (
                        <div className="provider" key={provider.name}>
                          <div className="provider-name">
                            <strong>{provider.name}</strong>
                            <div className="provider-track">
                              <span
                                style={{
                                  width: `${data.events ? ((provider.events - provider.blocked) / data.events) * 100 : 0}%`,
                                }}
                              />
                              <span
                                className="blocked"
                                style={{
                                  width: `${data.events ? (provider.blocked / data.events) * 100 : 0}%`,
                                }}
                              />
                            </div>
                          </div>
                          <span className="provider-count">
                            {number(provider.events)}
                            <small>
                              {number(provider.blocked)} {t("blocked2")}
                            </small>
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </Card>
              </div>
            </>
          );
        }}
      </ResourceView>
    </>
  );
}
function TimelineChart({
  timeline,
  label,
}: Readonly<{
  timeline: Overview["timeline"];
  label: string;
}>) {
  const { language } = useContext(Context);
  const width = 760;
  const height = 224;
  const left = 40;
  const top = 12;
  const bottom = 200;
  const max = Math.max(...timeline.map((point) => point.events), 1);
  const step = (width - left) / timeline.length;
  const bar = Math.max(2, Math.min(22, step - 6));
  const every = Math.max(1, Math.ceil(timeline.length / 5));
  const time = (iso: string) =>
    Number.isNaN(Date.parse(iso))
      ? iso
      : new Intl.DateTimeFormat(language, { hour: "2-digit", minute: "2-digit" }).format(new Date(iso));
  return (
    <svg className="chart-svg" viewBox={`0 0 ${width} ${height}`} role="img" aria-label={label}>
      {[0, 0.25, 0.5, 0.75, 1].map((tick) => {
        const y = bottom - tick * (bottom - top);
        return (
          <g key={tick}>
            <line className="grid" x1={left} x2={width} y1={y} y2={y} />
            <text className="axis" x={left - 8} y={y + 4} textAnchor="end">
              {Math.round(max * tick)}
            </text>
          </g>
        );
      })}
      {timeline.map((point, index) => {
        const x = left + index * step + (step - bar) / 2;
        const full = (point.events / max) * (bottom - top);
        const blocked = point.events ? (point.blocked / point.events) * full : 0;
        return (
          <g key={point.hour} className="bar-group">
            <title>{`${time(point.hour)} · ${point.events} / ${point.blocked}`}</title>
            <rect className="bar" x={x} y={bottom - full} width={bar} height={full} />
            <rect className="bar-blocked" x={x} y={bottom - blocked} width={bar} height={blocked} />
            {index % every === 0 && (
              <text className="axis" x={x} y={height - 4}>
                {time(point.hour)}
              </text>
            )}
          </g>
        );
      })}
    </svg>
  );
}

// Detail pages are reached by a UUID in the hash query: #devices?id= and #organizations?id=.
type DeviceArea = "details" | "policy" | "tools";

// The group a device follows. Managers change it here; the group page offers
// the same move for several devices at once through the same endpoint.
function DeviceGroupField({ device, changed }: Readonly<{ device: Device; changed: () => void }>) {
  const t = useText();
  const { session } = useContext(Context);
  const groups = useResource<{ items: DeviceGroup[] }>("/api/groups");
  const mutation = useMutation();
  const [picking, setPicking] = useState(false);
  const link = device.group_id ? (
    <a href={`#groups?id=${device.group_id}`}>{device.group_name || device.group_id}</a>
  ) : (
    <span className="muted">{t("noGroup")}</span>
  );
  const label = device.group_id ? device.group_name || device.group_id : t("noGroup");
  if (!can(session, "devices.manage")) {
    return device.group_id ? <span className="tags"><a className="tag tag-on" href={`#groups?id=${device.group_id}`}>{label}</a></span> : link;
  }
  async function choose(value: string) {
    setPicking(false);
    // Reassigning the same group writes nothing server-side; skip the call so the
    // row does not flash a success for a change that never happened.
    if ((device.group_id ?? "") === value) return;
    try {
      await mutation.run(`/api/devices/${encodeURIComponent(device.id)}/group`, "PUT", { group_id: value || null });
      changed();
    } catch {
      /* Displayed by ErrorNotice. */
    }
  }
  const items = groups.data?.items ?? [];
  return (
    <>
      {/* Closed, the row shows the current group alone; open, it becomes the list of
          groups, where clicking the current one simply closes it again. */}
      {!picking && (
        <span className="tags">
          <button
            type="button"
            className={`tag${device.group_id ? " tag-on" : " tag-empty"}`}
            aria-expanded={false}
            disabled={mutation.pending}
            onClick={() => setPicking(true)}
          >
            {label}
          </button>
          {device.group_id && <a className="tag-link" href={`#groups?id=${device.group_id}`}>{t("openTheGroup")}</a>}
        </span>
      )}
      {picking && (
        <fieldset className="tags" aria-label={t("group")}>
          {items.map((group) => (
            <button
              key={group.id}
              type="button"
              className={`tag${group.id === device.group_id ? " tag-on" : ""}`}
              aria-pressed={group.id === device.group_id}
              disabled={mutation.pending}
              onClick={() => void choose(group.id)}
            >
              {group.name}
            </button>
          ))}
          <button
            type="button"
            className={`tag${device.group_id ? "" : " tag-on"}`}
            aria-pressed={!device.group_id}
            disabled={mutation.pending}
            onClick={() => void choose("")}
          >
            {t("noGroup")}
          </button>
          {!groups.loading && items.length === 0 && <span className="muted">{t("noGroupsYet")}</span>}
        </fieldset>
      )}
      <ErrorNotice error={mutation.error} />
    </>
  );
}

// Which browsers still carry a live extension on this device. Without it, a user
// who disables the extension is indistinguishable from a user who simply never
// uses AI. A browser is called active only if its extension talked to the agent
// recently; anything older is dated rather than presented as present.
const BROWSER_NAMES: Record<string, string> = { chrome: "Chrome", edge: "Edge", firefox: "Firefox", chromium: "Chromium", brave: "Brave" };
function BrowserPresence({ browsers }: Readonly<{ browsers?: Record<string, string> }>) {
  const t = useText();
  const entries = Object.entries(browsers ?? {}).sort(([a], [b]) => a.localeCompare(b));
  if (entries.length === 0) {
    return <span className="muted">{t("noExtensionReported")}</span>;
  }
  const fresh = Date.now() - 15 * 60 * 1000;
  return <>{entries.map(([tool, seen]) => {
    const active = Date.parse(seen) >= fresh;
    return <span key={tool} className="cell-detail">
      {BROWSER_NAMES[tool] ?? tool}{" "}
      {active
        ? <Badge tone="success">{t("active")}</Badge>
        : <Badge tone="warning">{t("silentSince")} <DateValue value={seen} /></Badge>}
    </span>;
  })}</>;
}
// AI applications observed across the organization. A presence is not a use: an
// observation says an application exists on a device, and nothing about whether
// anyone ran it or what they sent.
type Observation = { device_id: string; hostname: string; tool: string; kind: string; observed_at: string; first_seen?: string };
type CatalogEntry = { id: string; name: string; vendor: string; category: string; hosting: string; risk: string };
// The risk level of an application, as a tone and a label. An unknown or
// absent risk carries no tone and reads as "low", as before.
const RISK_TONES: Partial<Record<string, "danger" | "warning">> = { high: "danger", medium: "warning" };
const RISK_LABELS: Partial<Record<string, TranslationKey>> = { high: "high", medium: "medium" };
const KIND_LABELS: Record<string, TranslationKey> = {
  process: "kindProcess",
  executable: "kindExecutable",
  installed: "kindInstalled",
  extension: "kindExtension",
  port: "kindPort",
};
function ApplicationsPage() {
  const t = useText();
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(50);
  const path = page === 1 && size === 50 ? "/api/tools" : `/api/tools?limit=${size}&offset=${(page - 1) * size}`;
  const resource = useResource<{ items: Observation[]; catalog: CatalogEntry[]; total?: number }>(path);
  const { current, pages } = useBoundedPage(page, setPage, size, resource.data?.total ?? resource.data?.items.length);
  const [inspected, setInspected] = useState<{ name: string; rows: Observation[] } | null>(null);
  return (
    <>
      <PageBar title={t("aiApplications")} />
      <ResourceView resource={resource}>
        {(data) => {
          const known = new Map(data.catalog.map((entry) => [entry.id, entry]));
          const grouped = new Map<string, { devices: Set<string>; kinds: Set<string>; rows: Observation[]; first?: string; last?: string }>();
          for (const item of data.items) {
            const row = grouped.get(item.tool) ?? { devices: new Set(), kinds: new Set(), rows: [] };
            row.devices.add(item.hostname || t("machineNameUnavailable") + " (" + item.device_id + ")");
            row.kinds.add(item.kind);
            row.rows.push(item);
            if (item.first_seen && (!row.first || item.first_seen < row.first)) row.first = item.first_seen;
            if (!row.last || item.observed_at > row.last) row.last = item.observed_at;
            grouped.set(item.tool, row);
          }
          const rows = [...grouped.entries()].sort((a, b) => b[1].devices.size - a[1].devices.size || a[0].localeCompare(b[0]));
          if (rows.length === 0) {
            return (
              <Empty title={t("noAiApplicationObserved")}>
                {t("enterpriseDevicesReportTheApplicationsDescri")}
              </Empty>
            );
          }
          return (
            <Card
              title={t("observedApplications")}
              description={t("aDetectedPresenceEstablishesNeitherA")}
              actions={<PageSize value={size} label={t("perPage")} change={value => { setSize(value); setPage(1); }} />}
            >
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>{t("application")}</th>
                      <th>{t("vendor")}</th>
                      <th>{t("risk")}</th>
                      {/* Which devices the tool was found on. A count alone forces a
                          reopen of every machine to know which one to act on; the name
                          is already returned by /api/tools, the console was discarding it by
                          grouping by tool. The "Hosting" column is gone:
                          it showed local/cloud and nothing, anywhere, depended on it. */}
                      <th>{t("devices")}</th>
                      <th>{t("onWhichDevices")}</th>
                      <th>{t("recognisedBy")}</th>
                      <th>{t("firstObservation")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map(([tool, row]) => {
                      const entry = known.get(tool);
                      return (
                        <tr key={tool}>
                          <td><strong>{entry?.name ?? tool}</strong><span className="cell-detail">{tool}</span></td>
                          <td>{entry?.vendor ?? "—"}</td>
                          <td><Badge tone={RISK_TONES[entry?.risk ?? ""]}>{t(RISK_LABELS[entry?.risk ?? ""] ?? "low")}</Badge></td>
                          <td>{row.devices.size}</td>
                          {/* The first names, then a counted remainder: a list of
                              forty machines in a cell does not read well, and the
                              per-device detail already lives in the machine's own page. */}
                          {/* The cell is a control: the full list opens
                              instead of forcing a reopen of every machine to find out
                              which ones carry the tool. */}
                          <td><button type="button" className="text-link" title={t("foundOnDevices")} onClick={() => setInspected({ name: entry?.name ?? tool, rows: row.rows })}>
                            {[...row.devices].sort((a, b) => a.localeCompare(b)).slice(0, 3).join(", ")}
                            {row.devices.size > 3 && <span className="cell-detail">{t("andNMoreDevices", [row.devices.size - 3])}</span>}
                          </button></td>
                          <td>{[...row.kinds].map((kind) => (KIND_LABELS[kind] ? t(KIND_LABELS[kind]) : kind)).join(", ")}</td>
                          <td>{row.first ? <DateValue value={row.first} /> : "—"}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              <PageNumbers page={current} pages={pages} go={setPage} label={t("pagination")} />
            </Card>
          );
        }}
      </ResourceView>
      {inspected && (
        <Dialog title={inspected.name} close={() => setInspected(null)} side="list">
          <div className="dialog-body">
            <div className="table-scroll">
              <table className="privacy-table">
                <thead><tr><th>{t("device")}</th><th>{t("recognisedBy")}</th><th>{t("firstObservation")}</th></tr></thead>
                <tbody>
                  {[...inspected.rows]
                    .sort((a, b) => (a.hostname || a.device_id).localeCompare(b.hostname || b.device_id) || a.kind.localeCompare(b.kind))
                    .map((row) => (
                      <tr key={row.device_id + ":" + row.kind}>
                        <td><a className="text-link" href={`#devices?id=${row.device_id}`}>{row.hostname || t("machineNameUnavailable")}</a></td>
                        <td>{KIND_LABELS[row.kind] ? t(KIND_LABELS[row.kind]) : row.kind}</td>
                        <td>{row.first_seen ? <DateValue value={row.first_seen} /> : "—"}</td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          </div>
        </Dialog>
      )}
    </>
  );
}
// No device at all, or none matching the filter: two distinct empty
// screens. `null` means there are rows to show.
function deviceEmptyState(total: number, matching: number, t: Translate) {
  if (total === 0) {
    return <Empty title={t("readyForYourFirstDevice")}>{t("downloadThePreconfiguredMsiOrRpm")}</Empty>;
  }
  if (matching === 0) {
    return <Empty title={t("noDeviceMatches")}>{t("adjustTheSearchCriteria")}</Empty>;
  }
  return null;
}
function DevicesPage() {
  const t = useText();
  const { session } = useContext(Context);
  const mutation = useMutation();
  const [installers, setInstallers] = useState(false);
  const [revoke, setRevoke] = useState<Device>();
  const [success, setSuccess] = useState("");
  const [id, setId] = useState(idFromHash);
  const [name, setName] = useState("");
  const [user, setUser] = useState("");
  const [platform, setPlatform] = useState("");
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(50);
  const deviceParameters = new URLSearchParams();
  if (id) {
    deviceParameters.set("device_id", id);
  } else {
    if (page !== 1 || size !== 50) {
      deviceParameters.set("limit", String(size));
      deviceParameters.set("offset", String((page - 1) * size));
    }
    if (name.trim()) deviceParameters.set("query", name.trim());
    if (user.trim()) deviceParameters.set("user", user.trim());
    if (platform) deviceParameters.set("platform", platform);
  }
  const deviceQuery = deviceParameters.toString();
  const devicePath = `/api/devices${deviceQuery ? `?${deviceQuery}` : ""}`;
  // The three facets are the server's, never rebuilt from the page: `items.length` in
  // their place made an empty filtered page read as an empty fleet.
  const resource = useResource<{ items: Device[]; total: number; fleet: number; platforms: string[] }>(devicePath);
  const { current: currentPage, pages: pageCount } = useBoundedPage(page, setPage, size, resource.data?.total);
  const [area, setArea] = useState<DeviceArea>("details");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [confirmDelete, setConfirmDelete] = useState<Device[] | null>(null);
  const [failures, setFailures] = useState<string[]>([]);
  // Deleting the open device returns to the list; that navigation must not wipe
  // the confirmation it just produced.
  const keepSuccess = useRef(false);
  useEffect(() => {
    const changed = () => {
      setId(idFromHash());
      setPage(1);
      if (keepSuccess.current) keepSuccess.current = false;
      else setSuccess("");
      setArea("details");
    };
    window.addEventListener("hashchange", changed);
    return () => window.removeEventListener("hashchange", changed);
  }, []);
  function toggle(deviceId: string, on: boolean) {
    setSelected((current) => {
      const next = new Set(current);
      if (on) next.add(deviceId);
      else next.delete(deviceId);
      return next;
    });
  }
  // Deleting is not revoking: the rows of each device go with it, so failures
  // are reported per device instead of aborting the whole selection.
  async function runDelete(targets: Device[]) {
    setSuccess("");
    setFailures([]);
    const failed: string[] = [];
    for (const device of targets) {
      try {
        await mutation.run(
          `/api/devices/${encodeURIComponent(device.id)}`,
          "DELETE",
        );
      } catch {
        failed.push(device.hostname || t("machineNameUnavailable"));
      }
    }
    setFailures(failed);
    if (failed.length < targets.length)
      setSuccess(
        targets.length - failed.length > 1
          ? t("theDevicesWereDeleted")
          : t("theDeviceWasDeleted"),
      );
    setSelected(new Set());
    setConfirmDelete(null);
    resource.reload();
    if (id && targets.some((device) => device.id === id)) {
      keepSuccess.current = true;
      window.location.hash = "#devices";
    }
  }
  async function change(device: Device, action: "approve" | "revoke") {
    setSuccess("");
    try {
      await mutation.run(
        `/api/devices/${encodeURIComponent(device.id)}/${action}`,
        "POST",
      );
      setRevoke(undefined);
      setSuccess(
        action === "approve"
          ? t("theDeviceWasApproved")
          : t("theDeviceWasRevoked"),
      );
      resource.reload();
    } catch {
      /* Displayed by ErrorNotice. */
    }
  }
  return (
    <>
      {!id && (
        <PageBar
          title={t("devices")}
          actions={
            <>
              <RefreshButton onClick={resource.reload} />
              {/* The server requires installers.manage on the download itself. */}
              {can(session, "installers.manage") && (
                <button
                  className="button primary"
                  onClick={() => setInstallers(true)}
                >
                  <Icon name="download" />
                  {t("downloadAgent")}
                </button>
              )}
            </>
          }
          info={
            session.edition === "community"
              ? t("theCommunityAgentCoversBrowserUsage")
              : t("theEnterpriseAgentCoversTheBrowser")
          }
        />
      )}
      <ErrorNotice error={mutation.error} />
      {success && (
        <output className="notice success">
          <Icon name="check" />
          {success}
        </output>
      )}
      {failures.length > 0 && (
        <Notice tone="danger" role="alert">
          {t("couldNotDelete") +
            failures.join(", ")}
        </Notice>
      )}
      <ResourceView resource={resource}>
        {(data) => {
          if (id) {
            const device = data.items.find((item) => item.id === id);
            if (!device) {
              return (
                <>
                  <PageBar
                    title={t("device")}
                    actions={
                      <a className="button secondary" href="#devices">
                        {t("backToDevices")}
                      </a>
                    }
                  />
                  <Empty title={t("deviceNotFound")}>
                    {t("thisDeviceDoesNotExistOr")}
                  </Empty>
                </>
              );
            }
            const areas: DeviceArea[] = ["details"];
            // Browser policy is served in both editions; only local tools are Enterprise.
            if (can(session, "policy.manage")) areas.push("policy");
            if (session.edition === "commercial" && canAnalyze(session))
              areas.push("tools");
            const areaNames: Record<DeviceArea, string> = {
              details: t("details"),
              policy: t("devicePolicy"),
              tools: t("localTools"),
            };
            const current = areas.includes(area) ? area : "details";
            return (
              <>
                <PageBar
                  title={device.hostname || t("machineNameUnavailable")}
                  actions={
                    <>
                      <a className="button secondary" href="#devices">
                        {t("backToDevices")}
                      </a>
                      <RefreshButton onClick={resource.reload} />
                      {canManage(session) && (
                        <button
                          className="button small danger"
                          disabled={mutation.pending}
                          onClick={() => {
                            mutation.clear();
                            setConfirmDelete([device]);
                          }}
                        >
                          <Icon name="trash" />
                          {t("delete")}
                        </button>
                      )}
                      {canManage(session) && device.status === "pending" && (
                        <button
                          className="button small primary"
                          disabled={mutation.pending}
                          onClick={() => void change(device, "approve")}
                        >
                          {t("approve")}
                        </button>
                      )}
                      {canManage(session) && device.status !== "revoked" && (
                        <button
                          className="button small danger"
                          disabled={mutation.pending}
                          onClick={() => {
                            mutation.clear();
                            setRevoke(device);
                          }}
                        >
                          {t("revoke")}
                        </button>
                      )}
                    </>
                  }
                  info={t("revocableDeviceIdentityOverridesAndLocal")}
                />
                {areas.length > 1 && (
                  <Tabs
                    label={t("deviceSections")}
                    selected={current}
                    onSelect={(value) => setArea(value as DeviceArea)}
                    items={areas.map((item) => ({
                      id: item,
                      name: areaNames[item],
                    }))}
                  />
                )}
                {current === "details" && (
                <Card title={areaNames.details}>
                  <dl className="dl">
                    <dt>{t("identifier")}</dt>
                    <dd>
                      <span className="mono">{device.id}</span>
                    </dd>
                    <dt>{t("platform")}</dt>
                    <dd>{device.platform}</dd>
                    <dt>{t("agent")}</dt>
                    <dd>{device.version}</dd>
                    <dt>{t("update")}</dt>
                    <dd>
                      <DeviceUpdateStatus status={device.update_status} />
                      {device.update_reported_at && (
                        <span className="cell-detail">
                          <DateValue value={device.update_reported_at} />
                        </span>
                      )}
                    </dd>
                    <dt>{t("signedInUser")}</dt>
                    <dd>
                      {device.os_user || (
                        <span className="muted">
                          {t("notReported")}
                        </span>
                      )}
                    </dd>
                    <dt>{t("declaredDomain")}</dt>
                    <dd>
                      {device.machine_domains?.length ? (
                        device.machine_domains.map((domain) => (
                          <span key={`${domain.kind}:${domain.name}`} className="cell-detail mono">
                            {domain.name} ({t(domain.kind === "entra" ? "domainKindEntra" : domain.kind === "realm" ? "domainKindRealm" : "domainKindAd")})
                          </span>
                        ))
                      ) : (
                        <span className="muted">{t("notReported")}</span>
                      )}
                    </dd>
                    <dt>{t("group")}</dt>
                    <dd>
                      <DeviceGroupField
                        device={device}
                        changed={() => {
                          setSuccess(t("deviceGroupUpdated"));
                          resource.reload();
                        }}
                      />
                    </dd>
                    {session.edition === "commercial" && <><dt>{t("nativeCollectors")}</dt><dd>{device.collector_health?.length ? device.collector_health.map(item=><section key={item.tool}><strong>{item.tool}</strong> / {item.state}<span className="cell-detail">{item.version || t("unknown")} / <DateValue value={item.last_ok_at || null}/></span><span className="cell-detail">{t("collectorSkipped")}: {item.skipped_trees} / {t("collectorTampered")}: {item.managed_config_tampered}</span></section>) : t("notReported")}</dd></>}
                    <dt>{t("browserExtensions")}</dt>
                    <dd>
                      <BrowserPresence browsers={device.browsers} />
                    </dd>
                    <dt>{t("status")}</dt>
                    <dd>
                      <Status value={device.status} />
                    </dd>
                    <dt>{t("lastSeen")}</dt>
                    <dd>
                      <DateValue value={device.last_seen} />
                    </dd>
                  </dl>
                </Card>
                )}
                {current === "policy" && (
                  <>
                    <div className="section-heading">
                      <div>
                        <h2>{areaNames.policy}</h2>
                        <p>
                          {t("overrideOfTheOrganizationPolicyInherited")}
                        </p>
                      </div>
                    </div>
                    <ScopedSettings device={device.id} />
                  </>
                )}
                {current === "tools" && <InventoryPanel deviceId={device.id} />}
              </>
            );
          }
          const total = data.total;
          const platforms = data.platforms;
          // The server already applies query/user/platform, so data.items is the
          // set to render directly; re-filtering it here would risk disagreeing
          // with the server's own total.
          // Only what is both selected and visible can be acted upon.
          const selectedDevices = data.items.filter((item) =>
            selected.has(item.id),
          );
          const allSelected =
            data.items.length > 0 && selectedDevices.length === data.items.length;
          return (
            <>
              {(data.items.length > 0 || name || user || platform) && (
                <form
                  className="filter-bar"
                  onSubmit={(e) => e.preventDefault()}
                >
                  <label className="filter-search">
                    {t("deviceName")}
                    <input
                      maxLength={200}
                      value={name}
                      onChange={(e) => { setName(e.target.value); setPage(1); }}
                      placeholder={t("allDevices")}
                    />
                  </label>
                  <label>
                    {t("user")}
                    <input
                      maxLength={200}
                      value={user}
                      onChange={(e) => { setUser(e.target.value); setPage(1); }}
                      placeholder={t("allUsers")}
                    />
                  </label>
                  <label>
                    {t("system")}
                    <select
                      value={platform}
                      onChange={(e) => { setPlatform(e.target.value); setPage(1); }}
                    >
                      <option value="">
                        {t("allSystems")}
                      </option>
                      {platforms.map((item) => (
                        <option key={item} value={item}>
                          {item}
                        </option>
                      ))}
                    </select>
                  </label>
                </form>
              )}
              <section className="panel table-panel">
                <div className="section-heading">
                  <div>
                    <h2>{t("enrolledDevices")}</h2>
                    <p>
                      {t("oneRevocableIdentityPerDevice")}
                    </p>
                  </div>
                  <div className="row-actions">
					<PageSize value={size} label={t("perPage")} change={value => { setSize(value); setPage(1); }} />
                    <span className="count-badge">{total}</span>
                    {canManage(session) && selectedDevices.length > 0 && (
                      <Button
                        variant="danger"
                        icon="trash"
                        disabled={mutation.pending}
                        onClick={() => {
                          mutation.clear();
                          setConfirmDelete(selectedDevices);
                        }}
                      >
                        {t("delete")} ({selectedDevices.length})
                      </Button>
                    )}
                  </div>
                </div>
                {/* `fleet` counts every machine whatever the filter, `total` the filtered
                    ones: an empty fleet and a filter that matches nothing are two screens.
                    `platforms` is the filter's option list and says nothing about size. */}
                {deviceEmptyState(data.fleet, data.total, t) ?? (
                  <div className="table-scroll">
                    <table>
                      <thead>
                        <tr>
                          {canManage(session) && (
                            <th className="select-cell">
                              <input
                                type="checkbox"
                                checked={allSelected}
                                aria-label={t("selectAll")}
                                onChange={(e) =>
                                  setSelected(
                                    e.target.checked
                                      ? new Set(data.items.map((d) => d.id))
                                      : new Set(),
                                  )
                                }
                              />
                            </th>
                          )}
                          {[
                            t("device"),
                            t("user"),
                            t("group"),
                            t("platform"),
                            t("status"),
                            t("lastSeen"),
                            t("actions"),
                          ].map((label) => (
                            <th key={label}>{label}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {data.items.map((device) => (
                          <tr key={device.id}>
                            {canManage(session) && (
                              <td className="select-cell">
                                <input
                                  type="checkbox"
                                  checked={selected.has(device.id)}
                                  aria-label={`${t("select")} ${device.hostname || t("machineNameUnavailable")}`}
                                  onChange={(e) =>
                                    toggle(device.id, e.target.checked)
                                  }
                                />
                              </td>
                            )}
                            <td>
                              <a href={`#devices?id=${device.id}`}>
                                <strong>{device.hostname || t("machineNameUnavailable")}</strong>
                              </a>
                              <small className="cell-detail mono">
                                {device.id.slice(0, 8)}
                              </small>
                            </td>
                            <td>
                              {device.os_user || (
                                <span className="muted">—</span>
                              )}
                            </td>
                            <td>
                              {device.group_id ? (
                                <a className="tag tag-on" href={`#groups?id=${device.group_id}`}>{device.group_name || device.group_id}</a>
                              ) : (
                                <span className="muted">—</span>
                              )}
                            </td>
                            <td>
                              {device.platform}
                              <small className="cell-detail">
                                {t("agent")} {device.version}
                              </small>
                            </td>
                            <td>
                              <Status value={device.status} />
                            </td>
                            <td className="nowrap">
                              <DateValue value={device.last_seen} />
                            </td>
                            <td>
                              <div className="row-actions">
                                {canManage(session) &&
                                  device.status === "pending" && (
                                    <button
                                      className="button small primary"
                                      disabled={mutation.pending}
                                      onClick={() =>
                                        void change(device, "approve")
                                      }
                                    >
                                      {t("approve")}
                                    </button>
                                  )}
                                {canManage(session) &&
                                  device.status !== "revoked" && (
                                    <button
                                      className="button small danger"
                                      disabled={mutation.pending}
                                      onClick={() => {
                                        mutation.clear();
                                        setRevoke(device);
                                      }}
                                    >
                                      {t("revoke")}
                                    </button>
                                  )}
                                {(!canManage(session) ||
                                  device.status === "revoked") && (
                                  <span className="muted">—</span>
                                )}
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                <PageNumbers page={currentPage} pages={pageCount} go={setPage} label={t("pagination")} />
              </section>
            </>
          );
        }}
      </ResourceView>
      {installers && <InstallerDialog close={() => setInstallers(false)} />}
      {confirmDelete && (
        <Dialog
          title={
            confirmDelete.length > 1
              ? t("deleteTheseDevices")
              : t("deleteThisDevice")
          }
          close={() => !mutation.pending && setConfirmDelete(null)}
        >
          <p>
            {t("deletionRemovesTheDeviceIdentityIt")}
          </p>
          <ul className="confirm-list">
            {confirmDelete.slice(0, 10).map((device) => (
              <li key={device.id}>{device.hostname || t("machineNameUnavailable")}</li>
            ))}
            {confirmDelete.length > 10 && (
              <li className="muted">
                {t("and")} {confirmDelete.length - 10}{" "}
                {t("others")}
              </li>
            )}
          </ul>
          <ErrorNotice error={mutation.error} />
          <div className="dialog-actions">
            <button
              type="button"
              className="button secondary"
              disabled={mutation.pending}
              onClick={() => setConfirmDelete(null)}
            >
              {t("cancel")}
            </button>
            <button
              className="button danger"
              disabled={mutation.pending}
              onClick={() => void runDelete(confirmDelete)}
            >
              {mutation.pending
                ? t("deleting")
                : t("confirmDeletion")}
            </button>
          </div>
        </Dialog>
      )}
      {revoke && (
        <Dialog
          title={t("revokeThisDevice")}
          close={() => !mutation.pending && setRevoke(undefined)}
        >
          <p>
            {t("device2")} <strong>{revoke.hostname || t("machineNameUnavailable")}</strong>{" "}
            {t("willLoseAccessToEventSubmission")}
          </p>
          <ErrorNotice error={mutation.error} />
          <div className="dialog-actions">
            <button
              className="button secondary"
              disabled={mutation.pending}
              onClick={() => setRevoke(undefined)}
            >
              {t("cancel")}
            </button>
            <button
              className="button primary"
              disabled={mutation.pending}
              onClick={() => void change(revoke, "revoke")}
            >
              {mutation.pending
                ? t("revoking")
                : t("confirmRevocation")}
            </button>
          </div>
        </Dialog>
      )}
    </>
  );
}
type MemberAction = "role" | "remove" | "language";
// The four texts of an action on a member, organized by action rather than
// repeated in nested ternaries in four places: the dialog's title, its
// explanatory sentence, the button's label and the confirmation message.
// Adding an action now requires supplying its four texts.
const MEMBER_ACTION_TEXT: Record<
  MemberAction,
  { title: TranslationKey; explanation: TranslationKey; submit: TranslationKey; done: TranslationKey }
> = {
  role: {
    title: "changeRole",
    explanation: "theNewRoleWillApplyAfter",
    submit: "saveRole",
    done: "roleUpdatedTheMemberSSessions",
  },
  language: {
    title: "changeLanguage",
    explanation: "theChosenLanguageAppliesToThis",
    submit: "saveLanguage",
    done: "languageUpdatedItAppliesTheNext",
  },
  remove: {
    title: "removeThisAccess",
    explanation: "thisMemberWillLoseAccessTo",
    submit: "confirmRemoval",
    done: "accessRemovedTheMemberSSessions",
  },
};

/**
 * Console language of an account; empty means the instance default applies.
 *
 * Read from the language list, never from a ladder of comparisons. As an if-ladder
 * over fr and en, this was the sixth place a language had to be added by hand —
 * and the most misleading one, because it did not fail loudly: an account set to
 * Spanish fell through to "Default" in the Members table, so an administrator
 * could not tell "chose Spanish" from "expressed no preference".
 */
function languageLabel(t: Translate, value: Member["language"]) {
  return languages.find((l) => l.code === value)?.label ?? t("default");
}

// Why a member's row is read-only. The reasons are checked
// in the same order as before: yourself, another organization, an owner, and
// failing that a simple lack of rights.
function readOnlyMemberReason(member: Member, session: Session): TranslationKey {
  if (member.id === session.user.id) { return "thisIsYouYouCannotChange"; }
  if (member.organization_id !== session.organization.id) { return "switchToThisOrganizationToManage"; }
  if (member.role === "owner") { return "ownerOnlyAnOwnerCanChange"; }
  return "readOnly";
}
function MembersPanel() {
  const t = useText();
  const { session, refreshSession } = useContext(Context);
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(50);
  const path = page === 1 && size === 50 ? "/api/members" : `/api/members?limit=${size}&offset=${(page - 1) * size}`;
  const resource = useResource<MembersResponse>(path);
  const { current, pages } = useBoundedPage(page, setPage, size, resource.data?.total ?? resource.data?.items.length);
  const roleList = useResource<{ items: { name: string }[] }>("/api/roles");
  const roleNames = roleList.data?.items.map((r) => r.name) ?? ["viewer", "admin"];
  const [inviting, setInviting] = useState(false);
  const [importing, setImporting] = useState(false);
  const [editing, setEditing] = useState<{
    member: Member;
    action: MemberAction;
  }>();
  const [success, setSuccess] = useState("");
  async function changed(member: Member, action: MemberAction) {
    setEditing(undefined);
    setSuccess(t(MEMBER_ACTION_TEXT[action].done));
    if (member.id === session.user.id) await refreshSession();
    else resource.reload();
  }
  return (
    <>
      {success && (
        <output className="notice success">
          <Icon name="check" />
          {success}
        </output>
      )}
      <ResourceView resource={resource}>
        {(data) => {
          const total = data.total ?? data.items.length;
          return (
          <section className="panel table-panel">
            <div className="section-heading">
              <h2>{t("organizationAccess")}</h2>
              <div className="row-actions">
                <PageSize value={size} label={t("perPage")} change={value => { setSize(value); setPage(1); }} />
                <span className="count-badge">{total}</span>
                {canManage(session) && (
                  <button
                    className="button secondary"
                    onClick={() => setInviting(true)}
                  >
                    <Icon name="plus" />
                    {t("inviteAMember")}
                  </button>
                )}
                {canManage(session) && data.directory_configured === true && (
                  <Button
                    variant="secondary"
                    icon="users"
                    onClick={() => setImporting(true)}
                  >
                    {t("importFromDirectory")}
                  </Button>
                )}
              </div>
            </div>
            {data.items.length === 0 ? (
              <Empty title={t("noVisibleMembers")} />
            ) : (
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>{t("member")}</th>
                      <th>{t("emailAddress")}</th>
                      <th>{t("role")}</th>
                      <th>{t("type")}</th>
                      <th>{t("language")}</th>
                      <th>{t("organization")}</th>
                      <th>{t("actions")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.items.map((member) => (
                      <tr key={`${member.organization_id ?? ""}-${member.id}`}>
                        {/*
                          Both cells nowrap: a person's name is written text with no
                          break points, and an address is what a reader scans to
                          recognise someone, so breaking it mid-local-part defeats
                          the column's purpose. At 390px the surrounding
                          .table-scroll absorbs the width, so the reader scrolls a
                          legible name instead of parsing a shredded one. The audit
                          columns deliberately keep the default: actor is a UUID,
                          action is a dotted code and target is mono -- identifiers
                          that break cleanly on their own separators.
                        */}
                        <td className="nowrap">
                          <strong>{member.display_name || "—"}</strong>
                        </td>
                        <td className="nowrap">{member.email}</td>
                        <td>
                          <span className="role-badge">{member.role}</span>
                        </td>
                        <td>
                          <Badge>{identityTypeLabel(member.identity_type)}</Badge>
                        </td>
                        <td>{languageLabel(t, member.language)}</td>
                        <td>{member.organization_name ?? "—"}</td>
                        <td>
                          {canManage(session) &&
                          member.organization_id === session.organization.id &&
                          member.id !== session.user.id &&
                          (member.role !== "owner" ||
                            session.organization.role === "owner") ? (
                            <div className="row-actions">
                              <button
                                className="button small secondary"
                                onClick={() => {
                                  setSuccess("");
                                  setEditing({ member, action: "role" });
                                }}
                              >
                                <Icon name="shield" />
                                {t("changeRole")}
                              </button>
                              <button
                                className="button small secondary"
                                onClick={() => {
                                  setSuccess("");
                                  setEditing({ member, action: "language" });
                                }}
                              >
                                <Icon name="globe" />
                                {t("changeLanguage")}
                              </button>
                              <button
                                className="button small danger"
                                onClick={() => {
                                  setSuccess("");
                                  setEditing({ member, action: "remove" });
                                }}
                              >
                                <Icon name="trash" />
                                {t("removeAccess")}
                              </button>
                            </div>
                          ) : (
                            <span
                              className="muted readonly-cell"
                              title={t(readOnlyMemberReason(member, session))}
                            >
                              <Icon name="lock" />
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <PageNumbers page={current} pages={pages} go={setPage} label={t("pagination")} />
          </section>
          );
        }}
      </ResourceView>
      <p className="fine-print">
        {t("identitiesAndInvitationsAreManagedBy")}{" "}
        {t("ssoAndLdapAccountsInvitedBy")}
      </p>
      {inviting && (
        <InvitationDialog
          close={() => setInviting(false)}
          done={resource.reload}
          roles={roleNames}
        />
      )}
      {editing && (
        <MemberDialog
          member={editing.member}
          action={editing.action}
          close={() => setEditing(undefined)}
          done={() => changed(editing.member, editing.action)}
          roles={roleNames}
        />
      )}
      {importing && (
        <DirectoryImportDialog
          roles={roleNames}
          close={() => setImporting(false)}
          done={() => {
            resource.reload();
            setImporting(false);
          }}
        />
      )}
    </>
  );
}
const identityTypeLabels: Partial<Record<string, string>> = { sso: "SSO", ldap: "LDAP" };
function identityTypeLabel(type: Member["identity_type"]) {
  return identityTypeLabels[type ?? "local"] ?? "Local";
}
function roleLabel(t: Translate, name: string) {
  if (name === "owner") return t("owner");
  if (name === "admin") return t("administrator");
  if (name === "viewer") return t("viewer");
  return name;
}
function MemberDialog({
  member,
  action,
  close,
  done,
  roles,
}: Readonly<{
  member: Member;
  action: MemberAction;
  close: () => void;
  done: () => Promise<void>;
  roles: string[];
}>) {
  const t = useText();
  const { session } = useContext(Context);
  const [role, setRole] = useState(member.role);
  const [memberLanguage, setMemberLanguage] = useState(member.language ?? "");
  const mutation = useMutation();
  const path = `/api/members/${encodeURIComponent(member.id)}`;
  async function submit(e: SubmitEvent) {
    e.preventDefault();
    try {
      if (action === "role") await mutation.run(`${path}/role`, "PUT", { role });
      else if (action === "language")
        await mutation.run(`${path}/language`, "PUT", { language: memberLanguage });
      else await mutation.run(path, "DELETE");
      await done();
    } catch {
      /* Role and last-owner protections are enforced by the server. */
    }
  }
  return (
    <Dialog
      title={t(MEMBER_ACTION_TEXT[action].title)}
      close={() => !mutation.pending && close()}
    >
      <form onSubmit={submit}>
        <p>
          <strong>{member.display_name || member.email}</strong>
          {member.display_name && (
            <>
              <br />
              {member.email}
            </>
          )}
        </p>
        <p>
          {t(MEMBER_ACTION_TEXT[action].explanation)}
        </p>
        {member.id === session.user.id && (
          <p className="notice">
            {t("thisActionAffectsYourOwnAccess")}
          </p>
        )}
        {action === "role" && (
          <label>
            {t("newRole")}
            <select
              value={role}
              disabled={mutation.pending}
              onChange={(e) => setRole(e.target.value)}
            >
              {roles
                .filter(
                  (r) =>
                    r !== "owner" || session.organization.role === "owner",
                )
                .map((r) => (
                  <option key={r} value={r}>
                    {roleLabel(t, r)}
                  </option>
                ))}
            </select>
          </label>
        )}
        {action === "language" && (
          <label>
            {t("consoleLanguage")}
            <select
              value={memberLanguage}
              disabled={mutation.pending}
              onChange={(e) => setMemberLanguage(e.target.value as Member["language"] & string)}
            >
              <option value="">{languageLabel(t, "")}</option>
              {languages.map((l) => <option key={l.code} value={l.code}>{l.label}</option>)}
            </select>
          </label>
        )}
        <ErrorNotice error={mutation.error} />
        <div className="dialog-actions">
          <button
            type="button"
            className="button secondary"
            disabled={mutation.pending}
            onClick={close}
          >
            {t("cancel")}
          </button>
          <button
            type="submit"
            className="button primary"
            disabled={
              mutation.pending ||
              (action === "role" && role === member.role) ||
              (action === "language" && memberLanguage === (member.language ?? ""))
            }
          >
            {mutation.pending ? t("applying") : t(MEMBER_ACTION_TEXT[action].submit)}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
function InvitationDialog({
  close,
  done,
  roles,
}: Readonly<{
  close: () => void;
  done: () => void;
  roles: string[];
}>) {
  const t = useText();
  const { session } = useContext(Context);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("viewer");
  const [invitedLanguage, setInvitedLanguage] = useState<Member["language"] & string>("");
  const [sent, setSent] = useState(false);
  const mutation = useMutation();
  async function invite(e: SubmitEvent) {
    e.preventDefault();
    try {
      await mutation.run("/api/members/invitations", "POST", {
        email: email.trim(),
        role,
        language: invitedLanguage,
      });
      setSent(true);
      done();
    } catch {
      /* SMTP or authorization failures remain visible. */
    }
  }
  return (
    <Dialog
      title={t("inviteAMember")}
      close={() => !mutation.pending && close()}
    >
      {sent ? (
        <>
          <output className="notice success">
            <Icon name="check" />
            {t("theServerConfirmedSendingAnInvitation")}{" "}
            {email}.
          </output>
          <div className="dialog-actions">
            <button className="button primary" onClick={close}>
              {t("done")}
            </button>
          </div>
        </>
      ) : (
        <form onSubmit={invite}>
          <p>
            {t("yourIdentityProviderWillSendAn")}
          </p>
          <div className="invitation-fields">
            <label>
              {t("emailAddress")}
              <input
                autoFocus
                required
                type="email"
                maxLength={254}
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="member@example.org"
              />
            </label>
            <label>
              {t("role")}
              <select value={role} onChange={(e) => setRole(e.target.value)}>
                {roles
                  .filter(
                    (r) =>
                      r !== "owner" || session.organization.role === "owner",
                  )
                  .map((r) => (
                    <option key={r} value={r}>
                      {roleLabel(t, r)}
                    </option>
                  ))}
              </select>
            </label>
            <label>
              {t("consoleLanguage")}
              <select
                value={invitedLanguage}
                onChange={(e) => setInvitedLanguage(e.target.value as Member["language"] & string)}
              >
                <option value="">{languageLabel(t, "")}</option>
                {languages.map((l) => <option key={l.code} value={l.code}>{l.label}</option>)}
              </select>
            </label>
          </div>
          <ErrorNotice error={mutation.error} />
          <div className="dialog-actions">
            <button
              type="button"
              className="button secondary"
              disabled={mutation.pending}
              onClick={close}
            >
              {t("cancel")}
            </button>
            <button type="submit" className="button primary" disabled={mutation.pending}>
              {mutation.pending
                ? t("sending")
                : t("sendInvitation")}
            </button>
          </div>
        </form>
      )}
    </Dialog>
  );
}
function InventoryPanel({ deviceId }: Readonly<{ deviceId: string }>) {
  const t = useText();
  const resource = useResource<{
    items: {
      device_id: string;
      hostname: string;
      tool: string;
      kind: string;
      observed_at: string;
      first_seen?: string;
    }[];
  }>(`/api/tools?device_id=${encodeURIComponent(deviceId)}`);
  return (
    <section className="inventory-section">
      <ResourceView resource={resource}>
        {(data) => (
          <div className="panel table-panel">
            <div className="section-heading">
              <div>
                <h2>{t("detectedLocalTools")}</h2>
                <p>
                  {t("enterpriseInventoryDeviceObservation")}
                </p>
              </div>
              <RefreshButton onClick={resource.reload} />
            </div>
            {data.items.length === 0 ? (
              <Empty
                title={t("noLocalToolsReported")}
              >
                {t("observationsFromTheEnterpriseInventoryModule")}
              </Empty>
            ) : (
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>{t("tool")}</th>
                      <th>{t("observationType")}</th>
                      <th>{t("firstObservation")}</th>
                      <th>{t("lastObservation")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.items.map((item, index) => (
                      <tr key={`${item.tool}:${item.kind}:${index}`}>
                        <td>{item.tool}</td>
                        <td>{item.kind}</td>
                        <td>
                          {item.first_seen ? <DateValue value={item.first_seen} /> : "—"}
                        </td>
                        <td>
                          <DateValue value={item.observed_at} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <p className="fine-print">
              {t("aDetectedLocalPresenceIsDistinct")}
            </p>
          </div>
        )}
      </ResourceView>
    </section>
  );
}
function AuditPanel() {
  const t = useText();
  const resource = useResource<{ items: Audit[] }>("/api/audit");
  return (
    <ResourceView resource={resource}>
      {(data) => (
        <section className="panel table-panel">
          <div className="section-heading">
            <div>
              <h2>{t("actionHistory")}</h2>
              <p>
                {t("appendOnlyServerLog")}
              </p>
            </div>
            <RefreshButton onClick={resource.reload} />
          </div>
          {data.items.length === 0 ? (
            <Empty
              title={t("noActionsLogged")}
            />
          ) : (
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    {[
                      t("date"),
                      t("actor"),
                      t("action"),
                      t("target"),
                    ].map((label) => (
                      <th key={label}>{label}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((item) => (
                    <tr key={item.id}>
                      <td className="nowrap">
                        <DateValue value={item.occurred_at} />
                      </td>
                      <td>{item.actor}</td>
                      <td>{item.action}</td>
                      <td className="mono">{item.target}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
    </ResourceView>
  );
}
function FirstRunBanner() {
  const t = useText();
  const resource = useResource<Settings>("/api/settings");
  const reloadRef = useRef(resource.reload);
  reloadRef.current = resource.reload;
  useEffect(() => {
    const handler = () => reloadRef.current();
    window.addEventListener("milvago:settings", handler);
    return () => window.removeEventListener("milvago:settings", handler);
  }, []);
  const [wizard, setWizard] = useState(false);
  const settings = resource.data;
  if (!settings || settings.public_url_confirmed || !settings.public_url_editable || !settings.default_language_editable) return null;
  return (
    <>
    {wizard && <SetupWizard initial={settings} close={() => setWizard(false)} />}
    <Notice
      tone="warning"
      role="status"
      title={t("completeSetup")}
      action={
        settings.public_url_editable ? (
          <button className="button small" onClick={() => setWizard(true)}>
            {t("configure")}
          </button>
        ) : undefined
      }
    >
      {t("agentsAndTheBrowserExtensionWill")}
    </Notice>
    </>
  );
}
/**
 * Read next to FirstRunBanner: a Community instance without a licence (5 devices, one
 * administrator, no roles/LDAP/SSO), or an Enterprise one running on borrowed time after
 * its licence expired. A locked instance never reaches here -- App renders its own
 * licence screen in place of the whole Shell before this component is mounted.
 */
function LicenseBanner() {
  const t = useText();
  const { session } = useContext(Context);
  const license = session.license;
  if (!license) return null;
  if (license.restricted) {
    return (
      <Notice tone="warning" title={t("licenseRestrictedTitle")} action={<a className="button small" href="#settings">{t("openSettings")}</a>}>
        {t("licenseRestrictedBanner")}
      </Notice>
    );
  }
  if (license.state === "grace") {
    return (
      <Notice tone="warning" title={t("licenseGraceTitle")}>
        {t("licenseGraceBanner")} <DateValue value={license.grace_until ?? null} />
      </Notice>
    );
  }
  return null;
}
type SettingsArea = "organization" | "license" | "directory" | "installers" | "connectors";

function SettingsPanel() {
  const t = useText();
  const { session } = useContext(Context);
  const resource = useResource<Settings>("/api/settings");
  const [area, setArea] = useState<SettingsArea>("organization");
  // The licence area is informational for everyone who can see Settings at all --
  // only the instance owner gets the form to change it (LicensePanel itself guards that).
  const areas: SettingsArea[] = ["organization", "license"];
  if (can(session, "directory.manage") && !session.license?.restricted) areas.push("directory");
  // The guard that shows the section must be the one the server enforces on it.
  if (can(session, "installers.manage")) areas.push("installers");
  // Self-registration is an instance-level decision written on the identity provider,
  // so the server refuses it to anyone but the root organization's owner. The client
  // cannot know which organization is root without asking, so it shows the section to
  // an owner with settings.manage and lets the section itself report the refusal.
  if (session.edition === "commercial" && session.organization.role === "owner" && can(session, "settings.manage")) {
    areas.push("connectors");
  }
  const names: Record<SettingsArea, string> = {
    organization: t("organization"),
    license: t("license"),
    directory: t("ldapDirectory"),
    installers: t("deploymentKey"),
    connectors: t("connectorSelfRegistration"),
  };
  // A permission lost between renders must never leave an unreachable area selected.
  const current = areas.includes(area) ? area : "organization";
  // One section per guard, rather than a chain of nested ternaries.
  function settingsArea() {
    if (current === "organization") {
      return (
        <ResourceView resource={resource}>
          {(settings) => <SettingsEditor initial={settings} />}
        </ResourceView>
      );
    }
    if (current === "license") { return <LicensePanel />; }
    if (current === "directory") { return <DirectoryCard />; }
    if (current === "connectors") { return <ConnectorRegistrationPanel />; }
    return <DeploymentKeyPanel />;
  }
  return (
    <div className="settings-layout">
      {areas.length > 1 && (
        <nav
          className="vnav"
          aria-label={t("settingsSections")}
        >
          {areas.map((item, index) => (
            <button
              key={item}
              type="button"
              aria-pressed={current === item}
              className={`vnav-item${current === item ? " active" : ""}`}
              onClick={() => setArea(item)}
            >
              <span className="n">0{index + 1}</span>
              <span>{names[item]}</span>
            </button>
          ))}
        </nav>
      )}
      <div className="settings-area">
        {settingsArea()}
      </div>
    </div>
  );
}
function SettingsEditor({ initial }: Readonly<{ initial: Settings }>) {
  const t = useText();
  const { session, refreshSession } = useContext(Context);
  const [settings, setSettings] = useState(initial);
  const [baseline, setBaseline] = useState(JSON.stringify(initial));
  const [saved, setSaved] = useState(false);
  const mutation = useMutation();
  const manage = session.organization.role === "owner";
  async function save(e: SubmitEvent) {
    e.preventDefault();
    setSaved(false);
    try {
      const updated = await mutation.run<Settings>("/api/settings", "PUT", {
        name: settings.name,
        event_retention_days: settings.event_retention_days,
        public_url: settings.public_url,
        ...(settings.default_language_editable ? { default_language: settings.default_language ?? "en" } : {}),
      });
      if (updated) {
        setSettings(updated);
        setBaseline(JSON.stringify(updated));
      } else {
        setBaseline(JSON.stringify(settings));
      }
      setSaved(true);
      window.dispatchEvent(new CustomEvent("milvago:settings"));
      await refreshSession();
    } catch {
      /* Displayed below. */
    }
  }
  return (
    <form className="panel settings-panel" onSubmit={save}>
      <div className="section-heading">
        <h2>{t("organizationSettings")}</h2>
      </div>
      <ErrorNotice error={mutation.error} />
      {saved && (
        <output className="notice success">
          <Icon name="check" />
          {t("settingsSaved")}
        </output>
      )}
      <fieldset disabled={!manage || mutation.pending}>
        <label>
          {t("organizationName")}
          <input
            required
            maxLength={120}
            value={settings.name}
            onChange={(e) => {
              setSaved(false);
              setSettings({ ...settings, name: e.target.value });
            }}
          />
        </label>
        <label>
          {t("publicAgentHttpsUrl")}
          <input
            type="url"
            value={settings.public_url}
            disabled={!settings.public_url_editable}
            placeholder="https://console.exemple.com"
            onChange={(e) => {
              setSaved(false);
              setSettings({ ...settings, public_url: e.target.value });
            }}
          />
          <span className="field-help">
            {settings.public_url_editable
              ? t("urlAdvertisedToAgentsAndThe")
              : t("onlyTheRootOrganizationOwnerCan")}
          </span>
        </label>
        <label>
          {t("instanceDefaultLanguage")}
          <select value={settings.default_language ?? "en"} disabled={!settings.default_language_editable}
            onChange={e => { setSaved(false); setSettings({ ...settings, default_language: e.target.value as Language }); }}>
            {languages.map(l => <option key={l.code} value={l.code}>{l.label}</option>)}
          </select>
          <span className="field-help">{t("appliesToSignInAndUsers")}</span>
        </label>
        <label>
          {t("eventRetentionDays")}
          <input
            type="number"
            required
            min={1}
            max={3650}
            value={settings.event_retention_days}
            onChange={(e) => {
              setSaved(false);
              setSettings({
                ...settings,
                event_retention_days: Number(e.target.value),
              });
            }}
          />
          <span className="field-help">
            {t("theServerValidatesAndAppliesThe")}
          </span>
        </label>
      </fieldset>
      {manage && (
        <div className="settings-actions">
          <button
            type="submit"
            className="button primary"
            disabled={mutation.pending || JSON.stringify(settings) === baseline}
          >
            {mutation.pending
              ? t("saving")
              : t("saveSettings")}
          </button>
        </div>
      )}
    </form>
  );
}
const licenseStateTone: Record<LicenseStatus["state"], "neutral" | "success" | "warning" | "danger"> = {
  none: "neutral",
  valid: "success",
  grace: "warning",
  expired: "danger",
};
/**
 * The instance's licence: status, kind, device ceiling, expiry and the instance
 * identifier a licence is issued against, with a copy button since it is what an
 * administrator has to hand over to get one. Shown to every signed-in reader who can
 * see Settings; only the instance owner gets the form to change it or, in Community,
 * to request a free one. Reused unmodified on the full-page licence screen App renders
 * when an Enterprise instance is locked -- same card, same owner-only gate.
 */
function LicensePanel() {
  const t = useText();
  const { session, refreshSession } = useContext(Context);
  const license = session.license;
  const mutation = useMutation();
  const [text, setText] = useState("");
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState<"idle" | "done" | "failed">("idle");
  const [requestEmail, setRequestEmail] = useState(session.user.email);
  const [requested, setRequested] = useState(false);
  if (!license) return null;
  const owner = Boolean(session.is_instance_owner);
  const stateLabels: Record<LicenseStatus["state"], string> = {
    none: t("licenseStateNone"),
    valid: t("licenseStateValid"),
    grace: t("licenseStateGrace"),
    expired: t("licenseStateExpired"),
  };
  async function save(e: SubmitEvent) {
    e.preventDefault();
    setSaved(false);
    try {
      await mutation.run("/api/license", "PUT", { license: text.trim() });
      setSaved(true);
      setText("");
      await refreshSession();
    } catch {
      /* Displayed via mutation.error below. */
    }
  }
  async function sendRequest() {
    setRequested(false);
    try {
      await mutation.run("/api/license/request", "POST", { email: requestEmail.trim() });
      setRequested(true);
    } catch {
      /* Displayed via mutation.error below. */
    }
  }
  return (
    <Card className="settings-panel" title={t("license")} description={t("licenseDescription")} flush>
      <ErrorNotice error={mutation.error} />
      <div style={{ padding: "16px 20px", display: "flex", flexDirection: "column", gap: 14 }}>
        <dl className="dl">
          <dt>{t("status")}</dt>
          <dd><Badge tone={licenseStateTone[license.state]}>{stateLabels[license.state]}</Badge></dd>
          <dt>{t("licenseKind")}</dt>
          <dd>{license.kind === "enterprise" ? "Enterprise" : license.kind === "community" ? "Community" : <span className="muted">—</span>}</dd>
          <dt>{t("licenseMaxDevices")}</dt>
          <dd>{license.max_devices === 0 ? t("unlimited") : license.max_devices}</dd>
          {license.expires_at && <>
            <dt>{t("licenseExpiresAt")}</dt>
            <dd><DateValue value={license.expires_at} /></dd>
          </>}
          {license.grace_until && <>
            <dt>{t("licenseGraceUntil")}</dt>
            <dd><DateValue value={license.grace_until} /></dd>
          </>}
          <dt>{t("licenseInstanceId")}</dt>
          <dd>
            <div className="actions">
              <code className="mono">{license.instance_id}</code>
              <button
                type="button"
                className="button secondary small"
                onClick={async () => setCopied((await copyToClipboard(license.instance_id)) ? "done" : "failed")}
              >
                <Icon name={copied === "done" ? "check" : "copy"} />
                {copied === "done" ? t("copied") : t("copyInstanceId")}
              </button>
            </div>
          </dd>
        </dl>
        {copied === "failed" && <Notice tone="warning">{t("automaticCopyFailedSelectTheText")}</Notice>}
        {owner ? (
          <form onSubmit={save} className="form-grid">
            <label>
              {t("licensePasteLabel")}
              <textarea rows={6} value={text} onChange={(e) => setText(e.target.value)} />
              <span className="field-help">{t("licensePasteHelp")}</span>
            </label>
            <div className="settings-actions">
              <button type="submit" className="button primary" disabled={mutation.pending || !text.trim()}>
                {t("licenseSave")}
              </button>
            </div>
            {saved && (
              <output className="notice success">
                <Icon name="check" />
                {t("licenseSaved")}
              </output>
            )}
          </form>
        ) : (
          <p className="fine-print">{t("licenseReadOnly")}</p>
        )}
        {owner && session.edition === "community" && (
          <div className="field">
            <span className="label">{t("licenseChoiceRequest")}</span>
            <div className="actions">
              <input type="email" maxLength={254} value={requestEmail} onChange={(e) => setRequestEmail(e.target.value)} />
              <button
                type="button"
                className="button secondary"
                disabled={mutation.pending || !requestEmail.trim()}
                onClick={() => void sendRequest()}
              >
                {t("licenseSendRequest")}
              </button>
            </div>
            {requested && <Notice tone="success">{t("licenseRequestSent", [requestEmail])}</Notice>}
          </div>
        )}
      </div>
    </Card>
  );
}
type Org = {
  id: string;
  name: string;
  role: string;
  parent_id: string | null;
  is_root: boolean;
};

function OrganizationsPanel() {
  return <OrganizationsView />;
}

/** One organization's own page, reached from its row at #organizations?id=. It carries what
 * belongs to that organization rather than to the session's — the deployment key first, since
 * a parent administrator has to be able to rotate a child's without switching into it. */
// The parent organization: the root has none, another with no known parent
// doesn't either, and otherwise the link to it.
function parentOrganizationCell(org: Org, t: Translate) {
  if (org.is_root) { return t("noneRootOrganization"); }
  if (!org.parent_id) { return <span className="muted">—</span>; }
  return (
    <a className="text-link" href={`#organizations?id=${encodeURIComponent(org.parent_id)}`}>
      <span className="mono">{org.parent_id}</span>
    </a>
  );
}
function OrganizationDetail({ org, reload }: Readonly<{ org: Org; reload: () => void }>) {
  const t = useText();
  const { session } = useContext(Context);
  return (
    <>
      <PageBar
        title={org.name}
        actions={
          <>
            <a className="button secondary" href="#organizations">
              {t("backToOrganizations")}
            </a>
            <RefreshButton onClick={reload} />
          </>
        }
        info={t("theOrganizationSIdentityAndThe")}
      />
      <Card title={t("details")}>
        <dl className="dl">
          <dt>{t("identifier")}</dt>
          <dd>
            <span className="mono">{org.id}</span>
          </dd>
          <dt>{t("parentOrganization")}</dt>
          <dd>
            {parentOrganizationCell(org, t)}
          </dd>
          <dt>{t("yourRole")}</dt>
          <dd>{org.role || <span className="muted">—</span>}</dd>
        </dl>
      </Card>
      {can(session, "installers.manage") && (
        <DeploymentKeyPanel organization={org.id} />
      )}
    </>
  );
}

function OrganizationsView() {
  const t = useText();
  const { refreshSession, session } = useContext(Context);
  const manage = can(session, "organizations.manage");
  const resource = useResource<{ items: Org[] }>("/api/organizations");
  const reload = resource.reload;
  const items = resource.data?.items ?? [];
  const [openId, setOpenId] = useState(idFromHash);
  useEffect(() => {
    const changed = () => setOpenId(idFromHash());
    window.addEventListener("hashchange", changed);
    return () => window.removeEventListener("hashchange", changed);
  }, []);
  const mutation = useMutation();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [creating, setCreating] = useState(false);
  const [renaming, setRenaming] = useState<Org | null>(null);
  const [confirm, setConfirm] = useState<Org[] | null>(null);
  const [message, setMessage] = useState("");
  const [failures, setFailures] = useState<string[]>([]);

  const currentId = session.organization.id;
  const byId = new Map(items.map((o) => [o.id, o]));
  const parentIds = new Set(items.map((o) => o.parent_id).filter((id): id is string => Boolean(id)));
  const hasChildren = (id: string) => parentIds.has(id);
  const depthOf = (id: string) => {
    let depth = 0;
    let cursor = byId.get(id);
    while (cursor?.parent_id) {
      depth += 1;
      cursor = byId.get(cursor.parent_id);
    }
    return depth;
  };
  // The current organization and the root can never be deleted.
  const selectable = (org: Org) => manage && !org.is_root && org.id !== currentId;
  // A single row deletes directly only when it also has no children.
  const singleDeletable = (org: Org) => selectable(org) && !hasChildren(org.id);
  const deleteReason = (org: Org) => {
    if (org.id === currentId)
      return t("currentOrganization");
    if (org.is_root) return t("rootOrganization");
    if (hasChildren(org.id))
      return t("deleteItsChildOrganizationsFirstOr");
    return undefined;
  };

  const selectableItems = items.filter(selectable);
  const allSelected =
    selectableItems.length > 0 &&
    selectableItems.every((org) => selected.has(org.id));

  function toggle(id: string, on: boolean) {
    setSelected((current) => {
      const next = new Set(current);
      if (on) next.add(id);
      else next.delete(id);
      return next;
    });
  }
  function toggleAll(on: boolean) {
    setSelected(on ? new Set(selectableItems.map((org) => org.id)) : new Set());
  }

  async function runDelete(targets: Org[]) {
    setMessage("");
    setFailures([]);
    // Delete deepest first so a parent is emptied of its selected children
    // before it is removed.
    const ordered = [...targets].sort((a, b) => depthOf(b.id) - depthOf(a.id));
    const failed: string[] = [];
    for (const org of ordered) {
      try {
        await mutation.run(`/api/organizations/${org.id}`, "DELETE");
      } catch {
        failed.push(org.name);
      }
    }
    setFailures(failed);
    if (!failed.length)
      setMessage(
        targets.length > 1
          ? t("organizationsDeleted")
          : t("organizationDeleted"),
      );
    setSelected(new Set());
    setConfirm(null);
    reload();
    await refreshSession();
  }

  const selectedOrgs = items.filter((org) => selected.has(org.id));
  const open = openId ? items.find((org) => org.id === openId) : undefined;
  if (openId)
    return (
      <ResourceView resource={resource}>
        {() =>
          open ? (
            <OrganizationDetail org={open} reload={reload} />
          ) : (
            <Empty
              title={t("organizationNotFound")}
              action={
                <a className="button secondary" href="#organizations">
                  {t("backToOrganizations")}
                </a>
              }
            />
          )
        }
      </ResourceView>
    );
  return (
    <>
      {message && (
        <output className="notice success">
          <Icon name="check" />
          {message}
        </output>
      )}
      {failures.length > 0 && (
        <Notice tone="danger" role="alert">
          {t("couldNotDelete") +
            failures.join(", ")}
        </Notice>
      )}
      <section className="panel table-panel">
        <div className="section-heading">
          <h2>{t("accessibleOrganizations")}</h2>
          {manage && (
            <div className="row-actions">
              {selectedOrgs.length > 0 && (
                <button
                  className="button danger"
                  onClick={() => {
                    setMessage("");
                    setConfirm(selectedOrgs);
                  }}
                >
                  <Icon name="trash" />
                  {t("deleteSelected")} (
                  {selectedOrgs.length})
                </button>
              )}
              <button
                className="button primary"
                onClick={() => {
                  setMessage("");
                  setCreating(true);
                }}
              >
                <Icon name="plus" />
                {t("newOrganization")}
              </button>
            </div>
          )}
        </div>
        <ResourceView resource={resource}>
          {(data) =>
            data.items.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  {manage && (
                    <th className="select-cell">
                      <input
                        type="checkbox"
                        aria-label={t("selectAll")}
                        checked={allSelected}
                        disabled={selectableItems.length === 0}
                        onChange={(e) => toggleAll(e.target.checked)}
                      />
                    </th>
                  )}
                  <th>{t("organization")}</th>
                  <th>{t("identifier")}</th>
                  <th>{t("parent")}</th>
                  {manage && <th>{t("actions")}</th>}
                </tr>
              </thead>
              <tbody>
                {items.map((org) => (
                  <tr key={org.id}>
                    {manage && (
                      <td className="select-cell">
                        <input
                          type="checkbox"
                          aria-label={t("select") + " " + org.name}
                          checked={selected.has(org.id)}
                          disabled={!selectable(org)}
                          onChange={(e) => toggle(org.id, e.target.checked)}
                        />
                      </td>
                    )}
                    <td>
                      <a
                        className="text-link"
                        href={`#organizations?id=${encodeURIComponent(org.id)}`}
                      >
                        <strong>{org.name}</strong>
                      </a>
                      {org.is_root && (
                        <span className="role-badge">{t("root")}</span>
                      )}
                      {org.id === currentId && (
                        <span className="role-badge">
                          {t("current")}
                        </span>
                      )}
                    </td>
                    <td className="mono">{org.id}</td>
                    <td>
                      {byId.get(org.parent_id ?? "")?.name ??
                        org.parent_id ??
                        "—"}
                    </td>
                    {manage && (
                      <td>
                        <div className="row-actions">
                          <button
                            className="button small secondary"
                            onClick={() => {
                              setMessage("");
                              setRenaming(org);
                            }}
                          >
                            <Icon name="settings" />
                            {t("rename")}
                          </button>
                          <button
                            className="button small danger"
                            disabled={!singleDeletable(org)}
                            title={deleteReason(org)}
                            onClick={() => {
                              setMessage("");
                              setConfirm([org]);
                            }}
                          >
                            <Icon name="trash" />
                            {t("delete")}
                          </button>
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
            ) : (
              <Empty
                title={t("noAccessibleOrganizations")}
              />
            )
          }
        </ResourceView>
      </section>
      {creating && (
        <CreateOrgDialog
          items={items}
          close={() => setCreating(false)}
          done={async (msg) => {
            setCreating(false);
            setMessage(msg);
            reload();
            await refreshSession();
          }}
        />
      )}
      {renaming && (
        <RenameOrgDialog
          org={renaming}
          close={() => setRenaming(null)}
          done={async (msg) => {
            setRenaming(null);
            setMessage(msg);
            reload();
            await refreshSession();
          }}
        />
      )}
      {confirm && (
        <Dialog
          title={t("deleteOrganizations")}
          close={() => setConfirm(null)}
        >
          <p>
            {t("thisPermanentlyDeletesTheFollowingOrganizati")}
          </p>
          <ul>
            {confirm.map((org) => (
              <li key={org.id}>{org.name}</li>
            ))}
          </ul>
          <ErrorNotice error={mutation.error} />
          <div className="dialog-actions">
            <button
              type="button"
              className="button secondary"
              onClick={() => setConfirm(null)}
            >
              {t("cancel")}
            </button>
            <button
              className="button danger"
              disabled={mutation.pending}
              onClick={() => runDelete(confirm)}
            >
              <Icon name="trash" />
              {mutation.pending
                ? t("deleting")
                : t("delete")}
            </button>
          </div>
        </Dialog>
      )}
    </>
  );
}

function RenameOrgDialog({
  org,
  close,
  done,
}: Readonly<{
  org: Org;
  close: () => void;
  done: (message: string) => void;
}>) {
  const t = useText();
  const mutation = useMutation();
  const [name, setName] = useState(org.name);
  async function save(e: SubmitEvent) {
    e.preventDefault();
    try {
      await mutation.run(`/api/organizations/${org.id}`, "PUT", {
        name: name.trim(),
      });
      done(t("organizationRenamed"));
    } catch {
      /* Displayed via mutation.error below. */
    }
  }
  return (
    <Dialog title={t("renameOrganization")} close={close}>
      <form onSubmit={save}>
        <label>
          {t("name")}
          <input
            required
            maxLength={120}
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </label>
        <ErrorNotice error={mutation.error} />
        <div className="dialog-actions">
          <button type="button" className="button secondary" onClick={close}>
            {t("cancel")}
          </button>
          <button
            type="submit"
            className="button primary"
            disabled={mutation.pending || !name.trim()}
          >
            {mutation.pending
              ? t("saving")
              : t("save")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}

function CreateOrgDialog({
  items,
  close,
  done,
}: Readonly<{
  items: Org[];
  close: () => void;
  done: (message: string) => void;
}>) {
  const t = useText();
  const { session } = useContext(Context);
  const mutation = useMutation();
  const [name, setName] = useState("");
  const parentOptions = items.filter((org) => org.role === "owner");
  const defaultParent =
    parentOptions.find((org) => org.id === session.organization.id) ??
    parentOptions.find((org) => org.is_root) ??
    parentOptions[0];
  const [parent, setParent] = useState(defaultParent?.id ?? "");
  const [requireMFA, setRequireMFA] = useState(false);
  const selectedParent = parent || defaultParent?.id || "";
  async function create(e: SubmitEvent) {
    e.preventDefault();
    if (!selectedParent) return;
    try {
      await mutation.run("/api/organizations", "POST", {
        name: name.trim(),
        parent_id: selectedParent,
        require_mfa: requireMFA,
      });
      done(t("organizationCreated"));
    } catch {
      /* Displayed via mutation.error below. */
    }
  }
  return (
    <Dialog
      title={t("newOrganization")}
      close={close}
    >
      <form onSubmit={create}>
        <p className="muted">
          {t("aParentOrganizationDoesNotGrant")}
        </p>
        <label>
          {t("name")}
          <input
            required
            maxLength={120}
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </label>
        <label>
          {t("parentOrganization2")}
          <select
            required
            value={selectedParent}
            onChange={(e) => setParent(e.target.value)}
          >
            {parentOptions.map((org) => (
              <option key={org.id} value={org.id}>
                {org.name}
              </option>
            ))}
          </select>
        </label>
        <label className="checkbox-label">
          <input
            type="checkbox"
            checked={requireMFA}
            onChange={(e) => setRequireMFA(e.target.checked)}
          />
          <span>
            {t("requireMultiFactorAuthenticationForAll")}
          </span>
        </label>
        <p className="muted">
          {t("cannotBeChangedAfterCreation")}
        </p>
        <ErrorNotice error={mutation.error} />
        <div className="dialog-actions">
          <button type="button" className="button secondary" onClick={close}>
            {t("cancel")}
          </button>
          <button
            type="submit"
            className="button primary"
            disabled={mutation.pending || !name.trim() || !selectedParent}
          >
            {mutation.pending ? t("creating") : t("create")}
          </button>
        </div>
      </form>
    </Dialog>
  );
}
