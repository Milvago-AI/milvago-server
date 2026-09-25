import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { speaks } from "./test-setup";
import { browserLanguage, matchLanguage } from "./locales/languages";
import type { Session } from "./api";
const base: Session = { user: { id: "user-test", email: "owner@example.org", display_name: "Propriétaire" }, organization: { id: "org-test", name: "Organisation de test", role: "owner" }, organizations: [{ id: "org-test", name: "Organisation de test", role: "owner" }], permissions: ["overview.read", "events.read", "observability.manage", "settings.manage"], csrf_token: "test-csrf", edition: "commercial", default_language: "fr" };
const settings = { name: "Organisation de test", event_retention_days: 90, public_url: "https://console.example.org", public_url_confirmed: true, public_url_editable: true, default_language: "fr", default_language_editable: true };
const config = { revision: 2, grafana_url: "https://grafana.example.org/d/test", destinations: ["grafana", "siem"].map(id => ({ id, enabled: true, endpoint: "https://collector.example.org", authorization_configured: true, event_filter: id === "siem" ? "security" : "all", metrics: true, shadow_events: true, audit: false })), status: [] };
function reply(body: unknown, status = 200) { return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }); }
function serve(session = base, handler?: (url: string, init?: RequestInit) => Response | undefined) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = String(input); const handled = handler?.(url, init); if (handled) return handled;
    if (url === "/api/bootstrap") return reply({ default_language: "fr" });
    if (url === "/api/session") return reply(session);
    if (url === "/api/settings") return reply(settings);
    if (url === "/api/observability") return reply(config);
    if (url === "/api/overview") return reply({ period_hours: 24, events: 0, blocked: 0, devices: 0, active_devices: 0, providers: [], timeline: [] });
    if (url === "/api/devices") return reply({ items: [] });
    return reply({ items: [] });
  });
}
beforeEach(() => {
  localStorage.clear(); window.location.hash = "#observability";
  Object.defineProperty(HTMLDialogElement.prototype, "showModal", { configurable: true, value() { this.setAttribute("open", ""); } });
  Object.defineProperty(HTMLDialogElement.prototype, "close", { configurable: true, value() { this.removeAttribute("open"); } });
});
describe("Observability", () => {
  it.each([{ ...base, edition: "community" as const }, { ...base, permissions: [] }])("blocks the page and API without the Enterprise permission", async session => {
    const fetchMock = serve(session); render(<App />);
    await screen.findByRole("heading", { name: "Accès réservé" });
    expect(screen.queryByRole("link", { name: "Observabilité" })).not.toBeInTheDocument();
    expect(fetchMock.mock.calls.some(([url]) => url === "/api/observability")).toBe(false);
  });
  it("keeps blank secrets, explicitly removes a secret, saves before testing and never claims final delivery", async () => {
    let current = structuredClone(config);
    const fetchMock = serve(base, (url, init) => {
      if (url === "/api/observability" && init?.method === "PUT") {
        const body = JSON.parse(String(init.body));
        current = { ...current, ...body, revision: current.revision + 1, destinations: body.destinations.map((d: { id: string; clear_authorization?: boolean }) => ({ ...d, authorization_configured: !d.clear_authorization })) };
        return reply(current);
      }
      if (url === "/api/observability") return reply(current);
      if (url === "/api/observability/test") return reply({ ok: true });
    });
    render(<App />); const user = userEvent.setup();
    const url = await screen.findByRole("textbox", { name: "URL de base du collecteur OTLP/HTTP JSON · grafana" });
    const grafanaCard = screen.getByRole("heading", { name: "Grafana" }).closest("section");
    expect(grafanaCard).not.toBeNull();
    expect(within(grafanaCard!).getByRole("heading", { name: "Export OTLP pour Grafana" })).toBeInTheDocument();
    expect(within(grafanaCard!).getByRole("textbox", { name: "URL de base du collecteur OTLP/HTTP JSON · grafana" })).toBe(url);
    expect(within(grafanaCard!).getByRole("link", { name: "Télécharger le tableau de bord" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Destination personnalisée (SIEM)" })).toBeInTheDocument();
    expect(screen.getByText(/audits sensibles de confidentialité partent vers cette destination/)).toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: "URL de Grafana" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Ouvrir Grafana" })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Télécharger le tableau de bord" })).toHaveAttribute("href", "/api/observability/dashboard");
    expect(screen.getByRole("combobox", { name: "Événements d’usage à exporter · siem" })).toHaveValue("security");
    await user.selectOptions(screen.getByRole("combobox", { name: "Événements d’usage à exporter · grafana" }), "sensitive");
    await user.click(screen.getByRole("checkbox", { name: "Événements Shadow AI · siem" }));
    expect(screen.getByRole("combobox", { name: "Événements d’usage à exporter · siem" })).toBeDisabled();
    await user.type(url, "2");
    expect(screen.getByRole("button", { name: "Tester la configuration enregistrée · grafana" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Supprimer le secret · siem" }));
    await user.click(screen.getByRole("button", { name: "Enregistrer l’observabilité" }));
    await screen.findByText(/Configuration enregistrée/);
    const call = fetchMock.mock.calls.find(([, init]) => init?.method === "PUT")!;
    const body = JSON.parse(String(call[1]?.body));
    expect(body).not.toHaveProperty("grafana_url");
    expect(body.destinations[0].event_filter).toBe("sensitive");
    expect(body.destinations[1].event_filter).toBe("security");
    expect(body.destinations[1].shadow_events).toBe(false);
    expect(body.destinations[0]).not.toHaveProperty("authorization");
    expect(body.destinations[1].clear_authorization).toBe(true);
    expect(body.destinations[1]).not.toHaveProperty("authorization");
    expect(screen.getByLabelText("Authorization · grafana")).toHaveValue("");
    await user.click(screen.getByRole("button", { name: "Tester la configuration enregistrée · grafana" }));
    await screen.findByText(/collecteur a accepté le test synthétique/);
    expect(fetchMock).toHaveBeenCalledWith("/api/observability/test", expect.objectContaining({ method: "POST", body: JSON.stringify({ destination_id: "grafana" }), headers: expect.objectContaining({ "X-CSRF-Token": "test-csrf" }) }));
    expect(screen.getAllByText("Aucune tentative")).toHaveLength(2);
  });
  it("replaces authorization only when entered and clears the input after save", async () => {
    const fetchMock = serve(); render(<App />); const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Authorization · grafana"), "Bearer synthetic-test");
    await user.click(screen.getByRole("button", { name: "Enregistrer l’observabilité" }));
    await screen.findByText(/Configuration enregistrée/);
    const call = fetchMock.mock.calls.find(([, init]) => init?.method === "PUT")!;
    expect(JSON.parse(String(call[1]?.body)).destinations[0].authorization).toBe("Bearer synthetic-test");
    expect(screen.getByLabelText("Authorization · grafana")).toHaveValue("");
  });
  it("tests a saved disabled destination and requires an endpoint and a stream", async () => {
    const inactive = { ...config, destinations: config.destinations.map(d => ({ ...d, enabled: false, ...(d.id === "siem" ? { metrics: false, shadow_events: false, audit: false } : {}) })) };
    const fetchMock = serve(base, url => url === "/api/observability" ? reply(inactive) : url === "/api/observability/test" ? reply({ ok: true }) : undefined);
    render(<App />); const user = userEvent.setup();
    const test = await screen.findByRole("button", { name: "Tester la configuration enregistrée · grafana" });
    expect(test).toBeEnabled();
    expect(screen.getByRole("button", { name: "Tester la configuration enregistrée · siem" })).toBeDisabled();
    await user.click(test);
    await screen.findByText(/collecteur a accepté le test synthétique/);
    expect(fetchMock.mock.calls.some(([url]) => url === "/api/observability/test")).toBe(true);
  });
  it("preserves a conflicting draft until an explicit discard and reload", async () => {
    let conflict = false;
    serve(base, (url, init) => {
      if (url === "/api/observability" && init?.method === "PUT") { conflict = true; return reply({ error: "revision_conflict", message: "Une autre version existe." }, 409); }
      if (url === "/api/observability") return reply(conflict ? { ...config, revision: 3, destinations: config.destinations.map(d => ({ ...d, endpoint: "https://collector.example.org/new" })) } : config);
    });
    render(<App />); const user = userEvent.setup();
    const url = await screen.findByRole("textbox", { name: "URL de base du collecteur OTLP/HTTP JSON · grafana" });
    await user.type(url, "draft");
    await user.click(screen.getByRole("button", { name: "Enregistrer l’observabilité" }));
    const reload = await screen.findByRole("button", { name: "Abandonner le brouillon et recharger" });
    expect(url).toHaveValue(config.destinations[0].endpoint + "draft");
    await user.click(reload);
    await waitFor(() => expect(url).toHaveValue("https://collector.example.org/new"));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Enregistrer l’observabilité" })).toBeDisabled();
  });
  it("shows inherited provenance, copies settings for customization without secrets and restores inheritance explicitly", async () => {
    const inherited = { ...config, inherit: true, inheritance_available: true, inherited_from: { id: "parent-test", name: "Organisation mère" } };
    let current = structuredClone(inherited);
    const fetchMock = serve(base, (url, init) => {
      if (url === "/api/observability" && init?.method === "PUT") {
        const body = JSON.parse(String(init.body));
        current = body.inherit ? { ...inherited, revision: 4 } : { ...inherited, ...body, revision: 3, inherited_from: null };
        return reply(current);
      }
      if (url === "/api/observability") return reply(current);
    });
    render(<App />); const user = userEvent.setup();
    expect(await screen.findByText("Hérité de Organisation mère")).toBeInTheDocument();
    const url = screen.getByRole("textbox", { name: "URL de base du collecteur OTLP/HTTP JSON · grafana" });
    expect(url).toBeDisabled();
    expect(screen.getByRole("checkbox", { name: "Métriques · grafana" })).toBeDisabled();
    expect(screen.getByLabelText("Authorization · grafana")).toHaveValue("");
    await user.click(screen.getByRole("button", { name: "Personnaliser" }));
    expect(url).toBeEnabled();
    expect(url).toHaveValue(config.destinations[0].endpoint);
    expect(screen.getByText(/Les secrets hérités ne sont pas copiés/)).toBeInTheDocument();
    expect(screen.getAllByText("Aucun secret enregistré")).toHaveLength(2);
    await user.type(screen.getByLabelText("Authorization · grafana"), "Bearer child-synthetic");
    await user.click(screen.getByRole("button", { name: "Enregistrer l’observabilité" }));
    await screen.findByText("Configuration propre à cette organisation");
    let calls = fetchMock.mock.calls.filter(([, init]) => init?.method === "PUT");
    expect(JSON.parse(String(calls[0][1]?.body)).inherit).toBe(false);
    expect(JSON.parse(String(calls[0][1]?.body)).destinations[0].authorization).toBe("Bearer child-synthetic");
    await user.click(screen.getByRole("button", { name: "Rétablir l’héritage" }));
    expect(url).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Enregistrer l’observabilité" }));
    await screen.findByText("Hérité de Organisation mère");
    calls = fetchMock.mock.calls.filter(([, init]) => init?.method === "PUT");
    const restore = JSON.parse(String(calls[1][1]?.body));
    expect(restore.inherit).toBe(true);
    expect(restore.destinations.every((d: Record<string, unknown>) => !("authorization" in d))).toBe(true);
  });
  it.each([true, false])("turns off both destinations explicitly without copying inherited secrets or clearing local secrets (%s)", async inherited => {
    const source = { ...config, inherit: inherited, inheritance_available: true, inherited_from: inherited ? { id: "parent-test", name: "Organisation mère" } : null };
    const fetchMock = serve(base, (url, init) => {
      if (url === "/api/observability" && init?.method === "PUT") return reply({ ...source, ...JSON.parse(String(init.body)) });
      if (url === "/api/observability") return reply(source);
    });
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Ne rien exporter" }));
    expect(screen.getByText("Pas d’export")).toBeInTheDocument();
    expect(screen.getByRole("checkbox", { name: "Activer l’export · Grafana" })).not.toBeChecked();
    expect(screen.getByRole("checkbox", { name: "Activer l’export · SIEM" })).not.toBeChecked();
    expect(screen.getAllByText(inherited ? "Aucun secret enregistré" : "Secret enregistré")).toHaveLength(2);
    await user.click(screen.getByRole("button", { name: "Enregistrer l’observabilité" }));
    await screen.findByText(/Configuration enregistrée/);
    const call = fetchMock.mock.calls.find(([, init]) => init?.method === "PUT")!;
    const body = JSON.parse(String(call[1]?.body));
    expect(body.inherit).toBe(false);
    expect(body.destinations).toHaveLength(2);
    for (const destination of body.destinations) {
      expect(destination.enabled).toBe(false);
      expect(destination).not.toHaveProperty("authorization");
      expect(destination).not.toHaveProperty("clear_authorization");
    }
  });
});
describe("Instance language", () => {
  it("follows this browser on the sign-in screen without persisting an automatic preference", async () => {
    // The instance default says English and the browser asks for Spanish: the
    // reader wins (product decision, 2026-09-17). The sign-in link carries the
    // resolved language, so the identity provider's page opens in it too.
    speaks("es-ES", "es");
    serve(base, url => url === "/api/session" ? reply({}, 401) : url === "/api/bootstrap" ? reply({ default_language: "en" }) : undefined);
    render(<App />);
    expect(await screen.findByRole("link", { name: /Iniciar sesión/ })).toHaveAttribute("href", "/auth/login?lang=es");
    expect(localStorage.getItem("milvago.language")).toBeNull();
    // The two-language toggle became a four-language picker; the behaviour under
    // test is unchanged, so the assertion moves to the new control.
    fireEvent.change(screen.getByRole("combobox", { name: "Idioma" }), { target: { value: "fr" } });
    expect(localStorage.getItem("milvago.language")).toBe("fr");
    expect(screen.getByRole("link", { name: /Se connecter/ })).toHaveAttribute("href", "/auth/login?lang=fr");
  });
  // Regression: the two new languages were silently dropped on load. The guards
  // spelled out ["fr","en"], so a remembered "es" read as "no explicit choice"
  // and was overwritten by the instance default. Nothing caught it because every
  // language test switched language inside one session and never reloaded, and
  // the visual pass was writing a preference the console then discarded — it
  // reported 32/32 "in Spanish" while rendering English.
  it.each([
    ["es", "Vista general"],
    ["pt-BR", "Visão geral"],
  ])("keeps a remembered %s preference across a session load", async (chosen, heading) => {
    window.location.hash = "#overview";
    localStorage.setItem("milvago.language", chosen);
    // The instance default and the account both say French: only the remembered
    // browser choice can produce the expected heading.
    serve({ ...base, default_language: "fr", user: { ...base.user, language: "" } });
    render(<App />);
    expect(await screen.findByRole("heading", { level: 1, name: heading })).toBeInTheDocument();
    expect(document.documentElement.lang).toBe(chosen);
    expect(localStorage.getItem("milvago.language")).toBe(chosen);
  });

  // An account left on "Default" follows the browser, not the instance (user
  // decision, 2026-09-17). The instance says French in each case below, so only
  // the browser can produce the expected heading. "pt" alone is served by
  // pt-BR, the only Portuguese we carry; a region we do not serve falls back to
  // its base language rather than past it.
  it.each([
    [["es-ES", "es"], "Vista general"],
    [["pt", "en"], "Visão geral"],
    [["fr-CA", "fr"], "Vue d’ensemble"],
  ])("serves %s from the browser when the account says Default", async (tags, heading) => {
    window.location.hash = "#overview";
    speaks(...tags);
    serve({ ...base, default_language: "fr", user: { ...base.user, language: "" } });
    render(<App />);
    expect(await screen.findByRole("heading", { level: 1, name: heading })).toBeInTheDocument();
    // An automatic choice is applied but never persisted: it must keep following
    // the browser, not freeze in it.
    expect(localStorage.getItem("milvago.language")).toBeNull();
  });

  it("ranks a browser's tags by the reader's order, then by how closely they match", () => {
    expect(matchLanguage(["pt-BR"])).toBe("pt-BR");
    expect(matchLanguage(["PT-br"])).toBe("pt-BR");
    expect(matchLanguage(["pt"])).toBe("pt-BR");
    expect(matchLanguage(["pt-PT"])).toBe("pt-BR");
    expect(matchLanguage(["en-US", "fr"])).toBe("en");
    // A regional Spanish we do not carry falls to Spanish, and not to the
    // exactly matched English the reader put second.
    expect(matchLanguage(["es-419", "en"])).toBe("es");
    expect(matchLanguage(["de", "fr-CA"])).toBe("fr");
    expect(matchLanguage(["de", "ja"])).toBeUndefined();
    expect(matchLanguage([])).toBeUndefined();
    speaks("de", "ja");
    expect(browserLanguage()).toBe("en");
  });

  it("falls back to English when the browser asks for a language we do not serve", async () => {
    window.location.hash = "#overview";
    // German first, then Japanese: neither is served, and the instance default
    // of French no longer answers for them.
    speaks("de-DE", "de", "ja");
    serve({ ...base, default_language: "fr", user: { ...base.user, language: "" } });
    render(<App />);
    expect(await screen.findByRole("heading", { level: 1, name: "Overview" })).toBeInTheDocument();
    expect(document.documentElement.lang).toBe("en");
  });

  it.each([
    ["es", "Vista general"],
    ["pt-BR", "Visão geral"],
  ])("lets an account language in %s win over the browser", async (account, heading) => {
    window.location.hash = "#overview";
    speaks("fr-FR", "fr");
    serve({ ...base, default_language: "fr", user: { ...base.user, language: account as "fr" } });
    render(<App />);
    expect(await screen.findByRole("heading", { level: 1, name: heading })).toBeInTheDocument();
  });

  // Regression: the catalogues and the header picker carried four languages
  // while five selectors still listed Français and English by hand, so Spanish
  // and Brazilian Portuguese were unreachable from Settings, the profile, the
  // member dialogs and the setup wizard. Every selector now maps over the same
  // list; this pins the one an administrator reaches first.
  it("offers every language as an instance default", async () => {
    window.location.hash = "#settings";
    serve();
    render(<App />);
    const select = await screen.findByRole("combobox", { name: /Langue par défaut de l’instance/ });
    expect(within(select).getAllByRole("option").map(o => (o as HTMLOptionElement).value)).toEqual(["fr", "en", "es", "pt-BR"]);
  });

  // Was: saving the instance default re-rendered the console in it. It no
  // longer does — the reader's browser answers for an account on "Default" —
  // and the setting now only reaches the sign-in page the server builds.
  it.each([false, true])("leaves the rendered language alone when the instance default changes (explicit preference: %s)", async explicit => {
    window.location.hash = "#settings";
    if (explicit) localStorage.setItem("milvago.language", "fr");
    let language = "fr";
    serve(base, (url, init) => {
      if (url === "/api/session") return reply({ ...base, default_language: language });
      if (url === "/api/settings" && init?.method === "PUT") { language = JSON.parse(String(init.body)).default_language; return reply({ ...settings, default_language: language }); }
      if (url === "/api/settings") return reply({ ...settings, default_language: language });
    });
    render(<App />); const user = userEvent.setup();
    await user.selectOptions(await screen.findByRole("combobox", { name: /Langue par défaut de l’instance/ }), "en");
    await user.click(screen.getByRole("button", { name: "Enregistrer les paramètres" }));
    await screen.findByText("Paramètres enregistrés.");
    expect(document.documentElement.lang).toBe("fr");
    expect(localStorage.getItem("milvago.language")).toBe(explicit ? "fr" : null);
  });
  it("completes two setup steps and preserves unrelated settings", async () => {
    window.location.hash = "#overview"; let saved = false;
    const fetchMock = serve(base, (url, init) => {
      if (url === "/api/settings" && init?.method === "PUT") { saved = true; return reply({ ...settings, default_language: "en" }); }
      if (url === "/api/settings") return reply({ ...settings, public_url_confirmed: saved });
      if (url === "/api/session") return reply({ ...base, default_language: saved ? "en" : "fr" });
    });
    render(<App />); const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Configurer" }));
    const dialog = screen.getByRole("dialog");
    await user.selectOptions(within(dialog).getByRole("combobox", { name: /Langue par défaut de l’instance/ }), "en");
    await user.click(within(dialog).getByRole("button", { name: "Suivant" }));
    expect(within(dialog).getByRole("textbox", { name: "Nom de l’organisation" })).toHaveValue(settings.name);
    await user.click(within(dialog).getByRole("button", { name: "Terminer l’installation" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(fetchMock).toHaveBeenCalledWith("/api/settings", expect.objectContaining({ method: "PUT", body: JSON.stringify({ name: settings.name, public_url: settings.public_url, default_language: "en", event_retention_days: 90 }) }));
    expect(screen.queryByRole("button", { name: "Configure" })).not.toBeInTheDocument();
    expect(localStorage.getItem("milvago.language")).toBeNull();
  });
  it("does not offer setup for a child owner or an already configured instance", async () => {
    serve(base, url => url === "/api/settings" ? reply({ ...settings, public_url_confirmed: false, default_language_editable: false }) : undefined);
    render(<App />);
    await screen.findByRole("heading", { name: "Observabilité" });
    expect(screen.queryByRole("button", { name: "Configurer" })).not.toBeInTheDocument();
  });
});
describe("Observability enforcement", () => {
  const lockLabel = "Imposer cette configuration aux organisations filles";
  it("sends the child lock with a custom configuration", async () => {
    let current: Record<string, unknown> = { ...config, lock_descendants: false, locked_by: null, custom_inactive: false };
    const fetchMock = serve(base, (url, init) => {
      if (url === "/api/observability" && init?.method === "PUT") { current = { ...current, ...JSON.parse(String(init.body)), revision: 3 }; return reply(current); }
      if (url === "/api/observability") return reply(current);
    });
    render(<App />); const user = userEvent.setup();
    const lock = await screen.findByRole("checkbox", { name: lockLabel });
    expect(lock).not.toBeChecked();
    expect(screen.getByRole("button", { name: "Enregistrer l’observabilité" })).toBeDisabled();
    await user.click(lock);
    await user.click(screen.getByRole("button", { name: "Enregistrer l’observabilité" }));
    await screen.findByText(/Configuration enregistrée/);
    const call = fetchMock.mock.calls.find(([, init]) => init?.method === "PUT")!;
    expect(JSON.parse(String(call[1]?.body)).lock_descendants).toBe(true);
    expect(screen.getByRole("checkbox", { name: lockLabel })).toBeChecked();
  });
  it("offers the child lock only for a configuration of its own", async () => {
    const inherited = { ...config, inherit: true, inheritance_available: true, inherited_from: { id: "parent-test", name: "Organisation mère" } };
    const fetchMock = serve(base, (url, init) => {
      if (url === "/api/observability" && init?.method === "PUT") return reply({ ...inherited, revision: 3 });
      if (url === "/api/observability") return reply(inherited);
    });
    render(<App />); const user = userEvent.setup();
    await screen.findByText("Hérité de Organisation mère");
    expect(screen.queryByRole("checkbox", { name: lockLabel })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Personnaliser" }));
    await user.click(screen.getByRole("checkbox", { name: lockLabel }));
    await user.click(screen.getByRole("button", { name: "Rétablir l’héritage" }));
    expect(screen.queryByRole("checkbox", { name: lockLabel })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Personnaliser" }));
    await user.click(screen.getByRole("button", { name: "Enregistrer l’observabilité" }));
    await screen.findByText(/Configuration enregistrée/);
    const call = fetchMock.mock.calls.find(([, init]) => init?.method === "PUT")!;
    expect(JSON.parse(String(call[1]?.body))).toMatchObject({ inherit: false, lock_descendants: true });
  });
  it("shows an enforced configuration without customization controls", async () => {
    const enforced = { ...config, inherit: true, inheritance_available: true, inherited_from: { id: "parent-test", name: "Organisation mère" }, locked_by: { id: "parent-test", name: "Organisation mère" }, custom_inactive: true };
    serve(base, url => url === "/api/observability" ? reply(enforced) : undefined);
    render(<App />);
    expect(await screen.findByText(/Configuration imposée par Organisation mère/)).toHaveTextContent(/configuration personnalisée est conservée mais inactive/);
    expect(screen.getByText("Hérité de Organisation mère")).toBeInTheDocument();
    for (const name of ["Personnaliser", "Ne rien exporter", "Rétablir l’héritage"]) expect(screen.queryByRole("button", { name })).not.toBeInTheDocument();
    expect(screen.queryByRole("checkbox", { name: lockLabel })).not.toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "URL de base du collecteur OTLP/HTTP JSON · grafana" })).toBeDisabled();
    expect(screen.getByRole("checkbox", { name: "Activer l’export · Grafana" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Enregistrer l’observabilité" })).toBeDisabled();
  });
});
