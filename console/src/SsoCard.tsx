import { useState } from "react";
import type { SubmitEvent } from "react";
import type { SsoProvider, SsoProviderView, SsoSettings } from "./api";
import {
  Button,
  Card,
  Dialog,
  ErrorNotice,
  Field,
  Notice,
  ResourceView,
  useMutation,
  useResource,
  useText,
} from "./ui";

type ProviderForm = {
  enabled: boolean;
  client_id: string;
  client_secret: string;
  hosted_domain: string;
  tenant_id: string;
  invitation_domain: string;
};

function fromView(view: SsoProviderView): ProviderForm {
  return {
    enabled: view.configured ? view.enabled : true,
    client_id: view.client_id ?? "",
    client_secret: "",
    hosted_domain: view.hosted_domain ?? "",
    tenant_id: view.tenant_id ?? "",
    invitation_domain: view.invitation_domain ?? "",
  };
}

type NoticeState = { tone: "success" | "danger"; text: string };

export function SsoCard() {
  const t = useText();
  const resource = useResource<SsoSettings>("/api/settings/sso");
  // Lives here, not in the child: reload() unmounts that child, and its state would go with it.
  const [notice, setNotice] = useState<NoticeState | null>(null);
  return (
    <Card title={t("sso")} description={t("ssoDescription")}>
      {notice && <Notice tone={notice.tone}>{notice.text}</Notice>}
      <ResourceView resource={resource}>
        {(data) => data.editable === false ? (
          <Notice>{t("ssoOperatorManaged")}</Notice>
        ) : (
          <>
            {(["google", "microsoft"] as const).map((provider) => (
              <ProviderEditor
                key={provider}
                provider={provider}
                view={data.providers[provider]}
                reload={resource.reload}
                notify={(tone, text) => setNotice({ tone, text })}
              />
            ))}
          </>
        )}
      </ResourceView>
    </Card>
  );
}

function ProviderEditor({
  provider,
  view,
  reload,
  notify,
}: Readonly<{
  provider: SsoProvider;
  view: SsoProviderView;
  reload: () => void;
  notify: (tone: "success" | "danger", text: string) => void;
}>) {
  const t = useText();
  const [form, setForm] = useState<ProviderForm>(() => fromView(view));
  const [removing, setRemoving] = useState(false);
  const mutation = useMutation();
  const google = provider === "google";
  const path = `/api/settings/sso/${provider}`;

  function set<K extends keyof ProviderForm>(key: K, value: ProviderForm[K]) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    try {
      await mutation.run(path, "PUT", form);
      notify("success", t("ssoProviderSaved"));
      reload();
    } catch {
      /* Displayed via mutation.error below. */
    }
  }

  return (
    <section className="sso-provider">
      <h3>{t(google ? "googleWorkspace" : "microsoftEntraId")}</h3>
      <form onSubmit={save}>
        <fieldset disabled={mutation.pending}>
          <div className="directory-fields">
            <Field label={t("ssoRedirectUri")} help={t("ssoRedirectUriHelp")}>
              <input readOnly value={view.redirect_uri} onFocus={(e) => e.target.select()} />
            </Field>
            <Field label={t(google ? "ssoGoogleClientId" : "ssoMicrosoftClientId")}>
              <input
                required
                maxLength={200}
                autoComplete="off"
                value={form.client_id}
                onChange={(e) => set("client_id", e.target.value)}
              />
            </Field>
            <Field
              label={t("ssoClientSecret")}
              help={view.configured ? t("ssoLeaveBlankToKeepSecret") : undefined}
            >
              <input
                type="password"
                autoComplete="off"
                required={!view.configured}
                maxLength={512}
                value={form.client_secret}
                onChange={(e) => set("client_secret", e.target.value)}
              />
            </Field>
            {google ? (
              <Field label={t("ssoGoogleDomain")} help={t("ssoGoogleDomainHelp")}>
                <input
                  required
                  placeholder="example.com"
                  value={form.hosted_domain}
                  onChange={(e) => set("hosted_domain", e.target.value)}
                />
              </Field>
            ) : (
              <Field label={t("ssoMicrosoftTenant")} help={t("ssoMicrosoftTenantHelp")}>
                <input
                  required
                  placeholder="00000000-0000-0000-0000-000000000000"
                  value={form.tenant_id}
                  onChange={(e) => set("tenant_id", e.target.value)}
                />
              </Field>
            )}
            {!google && (
              <Field label={t("ssoMicrosoftInvitationDomain")} help={t("ssoMicrosoftInvitationDomainHelp")}>
                <input
                  placeholder="example.com"
                  value={form.invitation_domain}
                  onChange={(e) => set("invitation_domain", e.target.value)}
                />
              </Field>
            )}
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={form.enabled}
                onChange={(e) => set("enabled", e.target.checked)}
              />
              <span>{t("ssoOfferOnSignIn")}</span>
            </label>
          </div>
        </fieldset>
        <ErrorNotice error={mutation.error} />
        <div className="dialog-actions">
          <Button variant="primary" type="submit" disabled={mutation.pending}>
            {t("save")}
          </Button>
          {view.configured && (
            <Button variant="danger" type="button" disabled={mutation.pending} onClick={() => setRemoving(true)}>
              {t("ssoRemoveProvider")}
            </Button>
          )}
        </div>
      </form>
      {removing && (
        <RemoveProviderDialog
          path={path}
          close={() => setRemoving(false)}
          done={() => {
            setRemoving(false);
            notify("success", t("ssoProviderRemoved"));
            reload();
          }}
        />
      )}
    </section>
  );
}

function RemoveProviderDialog({
  path,
  close,
  done,
}: Readonly<{
  path: string;
  close: () => void;
  done: () => void;
}>) {
  const t = useText();
  const mutation = useMutation();
  async function remove() {
    try {
      await mutation.run(path, "DELETE");
      done();
    } catch {
      /* Displayed via mutation.error below. */
    }
  }
  return (
    <Dialog title={t("ssoRemoveProvider")} close={() => !mutation.pending && close()}>
      <p>{t("ssoRemoveProviderWarning")}</p>
      <ErrorNotice error={mutation.error} />
      <div className="dialog-actions">
        <Button variant="secondary" disabled={mutation.pending} onClick={close}>
          {t("cancel")}
        </Button>
        <Button variant="danger" disabled={mutation.pending} onClick={() => void remove()}>
          {t("confirmRemoval2")}
        </Button>
      </div>
    </Dialog>
  );
}
