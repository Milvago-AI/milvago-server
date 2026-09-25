import { useContext, useEffect, useState } from "react";
import type { SubmitEvent } from "react";
import { request } from "./api";
import type { Profile } from "./api";
import { ApiKeysPanel } from "./ApiKeysPanel";
import {
  Badge,
  Card,
  Context,
  ErrorNotice,
  Notice,
  PageBar,
  ResourceView,
  readOnly,
  useMutation,
  useResource,
  useText,
  languages,
} from "./ui";
import type { Translate } from "./ui";

export function ProfilePage() {
  const t = useText();
  const resource = useResource<Profile>("/api/profile");
  return (
    <>
      <PageBar
        title={t("myProfile")}
        info={t("yourNameAndTheConsoleLanguage")}
      />
      <ResourceView resource={resource}>
        {(profile) => <ProfileView key={profile.email} profile={profile} />}
      </ResourceView>
    </>
  );
}

function identityLabel(
  t: Translate,
  type: Profile["identity_type"],
) {
  if (type === "sso") return t("sso");
  if (type === "ldap") return t("ldap");
  return t("local");
}

function mfaStatusLabel(t: Translate, configured: Profile["mfa_configured"]): string {
  if (configured === null) return t("unknownStatus");
  return configured ? t("configured") : t("notConfigured");
}

function ProfileView({ profile }: Readonly<{ profile: Profile }>) {
  const t = useText();
  const { language, refreshSession, session } = useContext(Context);
  const frozen = readOnly(session);
  const [mfaConfigured, setMfaConfigured] = useState(profile.mfa_configured);
  const [managingMFA, setManagingMFA] = useState(false);
  const mfaStatus = mfaStatusLabel(t, mfaConfigured);
  const enrollMFA = mfaConfigured === false;
  useEffect(() => {
    if (!managingMFA) return;
    const controller = new AbortController();
    let refreshing = false;
    const refreshMFA = () => {
      if (document.visibilityState === "hidden" || refreshing) return;
      refreshing = true;
      // Keep unsaved identity fields intact when returning from the security tab.
      request<Profile>("/api/profile", { signal: controller.signal })
        .then(updated => { if (!controller.signal.aborted) setMfaConfigured(updated.mfa_configured); })
        .catch(() => { if (!controller.signal.aborted) setMfaConfigured(null); })
        .finally(() => { refreshing = false; });
    };
    window.addEventListener("focus", refreshMFA);
    document.addEventListener("visibilitychange", refreshMFA);
    return () => {
      controller.abort();
      window.removeEventListener("focus", refreshMFA);
      document.removeEventListener("visibilitychange", refreshMFA);
    };
  }, [managingMFA]);
  return (
    <>
      <IdentityForm profile={profile} refreshSession={refreshSession} />
      <Card title={t("securityAndAccess")}>
        <p>
          <strong>{t("secondFactor")}</strong> {mfaStatus}
        </p>
        {profile.identity_type !== "local" && (
          <Notice tone="neutral">
            {profile.identity_type === "sso"
              ? t("thisAccountIsManagedByYour")
              : t("thisAccountComesFromTheLdap")}
          </Notice>
        )}
        {/* Une instance de démonstration ne propose aucune de ces trois actions : le
            mot de passe, l'adresse et le second facteur sont ceux du compte que tous
            les visiteurs partagent, et le premier qui en change verrouille les
            suivants. Le serveur refuse déjà `?action=` sous ce drapeau ; ceci retire
            les boutons qui y menaient. */}
        {frozen && <Notice tone="neutral">{t("demoReadOnlyProfileNotice")}</Notice>}
        <div className="actions">
          {!frozen && profile.editable.email && (
            <a
              className="button secondary"
              href={`/auth/login?action=update_email&lang=${language}`}
            >
              {t("changeMyEmailAddress")}
            </a>
          )}
          {!frozen && profile.editable.password && (
            <a
              className="button secondary"
              href={`/auth/login?action=update_password&lang=${language}`}
            >
              {t("changeMyPassword")}
            </a>
          )}
          {!frozen && profile.editable.mfa && (
            <a
              className="button secondary"
              href={`/auth/login?action=${enrollMFA ? "configure_totp" : "manage_mfa"}&lang=${language}`}
              target={enrollMFA ? undefined : "_blank"}
              rel={enrollMFA ? undefined : "noopener noreferrer"}
              onClick={() => { if (!enrollMFA) setManagingMFA(true); }}
            >
              {t(enrollMFA ? "configureMySecondFactor" : "manageMySecondFactors")}
            </a>
          )}
        </div>
        {!frozen && profile.editable.mfa && !enrollMFA && (
          <p className="field-help">{t("manageSecondFactorsHelp")}</p>
        )}
      </Card>
      <ApiKeysPanel />
    </>
  );
}

/** Name and console language, saved without leaving the page. */
function IdentityForm({
  profile,
  refreshSession,
}: Readonly<{
  profile: Profile;
  refreshSession: () => Promise<void>;
}>) {
  const t = useText();
  // The saved values live here, not in the resource: reloading it would unmount
  // this form and drop the confirmation (see design-system.md "Piège d'état").
  const [saved, setSaved] = useState<Pick<
    Profile,
    "first_name" | "last_name" | "language"
  >>({
    first_name: profile.first_name,
    last_name: profile.last_name,
    language: profile.language,
  });
  const [firstName, setFirstName] = useState(profile.first_name);
  const [lastName, setLastName] = useState(profile.last_name);
  const [profileLanguage, setProfileLanguage] = useState<Profile["language"]>(
    profile.language,
  );
  const [confirmed, setConfirmed] = useState(false);
  const mutation = useMutation();
  const nameEditable = profile.editable.profile;
  const dirty =
    profileLanguage !== saved.language ||
    (nameEditable &&
      (firstName !== saved.first_name || lastName !== saved.last_name));
  async function save(e: SubmitEvent) {
    e.preventDefault();
    setConfirmed(false);
    try {
      const updated = await mutation.run<Profile>("/api/profile", "PUT", {
        language: profileLanguage,
        ...(nameEditable
          ? { first_name: firstName.trim(), last_name: lastName.trim() }
          : {}),
      });
      if (updated) {
        setFirstName(updated.first_name);
        setLastName(updated.last_name);
        setProfileLanguage(updated.language);
        setSaved({
          first_name: updated.first_name,
          last_name: updated.last_name,
          language: updated.language,
        });
      }
      setConfirmed(true);
      // The sidebar name and the console language both read from the session.
      await refreshSession();
    } catch {
      /* Identity-provider refusals stay visible below. */
    }
  }
  return (
    <Card title={t("identity")}>
      <form onSubmit={save}>
        <fieldset disabled={mutation.pending}>
          <div className="profile-fields">
            <label>
              {t("firstName")}
              <input
                required={nameEditable}
                maxLength={60}
                disabled={!nameEditable}
                value={firstName}
                onChange={(e) => {
                  setConfirmed(false);
                  setFirstName(e.target.value);
                }}
              />
            </label>
            <label>
              {t("lastName")}
              <input
                required={nameEditable}
                maxLength={60}
                disabled={!nameEditable}
                value={lastName}
                onChange={(e) => {
                  setConfirmed(false);
                  setLastName(e.target.value);
                }}
              />
            </label>
            <label>
              {t("consoleLanguage")}
              <select
                value={profileLanguage}
                onChange={(e) => {
                  setConfirmed(false);
                  setProfileLanguage(e.target.value as Profile["language"]);
                }}
              >
                <option value="">{t("default")}</option>
                {languages.map(l => <option key={l.code} value={l.code}>{l.label}</option>)}
              </select>
            </label>
          </div>
        </fieldset>
        <dl className="profile-rows">
          <dt>{t("emailAddress")}</dt>
          <dd>{profile.email}</dd>
          <dt>{t("accountType")}</dt>
          <dd>
            <Badge>{identityLabel(t, profile.identity_type)}</Badge>
          </dd>
        </dl>
        {!nameEditable && (
          <p className="field-help">
            {t("yourNameComesFromYourIdentity")}
          </p>
        )}
        <ErrorNotice error={mutation.error} />
        {confirmed && (
          <Notice tone="success" role="status">
            {t("profileSaved")}
          </Notice>
        )}
        <div className="dialog-actions">
          <button type="submit" className="button primary" disabled={!dirty || mutation.pending}>
            {mutation.pending
              ? t("saving")
              : t("saveMyProfile")}
          </button>
        </div>
      </form>
    </Card>
  );
}
