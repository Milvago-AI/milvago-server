import { useContext, useEffect, useState } from "react";
import type { SubmitEvent } from "react";
import type { Profile } from "./api";
import { ApiKeysPanel } from "./ApiKeysPanel";
import {
  Badge,
  Card,
  Context,
  ErrorNotice,
  Icon,
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

// What the server says on the way back from an account action (fixed values only,
// see /auth/callback): the confirmation to show, or nothing for a cancelled one.
const returnedActions = {
  password: "passwordChanged",
  email: "emailChangeRequested",
  mfa_added: "deviceAdded",
  mfa_removed: "deviceRemoved",
  profile: "profileSaved",
} as const;

function returnedNotice(): { tone: "success" | "danger"; key: (typeof returnedActions)[keyof typeof returnedActions] | "accountActionFailed" } | null {
  const query = new URLSearchParams(window.location.hash.split("?")[1] ?? "");
  const done = query.get("done");
  if (!done || !Object.hasOwn(returnedActions, done)) return null;
  if (query.get("status") === "success") return { tone: "success", key: returnedActions[done as keyof typeof returnedActions] };
  if (query.get("status") === "error") return { tone: "danger", key: "accountActionFailed" };
  return null;
}

function ProfileView({ profile }: Readonly<{ profile: Profile }>) {
  const t = useText();
  const { language, refreshSession, session } = useContext(Context);
  const frozen = readOnly(session);
  const [returned] = useState(returnedNotice);
  // Read once: a reload of the page must not repeat the confirmation.
  useEffect(() => {
    if (window.location.hash.includes("?")) window.history.replaceState(null, "", "#profile");
  }, []);
  const action = (name: string, extra = "") => `/auth/login?action=${name}${extra}&lang=${language}`;
  const devices = profile.mfa_devices ?? null;
  const manageMFA = !frozen && profile.editable.mfa;
  return (
    <>
      {returned && <Notice tone={returned.tone} role="status">{t(returned.key)}</Notice>}
      <IdentityForm profile={profile} refreshSession={refreshSession} />
      <Card title={t("securityAndAccess")} description={!frozen && profile.identity_type !== "sso" ? t("securityActionsHelp") : undefined}>
        {profile.identity_type !== "local" && (
          <Notice tone="neutral">
            {profile.identity_type === "sso"
              ? t("thisAccountIsManagedByYour")
              : t("thisAccountComesFromTheLdap")}
          </Notice>
        )}
        {/* A demonstration instance offers none of these three actions: the password,
            the address and the second factor belong to the account every visitor
            shares, and the first one to change them would lock out the next. The server
            already refuses `?action=` under this flag; this removes the buttons that
            led there. */}
        {frozen && <Notice tone="neutral">{t("demoReadOnlyProfileNotice")}</Notice>}
        <dl className="security-rows">
          <dt>{t("emailAddress")}</dt>
          <dd>{profile.email}</dd>
          <dd>
            {!frozen && profile.editable.email && (
              <a className="button secondary small" href={action("update_email")} aria-label={t("changeMyEmailAddress")}>{t("change")}</a>
            )}
          </dd>
          {profile.editable.password && (
            <>
              <dt>{t("password")}</dt>
              <dd aria-hidden="true">••••••••</dd>
              <dd>
                {!frozen && (
                  <a className="button secondary small" href={action("update_password")} aria-label={t("changeMyPassword")}>{t("change")}</a>
                )}
              </dd>
            </>
          )}
          <dt>{t("secondFactorTitle")}</dt>
          <dd>
            {devices === null && <p className="muted">{t("secondFactorUnknown")}</p>}
            {devices?.length === 0 && <p className="muted">{t("secondFactorNone")}</p>}
            {devices && devices.length > 0 && (
              <>
                <ul className="mfa-devices">
                  {devices.map(device => (
                    <li key={device.id}>
                      <Icon name="smartphone" />
                      <div>
                        <strong>{device.label || t("unnamedDevice")}</strong>
                        <span>{t("deviceAddedOn", [new Intl.DateTimeFormat(language, { dateStyle: "long" }).format(new Date(device.created_at))])}</span>
                      </div>
                      {manageMFA && (
                        <a className="button danger small" href={action("remove_mfa", `&credential=${encodeURIComponent(device.id)}`)} aria-label={t("removeDeviceNamed", [device.label || t("unnamedDevice")])}>{t("remove")}</a>
                      )}
                    </li>
                  ))}
                </ul>
                <p className="field-help">{t("secondFactorAsked")}</p>
              </>
            )}
          </dd>
          <dd>
            {manageMFA && devices !== null && (
              <a className={devices.length === 0 ? "button primary small" : "button secondary small"} href={action("configure_totp")}>
                <Icon name="plus" />
                {t(devices.length === 0 ? "configureMySecondFactor" : "addDevice")}
              </a>
            )}
          </dd>
        </dl>
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
  // this form and drop the confirmation.
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
