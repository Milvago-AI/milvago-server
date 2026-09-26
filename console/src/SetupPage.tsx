import { Fragment, useState } from "react";
import type { ReactNode, SubmitEvent } from "react";
import { ApiError, request } from "./api";
import type { Session } from "./api";
import { PrivacyFields } from "./PrivacyDetectionPage";
import type { PrivacyConfig } from "./PrivacyDetectionPage";
import { Button, copyToClipboard, ErrorNotice, Field, Icon, Notice, languages, useText } from "./ui";
import type { Language } from "./ui";

// First-run setup wizard, shown instead of the entry page while the instance has no
// administrator. The password stays in memory until completion; a pasted license
// is verified at step two and submitted again at completion. Neither is stored in
// the browser.
export type SetupStatus = { pending: boolean; ready: boolean; edition: Session["edition"]; privacy_defaults?: PrivacyConfig; instance_id?: string };
type SMTP = { host: string; port: number; from: string; from_name: string; security: "none" | "starttls" | "tls"; username: string; password: string };
type LicenseChoice = "have" | "request" | "none";

const STEPS = 9;

function setupLicenseValue(license: string, commercial: boolean, choice: LicenseChoice): string {
  if (!commercial && choice === "none") return "";
  return license.trim();
}

export function SetupPage({ status, language, chooseLanguage }: Readonly<{ status: SetupStatus; language: Language; chooseLanguage: (next: Language) => void }>) {
  const t = useText();
  const [step, setStep] = useState(1);
  const [token, setToken] = useState("");
  const [csrf, setCsrf] = useState("");
  const [admin, setAdmin] = useState({ email: "", first_name: "", last_name: "", password: "" });
  const [confirmation, setConfirmation] = useState("");
  const [adminTOTP, setAdminTOTP] = useState(true);
  const [requireMFA, setRequireMFA] = useState(false);
  const [organization, setOrganization] = useState({ name: "", public_url: globalThis.location.origin, default_language: language });
  const [smtpEnabled, setSmtpEnabled] = useState(false);
  const [smtp, setSmtp] = useState<SMTP>({ host: "", port: 587, from: "", from_name: "Milvago", security: "starttls", username: "", password: "" });
  const [privacy, setPrivacy] = useState<PrivacyConfig | undefined>(status.privacy_defaults);
  const [error, setError] = useState<unknown>();
  const [pending, setPending] = useState(false);
  const [testSent, setTestSent] = useState("");
  // Community only: which of the three choices is active. Community's default is to
  // continue without one -- the instance already worked this way before licences
  // existed, so an administrator who skips the question keeps today's behaviour.
  const [licenseChoice, setLicenseChoice] = useState<LicenseChoice>("none");
  const [license, setLicense] = useState("");
  const [licenseEmail, setLicenseEmail] = useState("");
  const [licenseRequested, setLicenseRequested] = useState(false);
  const [idCopied, setIdCopied] = useState<"idle" | "done" | "failed">("idle");
  const commercial = status.edition === "commercial";
  // What is actually sent: a Community reader who typed something into the textarea
  // and then switched back to "continue without one" must not have that text leak
  // into the request behind their back.
  const effectiveLicense = setupLicenseValue(license, commercial, licenseChoice);

  if (!status.ready)
    return <main className="entry-main"><Notice tone="warning" title={t("setupClosed")}>{t("setupClosedHelp")}</Notice></main>;

  const titles = [t("setupToken"), t("setupLicense"), t("language"), t("setupAdministrator"), t("setupSecurity"), t("organizationAndAccess"), t("setupEmailServer"), t("privacy"), t("setupSummary")];
  const setSMTP = <K extends keyof SMTP>(key: K, value: SMTP[K]) => setSmtp(current => ({ ...current, [key]: value }));
  const setPrivacyValue = <K extends keyof PrivacyConfig>(key: K, value: PrivacyConfig[K]) => setPrivacy(current => current && { ...current, [key]: value });

  async function run(action: () => Promise<void>) {
    setError(undefined);
    setPending(true);
    try {
      await action();
    } catch (e) {
      // An expired setup session sends the administrator back to the token.
      if (e instanceof ApiError && e.code === "setup_session_required") { setCsrf(""); setStep(1); }
      setError(e);
    } finally {
      setPending(false);
    }
  }
  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (step === 1) {
      await run(async () => {
        const opened = await request<{ csrf: string }>("/api/setup/session", { method: "POST", body: { token } });
        setCsrf(opened.csrf);
        setToken("");
        setStep(2);
      });
      return;
    }
    // Enterprise always needs a licence; Community only when it chose to paste one --
    // "continue without one" and an unsent request are both valid ways to leave this step.
    if (step === 2 && (commercial || licenseChoice === "have") && !license.trim()) {
      setError(new ApiError(400, "invalid_request", t("licenseRequiredToContinue")));
      return;
    }
    if (step === 2 && effectiveLicense) {
      await run(async () => {
        await request("/api/setup/license-check", { method: "POST", csrf, body: { license: effectiveLicense } });
        setStep(3);
      });
      return;
    }
    if (step === 4 && admin.password !== confirmation) { setError(new ApiError(400, "invalid_request", t("setupPasswordsDiffer"))); return; }
    if (step < STEPS) { setError(undefined); setStep(step + 1); return; }
    await run(async () => {
      const done = await request<{ login: string }>("/api/setup/complete", {
        method: "POST", csrf,
        body: { admin, organization, admin_totp: adminTOTP, require_mfa: requireMFA, smtp: smtpEnabled ? smtp : null, privacy: privacy ?? null, license: effectiveLicense },
      });
      globalThis.location.assign(done.login);
    });
  }
  async function sendTest() {
    setTestSent("");
    await run(async () => {
      await request("/api/setup/smtp-test", { method: "POST", csrf, body: { smtp, to: admin.email } });
      setTestSent(admin.email);
    });
  }
  async function sendLicenseRequest() {
    setLicenseRequested(false);
    await run(async () => {
      await request("/api/setup/license-request", { method: "POST", csrf, body: { email: licenseEmail.trim() } });
      setLicenseRequested(true);
    });
  }
  const yesNo = (value: boolean) => value ? t("setupYes") : t("setupNo");
  // Same markup as the privacy settings: box and label on one line, help below.
  const checkbox = (label: string, help: string, checked: boolean, change: (value: boolean) => void) =>
    <div className="privacy-setting"><label className="checkbox-label"><input type="checkbox" checked={checked} onChange={e => change(e.target.checked)} />{label}</label>{help && <small className="field-help">{help}</small>}</div>;
  const summary: [string, ReactNode][] = [
    [t("license"), effectiveLicense ? t("licenseSummaryEntered") : t("licenseSummaryNone")],
    [t("setupAdministrator"), `${admin.first_name} ${admin.last_name} · ${admin.email}`],
    [t("setupAdminTOTP"), yesNo(adminTOTP)],
    [t("setupRequireMFA"), yesNo(requireMFA)],
    [t("organizationName"), organization.name],
    [t("publicAgentHttpsUrl"), organization.public_url],
    [t("instanceDefaultLanguage"), languages.find(l => l.code === organization.default_language)?.label ?? organization.default_language],
    [t("setupEmailServer"), smtpEnabled ? `${smtp.host}:${smtp.port}` : t("notConfigured")],
  ];

  let body: ReactNode;
  switch (step) {
    case 1:
      body = <Field label={t("setupToken")} help={t("setupTokenHelp")}><input required type="password" autoComplete="off" value={token} onChange={e => setToken(e.target.value)} /></Field>;
      break;
    case 2:
      body = commercial ? (
        <>
          <p className="help">{t("licenseEnterpriseHelp")}</p>
          <div className="field">
            <span className="label">{t("licenseInstanceId")}</span>
            <div className="actions">
              <code className="mono">{status.instance_id ?? "—"}</code>
              <Button
                onClick={async () => setIdCopied((await copyToClipboard(status.instance_id ?? "")) ? "done" : "failed")}
              >
                <Icon name={idCopied === "done" ? "check" : "copy"} />
                {idCopied === "done" ? t("copied") : t("copyInstanceId")}
              </Button>
            </div>
          </div>
          {idCopied === "failed" && <Notice tone="warning">{t("automaticCopyFailedSelectTheText")}</Notice>}
          <Field label={t("licensePasteLabel")} help={t("licensePasteHelp")}>
            <textarea rows={6} value={license} onChange={e => setLicense(e.target.value)} />
          </Field>
        </>
      ) : (
        <>
          <div className="field">
            <span className="label">{t("license")}</span>
            <label className="checkbox-label"><input type="radio" name="license-choice" checked={licenseChoice === "have"} onChange={() => setLicenseChoice("have")} />{t("licenseChoiceHave")}</label>
            <label className="checkbox-label"><input type="radio" name="license-choice" checked={licenseChoice === "request"} onChange={() => setLicenseChoice("request")} />{t("licenseChoiceRequest")}</label>
            <label className="checkbox-label"><input type="radio" name="license-choice" checked={licenseChoice === "none"} onChange={() => setLicenseChoice("none")} />{t("licenseChoiceNone")}</label>
          </div>
          <p className="help">{t("licenseFreeCommunityOnly")}</p>
          {licenseChoice === "have" && (
            <Field label={t("licensePasteLabel")} help={t("licensePasteHelp")}>
              <textarea rows={6} value={license} onChange={e => setLicense(e.target.value)} />
            </Field>
          )}
          {licenseChoice === "request" && <>
            <Field label={t("licenseRequestEmailLabel")}><input type="email" maxLength={254} value={licenseEmail} onChange={e => setLicenseEmail(e.target.value)} /></Field>
            <Button disabled={pending || !licenseEmail.trim()} onClick={() => void sendLicenseRequest()}>{t("licenseSendRequest")}</Button>
            {licenseRequested && <Notice tone="success">{t("licenseRequestSent", [licenseEmail])}</Notice>}
            {licenseRequested && (
              <Field label={t("licensePasteLabel")} help={t("licensePasteHelp")}>
                <textarea rows={6} value={license} onChange={e => setLicense(e.target.value)} />
              </Field>
            )}
          </>}
          {licenseChoice === "none" && <Notice tone="warning" title={t("licenseNoneWarningTitle")}>{t("licenseNoneWarningBody")}</Notice>}
        </>
      );
      break;
    case 3:
      body = <Field label={t("instanceDefaultLanguage")} help={t("eachUserCanChooseAPersonal")}>
        <select value={organization.default_language} onChange={e => { const next = e.target.value as Language; chooseLanguage(next); setOrganization(o => ({ ...o, default_language: next })); }}>
          {languages.map(l => <option key={l.code} value={l.code}>{l.label}</option>)}
        </select>
      </Field>;
      break;
    case 4:
      body = <>
        <p className="help">{t("setupAdministratorHelp")}</p>
        <Field label={t("emailAddress")}><input required type="email" maxLength={254} autoComplete="username" value={admin.email} onChange={e => setAdmin(a => ({ ...a, email: e.target.value }))} /></Field>
        <Field label={t("firstName")}><input required maxLength={100} autoComplete="given-name" value={admin.first_name} onChange={e => setAdmin(a => ({ ...a, first_name: e.target.value }))} /></Field>
        <Field label={t("lastName")}><input required maxLength={100} autoComplete="family-name" value={admin.last_name} onChange={e => setAdmin(a => ({ ...a, last_name: e.target.value }))} /></Field>
        <Field label={t("setupPassword")} help={t("setupPasswordHelp")}><input required type="password" minLength={12} maxLength={128} autoComplete="new-password" value={admin.password} onChange={e => setAdmin(a => ({ ...a, password: e.target.value }))} /></Field>
        <Field label={t("setupPasswordConfirm")}><input required type="password" minLength={12} maxLength={128} autoComplete="new-password" value={confirmation} onChange={e => setConfirmation(e.target.value)} /></Field>
      </>;
      break;
    case 5:
      body = <>
        {checkbox(t("setupAdminTOTP"), t("setupAdminTOTPHelp"), adminTOTP, setAdminTOTP)}
        {checkbox(t("setupRequireMFA"), t("setupRequireMFAHelp"), requireMFA, setRequireMFA)}
      </>;
      break;
    case 6:
      body = <>
        <Field label={t("organizationName")}><input required maxLength={120} value={organization.name} onChange={e => setOrganization(o => ({ ...o, name: e.target.value }))} /></Field>
        <Field label={t("publicAgentHttpsUrl")} help={t("addressUsedByAgentsAndThe")}><input required type="url" value={organization.public_url} onChange={e => setOrganization(o => ({ ...o, public_url: e.target.value }))} /></Field>
      </>;
      break;
    case 7:
      body = <>
        <p className="help">{t("setupEmailServerHelp")}</p>
        {checkbox(t("setupConfigureEmail"), "", smtpEnabled, setSmtpEnabled)}
        {smtpEnabled && <>
          <Field label={t("smtpHost")}><input required maxLength={253} value={smtp.host} onChange={e => setSMTP("host", e.target.value)} /></Field>
          <Field label={t("smtpPort")}><input required type="number" min={1} max={65535} value={smtp.port} onChange={e => setSMTP("port", Number(e.target.value))} /></Field>
          <Field label={t("smtpSecurity")}>
            <select value={smtp.security} onChange={e => setSMTP("security", e.target.value as SMTP["security"])}>
              <option value="starttls">{t("smtpStartTLS")}</option>
              <option value="tls">{t("smtpTLS")}</option>
              <option value="none">{t("none")}</option>
            </select>
          </Field>
          <Field label={t("smtpFrom")}><input required type="email" maxLength={254} value={smtp.from} onChange={e => setSMTP("from", e.target.value)} /></Field>
          <Field label={t("smtpFromName")}><input maxLength={100} value={smtp.from_name} onChange={e => setSMTP("from_name", e.target.value)} /></Field>
          <Field label={t("smtpUsername")}><input maxLength={256} autoComplete="off" value={smtp.username} onChange={e => setSMTP("username", e.target.value)} /></Field>
          <Field label={t("smtpPassword")}><input type="password" maxLength={1024} autoComplete="off" value={smtp.password} onChange={e => setSMTP("password", e.target.value)} /></Field>
          <p className="help">{t("setupTestRecipient", [admin.email])}</p>
          <Button disabled={pending || !smtp.host || !smtp.from} onClick={() => void sendTest()}>{t("setupSendTest")}</Button>
          {testSent && <Notice tone="success">{t("setupTestSent", [testSent])}</Notice>}
        </>}
      </>;
      break;
    case 8:
      body = <>
        <p className="help">{t("setupPrivacyHelp")}</p>
        {privacy && <PrivacyFields config={privacy} set={setPrivacyValue} locked={false} edition={status.edition} teamClaim={false} />}
      </>;
      break;
    default:
      body = <>
        <p className="help">{t("setupSummaryHelp")}</p>
        <dl className="dl">{summary.map(([label, value]) => <Fragment key={label}><dt>{label}</dt><dd>{value}</dd></Fragment>)}</dl>
      </>;
  }
  return <main className="entry-main setup">
    <h1>{t("setupWelcome")}</h1>
    <p className="entry-description">{t("setupWelcomeHelp")}</p>
    <output style={{ display: "block", margin: "1em 0" }}>{t("step")} {step} / {STEPS} · {titles[step - 1]}</output>
    <form onSubmit={submit} className="form-grid">
      <ErrorNotice error={error} />
      {/* A new element per step: React would otherwise reuse the previous step's
          inputs, carrying a value (the password included) into another field. */}
      <fieldset key={step} disabled={pending}>{body}</fieldset>
      {step === STEPS && pending && <output className="setup-progress" role="status"><span className="spinner" aria-hidden="true" />{t("setupCompleting")}</output>}
      <div className="dialog-actions">
        {step > 2 && <Button disabled={pending} onClick={() => { setError(undefined); setStep(step - 1); }}>{t("back")}</Button>}
        <Button type="submit" variant="primary" disabled={pending}>{step === STEPS ? t("setupFinish") : t("next")}</Button>
      </div>
    </form>
  </main>;
}
