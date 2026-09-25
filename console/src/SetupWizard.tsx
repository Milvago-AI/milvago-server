import { useContext, useState } from "react";
import type { SubmitEvent } from "react";
import type { Settings } from "./api";
import { Button, Context, Dialog, ErrorNotice, Field, useMutation, useText , languages } from "./ui";
import type { Language, Translate } from "./ui";

function setupButtonLabel(t: Translate, pending: boolean, step: number): string {
  if (pending) return t("saving");
  return step === 1 ? t("next") : t("completeSetup");
}

export function SetupWizard({ initial, close }: Readonly<{ initial: Settings; close: () => void }>) {
  const t = useText();
  const { refreshSession } = useContext(Context);
  const [step, setStep] = useState(1);
  const [language, setLanguage] = useState<Language>(initial.default_language ?? "fr");
  const [name, setName] = useState(initial.name);
  const [url, setUrl] = useState(initial.public_url);
  const mutation = useMutation();
  async function save(event: SubmitEvent) {
    event.preventDefault();
    if (step === 1) { setStep(2); return; }
    try {
      await mutation.run("/api/settings", "PUT", {
        name, public_url: url, default_language: language,
        event_retention_days: initial.event_retention_days,
      });
      await refreshSession();
      window.dispatchEvent(new CustomEvent("milvago:settings"));
      close();
    } catch { /* The dialog remains open with the server error. */ }
  }
  return <Dialog title={t("initialSetup")} close={close}>
    <output style={{ display: 'block', margin: '1em 0' }}>{t("step")} {step} / 2 · {step === 1 ? t("language") : t("organizationAndAccess")}</output>
    <form onSubmit={save}>
      <ErrorNotice error={mutation.error} />
      <fieldset disabled={mutation.pending}>
        {step === 1 ? <Field label={t("instanceDefaultLanguage")} help={t("eachUserCanChooseAPersonal")}>
          <select value={language} onChange={e => setLanguage(e.target.value as Language)}>{languages.map(l => <option key={l.code} value={l.code}>{l.label}</option>)}</select>
        </Field> : <>
          <Field label={t("organizationName")}><input required maxLength={120} value={name} onChange={e => setName(e.target.value)} /></Field>
          <Field label={t("publicAgentHttpsUrl")} help={t("addressUsedByAgentsAndThe")}><input required type="url" value={url} onChange={e => setUrl(e.target.value)} /></Field>
        </>}
      </fieldset>
      <div className="dialog-actions">
        {step === 2 && <Button disabled={mutation.pending} onClick={() => setStep(1)}>{t("back")}</Button>}
        <Button type="submit" variant="primary" disabled={mutation.pending}>{setupButtonLabel(t, mutation.pending, step)}</Button>
      </div>
    </form>
  </Dialog>;
}
