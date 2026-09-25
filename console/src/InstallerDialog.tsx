import { useContext, useEffect, useRef, useState } from 'react';
import { ApiError, requestRaw } from './api';
import type { DeploymentKey, Platform, Settings } from './api';
import type { ShadowSettings } from './shadow/types';
import { Card, Context, DateValue, Dialog, ErrorNotice, Icon, Loading, Notice, ResourceView, Status, useMutation, useResource, useText } from './ui';

/** Fixed, non-attacker-influenced download filenames: never interpolate a server-provided field
 * directly into a filename. Anything other than the two known platforms falls back to a generic safe name. */
const DOWNLOAD_NAMES: Record<Platform, string> = { windows: 'milvago-windows-installer.msi', linux: 'milvago-linux-installer.rpm' };
const downloadName = (platform: Platform) => DOWNLOAD_NAMES[platform] ?? 'milvago-installer';
const VERSION = /^(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})$/;

/** Download-only dialog. It creates nothing: the organization already holds a deployment key,
 * and the download only names a platform. Blocked until the public agent URL is confirmed. */
export function InstallerDialog({ close }: Readonly<{ close: () => void }>) {
  const t = useText();
  const { session } = useContext(Context);
  const settings = useResource<Settings>('/api/settings');
  const policy = useResource<ShadowSettings>('/api/shadow/settings');
  const mutation = useMutation();
  const [downloading, setDownloading] = useState('');
  const [downloadedVersions, setDownloadedVersions] = useState<Partial<Record<Platform, string>>>({});
  const [error, setError] = useState<ApiError>();
  const controller = useRef<AbortController | null>(null);
  useEffect(() => () => controller.current?.abort(), []);
  const ready = Boolean(settings.data?.public_url_confirmed && settings.data.public_url);
  const busy = mutation.pending || Boolean(downloading);
  const approval = policy.data?.config.enrollment.approval;

  async function download(platform: Platform) {
    if (!ready) return;
    controller.current = new AbortController();
    const signal = controller.current.signal;
    setDownloading(platform);
    setDownloadedVersions(current => {
      const next = { ...current };
      delete next[platform];
      return next;
    });
    setError(undefined);
    try {
      const response = await requestRaw(`/api/installer/${encodeURIComponent(platform)}`, { signal, accept: 'application/octet-stream', fallbackCode: 'download_failed' });
      const blob = await response.blob();
      if (signal.aborted) return;
      const version = response.headers.get('X-Milvago-Installer-Version');
      if (version && VERSION.test(version)) setDownloadedVersions(current => ({ ...current, [platform]: version }));
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = downloadName(platform);
      document.body.append(link);
      try { link.click(); } finally { link.remove(); window.setTimeout(() => URL.revokeObjectURL(url), 0); }
    } catch (cause) {
      if (signal.aborted) return;
      setError(cause instanceof ApiError ? cause : new ApiError(0, 'download_failed', t("downloadUnavailable")));
    } finally {
      setDownloading('');
    }
  }
  return (
    <Dialog title={t("downloadTheAgent")} close={() => !busy && close()}>
      <div className="dialog-body">
      <p><strong>{session.organization.name}</strong></p>
      <InstallerDialogBody
        settings={settings}
        ready={ready}
        approval={approval}
        downloadError={error}
        busy={busy}
        downloading={downloading}
        downloadedVersions={downloadedVersions}
        onDownload={(platform) => void download(platform)}
        close={close}
      />
      </div>
      <div className="dialog-actions"><button type="button" className="button ghost" disabled={busy} onClick={() => close()}>{t("close")}</button></div>
    </Dialog>
  );
}

/** The three ways a download attempt can be reported: none, the missing-key notice
 * (with a way to open settings) and the generic build failure, else whatever
 * ErrorNotice makes of it. Extracted so InstallerDialog's own branching stays flat. */
function InstallerError({ error, close }: Readonly<{ error: ApiError | undefined; close: () => void }>) {
  const t = useText();
  if (!error) return null;
  if (error.code === 'deployment_key_missing') {
    return (
      <Notice tone="warning" role="alert" title={t("noActiveDeploymentKey")} action={<a className="button small" href="#settings" onClick={close}>{t("openSettings")}</a>}>
        {t("thisOrganizationSKeyWasRevoked")}
      </Notice>
    );
  }
  if (error.code === 'installer_build_failed') {
    return <Notice tone="warning" role="alert" title={t("packageUnavailable")}>{error.message}</Notice>;
  }
  return <ErrorNotice error={error} />;
}

function InstallerTile({
  platform, label, hint, busy, downloading, downloadedVersion, onDownload,
}: Readonly<{
  platform: Platform;
  label: string;
  hint: string;
  busy: boolean;
  downloading: string;
  downloadedVersion: string | undefined;
  onDownload: (platform: Platform) => void;
}>) {
  const t = useText();
  return (
    <div className="card">
      <div className="card-body" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        <Icon name="download" size={20} />
        <span className="help">{hint}</span>
        <button className="button primary" disabled={busy} onClick={() => onDownload(platform)}>{downloading === platform ? t("downloading") : label}</button>
        {downloadedVersion && <output className="fine-print">{t("downloadedInstallerVersion", [downloadedVersion])}</output>}
      </div>
    </div>
  );
}

function InstallerDialogBody({
  settings, ready, approval, downloadError, busy, downloading, downloadedVersions, onDownload, close,
}: Readonly<{
  settings: { data: Settings | undefined; error: unknown; loading: boolean; reload: () => void };
  ready: boolean;
  approval: 'manual' | 'automatic' | 'network' | undefined;
  downloadError: ApiError | undefined;
  busy: boolean;
  downloading: string;
  downloadedVersions: Partial<Record<Platform, string>>;
  onDownload: (platform: Platform) => void;
  close: () => void;
}>) {
  const t = useText();
  if (settings.loading) return <Loading />;
  if (settings.error) return <ErrorNotice error={settings.error} retry={settings.reload} />;
  if (!ready) {
    return (
      <Notice
        tone="warning"
        role="alert"
        title={t("publicAgentUrlNotConfirmed")}
        action={settings.data?.public_url_editable ? <a className="button small" href="#settings" onClick={close}>{t("configure")}</a> : undefined}
      >
        {settings.data?.public_url_editable
          ? t("setAndConfirmThePublicHttps")
          : t("anOrganizationOwnerMustConfirmThe")}
      </Notice>
    );
  }
  return (
    <>
      <Notice>{t("thePackageCarriesThisOrganizationS")}</Notice>
      {/* A mass deployment under manual approval must not surprise anyone: the devices
          appear immediately and report nothing until they are approved. */}
      {approval === 'manual' && (
        <Notice tone="warning" title={t("manualApprovalIsOn")}>
          {t("everyInstalledDeviceWillAppearAs")}
        </Notice>
      )}
      {approval === 'network' && (
        <Notice title={t("approvalDependsOnTheNetwork")}>
          {t("aDeviceInstalledFromAnAllowed")}
        </Notice>
      )}
      <InstallerError error={downloadError} close={close} />
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0,1fr))', gap: 12 }}>
        <InstallerTile platform="windows" label="Windows MSI" hint={t("windowsServiceMachineWide")} busy={busy} downloading={downloading} downloadedVersion={downloadedVersions.windows} onDownload={onDownload} />
        <InstallerTile platform="linux" label="Linux RPM" hint={t("systemdServiceMachineWide")} busy={busy} downloading={downloading} downloadedVersion={downloadedVersions.linux} onDownload={onDownload} />
      </div>
      <p className="fine-print" style={{ marginTop: 12 }}>{t("theSamePackageServesTheWhole")}</p>
    </>
  );
}

/** The organization's deployment key: shown in Administration → Settings (Community) and on an
 * organization's own page (Enterprise). The secret is never displayed — not even once. What an
 * administrator can see is that a key exists, when it last changed, and how many installations
 * it has bought; what they can do is replace it or withdraw it. */
export function DeploymentKeyPanel({ organization }: Readonly<{ organization?: string }>) {
  const t = useText();
  const base = organization ? `/api/organizations/${encodeURIComponent(organization)}/deployment-key` : '/api/deployment-key';
  const resource = useResource<{ key: DeploymentKey | null }>(base);
  const mutation = useMutation();
  const [confirming, setConfirming] = useState<'rotate' | 'revoke'>();
  async function apply(action: 'rotate' | 'revoke') {
    try { await mutation.run(`${base}/${action}`, 'POST'); setConfirming(undefined); resource.reload(); } catch { /* Displayed below. */ }
  }
  const warning: Record<'rotate' | 'revoke', string> = {
    rotate: t("aNewInstallerWillBeRequired"),
    revoke: t("noInstallationWillBePossibleIn"),
  };
  return (
    <Card
      className="settings-panel"
      title={t("deploymentKey")}
      description={t("aRandomKeyUniqueToThis")}
      flush
    >
      <ErrorNotice error={mutation.error} />
      <ResourceView resource={resource}>
        {data => (
          <div style={{ padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 14 }}>
            {data.key ? (
              <dl className="dl">
                <dt>{t("status")}</dt>
                <dd><Status value="active" /></dd>
                <dt>{t("created")}</dt>
                <dd><DateValue value={data.key.created_at} /></dd>
                <dt>{t("lastRotation")}</dt>
                <dd>{data.key.rotated_at ? <DateValue value={data.key.rotated_at} /> : <span className="muted">—</span>}</dd>
                <dt>{t("installations")}</dt>
                <dd className="mono">{data.key.uses}</dd>
              </dl>
            ) : (
              <p className="fine-print">{t("noActiveKeyNoInstallerCan")}</p>
            )}
            {confirming ? (
              <Notice
                tone="warning"
                action={<><button className="button secondary" disabled={mutation.pending} onClick={() => setConfirming(undefined)}>{t("cancel")}</button><button className="button primary" disabled={mutation.pending} onClick={() => void apply(confirming)}>{confirming === 'rotate' ? t("confirmRotation") : t("confirmRevocation")}</button></>}
              >
                {warning[confirming]}
              </Notice>
            ) : (
              <div className="actions">
                <button className="button secondary" disabled={mutation.pending} onClick={() => setConfirming('rotate')}>{data.key ? t("rotate") : t("generateAKey")}</button>
                {data.key && <button className="button danger" disabled={mutation.pending} onClick={() => setConfirming('revoke')}>{t("revoke")}</button>}
              </div>
            )}
          </div>
        )}
      </ResourceView>
    </Card>
  );
}
