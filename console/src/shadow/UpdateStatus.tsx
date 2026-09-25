import { Badge, DateValue, useText } from '../ui';
import type { Operations } from './types';

function statusTone(value: string) {
  if (value === 'applied') return 'success' as const;
  if (value === 'unavailable') return 'danger' as const;
  return 'warning' as const;
}

/**
 * What one device reports about its own agent update. Lives on the device page
 * (Parc → Postes), next to the rest of that device's facts.
 */
export function DeviceUpdateStatus({ status }: Readonly<{ status?: string }>) {
  const t = useText();
  if (!status) return <span className="muted">{t("notReported")}</span>;
  const labels: Record<string, string> = { needs_update: t("needsUpdate"), pending: t("pending"), applied: t("applied"), unavailable: t("unavailable") };
  const label = labels[status] ?? status;
  return <Badge tone={statusTone(status)}>{label}</Badge>;
}

/** Signed releases the server can actually hand out, for Shadow AI → Operations. */
export function UpdateStatus({ updates }: Readonly<{ updates: Operations['updates'] }>) {
  const t = useText();
  if (updates.versions.length === 0) return null;
  return <div className="table-scroll"><table><caption>{t("availableSignedVersions")}</caption><thead><tr>{[t("version"), t("editionPlatform"), t("validity2")].map(label => <th key={label}>{label}</th>)}</tr></thead><tbody>{updates.versions.map(item => <tr key={`${item.version}:${item.edition}:${item.platform}`}><td>{item.version}</td><td>{item.edition} / {item.platform}</td><td><DateValue value={item.expires_at} /></td></tr>)}</tbody></table></div>;
}
