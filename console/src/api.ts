import type { Language } from "./locales/languages";
export type Session = {
  is_instance_owner?: boolean;
  // The instance runs with MILVAGO_DEBUG, which carries the detection-catalogue editor.
  // A maintenance surface, not a right: the server closes the routes that write a
  // catalogue on the same flag, so hiding the page here only spares the noise.
  console_debug?: boolean;
  // The instance runs with MILVAGO_DEMO_READONLY: the server refuses every console
  // mutation before routing, whatever this account may hold. The console reads it to
  // withhold the controls that would raise a refusal — a rendering decision, never a
  // permission one. The pages themselves stay open: a demonstration that hid its own
  // configuration screens would demonstrate half the product.
  demo_read_only?: boolean;
  privacy?: { aggregate_only: boolean };
  user: { id: string; email: string; display_name: string; language?: "" | Language };
  organization: { id: string; name: string; role: string };
  organizations: { id: string; name: string; role: string; parent_id?: string | null }[];
  permissions: string[];
  csrf_token: string;
  edition: "community" | "commercial";
  default_language?: Language;
  // Optional so an old mock or an out-of-step fixture reads as unlicensed rather than
  // throwing: every reader goes through `session.license?.restricted` / `?.locked`.
  license?: LicenseStatus;
};
/** Instance licence, read from `session.license`. `restricted` marks a Community
 * instance without one (5 devices, single admin, no roles/LDAP/SSO); `locked`
 * marks an Enterprise instance whose licence is missing or expired more than
 * 10 days, where every /api route but a short allow-list answers 402. */
export type LicenseStatus = {
  state: "none" | "valid" | "grace" | "expired";
  kind?: "community" | "enterprise";
  max_devices: number;
  expires_at?: string;
  grace_until?: string;
  instance_id: string;
  restricted: boolean;
  locked: boolean;
};
export type Role = { name: string; permissions: string[]; builtin: boolean };
export type RoleMember = { id: string; email: string; display_name: string };
export type RoleMembersResponse = { items: RoleMember[]; total: number };
export type Overview = {
  period_hours: number;
  events: number;
  navigations: number;
  blocked: number;
  devices: number;
  active_devices: number;
  pending_devices: number;
  providers: { name: string; events: number; blocked: number }[];
  timeline: { hour: string; events: number; blocked: number }[];
};
export type Device = {
  collector_health?: {tool:string;state:string;version?:string;last_ok_at?:string;skipped_trees:number;managed_config_tampered:number}[];
  id: string;
  hostname: string;
  platform: string;
  version: string;
  status: string;
  last_seen: string | null;
  os_user: string;
  /** Browsers whose extension last reported to the agent, keyed by tool. */
  browsers?: Record<string, string>;
  /** What the agent last reported about its own signed update, if anything. */
  update_status?: string;
  update_reported_at?: string | null;
  /** The device group whose policy override this device inherits, if any. */
  group_id?: string | null;
  group_name?: string | null;
  /** Directories the machine declared at enrollment (Active Directory, Entra tenant, realm). */
  machine_domains?: { kind: string; name: string }[];
};
/** A named set of devices sharing one Shadow AI policy override. */
export type DeviceGroup = {
  id: string;
  name: string;
  description: string;
  device_count: number;
  created_at: string;
  updated_at: string;
};
export type Platform = "windows" | "linux";
/** The organization's durable deployment credential. The secret is never part of it. */
export type DeploymentKey = {
  id: string;
  created_at: string;
  rotated_at?: string | null;
  uses: number;
};
export type Member = {
  id: string;
  email: string;
  display_name: string;
  role: string;
  organization_id?: string;
  organization_name?: string;
  identity_type?: "local" | "sso" | "ldap";
  language?: "" | Language;
};
export type MembersResponse = { items: Member[]; total?: number; limit?: number; offset?: number; directory_configured?: boolean };
export type Audit = {
  id: string;
  occurred_at: string;
  actor: string;
  action: string;
  target: string;
  details?: { reason?: unknown } | null;
};
export type Settings = {
  name: string;
  event_retention_days: number;
  public_url: string;
  public_url_confirmed: boolean;
  public_url_editable: boolean;
  default_language?: Language;
  default_language_editable?: boolean;
};
export type Profile = {
  email: string;
  display_name: string;
  first_name: string;
  last_name: string;
  language: "" | Language;
  identity_type: "local" | "sso" | "ldap";
  mfa_configured: boolean | null;
  editable: { profile: boolean; email: boolean; password: boolean; mfa: boolean };
};
/**
 * A personal API credential. The secret itself is absent by design: it is
 * returned once, by the creation call, and is never retrievable afterwards.
 */
export type ApiKey = {
  id: string;
  name: string;
  permissions: string[];
  content_access: boolean;
  created_at: string;
  expires_at: string;
  last_used_at: string | null;
};
export type ApiKeyExpiryDays = 30 | 90 | 365;
export type ApiKeyCreated = { key: ApiKey; secret: string };
export type LdapDirectory =
  | { configured: false; editable?: boolean }
  | {
      configured: true;
      editable?: boolean;
      name: string;
      vendor: "ad" | "rhds" | "tivoli" | "edirectory" | "other";
      connection_url: string;
      bind_dn: string;
      users_dn: string;
      username_attribute: string;
      rdn_attribute: string;
      uuid_attribute: string;
      user_object_classes: string;
      custom_filter: string;
      search_scope: 1 | 2;
      auth_type: "simple" | "none";
      start_tls: boolean;
      use_truststore: "always" | "never";
      connection_timeout_ms: number;
      read_timeout_ms: number;
      pagination: boolean;
      updated_at: string;
    };
export type SsoProvider = "google" | "microsoft";
export type SsoProviderView = {
  configured: boolean;
  enabled: boolean;
  client_id: string;
  hosted_domain?: string;
  tenant_id?: string;
  invitation_domain?: string;
  redirect_uri: string;
};
export type SsoSettings = {
  editable: boolean;
  providers: Record<SsoProvider, SsoProviderView>;
};
export type SsoDomain = {
  domain: string;
  record_name: string;
  record_value: string;
  verified: boolean;
};
export type SsoDomains = {
  editable: boolean;
  domains: SsoDomain[];
};
export type DirectoryUser = {
  subject: string;
  username: string;
  email: string;
  display_name: string;
};

export class ApiError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}
/**
 * The shared fetch beneath `request()`: same credentials/cache policy, same
 * `ok` check, same error-JSON parsing and the same 401 → `milvago:unauthorized`
 * dispatch, but it hands back the raw `Response` instead of parsed JSON. For
 * callers that need a `Response`/`Blob` (a file download) rather than a typed
 * body, so that path does not silently skip the unauthorized handling that
 * `request()` gives every other call.
 */
export async function requestRaw(
  path: string,
  options: {
    method?: string;
    body?: unknown;
    csrf?: string;
    signal?: AbortSignal;
    /** Overrides the default `application/json` Accept header, e.g. for a binary download. */
    accept?: string;
    /** Error code used when the server's error body carries none of its own. */
    fallbackCode?: string;
    /** Error message used when the server's error body carries none of its own. */
    fallbackMessage?: (status: number) => string;
  } = {},
): Promise<Response> {
  const response = await fetch(path, {
    method: options.method ?? "GET",
    credentials: "same-origin",
    cache: "no-store",
    signal: options.signal,
    headers: {
      Accept: options.accept ?? "application/json",
      ...(options.body !== undefined
        ? { "Content-Type": "application/json" }
        : {}),
      ...(options.csrf ? { "X-CSRF-Token": options.csrf } : {}),
    },
    ...(options.body !== undefined
      ? { body: JSON.stringify(options.body) }
      : {}),
  });
  if (!response.ok) {
    // A body that parses but is not an object (`null`, a string, a number from a
    // proxy) must still yield an ApiError, not a TypeError on `error.error`.
    const parsed: unknown = await response.json().catch(() => null);
    const error: { error?: unknown; message?: unknown } =
      parsed !== null && typeof parsed === "object" ? parsed : {};
    if (response.status === 401)
      window.dispatchEvent(new CustomEvent("milvago:unauthorized"));
    throw new ApiError(
      response.status,
      typeof error.error === "string" ? error.error : options.fallbackCode ?? "request_failed",
      typeof error.message === "string" ? error.message : options.fallbackMessage?.(response.status) ?? `HTTP ${response.status}`,
    );
  }
  return response;
}
export async function request<T>(
  path: string,
  options: {
    method?: string;
    body?: unknown;
    csrf?: string;
    signal?: AbortSignal;
  } = {},
): Promise<T> {
  const response = await requestRaw(path, options);
  if (response.status === 204) return undefined as T;
  const body = await response.text();
  return body ? (JSON.parse(body) as T) : (undefined as T);
}
