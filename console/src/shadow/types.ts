export type Criteria = Record<string, string | string[]>;
/** `sensitive` and `sensitivity` are Enterprise-only: the Community server omits them. */
export type Flow = { actor_id: string; actor_name: string; tool: string; provider: string; model: string; count: number; sensitive?: number; blocked: number };
/** Browser capture health per service: a service visited without a single observed request suggests a stale DOM adapter. */
export type CaptureHealth = { provider: string; navigations: number; requests: number; devices_seen: number; devices_reporting: number };
export type Cartography = { capture: CaptureHealth[]; totals: { requests: number; responses: number; navigations: number; conversations: number; actors: number; tools: number; providers: number; models: number; sensitive?: number; blocked: number }; flows: Flow[]; series: { at: string; requests: number }[]; unattributed: number };
export type ShadowEvent = { identity_expires_at?: string; id: string; device_id: string; hostname: string; actor_id?: string; actor_name?: string; kind: 'navigation' | 'prompt' | 'response'; occurred_at: string; provider: string; source: 'browser' | 'native'; tool: string; model?: string; effort?: string; conversation_id?: string; correlation_id?: string; url?: string; action: string; characters: number; labels: string[]; files?: string[]; user?: string; user_known?: boolean; sensitivity?: string; platform_id?: string; decision_reason?: 'model_denied' | 'model_unknown' | 'control_unavailable' | ''; has_content: boolean; policy_revision: number };
export type SavedFilter = { id: string; name: string; shared: boolean; owner_id: string; criteria: Criteria };
export type EventDetail = { event: ShadowEvent; content?: { prompt?: string; response?: string }; can_read_content: boolean };
/** Why a message carries no readable text. Empty on a navigation, which has none by nature. */
export type ContentState = '' | 'available' | 'denied' | 'not_retained' | 'identity';
/** `key` is opaque: `conv:<platform id>` for a thread, `event:<uuid>` for a lone record. */
export type Conversation = { key: string; started_at: string; last_at: string; prompts: number; responses: number; navigations: number; blocked: number; redirected: number; has_attachment?: boolean; model: string; effort: string; latest: ShadowEvent };
export type ThreadMessage = ShadowEvent & { content_state: ContentState; content?: { prompt?: string; response?: string } };
export type Thread = { key: string; device_id: string; items: ThreadMessage[]; older_cursor: string; can_read_content: boolean };
export type ShadowConfig = {
  /** `cidrs` are rules written before rules existed (a network, no domain); the console writes `rules`. */
  enrollment: { approval: 'manual' | 'automatic' | 'network'; cidrs: string[]; rules?: { cidr: string; domain: string }[] };
  collection: { enabled: boolean; store_content: boolean; store_file_names: boolean; content_retention_days: number };
  services: { id: string; domains: string[]; mode: 'observe' | 'block' | 'redirect'; redirect_url: string; enabled: boolean }[];
  model_access?: { platform_id: string; channel: 'browser' | 'native'; mode: 'off' | 'allowlist' | 'denylist'; models: string[] }[];
  protection: { block_uploads: boolean; keywords: string[]; exact: 'observe' | 'block'; unicode: 'observe' | 'block'; fuzzy: 'off' | 'observe' | 'block'; exceptions: string[]; message: string };
  privacy: { enabled: boolean; review: boolean; types: string[]; custom_rules: { id: string; label: string; pattern: string; case_insensitive: boolean; enabled: boolean }[] };
  classification: { browser: string[]; coding: string[]; medical_terms: string[] };
  /** `destinations` and `metrics_enabled` are retired: exports live in Administration
   *  → Observability, and the metrics route is governed by the MILVAGO_SHADOW_METRICS
   *  environment variable. The server keeps both fields so configurations stored
   *  before the change still decode, and always returns them blank. */
  operations: { metrics_enabled: false; destinations: never[]; updates: { enabled: boolean; device_ids: string[]; percentage: number; paused_versions: string[] } };
};
export type ShadowSection = keyof ShadowConfig;
export type ModelCatalogEntry = { platform_id: string; channel: 'browser' | 'native'; name: string; provider: string; models: string[] };
// Under aggregate-only reporting the server counts machines per state instead.
export type ModelAccessCount = { platform_id: string; channel: 'browser' | 'native'; status: ModelAccessStatus['status']; devices: number };
export type ModelAccessStatus = { device_id: string; hostname: string; version: string; platform: string; platform_id: string; channel: 'browser' | 'native'; expected_revision: number; applied_revision: number; status: 'needs_update' | 'pending' | 'applied' | 'unavailable'; reason?: string; reported_at?: string | null };
/** Where an inherited section's value comes from: a parent organization or, on a device, its group. */
export type InheritedFrom = { organization_id?: string; group_id?: string; name: string };
export type ShadowSettings = { revision: number; config: ShadowConfig; inherit_sections: string[]; inherited_from: Record<string, InheritedFrom>; capabilities: Record<string, boolean>; model_catalog?: ModelCatalogEntry[] };
export type Operations = { updates: { available: boolean; reason?: string; versions: { version: string; edition: string; platform: string; expires_at: string }[] } };
