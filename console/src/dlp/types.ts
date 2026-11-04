export type DlpMode = 'disabled' | 'simulation' | 'active';
export type DlpExpr =
  | { op: 'true' | 'upload' }
  | { op: 'all' | 'any' | 'one'; children: DlpExpr[] }
  | { op: 'not'; child: DlpExpr }
  | { op: 'contains'; field: string; value: string; ignore_case: boolean; whole_word: boolean }
  | { op: 'matches'; field: string; detector: string; minimum: number }
  | { op: 'eq'; field: string; value: string }
  | { op: 'in'; field: string; values: string[] };
export type DlpDefinition =
  | { kind: 'literal'; value: string; ignore_case: boolean; whole_word: boolean; unicode: boolean }
  | { kind: 'regex'; pattern: string; ignore_case: boolean }
  | { kind: 'builtin'; category: string }
  | { kind: 'dictionary'; values: string[]; exceptions: string[] }
  | { kind: 'dictionary_context'; dictionary: string; minimum: number }
  | { kind: 'keyword_tier'; dictionary: string; tier: string }
  | { kind: 'keyword'; value: string; exceptions: string[]; tier: string };
export type DlpDetector = { id: string; name: string; definition: DlpDefinition };
export type DlpEffect =
  | { action: 'observe' | 'block' | 'warn' }
  | { action: 'mask'; detector: string; label: string }
  | { action: 'replace'; value: string; replacement: string; ignore_case: boolean; whole_word: boolean };
export type DlpApplication = { kind: 'organization' } | { kind: 'group' | 'device'; id: string } | { kind: 'groups' | 'devices'; ids: string[] };
export type DlpRule = { application?: DlpApplication; id: string; revision: number; name: string; mode: DlpMode; priority: number; condition: DlpExpr; scope: DlpExpr; consequence: DlpEffect; review: boolean; message: string };
export type DlpPolicy = { schema_version: 1; domain: 'endpoint'; inspection: boolean; native_inspection: boolean; journal: boolean; detectors: DlpDetector[]; rules: DlpRule[] };
export type DlpScopeOptions = {browsers:{id:string;label:string}[];services:{id:string;label:string}[];applications:{id:string;label:string}[]};
export type DlpSettings = {default_rule_ids?:string[];scope_options?:DlpScopeOptions; revision: number; policy: DlpPolicy; inherited: boolean; inherited_from?: string; fingerprint: string; capabilities: Record<string, boolean> };
export type DlpDecision = { rule_id: string; rule_revision: number; rule_name: string; mode: DlpMode; consequence: string; condition: 'true' | 'false' | 'unknown'; scope: 'true' | 'false' | 'unknown'; outcome: string; occurrences: number };
export type DlpResult = { action: string; texts: Record<string, string[]>; decisions: DlpDecision[]; reason: string; confirmation?: boolean; transformed: boolean };
export type DlpInput = { policy: DlpPolicy; texts: Record<string, string[]>; facts: Record<string, string>; upload: boolean | null };
export type DlpDecisionEvent = { id: string; occurred_at: string; channel: string; policy_fingerprint: string; device_id?: string; event_id?: string; action: string; delivery: string; decisions: DlpDecision[] };
export type DlpTrace = { fingerprint: string; action: string; delivery: string; decisions: DlpDecision[] };

export const emptyCondition = (): DlpExpr => ({ op: 'contains', field: 'prompt', value: '', ignore_case: true, whole_word: false });
export const emptyScope = (): DlpExpr => ({ op: 'eq', field: 'channel', value: 'browser' });
export const newRule = (_domain: DlpPolicy['domain'], name: string): DlpRule => ({ id: crypto.randomUUID(), revision: 1, name, mode: 'simulation', priority: 100, condition: { ...emptyCondition(), ...{ field: 'prompt' } }, scope: { op: 'eq', field: 'channel', value: 'browser' }, consequence: { action: 'block' }, review: false, message: '' });
