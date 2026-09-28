import { ApiError, request, requestRaw } from './api';
import { saveBlob, WINDOWS_PACKAGE_NAME, WINDOWS_PACKAGE_PATH } from './download';

// Two server codes ask for the same thing — `fresh_mfa_required` when the session must
// have authenticated recently, `mfa_required` when it must carry a second factor at all.
// Both are answered by one verification, so the console treats them as one demand.
const codes = new Set(['fresh_mfa_required', 'mfa_required']);
export const secondFactorRequired = (error?: unknown): error is ApiError => error instanceof ApiError && codes.has(error.code);

const KEY = 'milvago.second-factor-retry';
// Long enough to sign in with a second factor, short enough that a forgotten tab does
// not replay a change much later, when the person no longer expects it.
const WINDOW_MS = 5 * 60 * 1000;

// Who and where the call was made: the verification signs in again and may land in
// another organization, or another person may sign in on this tab. A call is replayed
// only for the same person in the same organization (audit of 2026-09-24: a purge
// asked in a child organization was replayed in the root one).
export type HeldScope = { org: string; user: string };
type Held = { path: string; method: string; body?: unknown; download?: 'windows-package'; hash: string; at: number } & HeldScope;
const replayable = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Remembers the refused call and goes straight to the verification. Redirecting the
 * tab rather than opening a window is deliberate: a popup opened after an awaited
 * response is no longer tied to the click that started it, so browsers block it — the
 * person would be told to verify and then silently given nothing.
 *
 * Returns true when it took over, so the caller stops treating this as a failure.
 */
// Leaving the page is the one step a test cannot execute, so it goes through here and
// nowhere else: the decision stays testable, the navigation stays real.
// Guards against an open redirect: only a same-origin, http(s) destination is honored,
// and only its path is followed, so no other origin can be reached through here.
export function sameOriginTarget(url: string): URL | null {
  if (!url) return null;
  try {
    const parsed = new URL(String(url).replace(/[\t\n\r]/g, ''), window.location.origin);
    return parsed.origin === window.location.origin && (parsed.protocol === 'http:' || parsed.protocol === 'https:') ? parsed : null;
  } catch { return null; }
}
export const browser = { navigate: (url: string) => { const target = sameOriginTarget(url); if (target) window.location.assign(target.pathname + target.search + target.hash); } };

// sessionStorage outlives an abandoned verification and session restore can write it to
// disk, so a body carrying a secret (LDAP bind password, export token) is never held: the
// person re-enters it after verifying, as in private browsing.
const secretField = /(?:password|passphrase|secret|credential|token|authorization|header|(?:^|_)(?:key|pin|otp)$)/i;
const carriesSecret = (value: unknown): boolean =>
  typeof value === 'object' && value !== null &&
  Object.entries(value).some(([name, inner]) => (secretField.test(name) && inner !== '' && inner != null) || carriesSecret(inner));

export type SecondFactorChallenge = { path: string; method: string; body: unknown; error: ApiError; language: string; scope: HeldScope };
const challengeListeners = new Set<(challenge: SecondFactorChallenge) => void>();
export function onSecondFactorChallenge(listener: (challenge: SecondFactorChallenge) => void): () => void {
  challengeListeners.add(listener);
  return () => { challengeListeners.delete(listener); };
}
export function requestSecondFactor(path: string, method: string, body: unknown, error: unknown, language: string, scope: HeldScope): boolean {
  if (!secondFactorRequired(error)) return false;
  for (const listener of challengeListeners) listener({ path, method, body, error, language, scope });
  return true;
}

export function verifySecondFactor(path: string, method: string, body: unknown, error: unknown, language: string, scope: HeldScope, download?: 'windows-package'): boolean {
  if (!secondFactorRequired(error)) return false;
  const held: Held = { path, method, body, download, hash: window.location.hash, at: Date.now(), ...scope };
  // An older held change must not be replayed in place of this one.
  try { if (carriesSecret(body)) window.sessionStorage.removeItem(KEY); else window.sessionStorage.setItem(KEY, JSON.stringify(held)); }
  catch { /* Private browsing: the change is lost, the verification still happens. */ }
  browser.navigate(`/auth/login?mfa=1&lang=${encodeURIComponent(language)}`);
  return true;
}

/**
 * Replays the call the second factor was demanded for, once, on return. The entry is
 * dropped BEFORE the attempt so a repeated refusal cannot loop through the login page.
 */
export async function resumeSecondFactor(csrf: string, scope: HeldScope): Promise<'resumed' | 'downloaded' | 'refused' | 'none'> {
  let held: Held | undefined;
  try {
    const raw = window.sessionStorage.getItem(KEY);
    if (!raw) return 'none';
    window.sessionStorage.removeItem(KEY);
    held = JSON.parse(raw) as Held;
  } catch { return 'none'; }
  if (!held?.path || typeof held.at !== 'number' || Date.now() - held.at > WINDOW_MS) return 'none';
  if (held.org !== scope.org || held.user !== scope.user || !held.path.startsWith('/api/') || !replayable.has(held.method)) return 'none';
  if (held.download && (held.download !== 'windows-package' || held.path !== WINDOWS_PACKAGE_PATH || held.method !== 'POST' || held.body !== undefined)) return 'none';
  if (held.hash && window.location.hash !== held.hash) window.location.hash = held.hash;
  try {
    if (held.download === 'windows-package') {
      const response = await requestRaw(WINDOWS_PACKAGE_PATH, { method: 'POST', csrf, accept: 'application/zip' });
      saveBlob(await response.blob(), WINDOWS_PACKAGE_NAME);
      return 'downloaded';
    }
    await request(held.path, { method: held.method, body: held.body, csrf });
    return 'resumed';
  } catch {
    // Still refused, or refused for another reason entirely: the page is shown as it
    // is and the person decides. Never a second redirect.
    return 'refused';
  }
}
