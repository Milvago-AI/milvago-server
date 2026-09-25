/**
 * The offered languages. Declared here rather than in ui.tsx because the API
 * types need them too, and ui.tsx already imports from api.ts — putting the
 * union in either one would make the two import each other.
 *
 * Each label is the language's own name: a reader looking for their language
 * reads it in that language, not in whichever one the console happens to be
 * showing at the time.
 */
export const languages = [
  { code: 'fr', label: 'Français' },
  { code: 'en', label: 'English' },
  { code: 'es', label: 'Español' },
  { code: 'pt-BR', label: 'Português (Brasil)' },
] as const;

export type Language = (typeof languages)[number]['code'];

/** Narrows a value that came from storage, an API response or a URL. */
export function isLanguage(value: string): value is Language {
  return languages.some((l) => l.code === value);
}

/**
 * The language served when nothing else answers. English rather than French:
 * a reader whose browser asks for none of the served languages is better off
 * with the one they are most likely to read (product decision, 2026-09-17).
 */
export const fallbackLanguage: Language = 'en';

/**
 * The best served language for a list of BCP 47 tags, in the order the reader
 * ranked them, or undefined when we serve none of them.
 *
 * The reader's ranking decides first, and only then how closely a tag matches:
 * ['es-419','en'] is a reader who prefers Spanish, so a regional Spanish we do
 * not carry must fall to 'es' rather than jump to the exactly matched 'en'
 * further down the list. Within one tag, an exact code wins, then its base
 * subtag — which is what covers 'en-US', 'fr-CA', 'pt-PT' and 'pt' alone, the
 * last three served by the only French and Portuguese we carry.
 */
export function matchLanguage(tags: readonly string[]): Language | undefined {
  for (const tag of tags) {
    const wanted = tag.trim().toLowerCase();
    if (!wanted) continue;
    const exact = languages.find((l) => l.code.toLowerCase() === wanted);
    if (exact) return exact.code;
    const base = wanted.split('-')[0];
    const served = languages.find((l) => l.code.toLowerCase().split('-')[0] === base);
    if (served) return served.code;
  }
  return undefined;
}

/**
 * The language this browser asks for, English when it asks for none we serve.
 * `navigator.languages` is the ranked list the reader configured; `language`
 * alone is the fallback for the rare runtime that omits it.
 */
function navigatorTags(nav: Navigator | undefined): string[] {
  if (nav?.languages?.length) return [...nav.languages];
  if (nav?.language) return [nav.language];
  return [];
}

export function browserLanguage(): Language {
  const nav = typeof navigator === 'undefined' ? undefined : navigator;
  const tags = navigatorTags(nav);
  return matchLanguage(tags) ?? fallbackLanguage;
}
