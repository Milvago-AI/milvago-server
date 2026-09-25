/** Known vendor / tool brand resolution for the cartography tiles and ribbons.
 * No network access: `logo` only ever points at a local `/providers/<slug>.svg` file that an
 * administrator may or may not have dropped in `public/providers/` (see its README). */
export type BrandDimension = 'actor_id' | 'tool' | 'provider' | 'model';
export type Brand = { name: string; color: string; logo?: string; monogram: string };

const table: [match: string, name: string, color: string][] = [
  ['openai', 'OpenAI', '#10A37F'],
  ['chatgpt', 'OpenAI', '#10A37F'],
  ['gpt', 'OpenAI', '#10A37F'],
  ['codex', 'OpenAI', '#10A37F'],
  ['anthropic', 'Anthropic', '#D97757'],
  ['claude', 'Anthropic', '#D97757'],
  ['google', 'Google', '#4285F4'],
  ['gemini', 'Google', '#4285F4'],
  ['microsoft', 'Microsoft', '#5E5CE6'],
  ['copilot', 'Microsoft', '#5E5CE6'],
  ['perplexity', 'Perplexity', '#20808D'],
  ['mistral', 'Mistral', '#FF7000'],
  ['chrome', 'Chrome', '#1A73E8'],
  ['firefox', 'Firefox', '#FF7139'],
  ['edge', 'Edge', '#0078D4'],
  ['cursor', 'Cursor', '#18181B'],
];
const neutral = '#71717A';

/** Resolves a raw flow value (tool / provider / model — actors never match the table) to a brand.
 * Unknown values return an empty name (tiles render "Non attribué"/"Unattributed" separately). */
export function brand(dimension: BrandDimension, value: string): Brand {
  if (!value || value === 'unknown') return { name: '', color: neutral, monogram: '?' };
  if (dimension === 'actor_id') return { name: value, color: neutral, monogram: value.charAt(0).toUpperCase() };
  const lower = value.toLowerCase();
  const hit = table.find(([match]) => lower.includes(match));
  if (hit) { const [, name, color] = hit; return { name, color, monogram: name.charAt(0).toUpperCase(), logo: `/providers/${name.toLowerCase()}.svg` }; }
  return { name: value, color: neutral, monogram: value.charAt(0).toUpperCase() };
}
