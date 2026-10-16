/**
 * Detection + redaction core. Pure functions, no dependencies, no I/O.
 * Never logs. Never returns raw sensitive values from scan().
 */

export type EntityType =
  | "EMAIL" | "PHONE" | "CARD" | "SSN" | "IPV4"
  | "JWT" | "AWS_KEY" | "GITHUB_TOKEN" | "API_KEY" | "PRIVATE_KEY"
  | "BEARER_TOKEN" | (string & {}); // custom patterns add their own names

export interface Finding {
  type: EntityType;
  start: number;
  end: number;
  length: number;
  /** Safe preview: first/last 2 chars for long values, fully masked for short ones. */
  preview: string;
}

export interface CustomPattern { name: string; pattern: string; flags?: string }

export const MAX_INPUT_CHARS = 100_000;

interface Rule {
  type: EntityType;
  priority: number; // higher wins on overlap
  regex: RegExp;
  validate?: (m: string) => boolean;
}

const luhn = (digits: string): boolean => {
  let sum = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n; alt = !alt;
  }
  return sum % 10 === 0;
};

const digitsOf = (s: string) => s.replace(/\D/g, "");

const BUILTIN: Rule[] = [
  { type: "PRIVATE_KEY", priority: 100,
    regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  { type: "JWT", priority: 90,
    regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { type: "AWS_KEY", priority: 90, regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { type: "GITHUB_TOKEN", priority: 90, regex: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g },
  { type: "API_KEY", priority: 85,
    regex: /\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}\b|\bsai_[A-Za-z0-9]{16,}\b|\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { type: "BEARER_TOKEN", priority: 80,
    regex: /\bBearer\s+[A-Za-z0-9._~+\/-]{16,}=*/g },
  { type: "EMAIL", priority: 70,
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b/g },
  { type: "CARD", priority: 60,
    regex: /\b(?:\d[ -]?){12,18}\d\b/g,
    validate: (m) => { const d = digitsOf(m); return d.length >= 13 && d.length <= 19 && luhn(d); } },
  { type: "SSN", priority: 55,
    regex: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g },
  { type: "IPV4", priority: 50,
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g },
  { type: "PHONE", priority: 40,
    regex: /(?<![\w.])\+?\(?\d{1,4}\)?(?:[\s.-]?\(?\d{2,4}\)?){2,4}(?![\w])/g,
    validate: (m) => {
      const t = m.trim();
      const d = digitsOf(t).length;
      const hasStructure = t.startsWith("+") || /[\s().-]/.test(t);
      if (/^\d{4}-\d{2}-\d{2}$/.test(t)) return false; // ISO date
      return d >= 9 && d <= 15 && hasStructure;
    } },
];

export function compileCustom(custom: CustomPattern[] = []): Rule[] {
  return custom.map((c) => {
    if (!/^[A-Z][A-Z0-9_]{1,31}$/.test(c.name)) {
      throw new Error(`Custom pattern name must be UPPER_SNAKE_CASE (2-32 chars): "${c.name}"`);
    }
    if (c.pattern.length > 300) throw new Error(`Custom pattern "${c.name}" is too long (max 300 chars)`);
    const flags = (c.flags ?? "").replace(/[^imsu]/g, "");
    return { type: c.name, priority: 95, regex: new RegExp(c.pattern, flags + "g") };
  });
}

function mask(value: string): string {
  if (value.length <= 8) return "*".repeat(value.length);
  return `${value.slice(0, 2)}${"*".repeat(Math.min(value.length - 4, 12))}${value.slice(-2)}`;
}

function assertInput(text: string) {
  if (typeof text !== "string") throw new Error("text must be a string");
  if (text.length > MAX_INPUT_CHARS) {
    throw new Error(`Input too large: ${text.length} chars (max ${MAX_INPUT_CHARS})`);
  }
}

interface RawHit { type: EntityType; start: number; end: number; priority: number }

function collect(text: string, custom: CustomPattern[], types?: EntityType[]): RawHit[] {
  const rules = [...BUILTIN, ...compileCustom(custom)]
    .filter((r) => !types || types.includes(r.type));
  const hits: RawHit[] = [];
  for (const r of rules) {
    r.regex.lastIndex = 0;
    for (const m of text.matchAll(r.regex)) {
      const value = m[0];
      if (!value) continue;
      if (r.validate && !r.validate(value)) continue;
      hits.push({ type: r.type, start: m.index!, end: m.index! + value.length, priority: r.priority });
    }
  }
  // Resolve overlaps: higher priority first, then longer span, then earlier.
  hits.sort((a, b) => b.priority - a.priority || (b.end - b.start) - (a.end - a.start) || a.start - b.start);
  const kept: RawHit[] = [];
  for (const h of hits) {
    if (!kept.some((k) => h.start < k.end && k.start < h.end)) kept.push(h);
  }
  return kept.sort((a, b) => a.start - b.start);
}

export function scan(text: string, opts: { custom?: CustomPattern[]; types?: EntityType[] } = {}): Finding[] {
  assertInput(text);
  return collect(text, opts.custom ?? [], opts.types).map((h) => ({
    type: h.type, start: h.start, end: h.end, length: h.end - h.start,
    preview: mask(text.slice(h.start, h.end)),
  }));
}

export interface RedactResult {
  redacted: string;
  counts: Record<string, number>;
  total: number;
  /** Only present when reversible=true. Keys are placeholders, values are the originals. */
  map?: Record<string, string>;
}

export function redact(
  text: string,
  opts: { custom?: CustomPattern[]; types?: EntityType[]; reversible?: boolean } = {},
): RedactResult {
  assertInput(text);
  const hits = collect(text, opts.custom ?? [], opts.types);
  const counts: Record<string, number> = {};
  const map: Record<string, string> = {};
  const seen = new Map<string, string>(); // same type+value -> same placeholder
  const perType: Record<string, number> = {};
  let out = "", cursor = 0;
  for (const h of hits) {
    const value = text.slice(h.start, h.end);
    counts[h.type] = (counts[h.type] ?? 0) + 1;
    let placeholder: string;
    if (opts.reversible) {
      const key = `${h.type}\u0000${value}`;
      let existing = seen.get(key);
      if (!existing) {
        perType[h.type] = (perType[h.type] ?? 0) + 1;
        existing = `[${h.type}_${perType[h.type]}]`;
        seen.set(key, existing);
        map[existing] = value;
      }
      placeholder = existing;
    } else {
      placeholder = `[REDACTED_${h.type}]`;
    }
    out += text.slice(cursor, h.start) + placeholder;
    cursor = h.end;
  }
  out += text.slice(cursor);
  const res: RedactResult = { redacted: out, counts, total: hits.length };
  if (opts.reversible) res.map = map;
  return res;
}

export function restore(text: string, map: Record<string, string>): { text: string; restored: number } {
  assertInput(text);
  let restored = 0;
  const out = text.replace(/\[[A-Z0-9_]{2,40}_\d+\]/g, (ph) => {
    if (Object.prototype.hasOwnProperty.call(map, ph)) { restored++; return map[ph]; }
    return ph;
  });
  return { text: out, restored };
}
