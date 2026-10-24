import { defaultEngine, type Hit } from "../detect";
import { isPlaceholder } from "../detect/filters";
import type { Confidence } from "../detect/schema";

export { isPlaceholder };

export interface Rule {
  id: string;
  label: string;
  provider: string;
  re: RegExp;
}

export interface Match {
  rule: Rule;
  value: string;
  variable?: string;
  confidence: Confidence;
  /** Set when the value was found inside an encoded string, e.g. "base64". */
  via?: string;
}

const toMatch = (h: Hit): Match => ({ rule: h.rule, value: h.value, variable: h.variable, confidence: h.confidence, via: h.via });

/** Returns every secret on one line. */
export function matchLine(text: string, path?: string): Match[] {
  return defaultEngine().scan(text, path).map(toMatch);
}

/** Scans a file or diff hunk; `startLine` is the line number of its first line. */
export function matchContent(content: string, path: string | undefined, startLine = 1): (Match & { line: number })[] {
  return defaultEngine().scan(content, path, startLine).map((h) => ({ ...toMatch(h), line: h.line }));
}

export function mask(value: string, rule: Pick<Rule, "id">): string {
  if (rule.id.startsWith("private-key")) return "-----BEGIN … PRIVATE KEY-----";
  if (rule.id === "db-url") return value.replace(/:\/\/([^:/@\s]+):[^@\s]+@/, "://$1:••••@").slice(0, 48);
  if (rule.id === "tripwire-demo") return value.length > 22 ? `${value.slice(0, 22)}…` : value;
  const keep = Math.min(6, Math.floor(value.length / 4));
  return `${value.slice(0, keep)}${"•".repeat(8)} (${value.length} chars)`;
}
