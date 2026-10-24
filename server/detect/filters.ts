import { createHash } from "node:crypto";
import type { AllowlistDef, CheckId, Confidence } from "./schema";

export function entropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) h -= (c / s.length) * Math.log2(c / s.length);
  return h;
}

// ---- regex compilation ----

const LEADING_FLAGS = /^\(\?([ims]+)\)/;

/** Compiles a pack regex. Older runtimes without `(?i:...)` modifiers get the loosened (case-insensitive) pattern instead of crashing. */
export function compileRegex(src: string, extraFlags = ""): RegExp {
  let source = src;
  let flags = extraFlags;
  const lead = source.match(LEADING_FLAGS);
  if (lead) {
    source = source.slice(lead[0].length);
    for (const f of lead[1]) if (!flags.includes(f)) flags += f;
  }
  try {
    return new RegExp(source, flags);
  } catch (err) {
    const loosened = source.replace(/\(\?[ims]*(?:-[ims]+)?:/g, "(?:");
    if (loosened === source) throw err;
    return new RegExp(loosened, flags.includes("i") || /\(\?[ms]*i/.test(source) ? flags.replace("i", "") + "i" : flags);
  }
}

// ---- placeholders ----

/** Words that make a value a placeholder wherever they appear. */
const PLACEHOLDER_ANYWHERE = /example|sample|dummy|placeholder|changeme|change_me|your[_-]|xxxx|\*\*\*|<|>|\$\{|\{\{|process\.env|os\.environ|getenv|secrets\.|redacted|not[_-]?a[_-]?real|fake[_-]?key/i;
/** Weak words only count when they stand alone, so a random token that happens to contain "todo" is kept. */
const PLACEHOLDER_STANDALONE = /(?:^|[^a-z])(?:todo|replace|insert|test123|password123|secret123|true|false|null|none|undefined)(?:[^a-z]|$)/i;

export function isPlaceholder(value: string): boolean {
  return PLACEHOLDER_ANYWHERE.test(value) || PLACEHOLDER_STANDALONE.test(value) || /^(.)\1+$/.test(value);
}

// ---- shapes that are never secrets ----

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX_HASH = /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{56}|[0-9a-f]{64}|[0-9a-f]{96}|[0-9a-f]{128})$/i;
const VERSIONISH = /^v?\d+(?:\.\d+){1,3}(?:[-+][\w.]+)?$/;
const SRI_OR_INTEGRITY = /^(?:sha(?:1|256|384|512)[-:])/i;

/** UUIDs, bare hex digests, version strings and SRI hashes: high entropy, but not credentials on their own. */
export function looksBenign(value: string): boolean {
  return UUID.test(value) || HEX_HASH.test(value) || VERSIONISH.test(value) || SRI_OR_INTEGRITY.test(value);
}

// ---- allowlists ----

export interface CompiledAllowlist {
  condition: "OR" | "AND";
  target: "secret" | "match" | "line";
  regexes: RegExp[];
  stopwords: string[];
  paths: RegExp[];
}

export function compileAllowlist(def: AllowlistDef): CompiledAllowlist {
  return {
    condition: def.condition ?? "OR",
    target: def.regexTarget ?? "secret",
    regexes: (def.regexes ?? []).map((r) => compileRegex(r)),
    stopwords: (def.stopwords ?? []).map((s) => s.toLowerCase()),
    paths: (def.paths ?? []).map((p) => compileRegex(p)),
  };
}

export function allowed(a: CompiledAllowlist, ctx: { secret: string; match: string; line: string; path?: string }): boolean {
  const text = a.target === "match" ? ctx.match : a.target === "line" ? ctx.line : ctx.secret;
  const results: boolean[] = [];
  if (a.regexes.length) results.push(a.regexes.some((r) => r.test(text)));
  if (a.stopwords.length) {
    const lower = ctx.secret.toLowerCase();
    results.push(a.stopwords.some((w) => lower.includes(w)));
  }
  if (a.paths.length) results.push(!!ctx.path && a.paths.some((p) => p.test(ctx.path!)));
  if (!results.length) return false;
  return a.condition === "AND" ? results.every(Boolean) : results.some(Boolean);
}

// ---- structure checks ----

const B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

let crcTable: Uint32Array | undefined;
export function crc32(s: string): number {
  if (!crcTable) {
    crcTable = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      crcTable[n] = c >>> 0;
    }
  }
  let c = 0xffffffff;
  for (const b of Buffer.from(s, "utf8")) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

export function toBase62(n: number, width: number): string {
  let out = "";
  while (n > 0) {
    out = B62[n % 62] + out;
    n = Math.floor(n / 62);
  }
  return out.padStart(width, "0");
}

/** GitHub tokens end in a 6-char base62 CRC32 of the preceding 30 characters. */
export function githubChecksumOk(token: string): boolean {
  const body = token.replace(/^(?:ghp|gho|ghu|ghs|ghr)_/, "");
  if (body.length !== 36) return false;
  return toBase62(crc32(body.slice(0, 30)), 6) === body.slice(30);
}

export function jwtOk(token: string): boolean {
  const parts = token.split(".");
  if (parts.length < 2) return false;
  try {
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    return typeof header === "object" && header !== null && ("alg" in header || "typ" in header);
  } catch {
    return false;
  }
}

/** A failing check either drops the finding (`reject`) or lowers its confidence. */
export function runCheck(check: CheckId, secret: string): { reject?: boolean; confidence?: Confidence } {
  switch (check) {
    case "github-checksum":
      return githubChecksumOk(secret) ? { confidence: "high" } : { confidence: "low" };
    case "jwt":
      return jwtOk(secret) ? {} : { reject: true };
  }
}

// ---- fingerprints ----

/** Stable id for a finding that never contains the secret itself. */
export function fingerprint(ruleId: string, file: string, value: string): string {
  return createHash("sha256").update(`${ruleId}\0${file}\0${value}`).digest("hex").slice(0, 24);
}
