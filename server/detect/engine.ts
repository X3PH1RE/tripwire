import { allowed, compileAllowlist, compileRegex, entropy, HASHY_NAME, ILLUSTRATIVE_PATH, isPlaceholder, looksBenign, runCheck, type CompiledAllowlist } from "./filters";
import { KeywordIndex } from "./keywords";
import type { Confidence, Pack, RuleDef } from "./schema";

export interface CompiledRule {
  /** Position in the engine's rule list: earlier rules win when two match the same value. */
  index: number;
  def: RuleDef;
  id: string;
  label: string;
  provider: string;
  /** Kept for callers that print the pattern; the engine uses `re` with the `g` flag internally. */
  re: RegExp;
  confidence: Confidence;
  keywords: string[];
  allow: CompiledAllowlist[];
  path?: RegExp;
}

export interface Hit {
  rule: Pick<CompiledRule, "id" | "label" | "provider" | "re" | "confidence">;
  /** The value reported to the user (and fingerprinted). */
  value: string;
  variable?: string;
  /** 1-based line within the scanned content, offset by `startLine`. */
  line: number;
  confidence: Confidence;
  /** How the value was found when it was not in plain text, e.g. "base64". */
  via?: string;
}

const MAX_LINE = 2000;
const MAX_PER_RULE_PER_LINE = 10;

// A name ending in KEY/TOKEN/..., or one of the unambiguous bare names (`password: ...`, `secret = ...`).
const ASSIGN = /\b([A-Za-z][A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIALS?|AUTH|URL|URI|DSN)|PASSWORD|PASSWD|SECRET|TOKEN|CREDENTIALS?)["']?\s*[:=]\s*["']?([^\s"'`,;&]+)/i;
const STRONG_NAME = /SECRET|PASSWORD|PASSWD|PWD|TOKEN|API_?KEY|PRIVATE|CREDENTIAL/i;
/** Where generic (name-based) matches are noise: lockfiles, vendored code, fixtures and generated output. */
const GENERIC_SKIP_PATH = /(?:^|\/)(?:__snapshots__|__fixtures__|fixtures?|testdata|test-data|mocks?|node_modules|vendor)\/|\.(?:snap|lock|min\.js|map|svg)$|(?:^|\/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/i;

const NO_RULES: CompiledRule[] = [];
const NO_HITS: Hit[] = [];
const MIN_LINE = 8;
// Cheap yes/no probes so the decoders only allocate on lines that could hold an encoded value.
const PCT_PROBE = /%[0-9a-f]{2}/i;
const B64_PROBE = /[A-Za-z0-9+/_-]{24}/;
const HEX_PROBE = /[0-9a-fA-F]{32}/;
const MAX_DECODE_DEPTH = 2;
const MAX_DECODE_TOKENS = 6;
const B64_TOKEN = /[A-Za-z0-9+/_-]{24,}={0,2}/g;
const HEX_TOKEN = /\b(?:[0-9a-fA-F]{2}){16,}\b/g;

/** The text when it is (almost) all printable ASCII; random bytes from a bogus decode are not worth scanning. */
function printable(buf: Buffer): string | undefined {
  if (buf.length < 8) return undefined;
  let ok = 0;
  for (const b of buf) if ((b >= 32 && b < 127) || b === 9 || b === 10 || b === 13) ok++;
  return ok / buf.length >= 0.95 ? buf.toString("utf8") : undefined;
}


const GENERIC_RULE = { id: "generic-assignment", label: "High-entropy secret", provider: "unknown", re: /$^/, confidence: "low" as Confidence };

function pathLike(v: string): boolean {
  return /^(?:\.{1,2}\/|\/)[\w.-]+/.test(v) || /^[a-z0-9._-]+(?:\/[a-z0-9._-]+){2,}$/.test(v);
}

const ASCII = /^[\x00-\x7f]+$/;

export class Engine {
  readonly rules: CompiledRule[] = [];
  private global: CompiledAllowlist | undefined;
  /** Single-pass keyword matcher over every line rule's keywords. */
  private readonly keywordIndex: KeywordIndex;
  /** keyword id -> rules that list it. */
  private readonly keywordRules: CompiledRule[][] = [];
  /** Line rules with no usable keyword: candidates for every line. */
  private readonly always: CompiledRule[] = [];
  /** Rules restricted to certain paths; every other rule applies everywhere. */
  private readonly pathRules: CompiledRule[] = [];
  private readonly anywhere: CompiledRule[] = [];

  constructor(packs: Pack[]) {
    for (const pack of packs) {
      if (pack.allowlist && !this.global) this.global = compileAllowlist(pack.allowlist);
      for (const def of pack.rules) this.rules.push(this.compile(def, this.rules.length));
    }
    const ids = new Map<string, number>();
    const keywords: string[] = [];
    for (const r of this.rules) {
      if (r.path) this.pathRules.push(r);
      else this.anywhere.push(r);
      if (r.def.multiline) continue;
      if (!r.keywords.length || !r.keywords.every((k) => ASCII.test(k))) {
        this.always.push(r);
        continue;
      }
      for (const k of r.keywords) {
        let id = ids.get(k);
        if (id === undefined) {
          id = keywords.length;
          ids.set(k, id);
          keywords.push(k);
          this.keywordRules.push([]);
        }
        this.keywordRules[id].push(r);
      }
    }
    this.keywordIndex = new KeywordIndex(keywords);
  }

  private compile(def: RuleDef, index: number): CompiledRule {
    const re = compileRegex(def.regex, "g");
    return {
      index,
      def,
      id: def.id,
      label: def.label,
      provider: def.provider,
      re,
      confidence: def.confidence ?? "high",
      keywords: def.keywords.map((k) => k.toLowerCase()),
      allow: (def.allowlists ?? []).map(compileAllowlist),
      path: def.path ? compileRegex(def.path) : undefined,
    };
  }

  /** Scans a block of text (a whole file, a diff hunk or a single line). */
  scan(content: string, path?: string, startLine = 1): Hit[] {
    if (path && this.global?.paths.some((p) => p.test(path))) return [];
    const lowerAll = content.toLowerCase();
    const matching = path ? this.pathRules.filter((r) => r.path!.test(path)) : [];
    const forPath = matching.length ? [...this.anywhere, ...matching].sort((x, y) => x.index - y.index) : this.anywhere;
    const out: Hit[] = [];

    const lines = content.split(/\r?\n/);
    // Decoded text can contain keywords the file as a whole did not, so decoding tests against every rule that applies to this path.
    const decodeRules = forPath.filter((r) => !r.def.multiline);
    const perLine = this.candidates(lowerAll, lines.length, matching);
    for (let i = 0; i < lines.length; i++) out.push(...this.scanLine(lines[i], path, startLine + i, perLine[i] ?? NO_RULES, decodeRules));

    const multi = forPath.filter((r) => r.def.multiline && (!r.keywords.length || r.keywords.some((k) => lowerAll.includes(k))));
    if (multi.length) {
      const starts = [0];
      for (let i = 0; i < content.length; i++) if (content.charCodeAt(i) === 10) starts.push(i + 1);
      const lineAt = (idx: number) => {
        let lo = 0;
        let hi = starts.length - 1;
        while (lo < hi) {
          const mid = (lo + hi + 1) >> 1;
          if (starts[mid] <= idx) lo = mid;
          else hi = mid - 1;
        }
        return startLine + lo;
      };
      for (const rule of multi) {
        rule.re.lastIndex = 0;
        for (const m of content.matchAll(rule.re)) {
          const hit = this.accept(rule, m, m[0], path, lineAt(m.index ?? 0), undefined);
          if (hit) out.push(hit);
        }
      }
    }
    return out.sort((a, b) => a.line - b.line);
  }

  /**
   * For each line, the line rules whose keywords it contains, in rule order. One Aho-Corasick pass over the file finds
   * every keyword at once; testing each rule's keywords against each line (or sweeping the file once per keyword) is what
   * made large repos slow.
   */
  private candidates(lowerAll: string, lineCount: number, matching: CompiledRule[]): (CompiledRule[] | undefined)[] {
    const perLine: (CompiledRule[] | undefined)[] = new Array(lineCount);
    // A path-restricted rule only runs when this file's path matched it.
    const eligible = (r: CompiledRule) => !r.path || matching.includes(r);
    const lastLine = new Int32Array(this.rules.length).fill(-1);
    this.keywordIndex.scan(lowerAll, (keyword, line) => {
      if (line >= lineCount) return;
      for (const r of this.keywordRules[keyword]) {
        if (lastLine[r.index] === line || !eligible(r)) continue;
        lastLine[r.index] = line;
        (perLine[line] ??= []).push(r);
      }
    });
    for (const r of this.always) {
      if (!eligible(r)) continue;
      for (let i = 0; i < lineCount; i++) (perLine[i] ??= []).push(r);
    }
    // Keywords arrive in file order; rules must run in rule order so the earlier rule wins on identical values.
    for (const rules of perLine) if (rules && rules.length > 1) rules.sort((x, y) => x.index - y.index);
    return perLine;
  }

  /** `via` is set when `text` came out of a decoder; those lines were not pre-filtered by keyword, so they are checked here. */
  private scanLine(text: string, path: string | undefined, line: number, rules: CompiledRule[], decodeRules: CompiledRule[], via?: string): Hit[] {
    // Most lines in a repo have no candidate rule and no long token, so this path must stay allocation-free.
    if (text.length > MAX_LINE || text.length < MIN_LINE) return NO_HITS;
    let assign: RegExpMatchArray | null | undefined;
    const getAssign = () => (assign === undefined ? (assign = text.match(ASSIGN)) : assign);
    let hits: Hit[] | undefined;
    if (rules.length) {
      const lower = via === undefined ? "" : text.toLowerCase();
      const variable = getAssign()?.[1];
      for (const rule of rules) {
        if (via !== undefined && rule.keywords.length && !rule.keywords.some((k) => lower.includes(k))) continue;
        rule.re.lastIndex = 0;
        let n = 0;
        for (const m of text.matchAll(rule.re)) {
          if (++n > MAX_PER_RULE_PER_LINE) break;
          const hit = this.accept(rule, m, text, path, line, variable);
          if (hit) (hits ??= []).push(hit);
        }
      }
    }
    if (via === undefined || via.split(">").length < MAX_DECODE_DEPTH) {
      const found = this.decoded(text, path, line, decodeRules, via, getAssign);
      if (found.length) (hits ??= []).push(...found);
    }
    if (hits) {
      const resolved = resolve(hits);
      if (resolved.length) return via ? resolved.map((h) => (h.via ? h : { ...h, via })) : resolved;
    }
    const generic = this.generic(text, path, line, getAssign());
    return generic ? [{ ...generic, via }] : NO_HITS;
  }

  /** Re-scans base64, URL-encoded and hex values on the line, so a secret hidden in encoding is still found. */
  private decoded(text: string, path: string | undefined, line: number, rules: CompiledRule[], via: string | undefined, getAssign: () => RegExpMatchArray | null): Hit[] {
    const pct = PCT_PROBE.test(text);
    const b64 = B64_PROBE.test(text);
    const hex = HEX_PROBE.test(text);
    if (!pct && !b64 && !hex) return NO_HITS;
    const out: Hit[] = [];
    const next = (kind: string) => (via ? `${via}>${kind}` : kind);
    const rescan = (decodedText: string, kind: string) => out.push(...this.scanLine(decodedText, path, line, rules, rules, next(kind)));

    if (pct) {
      try {
        const url = decodeURIComponent(text);
        if (url !== text) rescan(url, "url");
      } catch {
        // malformed escape sequence: nothing to decode
      }
    }
    if (b64) {
      const assign = getAssign();
      for (const m of [...text.matchAll(B64_TOKEN)].slice(0, MAX_DECODE_TOKENS)) {
        const plain = printable(Buffer.from(m[0], /[-_]/.test(m[0]) ? "base64url" : "base64"));
        if (!plain) continue;
        // `password: <base64>` (Kubernetes secrets, CI variables): test the decoded value under the same name.
        rescan(assign && assign[2] === m[0] ? `${assign[1]}=${plain}` : plain, "base64");
      }
    }
    if (hex) {
      for (const m of [...text.matchAll(HEX_TOKEN)].slice(0, MAX_DECODE_TOKENS)) {
        const plain = printable(Buffer.from(m[0], "hex"));
        if (plain) rescan(plain, "hex");
      }
    }
    return out;
  }

  /** Applies the secret-group, placeholder, entropy, structure and allowlist filters to one regex match. */
  private accept(rule: CompiledRule, m: RegExpMatchArray, line: string, path: string | undefined, lineNo: number, variable: string | undefined): Hit | undefined {
    const def = rule.def;
    const groupValue = (g: number) => m[g] || undefined;
    const secret = (def.secretGroup ? groupValue(def.secretGroup) : m.slice(1).find((g) => !!g)) ?? m[0];
    if (!secret) return undefined;
    if (!def.id.startsWith("private-key") && !def.multiline && isPlaceholder(secret)) return undefined;
    if (def.minLength && secret.length < def.minLength) return undefined;
    if (def.entropy !== undefined && entropy(secret) <= def.entropy) return undefined;
    if (this.global && allowed(this.global, { secret, match: m[0], line, path })) return undefined;
    if (rule.allow.some((a) => allowed(a, { secret, match: m[0], line, path }))) return undefined;
    let confidence = rule.confidence;
    if (def.check) {
      const r = runCheck(def.check, secret, path);
      if (r.reject) return undefined;
      if (r.confidence) confidence = r.confidence;
    }
    const value = def.reportGroup ? (groupValue(def.reportGroup) ?? m[0]) : secret;
    return { rule, value, variable, line: lineNo, confidence };
  }

  /** Fallback for `NAME_KEY=<random-looking value>` when no provider rule matched. */
  private generic(text: string, path: string | undefined, line: number, a: RegExpMatchArray | null): Hit | undefined {
    if (!a || (path && GENERIC_SKIP_PATH.test(path))) return undefined;
    const value = a[2];
    if (value.length < 16 || value.length > 200) return undefined;
    const strong = STRONG_NAME.test(a[1]) && !HASHY_NAME.test(a[1]);
    if (value.includes("://") || /[\\()[\]{}^]/.test(value) || isPlaceholder(value) || looksBenign(value, strong) || pathLike(value)) return undefined;
    if (/^[a-z]+(?:[._-][a-z]+)*$/i.test(value)) return undefined;
    // A hex alphabet has 16 symbols, so random hex tops out near 4.0 bits; judge it on its own scale.
    const hexOnly = /^[0-9a-f]+$/i.test(value);
    const h = entropy(value);
    if (h < (hexOnly ? 3.2 : 3.8)) return undefined;
    // Examples in docs and tests are far more often illustrations than leaks, so they are reported but never rank above low.
    const illustrative = !!path && ILLUSTRATIVE_PATH.test(path);
    return { rule: GENERIC_RULE, value, variable: a[1], line, confidence: strong && h >= (hexOnly ? 3.4 : 4) && !illustrative ? "medium" : "low" };
  }
}

/** Drops hits whose value sits inside a longer hit on the same line and collapses identical values (earlier rule wins). */
function resolve(hits: Hit[]): Hit[] {
  const seen = new Set<string>();
  const unique = hits.filter((h) => (seen.has(h.value) ? false : (seen.add(h.value), true)));
  return unique.filter((h) => !unique.some((o) => o !== h && o.value.length > h.value.length && o.value.includes(h.value)));
}
