import { parse } from "smol-toml";
import type { AllowlistDef, Confidence, Pack, RuleDef } from "./schema";

const POSIX: Record<string, string> = {
  alnum: "a-zA-Z0-9",
  alpha: "a-zA-Z",
  digit: "0-9",
  lower: "a-z",
  upper: "A-Z",
  xdigit: "0-9a-fA-F",
  word: "\\w",
  space: "\\s",
  blank: " \\t",
  punct: "!-\\/:-@\\[-`{-~",
  print: " -~",
  graph: "!-~",
  cntrl: "\\x00-\\x1f\\x7f",
};

/**
 * Translates a Go (RE2) pattern to a JS one:
 * POSIX classes, `\z`/`\A`, named groups and mid-pattern flag groups like `(?i)` (which in Go last to the end of the enclosing group).
 * A leading `(?i)` is kept as-is; the engine peels it into real flags.
 */
export function translateGoRegex(src: string): string {
  let s = src.replace(/\[:(\w+):\]/g, (all, name) => POSIX[name] ?? all);
  s = s.replace(/\\z/g, "(?![\\s\\S])").replace(/\\A/g, "(?<![\\s\\S])").replace(/\(\?P</g, "(?<");

  const lead = s.match(/^\(\?([imsU]+)\)/);
  const head = lead ? `(?${lead[1].replace(/U/g, "")})` : "";
  const body = lead ? s.slice(lead[0].length) : s;

  let out = "";
  const closers: number[] = []; // per open group: extra ")" owed when it closes
  let extra = 0;
  let inClass = false;
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (c === "\\") {
      out += c + (body[i + 1] ?? "");
      i++;
      continue;
    }
    if (inClass) {
      if (c === "]") inClass = false;
      out += c;
      continue;
    }
    if (c === "[") {
      inClass = true;
      out += c;
      if (body[i + 1] === "^") out += body[++i];
      if (body[i + 1] === "]") out += body[++i];
      continue;
    }
    if (c === "(") {
      const flagGroup = body.slice(i).match(/^\(\?([imsU]*)(?:-([imsU]+))?\)/);
      if (flagGroup) {
        const on = flagGroup[1].replace(/U/g, "");
        const off = (flagGroup[2] ?? "").replace(/U/g, "");
        i += flagGroup[0].length - 1;
        if (on || off) {
          out += `(?${on}${off ? `-${off}` : ""}:`;
          extra++;
        }
        continue;
      }
      closers.push(extra);
      extra = 0;
      out += c;
      continue;
    }
    if (c === ")") {
      out += ")".repeat(extra) + c;
      extra = closers.pop() ?? 0;
      continue;
    }
    out += c;
  }
  return head + out + ")".repeat(extra);
}

const ACRONYMS: Record<string, string> = { aws: "AWS", gcp: "GCP", api: "API", pat: "PAT", npm: "npm", jwt: "JWT", ssh: "SSH", url: "URL", id: "ID", oauth: "OAuth", sas: "SAS", pgp: "PGP", rsa: "RSA", ci: "CI", cd: "CD", sdk: "SDK", db: "DB", sql: "SQL", ssl: "SSL", tls: "TLS", github: "GitHub", gitlab: "GitLab", sendgrid: "SendGrid", openai: "OpenAI", hubspot: "HubSpot", pypi: "PyPI", mailchimp: "Mailchimp", paypal: "PayPal", linkedin: "LinkedIn", youtube: "YouTube", dockerhub: "Docker Hub", okta: "Okta", ibm: "IBM", aes: "AES", hsm: "HSM" };

export function labelFromId(id: string): string {
  const words = id.split("-").map((w) => ACRONYMS[w] ?? w);
  const text = words.join(" ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/** Maps a Gitleaks rule id onto the provider names the verifier and graph already understand. */
export function providerFromId(id: string): string {
  if (id === "private-key") return "ssh";
  if (id.startsWith("gcp-") || id.startsWith("gcp")) return "gcp";
  if (id === "stripe-access-token") return "stripe";
  return id.split("-")[0];
}

/** Rules that wrap a key name around a value (`adobe ... = "abc"`) are less certain than a fixed token prefix. */
function confidenceOf(regex: string): Confidence {
  return /\[\\s'"\]\{0,3\}\(\?:=\|>/.test(regex) ? "medium" : "high";
}

// Ids Tripwire replaces with its own, better-filtered rule.
const SKIP = new Set(["generic-api-key", "private-key"]);
// Patterns that deliberately span lines.
const MULTILINE = new Set(["curl-auth-header", "curl-auth-user", "kubernetes-secret-yaml"]);

interface TomlAllowlist {
  description?: string;
  condition?: "OR" | "AND";
  regexTarget?: "secret" | "match" | "line";
  regexes?: string[];
  stopwords?: string[];
  paths?: string[];
}

const allowlist = (a: TomlAllowlist): AllowlistDef => ({
  condition: a.condition,
  regexTarget: a.regexTarget,
  regexes: a.regexes?.map(translateGoRegex),
  stopwords: a.stopwords,
  // SVG is plain text and can carry a key; Gitleaks skips it by default, which makes it a hiding place.
  paths: a.paths?.map((p) => translateGoRegex(p.replace("|svg|", "|"))),
});

export function importGitleaks(toml: string): Pack {
  const doc = parse(toml) as unknown as { allowlist?: TomlAllowlist; allowlists?: TomlAllowlist[]; rules: (Record<string, any> & { allowlists?: TomlAllowlist[] })[] };
  const rules: RuleDef[] = [];
  for (const r of doc.rules) {
    if (SKIP.has(r.id) || !r.regex) continue;
    const regex = translateGoRegex(r.regex);
    const def: RuleDef = {
      id: r.id,
      label: labelFromId(r.id),
      provider: providerFromId(r.id),
      regex,
      keywords: (r.keywords ?? []).map((k: string) => k.toLowerCase()),
      source: "gitleaks",
      confidence: confidenceOf(r.regex),
    };
    if (MULTILINE.has(r.id)) def.multiline = true;
    if (r.secretGroup) def.secretGroup = r.secretGroup;
    if (r.entropy) def.entropy = r.entropy;
    if (r.path) def.path = translateGoRegex(r.path);
    if (r.allowlists?.length) def.allowlists = r.allowlists.map(allowlist);
    rules.push(def);
  }
  const global = doc.allowlist ?? doc.allowlists?.[0];
  return { source: "gitleaks", license: "MIT (c) Zachary Rice and the Gitleaks contributors", allowlist: global ? allowlist(global) : undefined, rules };
}
