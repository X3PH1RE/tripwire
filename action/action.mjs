#!/usr/bin/env node

// server/cli/action.ts
import { readFileSync as readFileSync7 } from "node:fs";

// server/cli/main.ts
import { writeFileSync as writeFileSync4 } from "node:fs";
import { parseArgs } from "node:util";
import { resolve as resolve5 } from "node:path";

// server/real/core.ts
import { existsSync as existsSync5, rmSync as rmSync2 } from "node:fs";
import { resolve as resolve3 } from "node:path";

// server/detect/baseline.ts
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
var BASELINE_FILE = ".tripwire-baseline.json";
function loadBaseline(dir) {
  const path = join(dir, BASELINE_FILE);
  if (!existsSync(path)) return /* @__PURE__ */ new Set();
  try {
    const doc = JSON.parse(readFileSync(path, "utf8"));
    return new Set((doc.entries ?? []).map((e) => e.fingerprint));
  } catch {
    return /* @__PURE__ */ new Set();
  }
}
function writeBaseline(dir, entries) {
  const unique = new Map(entries.map((e) => [e.fingerprint, e]));
  const doc = { version: 1, entries: [...unique.values()].sort((a, b) => a.file.localeCompare(b.file) || a.rule.localeCompare(b.rule)) };
  const path = join(dir, BASELINE_FILE);
  writeFileSync(path, JSON.stringify(doc, null, 2) + "\n");
  return path;
}

// server/detect/filters.ts
import { createHash } from "node:crypto";
function entropy(s) {
  const counts = /* @__PURE__ */ new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) h -= c / s.length * Math.log2(c / s.length);
  return h;
}
var LEADING_FLAGS = /^\(\?([ims]+)\)/;
function compileRegex(src, extraFlags = "") {
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
var PLACEHOLDER_ANYWHERE = /example|sample|dummy|placeholder|changeme|change_me|your[_-]|xxxx|\*\*\*|<|>|\$\{|\{\{|process\.env|os\.environ|getenv|secrets\.|redacted|not[_-]?a[_-]?real|fake[_-]?key/i;
var PLACEHOLDER_STANDALONE = /(?:^|[^a-z])(?:todo|replace|insert|test123|password123|secret123|true|false|null|none|undefined)(?:[^a-z]|$)/i;
function isPlaceholder(value) {
  return PLACEHOLDER_ANYWHERE.test(value) || PLACEHOLDER_STANDALONE.test(value) || /^(.)\1+$/.test(value);
}
var UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
var HEX_HASH = /^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{56}|[0-9a-f]{64}|[0-9a-f]{96}|[0-9a-f]{128})$/i;
var VERSIONISH = /^v?\d+(?:\.\d+){1,3}(?:[-+][\w.]+)?$/;
var SRI_OR_INTEGRITY = /^(?:sha(?:1|256|384|512)[-:])/i;
var FORMAT_STRING = /%[sdifr]|%\(\w+\)[sd]|%\{\w+\}/;
var MEMBER_CHAIN = /^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*){2,}$/;
var FILENAME = /^[\w%./-]+\.(?:map|css|js|mjs|cjs|ts|tsx|jsx|json|ya?ml|xml|html?|txt|md|rst|py|rb|go|java|php|cs|rs|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|tgz|tar|gz|zip|lock|conf|cfg|ini|log|sql|sh|pem|crt|cer|key|pub)$/i;
var PASSWORD_HASH = /^(?:\$2[abxy]?\$\d{2}\$|\$argon2(?:id|i|d)\$|\$[156]\$|\$pbkdf2|\$scrypt\$|\{(?:SHA|SSHA|MD5|SHA256|SHA512|CRYPT|BCRYPT)\}|pbkdf2_sha\d+\$)/i;
var HASHY_NAME = /HASH|DIGEST|CHECKSUM|SHA\d*|MD5|FINGERPRINT|ETAG|SALT|COMMIT|REVISION/i;
function looksBenign(value, strongName = false) {
  if (UUID.test(value) || VERSIONISH.test(value) || SRI_OR_INTEGRITY.test(value) || PASSWORD_HASH.test(value)) return true;
  if (FORMAT_STRING.test(value) || MEMBER_CHAIN.test(value) || FILENAME.test(value)) return true;
  return HEX_HASH.test(value) && !strongName;
}
function compileAllowlist(def) {
  return {
    condition: def.condition ?? "OR",
    target: def.regexTarget ?? "secret",
    regexes: (def.regexes ?? []).map((r) => compileRegex(r)),
    stopwords: (def.stopwords ?? []).map((s) => s.toLowerCase()),
    paths: (def.paths ?? []).map((p) => compileRegex(p))
  };
}
function allowed(a, ctx) {
  const text = a.target === "match" ? ctx.match : a.target === "line" ? ctx.line : ctx.secret;
  const results = [];
  if (a.regexes.length) results.push(a.regexes.some((r) => r.test(text)));
  if (a.stopwords.length) {
    const lower = ctx.secret.toLowerCase();
    results.push(a.stopwords.some((w) => lower.includes(w)));
  }
  if (a.paths.length) results.push(!!ctx.path && a.paths.some((p) => p.test(ctx.path)));
  if (!results.length) return false;
  return a.condition === "AND" ? results.every(Boolean) : results.some(Boolean);
}
var B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
var crcTable;
function crc32(s) {
  if (!crcTable) {
    crcTable = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c2 = n;
      for (let k = 0; k < 8; k++) c2 = c2 & 1 ? 3988292384 ^ c2 >>> 1 : c2 >>> 1;
      crcTable[n] = c2 >>> 0;
    }
  }
  let c = 4294967295;
  for (const b of Buffer.from(s, "utf8")) c = crcTable[(c ^ b) & 255] ^ c >>> 8;
  return (c ^ 4294967295) >>> 0;
}
function toBase62(n, width) {
  let out = "";
  while (n > 0) {
    out = B62[n % 62] + out;
    n = Math.floor(n / 62);
  }
  return out.padStart(width, "0");
}
function githubChecksumOk(token2) {
  const body = token2.replace(/^(?:ghp|gho|ghu|ghs|ghr)_/, "");
  if (body.length !== 36) return false;
  return toBase62(crc32(body.slice(0, 30)), 6) === body.slice(30);
}
function jwtOk(token2) {
  const parts = token2.split(".");
  if (parts.length < 2) return false;
  try {
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    return typeof header === "object" && header !== null && ("alg" in header || "typ" in header);
  } catch {
    return false;
  }
}
var WEAK_PASSWORD = /^(?:pass(?:word|wd)?|secret|changeme|change_me|root|admin|test|testing|dev|development|postgres|mysql|mongo|redis|guest|example|demo|default|letmein|qwerty|0*1234\d*|\*+|x+)$/i;
function runCheck(check, secret, path) {
  switch (check) {
    case "github-checksum":
      return githubChecksumOk(secret) ? { confidence: "high" } : { confidence: "low" };
    case "jwt":
      return jwtOk(secret) ? {} : { reject: true };
    case "db-password":
      return WEAK_PASSWORD.test(secret) || !!path && ILLUSTRATIVE_PATH.test(path) ? { confidence: "low" } : {};
  }
}
var ILLUSTRATIVE_PATH = /(?:^|\/)(?:docs?|documentation|examples?|samples?|demos?|tests?|__tests__|specs?|e2e)\/|\.(?:md|mdx|rst|adoc|txt)$|(?:^|\/)README/i;
function fingerprint(ruleId, file, value) {
  return createHash("sha256").update(`${ruleId}\0${file}\0${value}`).digest("hex").slice(0, 24);
}

// server/real/graph.ts
var DB_LABEL = { postgres: "Postgres database", postgresql: "Postgres database", mysql: "MySQL database", mariadb: "MySQL database", mongodb: "MongoDB database", "mongodb+srv": "MongoDB database", redis: "Redis", rediss: "Redis", amqp: "Message queue", amqps: "Message queue" };
function resourceFor(provider, variable = "", sample = "") {
  const v = variable.toUpperCase();
  const scheme = sample.match(/^([a-z+]+):\/\//)?.[1];
  if (scheme && DB_LABEL[scheme]) return { key: `db-${DB_LABEL[scheme]}`, label: DB_LABEL[scheme], sensitivity: "high", provider: scheme.replace(/ql$|\+srv$/, "") };
  if (/DATABASE|POSTGRES|PG_|MYSQL|MONGO|DB_|_DB\b/.test(v)) return { key: "db", label: "Database", sensitivity: "high", provider: "database" };
  if (/REDIS/.test(v)) return { key: "db-Redis", label: "Redis", sensitivity: "high", provider: "redis" };
  if (/DEPLOY|VERCEL|NETLIFY|HEROKU|RAILWAY|FLY_|RENDER_|CLOUDFLARE/.test(v) || provider === "deploy") return { key: "deploy", label: "Production deploy", sensitivity: "production", provider: "deploy" };
  switch (provider) {
    case "github":
    case "gitlab":
      return { key: "scm", label: "Source code (write access)", sensitivity: "production", provider };
    case "npm":
      return { key: "npm", label: "npm package publishing", sensitivity: "production", provider };
    case "aws":
      return { key: "aws", label: "AWS account", sensitivity: "high", provider };
    case "gcp":
      return { key: "gcp", label: "Google Cloud APIs", sensitivity: "medium", provider };
    case "stripe":
      return { key: "stripe", label: "Payments (Stripe live)", sensitivity: "high", provider };
    case "stripe-test":
      return { key: "stripe-test", label: "Stripe test mode", sensitivity: "low", provider: "stripe" };
    case "slack":
      return { key: "slack", label: "Slack workspace", sensitivity: "medium", provider };
    case "openai":
    case "anthropic":
      return { key: "llm", label: "AI API billing", sensitivity: "medium", provider };
    case "sendgrid":
    case "twilio":
      return { key: `msg-${provider}`, label: provider === "twilio" ? "SMS sending (Twilio)" : "Email sending", sensitivity: "medium", provider };
    case "ssh":
      return { key: "ssh", label: "Servers (private key)", sensitivity: "high", provider };
  }
  if (/AWS|S3_|BUCKET|STORAGE|CLOUD/.test(v)) return { key: "cloud", label: "Cloud storage", sensitivity: "high", provider: "cloud" };
  if (/STRIPE|PAYPAL|PAYMENT|BRAINTREE/.test(v)) return { key: "payments", label: "Payments", sensitivity: "high", provider: "payments" };
  if (/SMTP|MAIL|SENDGRID/.test(v)) return { key: "mail", label: "Email sending", sensitivity: "medium", provider: "mail" };
  if (/JWT|SESSION|COOKIE|SIGNING|ENCRYPT/.test(v)) return { key: "auth", label: "User sessions (forge logins)", sensitivity: "high", provider: "app" };
  if (/ADMIN|ROOT|MASTER/.test(v)) return { key: "admin", label: "Admin access", sensitivity: "high", provider: "app" };
  return { key: "unknown", label: "Unclassified access", sensitivity: "low", provider: "unknown" };
}
var COL = { repo: -60, service: 240, secret: 560, resource: 880, ciSecret: 1200, ciResource: 1520 };
var ROW = 105;
var MAX_SECRET_NODES = 24;
var slug = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
function settle(items) {
  items.sort((a, b) => a.want - b.want);
  let last = -Infinity;
  for (const it of items) {
    const y = Math.max(it.want, last + ROW);
    it.node.position.y = y;
    last = y;
  }
}
function buildGraph(repoName, findings, ciRefs, samples) {
  const nodes = [];
  const edges = [];
  const byId = /* @__PURE__ */ new Map();
  const add = (n) => {
    if (!byId.has(n.id)) {
      byId.set(n.id, n);
      nodes.push(n);
    }
    return byId.get(n.id);
  };
  const link = (from, to, kind) => {
    const id = `r-e-${from}-${to}`;
    if (!edges.some((e) => e.id === id)) edges.push({ id, from, to, kind });
  };
  const repo = add({ id: "r-repo", type: "repo", label: repoName, status: "ok", position: { x: COL.repo, y: 0 } });
  const ordered = [...findings].sort((a, b) => a.service.localeCompare(b.service) || Number(b.inHead) - Number(a.inHead));
  const secretRows = [];
  let row = 0;
  for (const f of ordered) {
    const name = f.variable ?? f.ruleLabel;
    const id = `r-sec-${slug(f.service)}-${slug(name)}`;
    f.nodeId = id;
    if (byId.has(id)) {
      const existing = byId.get(id);
      if (f.inHead && existing.badge === "history") Object.assign(existing, { file: f.file, line: f.line, badge: void 0 });
      continue;
    }
    if (secretRows.length >= MAX_SECRET_NODES) {
      f.nodeId = "";
      continue;
    }
    const serviceId = `r-svc-${slug(f.service)}`;
    add({ id: serviceId, type: "service", label: f.service, version: f.service === "CI (GitHub Actions)" ? "workflows" : void 0, status: "ok", position: { x: COL.service, y: 0 } });
    const v = f.verify?.status;
    const badge = v === "live" ? "live" : v === "revoked" ? "revoked" : v === "honey" ? "honey" : f.inHead ? void 0 : "history";
    const node = add({ id, type: v === "honey" ? "decoy" : "secret", label: name, file: f.file, line: f.line, provider: f.provider, status: v === "revoked" ? "rotated" : "exposed", badge, position: { x: COL.secret, y: 0 } });
    secretRows.push({ want: row++ * ROW, node });
    link(serviceId, id, "stored_in");
    if (v === "revoked" || v === "honey") continue;
    const reach2 = f.verify?.access?.length ? f.verify.access.map((a) => ({ key: `v-${f.provider}-${a.label}`, label: a.label, sensitivity: a.sensitivity, provider: f.provider })) : [resourceFor(f.provider, f.variable, samples.get(f.id))];
    for (const r of reach2.slice(0, 6)) {
      const rid = `r-res-${slug(r.key)}`;
      add({ id: rid, type: "resource", label: r.label, sensitivity: r.sensitivity, provider: r.provider, status: "exposed", position: { x: COL.resource, y: 0 } });
      link(id, rid, "unlocks");
    }
  }
  settle(secretRows);
  const scm = byId.get("r-res-scm");
  if (scm && ciRefs.length) {
    const ciRows = [];
    const resRows = [];
    for (const [i, ref] of ciRefs.slice(0, 12).entries()) {
      const id = `r-ci-${slug(ref.name)}`;
      const node = add({ id, type: "secret", label: ref.name, file: ref.file, line: ref.line, provider: "gh secret", status: "ok", position: { x: COL.ciSecret, y: 0 } });
      ciRows.push({ want: i * ROW, node });
      link(scm.id, id, "unlocks");
      const r = resourceFor("", ref.name);
      if (r.key === "unknown") continue;
      const rid = `r-res-${slug(r.key)}`;
      const res = add({ id: rid, type: "resource", label: r.label, sensitivity: r.sensitivity, provider: r.provider, status: "ok", position: { x: COL.ciResource, y: 0 } });
      if (res.position.x === COL.ciResource) resRows.push({ want: i * ROW, node: res });
      link(id, rid, "unlocks");
    }
    settle(ciRows);
    settle(resRows.filter((r, i, a) => a.findIndex((x) => x.node === r.node) === i));
  }
  const avgY = (ids) => {
    const ys = ids.map((i) => byId.get(i)?.position.y).filter((y) => y !== void 0);
    return ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : 0;
  };
  const services = nodes.filter((n) => n.type === "service");
  settle(services.map((s) => ({ want: avgY(edges.filter((e) => e.from === s.id).map((e) => e.to)), node: s })));
  settle(nodes.filter((n) => n.type === "resource" && n.position.x === COL.resource).map((r) => ({ want: avgY(edges.filter((e) => e.to === r.id).map((e) => e.from)), node: r })));
  for (const s of services) link(repo.id, s.id, "stored_in");
  repo.position.y = avgY(services.map((s) => s.id));
  return { nodes, edges };
}

// server/real/honey.ts
import { randomUUID } from "node:crypto";
import { existsSync as existsSync2, mkdirSync, readFileSync as readFileSync2, writeFileSync as writeFileSync2 } from "node:fs";
import { homedir } from "node:os";
import { dirname, join as join2 } from "node:path";

// server/github.ts
var API = "https://api.github.com";
var hasToken = () => !!process.env.GITHUB_TOKEN;
async function gh(path, init = {}) {
  const res = await fetch(`${API}${path}`, {
    method: init.method ?? "GET",
    headers: {
      Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "Content-Type": "application/json"
    },
    body: init.body ? JSON.stringify(init.body) : void 0,
    signal: AbortSignal.timeout(1e4)
  });
  if (!res.ok) {
    const msg = (await res.json().catch(() => ({}))).message;
    throw new Error(`GitHub ${init.method ?? "GET"} ${path}: ${res.status}${msg ? ` ${msg}` : ""}`);
  }
  return res.status === 204 ? void 0 : await res.json();
}
async function repoInfo(repo) {
  return gh(`/repos/${repo}`);
}
async function openMultiFilePr(repo, opts) {
  const head = await gh(`/repos/${repo}/git/ref/heads/${opts.base}`);
  const parent = await gh(`/repos/${repo}/git/commits/${head.object.sha}`);
  const tree = await gh(`/repos/${repo}/git/trees`, { method: "POST", body: { base_tree: parent.tree.sha, tree: opts.files.map((f) => ({ path: f.path, mode: "100644", type: "blob", content: f.content })) } });
  const commit = await gh(`/repos/${repo}/git/commits`, { method: "POST", body: { message: opts.message, tree: tree.sha, parents: [parent.sha] } });
  await gh(`/repos/${repo}/git/refs`, { method: "POST", body: { ref: `refs/heads/${opts.branch}`, sha: commit.sha } });
  const pr = await gh(`/repos/${repo}/pulls`, { method: "POST", body: { title: opts.title, body: opts.body, head: opts.branch, base: opts.base } });
  return { url: pr.html_url, number: pr.number };
}

// server/real/honey.ts
var CANARY = process.env.CANARYTOKENS_URL ?? "https://canarytokens.org";
var API2 = `${CANARY}/d3aece8093b71007b5ccfedad91ebb11`;
var HONEY_FILE = process.env.TRIPWIRE_HONEY_FILE ?? join2(process.env.TRIPWIRE_HOME ?? join2(homedir(), ".tripwire"), "honey.json");
var HONEY_BRANCH_PREFIX = "tripwire/honey-";
function loadHoney() {
  try {
    return existsSync2(HONEY_FILE) ? JSON.parse(readFileSync2(HONEY_FILE, "utf8")) : [];
  } catch {
    return [];
  }
}
function saveHoney(records) {
  mkdirSync(dirname(HONEY_FILE), { recursive: true });
  writeFileSync2(HONEY_FILE, JSON.stringify(records, null, 2), { mode: 384 });
}
var honeyKeyIds = () => new Set(loadHoney().flatMap((r) => [r.accessKeyId, r.secretAccessKey]));
var mask = (s) => `${s.slice(0, 8)}\u2022\u2022\u2022\u2022${s.slice(-4)}`;
function publicHoney(r) {
  return {
    id: r.id,
    accessKeyPreview: mask(r.accessKeyId),
    memo: r.memo,
    createdAt: r.createdAt,
    repo: r.prUrl ? r.repo : void 0,
    file: r.prUrl ? r.file : void 0,
    prUrl: r.prUrl,
    snippet: r.prUrl ? void 0 : decoyFile(r),
    historyUrl: `${CANARY}/history?token=${r.token}&auth=${r.auth}`,
    lastCheck: r.lastCheck,
    checkError: r.checkError,
    hits: r.hits
  };
}
async function createHoney(opts) {
  const email = opts.email ?? process.env.HONEY_ALERT_EMAIL;
  const webhook = opts.webhook ?? process.env.HONEY_ALERT_WEBHOOK;
  if (!email && !webhook) throw new Error("Set HONEY_ALERT_EMAIL (or HONEY_ALERT_WEBHOOK) so Canarytokens knows where to send alerts.");
  const res = await fetch(`${API2}/generate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token_type: "aws_keys", memo: opts.memo, email: email ?? "", webhook_url: webhook ?? "" }),
    signal: AbortSignal.timeout(2e4)
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.error || !data.aws_access_key_id) throw new Error(`Canarytokens: ${data.error_message ?? data.error ?? res.status}`);
  const record2 = {
    id: randomUUID().slice(0, 8),
    token: data.token,
    auth: data.auth_token,
    accessKeyId: data.aws_access_key_id,
    secretAccessKey: data.aws_secret_access_key,
    region: data.region ?? "us-east-1",
    memo: opts.memo,
    createdAt: Date.now(),
    repo: opts.repo,
    hits: []
  };
  saveHoney([...loadHoney(), record2]);
  return record2;
}
var first = (v) => Array.isArray(v) ? v[0] : v;
function parseHits(raw) {
  return raw.map((h) => {
    const geo = h.geo_info && typeof h.geo_info === "object" ? h.geo_info : {};
    const log = h.additional_info?.aws_key_log_data ?? h.additional_info?.["AWS Key Log Data"] ?? {};
    return {
      at: Math.round(Number(h.time_of_hit) * 1e3),
      ip: h.src_ip || void 0,
      location: [geo.city, geo.country].filter(Boolean).join(", ") || void 0,
      org: geo.org || void 0,
      userAgent: h.useragent ?? h.user_agent ?? void 0,
      action: first(log.eventName) ?? first(log.service_used) ?? void 0
    };
  }).sort((a, b) => b.at - a.at);
}
async function checkHoney() {
  const records = loadHoney();
  const fresh = [];
  for (const r of records) {
    try {
      const res = await fetch(`${API2}/history?token=${encodeURIComponent(r.token)}&auth=${encodeURIComponent(r.auth)}`, { signal: AbortSignal.timeout(15e3) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const hits = parseHits(data?.history?.hits ?? []);
      const known = new Set(r.hits.map((h) => h.at));
      for (const hit of hits) if (!known.has(hit.at)) fresh.push({ record: r, hit });
      r.hits = hits;
      r.checkError = void 0;
    } catch (err) {
      r.checkError = err.message;
    }
    r.lastCheck = Date.now();
  }
  const latest = loadHoney();
  saveHoney(latest.map((l) => records.find((r) => r.id === l.id) ?? l));
  return { records, fresh };
}
function decoyFile(r) {
  return ["# Backup job credentials (read-only bucket). Rotated quarterly.", `AWS_ACCESS_KEY_ID=${r.accessKeyId}`, `AWS_SECRET_ACCESS_KEY=${r.secretAccessKey}`, `AWS_DEFAULT_REGION=${r.region}`, ""].join("\n");
}
async function plantHoney(id, repo, file = "deploy/backup.env") {
  if (!hasToken()) throw new Error("GITHUB_TOKEN not set");
  const records = loadHoney();
  const r = records.find((x) => x.id === id);
  if (!r) throw new Error(`No honey secret ${id}`);
  const info = await repoInfo(repo);
  const exists = await gh(`/repos/${repo}/contents/${file}?ref=${info.default_branch}`).then(() => true, () => false);
  if (exists) throw new Error(`${file} already exists in ${repo}`);
  const pr = await openMultiFilePr(repo, {
    base: info.default_branch,
    branch: `${HONEY_BRANCH_PREFIX}${r.id}`,
    files: [{ path: file, content: decoyFile(r) }],
    message: "chore: add backup job config",
    title: "Tripwire: plant honey credentials",
    body: [
      `Adds \`${file}\` with a **decoy** AWS key from [Canarytokens](https://canarytokens.org). It has no permissions on anything.`,
      "",
      "If anyone ever uses it (someone scraping the repo, a leaked clone, an insider), Tripwire and the alert email/webhook get the source IP, user agent and the AWS call they tried.",
      "",
      "Merge it to arm the tripwire. Do not mention it elsewhere in the repo."
    ].join("\n")
  }).catch((err) => {
    if (/Secret detected|push protection|rule violations/i.test(err.message))
      throw new Error("GitHub push protection blocked the decoy because it is a real AWS-format key (the same check would block a real leak). The decoy is saved; place it where GitHub doesn't scan: CI/CD variables, a server .env, an S3 backup, an internal wiki.");
    throw err;
  });
  Object.assign(r, { repo, file, prUrl: pr.url });
  saveHoney(records);
  return r;
}

// server/real/osv.ts
import { readFileSync as readFileSync3 } from "node:fs";
import { dirname as dirname2, join as join3 } from "node:path";
var json = (p) => {
  try {
    return JSON.parse(readFileSync3(p, "utf8"));
  } catch {
    return void 0;
  }
};
var LOCKS = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"];
function lockedByAncestor(files, pkgFile) {
  const set = new Set(files);
  const parts = pkgFile.split("/").slice(0, -1);
  for (let i = parts.length; i >= 0; i--) {
    const prefix = parts.slice(0, i).join("/");
    if (LOCKS.some((l) => set.has(prefix ? `${prefix}/${l}` : l))) return true;
  }
  return false;
}
function parseDeps(dir, files) {
  const deps = [];
  const at = (f) => join3(dir, f);
  for (const f of files) {
    const name = f.split("/").pop();
    const sib = (n) => dirname2(f) === "." ? n : `${dirname2(f)}/${n}`;
    if (name === "package-lock.json") {
      const lock = json(at(f));
      const pkg = json(at(sib("package.json"))) ?? {};
      const direct = new Set(Object.keys({ ...pkg.dependencies, ...pkg.devDependencies, ...pkg.optionalDependencies }));
      if (lock?.packages) {
        for (const [key, v] of Object.entries(lock.packages)) {
          if (!key || !v?.version || v.link) continue;
          const n = key.slice(key.lastIndexOf("node_modules/") + 13);
          deps.push({ ecosystem: "npm", name: n, version: v.version, file: f, direct: key === `node_modules/${n}` && direct.has(n) });
        }
      } else if (lock?.dependencies) {
        for (const [n, v] of Object.entries(lock.dependencies)) if (v?.version) deps.push({ ecosystem: "npm", name: n, version: v.version, file: f, direct: direct.has(n) });
      }
    } else if (name === "package.json" && !lockedByAncestor(files, f)) {
      const pkg = json(at(f)) ?? {};
      for (const [n, spec] of Object.entries({ ...pkg.dependencies, ...pkg.devDependencies })) {
        const m = typeof spec === "string" && spec.match(/^=?v?(\d+\.\d+\.\d+(?:-[\w.]+)?)$/);
        if (m) deps.push({ ecosystem: "npm", name: n, version: m[1], file: f, direct: true });
      }
    } else if (/^requirements.*\.txt$/.test(name)) {
      for (const l of readFileSync3(at(f), "utf8").split(/\r?\n/)) {
        const m = l.match(/^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)/);
        if (m) deps.push({ ecosystem: "PyPI", name: m[1], version: m[2], file: f, direct: true });
      }
    } else if (name === "go.mod") {
      let block = false;
      for (const l of readFileSync3(at(f), "utf8").split(/\r?\n/)) {
        if (/^require\s*\($/.test(l.trim())) block = true;
        else if (l.trim() === ")") block = false;
        const m = (block ? l : l.replace(/^require\s+/, "")).trim().match(/^([\w./-]+\.[\w./-]+)\s+v([\w.+-]+)(\s*\/\/ indirect)?/);
        if (m && (block || l.startsWith("require"))) deps.push({ ecosystem: "Go", name: m[1], version: m[2], file: f, direct: !m[3] });
      }
    } else if (name === "composer.lock") {
      const lock = json(at(f));
      const req = Object.keys((json(at(sib("composer.json"))) ?? {}).require ?? {});
      for (const p of [...lock?.packages ?? [], ...lock?.["packages-dev"] ?? []]) deps.push({ ecosystem: "Packagist", name: p.name, version: String(p.version).replace(/^v/, ""), file: f, direct: req.includes(p.name) });
    } else if (name === "Gemfile.lock") {
      const text = readFileSync3(at(f), "utf8");
      const direct = new Set([...(text.split(/^DEPENDENCIES$/m)[1] ?? "").matchAll(/^\s{2}([\w.-]+)/gm)].map((m) => m[1]));
      for (const m of text.matchAll(/^ {4}([\w.-]+) \(([\d.]+)\)$/gm)) deps.push({ ecosystem: "RubyGems", name: m[1], version: m[2], file: f, direct: direct.has(m[1]) });
    }
  }
  const seen = /* @__PURE__ */ new Set();
  return deps.filter((d) => {
    const k = `${d.ecosystem}|${d.name}|${d.version}|${d.file}`;
    return seen.has(k) ? false : (seen.add(k), true);
  });
}
function compareVersions(a, b) {
  const pa = a.replace(/^v/, "").split(/[.+-]/);
  const pb = b.replace(/^v/, "").split(/[.+-]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? "0";
    const y = pb[i] ?? "0";
    const nx = Number(x);
    const ny = Number(y);
    if (!Number.isNaN(nx) && !Number.isNaN(ny)) {
      if (nx !== ny) return nx - ny;
    } else if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}
var RANK = { CRITICAL: 4, HIGH: 3, MODERATE: 2, LOW: 1, UNKNOWN: 0 };
var OSV = process.env.OSV_API ?? "https://api.osv.dev/v1";
function severityOf(v) {
  const s = v.database_specific?.severity?.toUpperCase();
  if (s === "MEDIUM") return "MODERATE";
  return s && s in RANK ? s : "UNKNOWN";
}
var pkgName = (name, eco) => eco === "PyPI" ? name.toLowerCase().replace(/[-_.]+/g, "-") : name;
function fixedFor(v, dep) {
  const candidates = [];
  for (const a of v.affected ?? []) {
    if (!a.package || a.package.ecosystem !== dep.ecosystem || pkgName(a.package.name, dep.ecosystem) !== pkgName(dep.name, dep.ecosystem)) continue;
    for (const r of a.ranges ?? []) {
      if (r.type === "GIT") continue;
      for (const e of r.events) if (e.fixed && compareVersions(e.fixed, dep.version) > 0) candidates.push(e.fixed);
    }
  }
  return candidates.sort(compareVersions)[0];
}
async function post(path, body) {
  const res = await fetch(`${OSV}${path}`, { method: "POST", body: JSON.stringify(body), headers: { "Content-Type": "application/json" }, signal: AbortSignal.timeout(2e4) });
  if (!res.ok) throw new Error(`OSV ${path}: ${res.status}`);
  return res.json();
}
async function findVulns(deps) {
  const ids = [];
  for (let i = 0; i < deps.length; i += 500) {
    const chunk = deps.slice(i, i + 500);
    const res = await post("/querybatch", { queries: chunk.map((d) => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version })) });
    res.results.forEach((r) => ids.push((r.vulns ?? []).map((v) => v.id)));
  }
  const unique = [...new Set(ids.flat())].slice(0, 200);
  const details = /* @__PURE__ */ new Map();
  for (let i = 0; i < unique.length; i += 10) {
    await Promise.all(
      unique.slice(i, i + 10).map(async (id) => {
        const res = await fetch(`${OSV}/vulns/${id}`, { signal: AbortSignal.timeout(15e3) });
        if (res.ok) details.set(id, await res.json());
      })
    );
  }
  const out = [];
  deps.forEach((dep, i) => {
    const advisories = ids[i].map((id) => details.get(id)).filter((v) => !!v);
    if (!advisories.length) return;
    const fixes = advisories.map((v) => fixedFor(v, dep));
    const fixed = fixes.filter((f) => !!f).sort(compareVersions).pop();
    const list = advisories.map((v) => ({ id: v.aliases?.find((a) => a.startsWith("CVE-")) ?? v.id, summary: v.summary ?? v.details?.slice(0, 140) ?? v.id, severity: severityOf(v) }));
    list.sort((a, b) => RANK[b.severity] - RANK[a.severity]);
    const sameMajor = !!fixed && fixed.split(".")[0] === dep.version.split(".")[0];
    const fixable = !!fixed && (dep.ecosystem === "npm" && /package(-lock)?\.json$/.test(dep.file) && (dep.direct || sameMajor) || dep.ecosystem === "PyPI" && dep.direct);
    out.push({ key: `${dep.ecosystem}:${dep.name}@${dep.version}:${dep.file}`, ecosystem: dep.ecosystem, name: dep.name, version: dep.version, file: dep.file, direct: dep.direct, severity: list[0].severity, advisories: list, fixed, fixable });
  });
  return out.sort((a, b) => RANK[b.severity] - RANK[a.severity] || Number(b.direct) - Number(a.direct) || b.advisories.length - a.advisories.length);
}

// server/real/verify.ts
import { createHmac, createHash as createHash2 } from "node:crypto";
var TIMEOUT = Number(process.env.VERIFY_TIMEOUT_MS ?? 8e3);
var CONCURRENCY = 6;
var get = async (url, headers, method = "GET", body) => fetch(url, { method, headers, body, signal: AbortSignal.timeout(TIMEOUT) });
var live = (identity, access = [], note) => ({ status: "live", identity, access, note });
var revoked = (note) => ({ status: "revoked", note });
var hmac = (key, data) => createHmac("sha256", key).update(data, "utf8").digest();
var sha256 = (s) => createHash2("sha256").update(s, "utf8").digest("hex");
function sigV4(opts) {
  const amzDate = opts.now.toISOString().replace(/[-:]|\.\d{3}/g, "");
  const date = amzDate.slice(0, 8);
  const headers = `content-type:application/x-www-form-urlencoded; charset=utf-8
host:${opts.host}
x-amz-date:${amzDate}
`;
  const signed = "content-type;host;x-amz-date";
  const canonical = ["POST", "/", "", headers, signed, sha256(opts.body)].join("\n");
  const scope = `${date}/${opts.region}/${opts.service}/aws4_request`;
  const toSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256(canonical)].join("\n");
  const kDate = hmac(`AWS4${opts.secret}`, date);
  const signature = createHmac("sha256", hmac(hmac(hmac(kDate, opts.region), opts.service), "aws4_request")).update(toSign, "utf8").digest("hex");
  return {
    "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
    "X-Amz-Date": amzDate,
    Authorization: `AWS4-HMAC-SHA256 Credential=${opts.id}/${scope}, SignedHeaders=${signed}, Signature=${signature}`
  };
}
var xml = (text, tag) => text.match(new RegExp(`<${tag}>([^<]*)</${tag}>`))?.[1];
var xmlAll = (text, tag) => [...text.matchAll(new RegExp(`<${tag}>([^<]*)</${tag}>`, "g"))].map((m) => m[1]);
async function awsCall(id, secret, service, host, body) {
  const res = await get(`https://${host}/`, sigV4({ id, secret, service, host, region: "us-east-1", body, now: /* @__PURE__ */ new Date() }), "POST", body);
  const text = await res.text();
  return res.ok ? text : void 0;
}
async function verifyAws(id, secret) {
  const res = await get("https://sts.amazonaws.com/", sigV4({ id, secret, service: "sts", host: "sts.amazonaws.com", region: "us-east-1", body: "Action=GetCallerIdentity&Version=2011-06-15", now: /* @__PURE__ */ new Date() }), "POST", "Action=GetCallerIdentity&Version=2011-06-15");
  const text = await res.text();
  if (!res.ok) {
    const code = xml(text, "Code") ?? String(res.status);
    if (/InvalidClientTokenId|SignatureDoesNotMatch|AccessDenied/.test(code)) return revoked(`AWS rejected the key (${code}).`);
    return { status: "unverified", note: `AWS returned ${code}.` };
  }
  const arn = xml(text, "Arn") ?? "unknown";
  const account = xml(text, "Account");
  const user = arn.split("/").pop();
  const access = [{ label: `AWS account ${account}`, sensitivity: "high", detail: arn }];
  if (user && arn.includes(":user/")) {
    const attached = await awsCall(id, secret, "iam", "iam.amazonaws.com", `Action=ListAttachedUserPolicies&UserName=${encodeURIComponent(user)}&Version=2010-05-08`).catch(() => void 0);
    const inline = await awsCall(id, secret, "iam", "iam.amazonaws.com", `Action=ListUserPolicies&UserName=${encodeURIComponent(user)}&Version=2010-05-08`).catch(() => void 0);
    const names = [...attached ? xmlAll(attached, "PolicyName") : [], ...inline ? xmlAll(inline, "member") : []];
    for (const n of new Set(names)) access.push({ label: n === "AdministratorAccess" ? "Full AWS admin" : `IAM policy ${n}`, sensitivity: /Admin|FullAccess|PowerUser/.test(n) ? "production" : "high", detail: `attached to ${user}` });
    if (!names.length && (attached || inline)) access.push({ label: "No IAM policies attached", sensitivity: "low" });
  }
  return live(arn, access, `Live key for ${arn}.`);
}
async function verifyGithub(token2) {
  const res = await get("https://api.github.com/user", { Authorization: `Bearer ${token2}`, Accept: "application/vnd.github+json" });
  if (res.status === 401) return revoked("GitHub rejected the token (401).");
  if (!res.ok) return { status: "unverified", note: `GitHub returned ${res.status}.` };
  const user = await res.json();
  const scopes = (res.headers.get("x-oauth-scopes") ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const access = [];
  if (scopes.length) for (const s of scopes) access.push({ label: `GitHub scope ${s}`, sensitivity: /^(repo|admin|workflow|write)/.test(s) ? "production" : "medium" });
  else access.push({ label: "GitHub account (fine-grained token)", sensitivity: "production", detail: "scopes not reported by the API" });
  const repos = await get("https://api.github.com/user/repos?per_page=100&affiliation=owner,collaborator,organization_member", { Authorization: `Bearer ${token2}` }).catch(() => void 0);
  if (repos?.ok) {
    const list = await repos.json();
    const writable = list.filter((r) => r.permissions?.push);
    if (writable.length) access.push({ label: `Write access to ${writable.length} repo${writable.length === 1 ? "" : "s"}`, sensitivity: "production", detail: writable.slice(0, 5).map((r) => r.full_name).join(", ") });
    const priv = list.filter((r) => r.private).length;
    if (priv) access.push({ label: `${priv} private repo${priv === 1 ? "" : "s"} readable`, sensitivity: "high" });
  }
  return live(user.login, access, `Live token for @${user.login}.`);
}
async function verifyStripe(key) {
  const res = await get("https://api.stripe.com/v1/account", { Authorization: `Bearer ${key}` });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) return revoked("Stripe rejected the key (401).");
  if (!res.ok && res.status !== 403) return { status: "unverified", note: `Stripe returned ${res.status}.` };
  const test = key.includes("_test_");
  const name = data?.settings?.dashboard?.display_name ?? data?.business_profile?.name ?? data?.id ?? "Stripe account";
  const access = [{ label: test ? "Stripe test mode" : "Stripe live payments", sensitivity: test ? "low" : "production", detail: data?.id }];
  if (!test) {
    const charges = await get("https://api.stripe.com/v1/charges?limit=1", { Authorization: `Bearer ${key}` });
    if (charges.ok) access.push({ label: "Read customer payment history", sensitivity: "high" });
  }
  return live(name, access, res.status === 403 ? "Live but restricted key." : void 0);
}
async function verifySlack(token2) {
  const res = await get("https://slack.com/api/auth.test", { Authorization: `Bearer ${token2}` });
  const data = await res.json().catch(() => ({}));
  if (!data?.ok) return /invalid_auth|token_revoked|account_inactive/.test(data?.error ?? "") ? revoked(`Slack rejected the token (${data.error}).`) : { status: "unverified", note: `Slack: ${data?.error ?? res.status}.` };
  const scopes = (res.headers.get("x-oauth-scopes") ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const access = [{ label: `Slack workspace ${data.team}`, sensitivity: "high", detail: data.url }];
  for (const s of scopes.slice(0, 8)) access.push({ label: `Slack scope ${s}`, sensitivity: /admin|channels:history|files|users:read.email/.test(s) ? "high" : "medium" });
  return live(`${data.user ?? "bot"}@${data.team}`, access);
}
async function verifyBearer(name, url, key, headers, label, sensitivity) {
  const res = await get(url, headers);
  if (res.status === 401 || res.status === 403) return revoked(`${name} rejected the key (${res.status}).`);
  if (!res.ok && res.status !== 400) return { status: "unverified", note: `${name} returned ${res.status}.` };
  return live(`${name} key`, [{ label, sensitivity }], `Live ${name} key \u2014 it can spend on the owner's account.`);
}
async function verifyNpm(token2) {
  const res = await get("https://registry.npmjs.org/-/whoami", { Authorization: `Bearer ${token2}` });
  if (res.status === 401) return revoked("npm rejected the token (401).");
  if (!res.ok) return { status: "unverified", note: `npm returned ${res.status}.` };
  const who = (await res.json()).username;
  return live(who, [{ label: "Publish npm packages", sensitivity: "production", detail: `as ${who}` }]);
}
async function verifyOne(f, value, context) {
  switch (f.provider) {
    case "aws": {
      if (f.rule === "aws-secret-key") return void 0;
      const secret = context.get("aws-secret");
      if (!secret) return { status: "unverified", note: "No matching AWS secret access key was found next to this key ID." };
      return verifyAws(value, secret);
    }
    case "github":
      return verifyGithub(value);
    case "stripe":
    case "stripe-test":
      return verifyStripe(value);
    case "slack":
      return f.rule === "slack-webhook" ? void 0 : verifySlack(value);
    case "openai":
      return verifyBearer("OpenAI", "https://api.openai.com/v1/models", value, { Authorization: `Bearer ${value}` }, "OpenAI API billing", "medium");
    case "anthropic":
      return verifyBearer("Anthropic", "https://api.anthropic.com/v1/models", value, { "x-api-key": value, "anthropic-version": "2023-06-01" }, "Anthropic API billing", "medium");
    case "sendgrid":
      return verifyBearer("SendGrid", "https://api.sendgrid.com/v3/scopes", value, { Authorization: `Bearer ${value}` }, "Send email as the owner's domain", "high");
    case "npm":
      return verifyNpm(value);
    default:
      return void 0;
  }
}
var VERIFIABLE = /* @__PURE__ */ new Set(["aws", "github", "stripe", "stripe-test", "slack", "openai", "anthropic", "sendgrid", "npm"]);
function awsSecretFor(findings, f) {
  const secrets = findings.filter((s) => s.rule === "aws-secret-key");
  const near = secrets.filter((s) => s.file === f.file).sort((a, b) => Math.abs(a.line - f.line) - Math.abs(b.line - f.line))[0];
  return near ?? (secrets.length === 1 ? secrets[0] : void 0);
}
async function verifyFindings(findings, values, honeyIds = /* @__PURE__ */ new Set()) {
  const pairFor = (f) => awsSecretFor(findings, f);
  const queue = findings.filter((f) => VERIFIABLE.has(f.provider));
  let i = 0;
  const worker = async () => {
    while (i < queue.length) {
      const f = queue[i++];
      const value = values.get(f.id);
      if (!value) continue;
      if (honeyIds.has(value)) {
        f.verify = { status: "honey", identity: "Tripwire decoy", note: "This is a Tripwire honey secret. Using it alerts you; it unlocks nothing." };
        continue;
      }
      const context = /* @__PURE__ */ new Map();
      const pair = f.rule === "aws-access-key" ? pairFor(f) : void 0;
      if (pair) context.set("aws-secret", values.get(pair.id));
      f.verify = await verifyOne(f, value, context).catch((err) => ({ status: "unverified", note: `Check failed: ${err.message}` }));
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, queue.length) }, worker));
  for (const f of findings) {
    if (f.rule !== "aws-access-key" || !f.verify) continue;
    const pair = pairFor(f);
    if (pair && !pair.verify) pair.verify = f.verify;
  }
}

// server/real/scan.ts
import { execFile } from "node:child_process";
import { existsSync as existsSync4, mkdtempSync, readdirSync, readFileSync as readFileSync4, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join as join4, relative, resolve as resolve2 } from "node:path";
import { promisify } from "node:util";

// server/detect/keywords.ts
var KeywordIndex = class {
  next;
  // dense DFA: next[state << 7 | ascii]
  outs;
  size;
  constructor(keywords) {
    this.size = keywords.length;
    let states = 1;
    for (const k of keywords) states += k.length;
    const goto = new Int32Array(states << 7).fill(-1);
    const outs = new Array(states);
    let count = 1;
    keywords.forEach((k, id) => {
      let s = 0;
      for (let i = 0; i < k.length; i++) {
        const c = k.charCodeAt(i);
        if (c >= 128) throw new Error(`keyword must be ASCII: ${k}`);
        const at = s << 7 | c;
        if (goto[at] === -1) goto[at] = count++;
        s = goto[at];
      }
      (outs[s] ??= []).push(id);
    });
    const fail = new Int32Array(count);
    const queue = [];
    for (let c = 0; c < 128; c++) {
      const s = goto[c];
      if (s === -1) goto[c] = 0;
      else queue.push(s);
    }
    for (let head = 0; head < queue.length; head++) {
      const s = queue[head];
      for (let c = 0; c < 128; c++) {
        const t = goto[s << 7 | c];
        const viaFail = goto[fail[s] << 7 | c];
        if (t === -1) goto[s << 7 | c] = viaFail;
        else {
          fail[t] = viaFail;
          const inherited = outs[viaFail];
          if (inherited) outs[t] = [...outs[t] ?? [], ...inherited];
          queue.push(t);
        }
      }
    }
    this.next = goto.slice(0, count << 7);
    this.outs = outs.slice(0, count);
  }
  /** Calls `found(keywordId, lineIndex)` once per keyword per line. `text` must be lower-cased; lines are counted by `\n`. */
  scan(text, found) {
    const lastLine = new Int32Array(this.size).fill(-1);
    const { next, outs } = this;
    let state = 0;
    let line = 0;
    for (let i = 0; i < text.length; i++) {
      const c = text.charCodeAt(i);
      if (c === 10) line++;
      state = next[state << 7 | (c < 128 ? c : 0)];
      const o = outs[state];
      if (o !== void 0)
        for (let j = 0; j < o.length; j++) {
          const k = o[j];
          if (lastLine[k] !== line) {
            lastLine[k] = line;
            found(k, line);
          }
        }
    }
  }
};

// server/detect/engine.ts
var MAX_LINE = 2e3;
var MAX_PER_RULE_PER_LINE = 10;
var ASSIGN = /\b([A-Za-z][A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIALS?|AUTH|URL|URI|DSN)|PASSWORD|PASSWD|SECRET|TOKEN|CREDENTIALS?)["']?\s*[:=]\s*["']?([^\s"'`,;&]+)/i;
var STRONG_NAME = /SECRET|PASSWORD|PASSWD|PWD|TOKEN|API_?KEY|PRIVATE|CREDENTIAL/i;
var GENERIC_SKIP_PATH = /(?:^|\/)(?:__snapshots__|__fixtures__|fixtures?|testdata|test-data|mocks?|node_modules|vendor)\/|\.(?:snap|lock|min\.js|map|svg)$|(?:^|\/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/i;
var NO_RULES = [];
var NO_HITS = [];
var MIN_LINE = 8;
var PCT_PROBE = /%[0-9a-f]{2}/i;
var B64_PROBE = /[A-Za-z0-9+/_-]{24}/;
var HEX_PROBE = /[0-9a-fA-F]{32}/;
var MAX_DECODE_DEPTH = 2;
var MAX_DECODE_TOKENS = 6;
var B64_TOKEN = /[A-Za-z0-9+/_-]{24,}={0,2}/g;
var HEX_TOKEN = /\b(?:[0-9a-fA-F]{2}){16,}\b/g;
function printable(buf) {
  if (buf.length < 8) return void 0;
  let ok = 0;
  for (const b of buf) if (b >= 32 && b < 127 || b === 9 || b === 10 || b === 13) ok++;
  return ok / buf.length >= 0.95 ? buf.toString("utf8") : void 0;
}
var GENERIC_RULE = { id: "generic-assignment", label: "High-entropy secret", provider: "unknown", re: /$^/, confidence: "low" };
function pathLike(v) {
  return /^(?:\.{1,2}\/|\/)[\w.-]+/.test(v) || /^[a-z0-9._-]+(?:\/[a-z0-9._-]+){2,}$/.test(v);
}
var ASCII = /^[\x00-\x7f]+$/;
var Engine = class {
  rules = [];
  global;
  /** Single-pass keyword matcher over every line rule's keywords. */
  keywordIndex;
  /** keyword id -> rules that list it. */
  keywordRules = [];
  /** Line rules with no usable keyword: candidates for every line. */
  always = [];
  /** Rules restricted to certain paths; every other rule applies everywhere. */
  pathRules = [];
  anywhere = [];
  constructor(packs) {
    for (const pack of packs) {
      if (pack.allowlist && !this.global) this.global = compileAllowlist(pack.allowlist);
      for (const def of pack.rules) this.rules.push(this.compile(def, this.rules.length));
    }
    const ids = /* @__PURE__ */ new Map();
    const keywords = [];
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
        if (id === void 0) {
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
  compile(def, index) {
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
      path: def.path ? compileRegex(def.path) : void 0
    };
  }
  /** Scans a block of text (a whole file, a diff hunk or a single line). */
  scan(content, path, startLine = 1) {
    if (path && this.global?.paths.some((p) => p.test(path))) return [];
    const lowerAll = content.toLowerCase();
    const matching = path ? this.pathRules.filter((r) => r.path.test(path)) : [];
    const forPath = matching.length ? [...this.anywhere, ...matching].sort((x, y) => x.index - y.index) : this.anywhere;
    const out = [];
    const lines = content.split(/\r?\n/);
    const decodeRules = forPath.filter((r) => !r.def.multiline);
    const perLine = this.candidates(lowerAll, lines.length, matching);
    for (let i = 0; i < lines.length; i++) out.push(...this.scanLine(lines[i], path, startLine + i, perLine[i] ?? NO_RULES, decodeRules));
    const multi = forPath.filter((r) => r.def.multiline && (!r.keywords.length || r.keywords.some((k) => lowerAll.includes(k))));
    if (multi.length) {
      const starts = [0];
      for (let i = 0; i < content.length; i++) if (content.charCodeAt(i) === 10) starts.push(i + 1);
      const lineAt = (idx) => {
        let lo = 0;
        let hi = starts.length - 1;
        while (lo < hi) {
          const mid = lo + hi + 1 >> 1;
          if (starts[mid] <= idx) lo = mid;
          else hi = mid - 1;
        }
        return startLine + lo;
      };
      for (const rule2 of multi) {
        rule2.re.lastIndex = 0;
        for (const m of content.matchAll(rule2.re)) {
          const hit = this.accept(rule2, m, m[0], path, lineAt(m.index ?? 0), void 0);
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
  candidates(lowerAll, lineCount, matching) {
    const perLine = new Array(lineCount);
    const eligible = (r) => !r.path || matching.includes(r);
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
    for (const rules of perLine) if (rules && rules.length > 1) rules.sort((x, y) => x.index - y.index);
    return perLine;
  }
  /** `via` is set when `text` came out of a decoder; those lines were not pre-filtered by keyword, so they are checked here. */
  scanLine(text, path, line, rules, decodeRules, via) {
    if (text.length > MAX_LINE || text.length < MIN_LINE) return NO_HITS;
    let assign;
    const getAssign = () => assign === void 0 ? assign = text.match(ASSIGN) : assign;
    let hits;
    if (rules.length) {
      const lower = via === void 0 ? "" : text.toLowerCase();
      const variable = getAssign()?.[1];
      for (const rule2 of rules) {
        if (via !== void 0 && rule2.keywords.length && !rule2.keywords.some((k) => lower.includes(k))) continue;
        rule2.re.lastIndex = 0;
        let n = 0;
        for (const m of text.matchAll(rule2.re)) {
          if (++n > MAX_PER_RULE_PER_LINE) break;
          const hit = this.accept(rule2, m, text, path, line, variable);
          if (hit) (hits ??= []).push(hit);
        }
      }
    }
    if (via === void 0 || via.split(">").length < MAX_DECODE_DEPTH) {
      const found = this.decoded(text, path, line, decodeRules, via, getAssign);
      if (found.length) (hits ??= []).push(...found);
    }
    if (hits) {
      const resolved = resolve(hits);
      if (resolved.length) return via ? resolved.map((h) => h.via ? h : { ...h, via }) : resolved;
    }
    const generic = this.generic(text, path, line, getAssign());
    return generic ? [{ ...generic, via }] : NO_HITS;
  }
  /** Re-scans base64, URL-encoded and hex values on the line, so a secret hidden in encoding is still found. */
  decoded(text, path, line, rules, via, getAssign) {
    const pct = PCT_PROBE.test(text);
    const b64 = B64_PROBE.test(text);
    const hex = HEX_PROBE.test(text);
    if (!pct && !b64 && !hex) return NO_HITS;
    const out = [];
    const next = (kind) => via ? `${via}>${kind}` : kind;
    const rescan = (decodedText, kind) => out.push(...this.scanLine(decodedText, path, line, rules, rules, next(kind)));
    if (pct) {
      try {
        const url = decodeURIComponent(text);
        if (url !== text) rescan(url, "url");
      } catch {
      }
    }
    if (b64) {
      const assign = getAssign();
      for (const m of [...text.matchAll(B64_TOKEN)].slice(0, MAX_DECODE_TOKENS)) {
        const plain = printable(Buffer.from(m[0], /[-_]/.test(m[0]) ? "base64url" : "base64"));
        if (!plain) continue;
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
  accept(rule2, m, line, path, lineNo, variable) {
    const def = rule2.def;
    const groupValue = (g) => m[g] || void 0;
    const secret = (def.secretGroup ? groupValue(def.secretGroup) : m.slice(1).find((g) => !!g)) ?? m[0];
    if (!secret) return void 0;
    if (!def.id.startsWith("private-key") && !def.multiline && isPlaceholder(secret)) return void 0;
    if (def.minLength && secret.length < def.minLength) return void 0;
    if (def.entropy !== void 0 && entropy(secret) <= def.entropy) return void 0;
    if (this.global && allowed(this.global, { secret, match: m[0], line, path })) return void 0;
    if (rule2.allow.some((a) => allowed(a, { secret, match: m[0], line, path }))) return void 0;
    let confidence = rule2.confidence;
    if (def.check) {
      const r = runCheck(def.check, secret, path);
      if (r.reject) return void 0;
      if (r.confidence) confidence = r.confidence;
    }
    const reported = def.reportGroup ? groupValue(def.reportGroup) ?? m[0] : secret;
    const value = def.multiline ? reported.replace(/\r/g, "") : reported;
    return { rule: rule2, value, variable, line: lineNo, confidence };
  }
  /** Fallback for `NAME_KEY=<random-looking value>` when no provider rule matched. */
  generic(text, path, line, a) {
    if (!a || path && GENERIC_SKIP_PATH.test(path)) return void 0;
    const value = a[2];
    if (value.length < 16 || value.length > 200) return void 0;
    const strong = STRONG_NAME.test(a[1]) && !HASHY_NAME.test(a[1]);
    if (value.includes("://") || /[\\()[\]{}^]/.test(value) || isPlaceholder(value) || looksBenign(value, strong) || pathLike(value)) return void 0;
    if (/^[a-z]+(?:[._-][a-z]+)*$/i.test(value)) return void 0;
    const hexOnly = /^[0-9a-f]+$/i.test(value);
    const h = entropy(value);
    if (h < (hexOnly ? 3.2 : 3.8)) return void 0;
    const illustrative = !!path && ILLUSTRATIVE_PATH.test(path);
    return { rule: GENERIC_RULE, value, variable: a[1], line, confidence: strong && h >= (hexOnly ? 3.4 : 4) && !illustrative ? "medium" : "low" };
  }
};
function resolve(hits) {
  const seen = /* @__PURE__ */ new Set();
  const unique = hits.filter((h) => seen.has(h.value) ? false : (seen.add(h.value), true));
  return unique.filter((h) => !unique.some((o) => o !== h && o.value.length > h.value.length && o.value.includes(h.value)));
}

// server/detect/rules/gitleaks.json
var gitleaks_default = {
  source: "gitleaks",
  license: "MIT (c) Zachary Rice and the Gitleaks contributors",
  allowlist: {
    regexes: [
      "(?i)^true|false|null$",
      "^(?i:a+|b+|c+|d+|e+|f+|g+|h+|i+|j+|k+|l+|m+|n+|o+|p+|q+|r+|s+|t+|u+|v+|w+|x+|y+|z+|\\*+|\\.+)$",
      "^\\$(?:\\d+|{\\d+})$",
      "^\\$(?:[A-Z_]+|[a-z_]+)$",
      "^\\${(?:[A-Z_]+|[a-z_]+)}$",
      "^\\{\\{[ \\t]*[\\w ().|]+[ \\t]*}}$",
      `^\\$\\{\\{[ \\t]*(?:(?:env|github|secrets|vars)(?:\\.[A-Za-z]\\w+)+[\\w "'&./=|]*)[ \\t]*}}$`,
      "^%(?:[A-Z_]+|[a-z_]+)%$",
      "^%[+\\-# 0]?[bcdeEfFgGoOpqstTUvxX]$",
      "^\\{\\d{0,2}}$",
      "^@(?:[A-Z_]+|[a-z_]+)@$",
      "^/Users/(?i:[a-z0-9]+/[\\w .-/]+$)",
      "^/(?:bin|etc|home|opt|tmp|usr|var)/[\\w ./-]+$"
    ],
    stopwords: [
      "014df517-39d1-4453-b7b3-9930c563627c",
      "abcdefghijklmnopqrstuvwxyz"
    ],
    paths: [
      "gitleaks\\.toml",
      "(?i)\\.(?:bmp|gif|jpe?g|png|svg|tiff?)$",
      "(?i)\\.(?:eot|[ot]tf|woff2?)$",
      "(?i)\\.(?:docx?|xlsx?|pdf|bin|socket|vsidx|v2|suo|wsuo|.dll|pdb|exe|gltf)$",
      "go\\.(?:mod|sum|work(?:\\.sum)?)$",
      "(?:^|/)vendor/modules\\.txt$",
      "(?:^|/)vendor/(?:github\\.com|golang\\.org/x|google\\.golang\\.org|gopkg\\.in|istio\\.io|k8s\\.io|sigs\\.k8s\\.io)(?:/.*)?$",
      "(?:^|/)gradlew(?:\\.bat)?$",
      "(?:^|/)gradle\\.lockfile$",
      "(?:^|/)mvnw(?:\\.cmd)?$",
      "(?:^|/)\\.mvn/wrapper/MavenWrapperDownloader\\.java$",
      "(?:^|/)node_modules(?:/.*)?$",
      "(?:^|/)(?:deno\\.lock|npm-shrinkwrap\\.json|package-lock\\.json|pnpm-lock\\.yaml|yarn\\.lock)$",
      "(?:^|/)bower_components(?:/.*)?$",
      "(?:^|/)(?:angular|bootstrap|jquery(?:-?ui)?|plotly|swagger-?ui)[a-zA-Z0-9.-]*(?:\\.min)?\\.js(?:\\.map)?$",
      "(?:^|/)javascript\\.json$",
      "(?:^|/)(?:Pipfile|poetry)\\.lock$",
      "(?i)(?:^|/)(?:v?env|virtualenv)/lib(?:64)?(?:/.*)?$",
      "(?i)(?:^|/)(?:lib(?:64)?/python[23](?:\\.\\d{1,2})+|python/[23](?:\\.\\d{1,2})+/lib(?:64)?)(?:/.*)?$",
      "(?i)(?:^|/)[a-z0-9_.]+-[0-9.]+\\.dist-info(?:/.+)?$",
      "(?:^|/)vendor/(?:bundle|ruby)(?:/.*?)?$",
      "\\.gem$",
      "verification-metadata\\.xml",
      "Database.refactorlog",
      "(?:^|/)\\.git$"
    ]
  },
  rules: [
    {
      id: "1password-secret-key",
      label: "1password secret key",
      provider: "1password",
      regex: "\\bA3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\\b",
      keywords: [
        "a3-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3.8
    },
    {
      id: "1password-service-account-token",
      label: "1password service account token",
      provider: "1password",
      regex: "ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}",
      keywords: [
        "ops_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 4
    },
    {
      id: "adafruit-api-key",
      label: "Adafruit API key",
      provider: "adafruit",
      regex: `(?i)[\\w.-]{0,50}?(?:adafruit)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9_-]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "adafruit"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "adobe-client-id",
      label: "Adobe client ID",
      provider: "adobe",
      regex: `(?i)[\\w.-]{0,50}?(?:adobe)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "adobe"
      ],
      source: "gitleaks",
      confidence: "medium",
      entropy: 2
    },
    {
      id: "adobe-client-secret",
      label: "Adobe client secret",
      provider: "adobe",
      regex: `\\b(p8e-(?i:[a-z0-9]{32}))(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "p8e-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "age-secret-key",
      label: "Age secret key",
      provider: "age",
      regex: "AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}",
      keywords: [
        "age-secret-key-1"
      ],
      source: "gitleaks",
      confidence: "high"
    },
    {
      id: "airtable-api-key",
      label: "Airtable API key",
      provider: "airtable",
      regex: `(?i)[\\w.-]{0,50}?(?:airtable)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{17})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "airtable"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "airtable-personnal-access-token",
      label: "Airtable personnal access token",
      provider: "airtable",
      regex: "\\b(pat[a-zA-Z0-9]{14}\\.[a-f0-9]{64})\\b",
      keywords: [
        "airtable"
      ],
      source: "gitleaks",
      confidence: "high"
    },
    {
      id: "algolia-api-key",
      label: "Algolia API key",
      provider: "algolia",
      regex: `(?i)[\\w.-]{0,50}?(?:algolia)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "algolia"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "alibaba-access-key-id",
      label: "Alibaba access key ID",
      provider: "alibaba",
      regex: `\\b(LTAI(?i:[a-z0-9]{20}))(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "ltai"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "alibaba-secret-key",
      label: "Alibaba secret key",
      provider: "alibaba",
      regex: `(?i)[\\w.-]{0,50}?(?:alibaba)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{30})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "alibaba"
      ],
      source: "gitleaks",
      confidence: "medium",
      entropy: 2
    },
    {
      id: "anthropic-admin-api-key",
      label: "Anthropic admin API key",
      provider: "anthropic",
      regex: `\\b(sk-ant-admin01-[a-zA-Z0-9_\\-]{93}AA)(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "sk-ant-admin01"
      ],
      source: "gitleaks",
      confidence: "high"
    },
    {
      id: "anthropic-api-key",
      label: "Anthropic API key",
      provider: "anthropic",
      regex: `\\b(sk-ant-api03-[a-zA-Z0-9_\\-]{93}AA)(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "sk-ant-api03"
      ],
      source: "gitleaks",
      confidence: "high"
    },
    {
      id: "artifactory-api-key",
      label: "Artifactory API key",
      provider: "artifactory",
      regex: "\\bAKCp[A-Za-z0-9]{69}\\b",
      keywords: [
        "akcp"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 4.5
    },
    {
      id: "artifactory-reference-token",
      label: "Artifactory reference token",
      provider: "artifactory",
      regex: "\\bcmVmd[A-Za-z0-9]{59}\\b",
      keywords: [
        "cmvmd"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 4.5
    },
    {
      id: "asana-client-id",
      label: "Asana client ID",
      provider: "asana",
      regex: `(?i)[\\w.-]{0,50}?(?:asana)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9]{16})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "asana"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "asana-client-secret",
      label: "Asana client secret",
      provider: "asana",
      regex: `(?i)[\\w.-]{0,50}?(?:asana)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "asana"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "atlassian-api-token",
      label: "Atlassian API token",
      provider: "atlassian",
      regex: `(?i)[\\w.-]{0,50}?(?:(?-i:ATLASSIAN|[Aa]tlassian)|(?-i:CONFLUENCE|[Cc]onfluence)|(?-i:JIRA|[Jj]ira))(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{20}[a-f0-9]{4})(?:[\\x60'"\\s;]|\\\\[nr]|$)|\\b(ATATT3[A-Za-z0-9_\\-=]{186})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "atlassian",
        "confluence",
        "jira",
        "atatt3"
      ],
      source: "gitleaks",
      confidence: "medium",
      entropy: 3.5
    },
    {
      id: "authress-service-client-access-key",
      label: "Authress service client access key",
      provider: "authress",
      regex: `\\b((?:sc|ext|scauth|authress)_(?i:[a-z0-9]{5,30}\\.[a-z0-9]{4,6}\\.(?-i:acc)[_-][a-z0-9-]{10,32}\\.[a-z0-9+/_=-]{30,120}))(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "sc_",
        "ext_",
        "scauth_",
        "authress_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "aws-access-token",
      label: "AWS access token",
      provider: "aws",
      regex: "\\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\\b",
      keywords: [
        "a3t",
        "akia",
        "asia",
        "abia",
        "acca"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3,
      allowlists: [
        {
          regexes: [
            ".+EXAMPLE$"
          ]
        }
      ]
    },
    {
      id: "aws-amazon-bedrock-api-key-long-lived",
      label: "AWS amazon bedrock API key long lived",
      provider: "aws",
      regex: `\\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "absk"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "aws-amazon-bedrock-api-key-short-lived",
      label: "AWS amazon bedrock API key short lived",
      provider: "aws",
      regex: "bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t",
      keywords: [
        "bedrock-api-key-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "azure-ad-client-secret",
      label: "Azure ad client secret",
      provider: "azure",
      regex: `(?:^|[\\\\'"\\x60\\s>=:(,)])([a-zA-Z0-9_~.]{3}\\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\\\'"\\x60\\s<),])`,
      keywords: [
        "q~"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "beamer-api-token",
      label: "Beamer API token",
      provider: "beamer",
      regex: `(?i)[\\w.-]{0,50}?(?:beamer)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(b_[a-z0-9=_\\-]{44})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "beamer"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "bitbucket-client-id",
      label: "Bitbucket client ID",
      provider: "bitbucket",
      regex: `(?i)[\\w.-]{0,50}?(?:bitbucket)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "bitbucket"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "bitbucket-client-secret",
      label: "Bitbucket client secret",
      provider: "bitbucket",
      regex: `(?i)[\\w.-]{0,50}?(?:bitbucket)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9=_\\-]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "bitbucket"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "bittrex-access-key",
      label: "Bittrex access key",
      provider: "bittrex",
      regex: `(?i)[\\w.-]{0,50}?(?:bittrex)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "bittrex"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "bittrex-secret-key",
      label: "Bittrex secret key",
      provider: "bittrex",
      regex: `(?i)[\\w.-]{0,50}?(?:bittrex)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "bittrex"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "cisco-meraki-api-key",
      label: "Cisco meraki API key",
      provider: "cisco",
      regex: `[\\w.-]{0,50}?(?i:[\\w.-]{0,50}?(?:(?-i:[Mm]eraki|MERAKI))(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9a-f]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "meraki"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "clickhouse-cloud-api-secret-key",
      label: "Clickhouse cloud API secret key",
      provider: "clickhouse",
      regex: "\\b(4b1d[A-Za-z0-9]{38})\\b",
      keywords: [
        "4b1d"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "clojars-api-token",
      label: "Clojars API token",
      provider: "clojars",
      regex: "(?i)CLOJARS_[a-z0-9]{60}",
      keywords: [
        "clojars_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "cloudflare-api-key",
      label: "Cloudflare API key",
      provider: "cloudflare",
      regex: `(?i)[\\w.-]{0,50}?(?:cloudflare)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9_-]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "cloudflare"
      ],
      source: "gitleaks",
      confidence: "medium",
      entropy: 2
    },
    {
      id: "cloudflare-global-api-key",
      label: "Cloudflare global API key",
      provider: "cloudflare",
      regex: `(?i)[\\w.-]{0,50}?(?:cloudflare)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{37})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "cloudflare"
      ],
      source: "gitleaks",
      confidence: "medium",
      entropy: 2
    },
    {
      id: "cloudflare-origin-ca-key",
      label: "Cloudflare origin ca key",
      provider: "cloudflare",
      regex: `\\b(v1\\.0-[a-f0-9]{24}-[a-f0-9]{146})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "cloudflare",
        "v1.0-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "codecov-access-token",
      label: "Codecov access token",
      provider: "codecov",
      regex: `(?i)[\\w.-]{0,50}?(?:codecov)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "codecov"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "cohere-api-token",
      label: "Cohere API token",
      provider: "cohere",
      regex: `[\\w.-]{0,50}?(?i:[\\w.-]{0,50}?(?:cohere|CO_API_KEY)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-zA-Z0-9]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "cohere",
        "co_api_key"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 4
    },
    {
      id: "coinbase-access-token",
      label: "Coinbase access token",
      provider: "coinbase",
      regex: `(?i)[\\w.-]{0,50}?(?:coinbase)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9_-]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "coinbase"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "confluent-access-token",
      label: "Confluent access token",
      provider: "confluent",
      regex: `(?i)[\\w.-]{0,50}?(?:confluent)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{16})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "confluent"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "confluent-secret-key",
      label: "Confluent secret key",
      provider: "confluent",
      regex: `(?i)[\\w.-]{0,50}?(?:confluent)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "confluent"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "contentful-delivery-api-token",
      label: "Contentful delivery API token",
      provider: "contentful",
      regex: `(?i)[\\w.-]{0,50}?(?:contentful)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9=_\\-]{43})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "contentful"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "curl-auth-header",
      label: "Curl auth header",
      provider: "curl",
      regex: `\\bcurl\\b(?:.*?|.*?(?:[\\r\\n]{1,2}.*?){1,5})[ \\t\\n\\r](?:-H|--header)(?:=|[ \\t]{0,5})(?:"(?i:(?:Authorization:[ \\t]{0,5}(?:Basic[ \\t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \\t]([\\w=~@.+/-]{8,})|([\\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \\t]{0,5}([\\w=~@.+/-]{8,}))"|'(?i:(?:Authorization:[ \\t]{0,5}(?:Basic[ \\t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \\t]([\\w=~@.+/-]{8,})|([\\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \\t]{0,5}([\\w=~@.+/-]{8,}))')))(?:\\B|\\s|(?![\\s\\S]))`,
      keywords: [
        "curl"
      ],
      source: "gitleaks",
      confidence: "high",
      multiline: true,
      entropy: 2.75
    },
    {
      id: "curl-auth-user",
      label: "Curl auth user",
      provider: "curl",
      regex: `\\bcurl\\b(?:.*|.*(?:[\\r\\n]{1,2}.*){1,5})[ \\t\\n\\r](?:-u|--user)(?:=|[ \\t]{0,5})("(:[^"]{3,}|[^:"]{3,}:|[^:"]{3,}:[^"]{3,})"|'([^:']{3,}:[^']{3,})'|((?:"[^"]{3,}"|'[^']{3,}'|[\\w$@.-]+):(?:"[^"]{3,}"|'[^']{3,}'|[\\w\${}@.-]+)))(?:\\s|(?![\\s\\S]))`,
      keywords: [
        "curl"
      ],
      source: "gitleaks",
      confidence: "high",
      multiline: true,
      entropy: 2,
      allowlists: [
        {
          regexes: [
            "[^:]+:(?:change(?:it|me)|pass(?:word)?|pwd|test|token|\\*+|x+)",
            `['"]?<[^>]+>['"]?:['"]?<[^>]+>|<[^:]+:[^>]+>['"]?`,
            "[^:]+:\\[[^]]+]",
            `['"]?[^:]+['"]?:['"]?\\$(?:\\d|\\w+|\\{(?:\\d|\\w+)})['"]?`,
            "\\$\\([^)]+\\):\\$\\([^)]+\\)",
            `['"]?\\$?{{[^}]+}}['"]?:['"]?\\$?{{[^}]+}}['"]?`
          ]
        }
      ]
    },
    {
      id: "databricks-api-token",
      label: "Databricks API token",
      provider: "databricks",
      regex: `\\b(dapi[a-f0-9]{32}(?:-\\d)?)(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "dapi"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "datadog-access-token",
      label: "Datadog access token",
      provider: "datadog",
      regex: `(?i)[\\w.-]{0,50}?(?:datadog)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "datadog"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "defined-networking-api-token",
      label: "Defined networking API token",
      provider: "defined",
      regex: `(?i)[\\w.-]{0,50}?(?:dnkey)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(dnkey-[a-z0-9=_\\-]{26}-[a-z0-9=_\\-]{52})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "dnkey"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "digitalocean-access-token",
      label: "Digitalocean access token",
      provider: "digitalocean",
      regex: `\\b(doo_v1_[a-f0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "doo_v1_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "digitalocean-pat",
      label: "Digitalocean PAT",
      provider: "digitalocean",
      regex: `\\b(dop_v1_[a-f0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "dop_v1_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "digitalocean-refresh-token",
      label: "Digitalocean refresh token",
      provider: "digitalocean",
      regex: `(?i)\\b(dor_v1_[a-f0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "dor_v1_"
      ],
      source: "gitleaks",
      confidence: "high"
    },
    {
      id: "discord-api-token",
      label: "Discord API token",
      provider: "discord",
      regex: `(?i)[\\w.-]{0,50}?(?:discord)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "discord"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "discord-client-id",
      label: "Discord client ID",
      provider: "discord",
      regex: `(?i)[\\w.-]{0,50}?(?:discord)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9]{18})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "discord"
      ],
      source: "gitleaks",
      confidence: "medium",
      entropy: 2
    },
    {
      id: "discord-client-secret",
      label: "Discord client secret",
      provider: "discord",
      regex: `(?i)[\\w.-]{0,50}?(?:discord)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9=_\\-]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "discord"
      ],
      source: "gitleaks",
      confidence: "medium",
      entropy: 2
    },
    {
      id: "doppler-api-token",
      label: "Doppler API token",
      provider: "doppler",
      regex: "dp\\.pt\\.(?i:[a-z0-9]{43})",
      keywords: [
        "dp.pt."
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "droneci-access-token",
      label: "Droneci access token",
      provider: "droneci",
      regex: `(?i)[\\w.-]{0,50}?(?:droneci)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "droneci"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "dropbox-api-token",
      label: "Dropbox API token",
      provider: "dropbox",
      regex: `(?i)[\\w.-]{0,50}?(?:dropbox)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{15})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "dropbox"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "dropbox-long-lived-api-token",
      label: "Dropbox long lived API token",
      provider: "dropbox",
      regex: `(?i)[\\w.-]{0,50}?(?:dropbox)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\\-_=]{43})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "dropbox"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "dropbox-short-lived-api-token",
      label: "Dropbox short lived API token",
      provider: "dropbox",
      regex: `(?i)[\\w.-]{0,50}?(?:dropbox)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(sl\\.[a-z0-9\\-=_]{135})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "dropbox"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "duffel-api-token",
      label: "Duffel API token",
      provider: "duffel",
      regex: "duffel_(?:test|live)_(?i:[a-z0-9_\\-=]{43})",
      keywords: [
        "duffel_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "dynatrace-api-token",
      label: "Dynatrace API token",
      provider: "dynatrace",
      regex: "dt0c01\\.(?i:[a-z0-9]{24}\\.[a-z0-9]{64})",
      keywords: [
        "dt0c01."
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 4
    },
    {
      id: "easypost-api-token",
      label: "Easypost API token",
      provider: "easypost",
      regex: "\\bEZAK(?i:[a-z0-9]{54}\\b)",
      keywords: [
        "ezak"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "easypost-test-api-token",
      label: "Easypost test API token",
      provider: "easypost",
      regex: "\\bEZTK(?i:[a-z0-9]{54}\\b)",
      keywords: [
        "eztk"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "etsy-access-token",
      label: "Etsy access token",
      provider: "etsy",
      regex: `(?i)[\\w.-]{0,50}?(?:(?-i:ETSY|[Ee]tsy))(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{24})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "etsy"
      ],
      source: "gitleaks",
      confidence: "medium",
      entropy: 3
    },
    {
      id: "facebook-access-token",
      label: "Facebook access token",
      provider: "facebook",
      regex: `(?i)\\b(\\d{15,16}(\\||%)[0-9a-z\\-_]{27,40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "facebook"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "facebook-page-access-token",
      label: "Facebook page access token",
      provider: "facebook",
      regex: `\\b(EAA[MC](?i:[a-z0-9]{100,}))(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "eaam",
        "eaac"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 4
    },
    {
      id: "facebook-secret",
      label: "Facebook secret",
      provider: "facebook",
      regex: `(?i)[\\w.-]{0,50}?(?:facebook)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "facebook"
      ],
      source: "gitleaks",
      confidence: "medium",
      entropy: 3
    },
    {
      id: "fastly-api-token",
      label: "Fastly API token",
      provider: "fastly",
      regex: `(?i)[\\w.-]{0,50}?(?:fastly)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9=_\\-]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "fastly"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "finicity-api-token",
      label: "Finicity API token",
      provider: "finicity",
      regex: `(?i)[\\w.-]{0,50}?(?:finicity)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "finicity"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "finicity-client-secret",
      label: "Finicity client secret",
      provider: "finicity",
      regex: `(?i)[\\w.-]{0,50}?(?:finicity)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{20})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "finicity"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "finnhub-access-token",
      label: "Finnhub access token",
      provider: "finnhub",
      regex: `(?i)[\\w.-]{0,50}?(?:finnhub)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{20})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "finnhub"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "flickr-access-token",
      label: "Flickr access token",
      provider: "flickr",
      regex: `(?i)[\\w.-]{0,50}?(?:flickr)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "flickr"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "flutterwave-encryption-key",
      label: "Flutterwave encryption key",
      provider: "flutterwave",
      regex: "FLWSECK_TEST-(?i:[a-h0-9]{12})",
      keywords: [
        "flwseck_test"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "flutterwave-public-key",
      label: "Flutterwave public key",
      provider: "flutterwave",
      regex: "FLWPUBK_TEST-(?i:[a-h0-9]{32}-X)",
      keywords: [
        "flwpubk_test"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "flutterwave-secret-key",
      label: "Flutterwave secret key",
      provider: "flutterwave",
      regex: "FLWSECK_TEST-(?i:[a-h0-9]{32}-X)",
      keywords: [
        "flwseck_test"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "flyio-access-token",
      label: "Flyio access token",
      provider: "flyio",
      regex: `\\b((?:fo1_[\\w-]{43}|fm1[ar]_[a-zA-Z0-9+\\/]{100,}={0,3}|fm2_[a-zA-Z0-9+\\/]{100,}={0,3}))(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "fo1_",
        "fm1",
        "fm2_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 4
    },
    {
      id: "frameio-api-token",
      label: "Frameio API token",
      provider: "frameio",
      regex: "fio-u-(?i:[a-z0-9\\-_=]{64})",
      keywords: [
        "fio-u-"
      ],
      source: "gitleaks",
      confidence: "high"
    },
    {
      id: "freemius-secret-key",
      label: "Freemius secret key",
      provider: "freemius",
      regex: `(?i)["']secret_key["']\\s*=>\\s*["'](sk_[\\S]{29})["']`,
      keywords: [
        "secret_key"
      ],
      source: "gitleaks",
      confidence: "high",
      path: "(?i)\\.php$"
    },
    {
      id: "freshbooks-access-token",
      label: "Freshbooks access token",
      provider: "freshbooks",
      regex: `(?i)[\\w.-]{0,50}?(?:freshbooks)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "freshbooks"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "gcp-api-key",
      label: "GCP API key",
      provider: "gcp",
      regex: `\\b(AIza[\\w-]{35})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "aiza"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 4,
      allowlists: [
        {
          regexes: [
            "AIzaSyabcdefghijklmnopqrstuvwxyz1234567",
            "AIzaSyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs",
            "AIzaSyCkEhVjf3pduRDt6d1yKOMitrUEke8agEM",
            "AIzaSyDMAScliyLx7F0NPDEJi1QmyCgHIAODrlU",
            "AIzaSyD3asb-2pEZVqMkmL6M9N6nHZRR_znhrh0",
            "AIzayDNSXIbFmlXbIE6mCzDLQAqITYefhixbX4A",
            "AIzaSyAdOS2zB6NCsk1pCdZ4-P6GBdi_UUPwX7c",
            "AIzaSyASWm6HmTMdYWpgMnjRBjxcQ9CKctWmLd4",
            "AIzaSyANUvH9H9BsUccjsu2pCmEkOPjjaXeDQgY",
            "AIzaSyA5_iVawFQ8ABuTZNUdcwERLJv_a_p4wtM",
            "AIzaSyA4UrcGxgwQFTfaI3no3t7Lt1sjmdnP5sQ",
            "AIzaSyDSb51JiIcB6OJpwwMicseKRhhrOq1cS7g",
            "AIzaSyBF2RrAIm4a0mO64EShQfqfd2AFnzAvvuU",
            "AIzaSyBcE-OOIbhjyR83gm4r2MFCu4MJmprNXsw",
            "AIzaSyB8qGxt4ec15vitgn44duC5ucxaOi4FmqE",
            "AIzaSyA8vmApnrHNFE0bApF4hoZ11srVL_n0nvY"
          ]
        }
      ]
    },
    {
      id: "github-app-token",
      label: "GitHub app token",
      provider: "github",
      regex: "(?:ghu|ghs)_[0-9a-zA-Z]{36}",
      keywords: [
        "ghu_",
        "ghs_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3,
      allowlists: [
        {
          paths: [
            "(?:^|/)@octokit/auth-token/README\\.md$"
          ]
        }
      ]
    },
    {
      id: "github-fine-grained-pat",
      label: "GitHub fine grained PAT",
      provider: "github",
      regex: "github_pat_\\w{82}",
      keywords: [
        "github_pat_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "github-oauth",
      label: "GitHub OAuth",
      provider: "github",
      regex: "gho_[0-9a-zA-Z]{36}",
      keywords: [
        "gho_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "github-pat",
      label: "GitHub PAT",
      provider: "github",
      regex: "ghp_[0-9a-zA-Z]{36}",
      keywords: [
        "ghp_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3,
      allowlists: [
        {
          paths: [
            "(?:^|/)@octokit/auth-token/README\\.md$"
          ]
        }
      ]
    },
    {
      id: "github-refresh-token",
      label: "GitHub refresh token",
      provider: "github",
      regex: "ghr_[0-9a-zA-Z]{36}",
      keywords: [
        "ghr_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "gitlab-cicd-job-token",
      label: "GitLab cicd job token",
      provider: "gitlab",
      regex: "glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}",
      keywords: [
        "glcbt-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "gitlab-deploy-token",
      label: "GitLab deploy token",
      provider: "gitlab",
      regex: "gldt-[0-9a-zA-Z_\\-]{20}",
      keywords: [
        "gldt-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "gitlab-feature-flag-client-token",
      label: "GitLab feature flag client token",
      provider: "gitlab",
      regex: "glffct-[0-9a-zA-Z_\\-]{20}",
      keywords: [
        "glffct-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "gitlab-feed-token",
      label: "GitLab feed token",
      provider: "gitlab",
      regex: "glft-[0-9a-zA-Z_\\-]{20}",
      keywords: [
        "glft-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "gitlab-incoming-mail-token",
      label: "GitLab incoming mail token",
      provider: "gitlab",
      regex: "glimt-[0-9a-zA-Z_\\-]{25}",
      keywords: [
        "glimt-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "gitlab-kubernetes-agent-token",
      label: "GitLab kubernetes agent token",
      provider: "gitlab",
      regex: "glagent-[0-9a-zA-Z_\\-]{50}",
      keywords: [
        "glagent-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "gitlab-oauth-app-secret",
      label: "GitLab OAuth app secret",
      provider: "gitlab",
      regex: "gloas-[0-9a-zA-Z_\\-]{64}",
      keywords: [
        "gloas-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "gitlab-pat",
      label: "GitLab PAT",
      provider: "gitlab",
      regex: "glpat-[\\w-]{20}",
      keywords: [
        "glpat-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "gitlab-pat-routable",
      label: "GitLab PAT routable",
      provider: "gitlab",
      regex: "\\bglpat-[0-9a-zA-Z_-]{27,300}\\.[0-9a-z]{2}[0-9a-z]{7}\\b",
      keywords: [
        "glpat-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 4
    },
    {
      id: "gitlab-ptt",
      label: "GitLab ptt",
      provider: "gitlab",
      regex: "glptt-[0-9a-f]{40}",
      keywords: [
        "glptt-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "gitlab-rrt",
      label: "GitLab rrt",
      provider: "gitlab",
      regex: "GR1348941[\\w-]{20}",
      keywords: [
        "gr1348941"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "gitlab-runner-authentication-token",
      label: "GitLab runner authentication token",
      provider: "gitlab",
      regex: "glrt-[0-9a-zA-Z_\\-]{20}",
      keywords: [
        "glrt-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "gitlab-runner-authentication-token-routable",
      label: "GitLab runner authentication token routable",
      provider: "gitlab",
      regex: "\\bglrt-t\\d_[0-9a-zA-Z_\\-]{27,300}\\.[0-9a-z]{2}[0-9a-z]{7}\\b",
      keywords: [
        "glrt-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 4
    },
    {
      id: "gitlab-scim-token",
      label: "GitLab scim token",
      provider: "gitlab",
      regex: "glsoat-[0-9a-zA-Z_\\-]{20}",
      keywords: [
        "glsoat-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "gitlab-session-cookie",
      label: "GitLab session cookie",
      provider: "gitlab",
      regex: "_gitlab_session=[0-9a-z]{32}",
      keywords: [
        "_gitlab_session="
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "gitter-access-token",
      label: "Gitter access token",
      provider: "gitter",
      regex: `(?i)[\\w.-]{0,50}?(?:gitter)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9_-]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "gitter"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "gocardless-api-token",
      label: "Gocardless API token",
      provider: "gocardless",
      regex: `(?i)[\\w.-]{0,50}?(?:gocardless)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(live_(?i:[a-z0-9\\-_=]{40}))(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "live_",
        "gocardless"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "grafana-api-key",
      label: "Grafana API key",
      provider: "grafana",
      regex: `(?i)\\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,3})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "eyjrijoi"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "grafana-cloud-api-token",
      label: "Grafana cloud API token",
      provider: "grafana",
      regex: `(?i)\\b(glc_[A-Za-z0-9+/]{32,400}={0,3})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "glc_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "grafana-service-account-token",
      label: "Grafana service account token",
      provider: "grafana",
      regex: `(?i)\\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "glsa_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "harness-api-key",
      label: "Harness API key",
      provider: "harness",
      regex: "(?:pat|sat)\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{20}",
      keywords: [
        "pat.",
        "sat."
      ],
      source: "gitleaks",
      confidence: "high"
    },
    {
      id: "hashicorp-tf-api-token",
      label: "Hashicorp tf API token",
      provider: "hashicorp",
      regex: "(?i)[a-z0-9]{14}\\.(?-i:atlasv1)\\.[a-z0-9\\-_=]{60,70}",
      keywords: [
        "atlasv1"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3.5
    },
    {
      id: "hashicorp-tf-password",
      label: "Hashicorp tf password",
      provider: "hashicorp",
      regex: `(?i)[\\w.-]{0,50}?(?:administrator_login_password|password)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}("[a-z0-9=_\\-]{8,20}")(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "administrator_login_password",
        "password"
      ],
      source: "gitleaks",
      confidence: "medium",
      entropy: 2,
      path: "(?i)\\.(?:tf|hcl)$"
    },
    {
      id: "heroku-api-key",
      label: "Heroku API key",
      provider: "heroku",
      regex: `(?i)[\\w.-]{0,50}?(?:heroku)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "heroku"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "heroku-api-key-v2",
      label: "Heroku API key v2",
      provider: "heroku",
      regex: `\\b((HRKU-AA[0-9a-zA-Z_-]{58}))(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "hrku-aa"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 4
    },
    {
      id: "hubspot-api-key",
      label: "HubSpot API key",
      provider: "hubspot",
      regex: `(?i)[\\w.-]{0,50}?(?:hubspot)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "hubspot"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "huggingface-access-token",
      label: "Huggingface access token",
      provider: "huggingface",
      regex: `\\b(hf_(?i:[a-z]{34}))(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "hf_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "huggingface-organization-api-token",
      label: "Huggingface organization API token",
      provider: "huggingface",
      regex: `\\b(api_org_(?i:[a-z]{34}))(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "api_org_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "infracost-api-token",
      label: "Infracost API token",
      provider: "infracost",
      regex: `\\b(ico-[a-zA-Z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "ico-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "intercom-api-key",
      label: "Intercom API key",
      provider: "intercom",
      regex: `(?i)[\\w.-]{0,50}?(?:intercom)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9=_\\-]{60})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "intercom"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "intra42-client-secret",
      label: "Intra42 client secret",
      provider: "intra42",
      regex: `\\b(s-s4t2(?:ud|af)-(?i:[abcdef0123456789]{64}))(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "intra",
        "s-s4t2ud-",
        "s-s4t2af-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "jfrog-api-key",
      label: "Jfrog API key",
      provider: "jfrog",
      regex: `(?i)[\\w.-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{73})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "jfrog",
        "artifactory",
        "bintray",
        "xray"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "jfrog-identity-token",
      label: "Jfrog identity token",
      provider: "jfrog",
      regex: `(?i)[\\w.-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "jfrog",
        "artifactory",
        "bintray",
        "xray"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "jwt",
      label: "JWT",
      provider: "jwt",
      regex: `\\b(ey[a-zA-Z0-9]{17,}\\.ey[a-zA-Z0-9\\/\\\\_-]{17,}\\.(?:[a-zA-Z0-9\\/\\\\_-]{10,}={0,2})?)(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "ey"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "jwt-base64",
      label: "JWT base64",
      provider: "jwt",
      regex: "\\bZXlK(?:(?<alg>aGJHY2lPaU)|(?<apu>aGNIVWlPaU)|(?<apv>aGNIWWlPaU)|(?<aud>aGRXUWlPaU)|(?<b64>aU5qUWlP)|(?<crit>amNtbDBJanBi)|(?<cty>amRIa2lPaU)|(?<epk>bGNHc2lPbn)|(?<enc>bGJtTWlPaU)|(?<jku>cWEzVWlPaU)|(?<jwk>cWQyc2lPb)|(?<iss>cGMzTWlPaU)|(?<iv>cGRpSTZJ)|(?<kid>cmFXUWlP)|(?<key_ops>clpYbGZiM0J6SWpwY)|(?<kty>cmRIa2lPaUp)|(?<nonce>dWIyNWpaU0k2)|(?<p2c>d01tTWlP)|(?<p2s>d01uTWlPaU)|(?<ppt>d2NIUWlPaU)|(?<sub>emRXSWlPaU)|(?<svt>emRuUWlP)|(?<tag>MFlXY2lPaU)|(?<typ>MGVYQWlPaUp)|(?<url>MWNtd2l)|(?<use>MWMyVWlPaUp)|(?<ver>MlpYSWlPaU)|(?<version>MlpYSnphVzl1SWpv)|(?<x>NElqb2)|(?<x5c>NE5XTWlP)|(?<x5t>NE5YUWlPaU)|(?<x5ts256>NE5YUWpVekkxTmlJNkl)|(?<x5u>NE5YVWlPaU)|(?<zip>NmFYQWlPaU))[a-zA-Z0-9\\/\\\\_+\\-\\r\\n]{40,}={0,2}",
      keywords: [
        "zxlk"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "kraken-access-token",
      label: "Kraken access token",
      provider: "kraken",
      regex: `(?i)[\\w.-]{0,50}?(?:kraken)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9\\/=_\\+\\-]{80,90})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "kraken"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "kubernetes-secret-yaml",
      label: "Kubernetes secret yaml",
      provider: "kubernetes",
      regex: `(?i)(?:\\bkind:[ \\t]*["']?\\bsecret\\b["']?(?s:.){0,200}?\\bdata:(?s:.){0,100}?\\s+([\\w.-]+:(?:[ \\t]*(?:\\||>[-+]?)\\s+)?[ \\t]*(?:["']?[a-z0-9+/]{10,}={0,3}["']?|\\{\\{[ \\t\\w"|$:=,.-]+}}|""|''))|\\bdata:(?s:.){0,100}?\\s+([\\w.-]+:(?:[ \\t]*(?:\\||>[-+]?)\\s+)?[ \\t]*(?:["']?[a-z0-9+/]{10,}={0,3}["']?|\\{\\{[ \\t\\w"|$:=,.-]+}}|""|''))(?s:.){0,200}?\\bkind:[ \\t]*["']?\\bsecret\\b["']?)`,
      keywords: [
        "secret"
      ],
      source: "gitleaks",
      confidence: "high",
      multiline: true,
      path: "(?i)\\.ya?ml$",
      allowlists: [
        {
          regexes: [
            `[\\w.-]+:(?:[ \\t]*(?:\\||>[-+]?)\\s+)?[ \\t]*(?:\\{\\{[ \\t\\w"|$:=,.-]+}}|""|'')`
          ]
        },
        {
          regexTarget: "match",
          regexes: [
            "(kind:(?s:.)+\\n---\\n(?s:.)+\\bdata:|data:(?s:.)+\\n---\\n(?s:.)+\\bkind:)"
          ]
        }
      ]
    },
    {
      id: "kucoin-access-token",
      label: "Kucoin access token",
      provider: "kucoin",
      regex: `(?i)[\\w.-]{0,50}?(?:kucoin)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{24})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "kucoin"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "kucoin-secret-key",
      label: "Kucoin secret key",
      provider: "kucoin",
      regex: `(?i)[\\w.-]{0,50}?(?:kucoin)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "kucoin"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "launchdarkly-access-token",
      label: "Launchdarkly access token",
      provider: "launchdarkly",
      regex: `(?i)[\\w.-]{0,50}?(?:launchdarkly)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9=_\\-]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "launchdarkly"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "linear-api-key",
      label: "Linear API key",
      provider: "linear",
      regex: "lin_api_(?i:[a-z0-9]{40})",
      keywords: [
        "lin_api_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "linear-client-secret",
      label: "Linear client secret",
      provider: "linear",
      regex: `(?i)[\\w.-]{0,50}?(?:linear)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "linear"
      ],
      source: "gitleaks",
      confidence: "medium",
      entropy: 2
    },
    {
      id: "linkedin-client-id",
      label: "LinkedIn client ID",
      provider: "linkedin",
      regex: `(?i)[\\w.-]{0,50}?(?:linked[_-]?in)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{14})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "linkedin",
        "linked_in",
        "linked-in"
      ],
      source: "gitleaks",
      confidence: "medium",
      entropy: 2
    },
    {
      id: "linkedin-client-secret",
      label: "LinkedIn client secret",
      provider: "linkedin",
      regex: `(?i)[\\w.-]{0,50}?(?:linked[_-]?in)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{16})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "linkedin",
        "linked_in",
        "linked-in"
      ],
      source: "gitleaks",
      confidence: "medium",
      entropy: 2
    },
    {
      id: "lob-api-key",
      label: "Lob API key",
      provider: "lob",
      regex: `(?i)[\\w.-]{0,50}?(?:lob)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}((live|test)_[a-f0-9]{35})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "test_",
        "live_"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "lob-pub-api-key",
      label: "Lob pub API key",
      provider: "lob",
      regex: `(?i)[\\w.-]{0,50}?(?:lob)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}((test|live)_pub_[a-f0-9]{31})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "test_pub",
        "live_pub",
        "_pub"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "looker-client-id",
      label: "Looker client ID",
      provider: "looker",
      regex: `(?i)[\\w.-]{0,50}?(?:looker)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{20})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "looker"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "looker-client-secret",
      label: "Looker client secret",
      provider: "looker",
      regex: `(?i)[\\w.-]{0,50}?(?:looker)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{24})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "looker"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "mailchimp-api-key",
      label: "Mailchimp API key",
      provider: "mailchimp",
      regex: `(?i)[\\w.-]{0,50}?(?:MailchimpSDK.initialize|mailchimp)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{32}-us\\d\\d)(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "mailchimp"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "mailgun-private-api-token",
      label: "Mailgun private API token",
      provider: "mailgun",
      regex: `(?i)[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(key-[a-f0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "mailgun"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "mailgun-pub-key",
      label: "Mailgun pub key",
      provider: "mailgun",
      regex: `(?i)[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(pubkey-[a-f0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "mailgun"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "mailgun-signing-key",
      label: "Mailgun signing key",
      provider: "mailgun",
      regex: `(?i)[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "mailgun"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "mapbox-api-token",
      label: "Mapbox API token",
      provider: "mapbox",
      regex: `(?i)[\\w.-]{0,50}?(?:mapbox)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(pk\\.[a-z0-9]{60}\\.[a-z0-9]{22})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "mapbox"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "mattermost-access-token",
      label: "Mattermost access token",
      provider: "mattermost",
      regex: `(?i)[\\w.-]{0,50}?(?:mattermost)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{26})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "mattermost"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "maxmind-license-key",
      label: "Maxmind license key",
      provider: "maxmind",
      regex: `\\b([A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk)(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "_mmk"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 4
    },
    {
      id: "messagebird-api-token",
      label: "Messagebird API token",
      provider: "messagebird",
      regex: `(?i)[\\w.-]{0,50}?(?:message[_-]?bird)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{25})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "messagebird",
        "message-bird",
        "message_bird"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "messagebird-client-id",
      label: "Messagebird client ID",
      provider: "messagebird",
      regex: `(?i)[\\w.-]{0,50}?(?:message[_-]?bird)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "messagebird",
        "message-bird",
        "message_bird"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "microsoft-teams-webhook",
      label: "Microsoft teams webhook",
      provider: "microsoft",
      regex: "https://[a-z0-9]+\\.webhook\\.office\\.com/webhookb2/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}",
      keywords: [
        "webhook.office.com",
        "webhookb2",
        "incomingwebhook"
      ],
      source: "gitleaks",
      confidence: "high"
    },
    {
      id: "netlify-access-token",
      label: "Netlify access token",
      provider: "netlify",
      regex: `(?i)[\\w.-]{0,50}?(?:netlify)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9=_\\-]{40,46})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "netlify"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "new-relic-browser-api-token",
      label: "New relic browser API token",
      provider: "new",
      regex: `(?i)[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(NRJS-[a-f0-9]{19})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "nrjs-"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "new-relic-insert-key",
      label: "New relic insert key",
      provider: "new",
      regex: `(?i)[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(NRII-[a-z0-9-]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "nrii-"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "new-relic-user-api-id",
      label: "New relic user API ID",
      provider: "new",
      regex: `(?i)[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "new-relic",
        "newrelic",
        "new_relic"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "new-relic-user-api-key",
      label: "New relic user API key",
      provider: "new",
      regex: `(?i)[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(NRAK-[a-z0-9]{27})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "nrak"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "notion-api-token",
      label: "Notion API token",
      provider: "notion",
      regex: `\\b(ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "ntn_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 4
    },
    {
      id: "npm-access-token",
      label: "Npm access token",
      provider: "npm",
      regex: `(?i)\\b(npm_[a-z0-9]{36})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "npm_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "nuget-config-password",
      label: "Nuget config password",
      provider: "nuget",
      regex: '(?i)<add key=\\"(?:(?:ClearText)?Password)\\"\\s*value=\\"(.{8,})\\"\\s*/>',
      keywords: [
        "<add key="
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 1,
      path: "(?i)nuget\\.config$",
      allowlists: [
        {
          regexes: [
            "33f!!lloppa",
            "hal\\+9ooo_da!sY",
            "^\\%\\S.*\\%$"
          ]
        }
      ]
    },
    {
      id: "nytimes-access-token",
      label: "Nytimes access token",
      provider: "nytimes",
      regex: `(?i)[\\w.-]{0,50}?(?:nytimes|new-york-times,|newyorktimes)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9=_\\-]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "nytimes",
        "new-york-times",
        "newyorktimes"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "octopus-deploy-api-key",
      label: "Octopus deploy API key",
      provider: "octopus",
      regex: `\\b(API-[A-Z0-9]{26})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "api-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "okta-access-token",
      label: "Okta access token",
      provider: "okta",
      regex: `[\\w.-]{0,50}?(?i:[\\w.-]{0,50}?(?:(?-i:[Oo]kta|OKTA))(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(00[\\w=\\-]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "okta"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 4
    },
    {
      id: "openai-api-key",
      label: "OpenAI API key",
      provider: "openai",
      regex: `\\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "t3blbkfj"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "openshift-user-token",
      label: "Openshift user token",
      provider: "openshift",
      regex: "\\b(sha256~[\\w-]{43})(?:[^\\w-]|(?![\\s\\S]))",
      keywords: [
        "sha256~"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3.5
    },
    {
      id: "perplexity-api-key",
      label: "Perplexity API key",
      provider: "perplexity",
      regex: `\\b(pplx-[a-zA-Z0-9]{48})(?:[\\x60'"\\s;]|\\\\[nr]|$|\\b)`,
      keywords: [
        "pplx-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 4
    },
    {
      id: "plaid-api-token",
      label: "Plaid API token",
      provider: "plaid",
      regex: `(?i)[\\w.-]{0,50}?(?:plaid)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "plaid"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "plaid-client-id",
      label: "Plaid client ID",
      provider: "plaid",
      regex: `(?i)[\\w.-]{0,50}?(?:plaid)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{24})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "plaid"
      ],
      source: "gitleaks",
      confidence: "medium",
      entropy: 3.5
    },
    {
      id: "plaid-secret-key",
      label: "Plaid secret key",
      provider: "plaid",
      regex: `(?i)[\\w.-]{0,50}?(?:plaid)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{30})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "plaid"
      ],
      source: "gitleaks",
      confidence: "medium",
      entropy: 3.5
    },
    {
      id: "planetscale-api-token",
      label: "Planetscale API token",
      provider: "planetscale",
      regex: `\\b(pscale_tkn_(?i:[\\w=\\.-]{32,64}))(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "pscale_tkn_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "planetscale-oauth-token",
      label: "Planetscale OAuth token",
      provider: "planetscale",
      regex: `\\b(pscale_oauth_[\\w=\\.-]{32,64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "pscale_oauth_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "planetscale-password",
      label: "Planetscale password",
      provider: "planetscale",
      regex: `(?i)\\b(pscale_pw_(?i:[\\w=\\.-]{32,64}))(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "pscale_pw_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "postman-api-token",
      label: "Postman API token",
      provider: "postman",
      regex: `\\b(PMAK-(?i:[a-f0-9]{24}\\-[a-f0-9]{34}))(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "pmak-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "prefect-api-token",
      label: "Prefect API token",
      provider: "prefect",
      regex: `\\b(pnu_[a-zA-Z0-9]{36})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "pnu_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "privateai-api-token",
      label: "Privateai API token",
      provider: "privateai",
      regex: `[\\w.-]{0,50}?(?i:[\\w.-]{0,50}?(?:private[_-]?ai)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "privateai",
        "private_ai",
        "private-ai"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "pulumi-api-token",
      label: "Pulumi API token",
      provider: "pulumi",
      regex: `\\b(pul-[a-f0-9]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "pul-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "pypi-upload-token",
      label: "PyPI upload token",
      provider: "pypi",
      regex: "pypi-AgEIcHlwaS5vcmc[\\w-]{50,1000}",
      keywords: [
        "pypi-ageichlwas5vcmc"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "rapidapi-access-token",
      label: "Rapidapi access token",
      provider: "rapidapi",
      regex: `(?i)[\\w.-]{0,50}?(?:rapidapi)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9_-]{50})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "rapidapi"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "readme-api-token",
      label: "Readme API token",
      provider: "readme",
      regex: `\\b(rdme_[a-z0-9]{70})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "rdme_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "rubygems-api-token",
      label: "Rubygems API token",
      provider: "rubygems",
      regex: `\\b(rubygems_[a-f0-9]{48})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "rubygems_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "scalingo-api-token",
      label: "Scalingo API token",
      provider: "scalingo",
      regex: `\\b(tk-us-[\\w-]{48})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "tk-us-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "sendbird-access-id",
      label: "Sendbird access ID",
      provider: "sendbird",
      regex: `(?i)[\\w.-]{0,50}?(?:sendbird)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "sendbird"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "sendbird-access-token",
      label: "Sendbird access token",
      provider: "sendbird",
      regex: `(?i)[\\w.-]{0,50}?(?:sendbird)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "sendbird"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "sendgrid-api-token",
      label: "SendGrid API token",
      provider: "sendgrid",
      regex: `\\b(SG\\.(?i:[a-z0-9=_\\-\\.]{66}))(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "sg."
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "sendinblue-api-token",
      label: "Sendinblue API token",
      provider: "sendinblue",
      regex: `\\b(xkeysib-[a-f0-9]{64}\\-(?i:[a-z0-9]{16}))(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "xkeysib-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "sentry-access-token",
      label: "Sentry access token",
      provider: "sentry",
      regex: `(?i)[\\w.-]{0,50}?(?:sentry)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "sentry"
      ],
      source: "gitleaks",
      confidence: "medium",
      entropy: 3
    },
    {
      id: "sentry-org-token",
      label: "Sentry org token",
      provider: "sentry",
      regex: "\\bsntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[a-zA-Z0-9+/]{10,200}={0,2}_[a-zA-Z0-9+/]{43}(?:[^a-zA-Z0-9+/]|(?![\\s\\S]))",
      keywords: [
        "sntrys_eyjpyxqio"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 4.5
    },
    {
      id: "sentry-user-token",
      label: "Sentry user token",
      provider: "sentry",
      regex: `\\b(sntryu_[a-f0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "sntryu_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3.5
    },
    {
      id: "settlemint-application-access-token",
      label: "Settlemint application access token",
      provider: "settlemint",
      regex: `\\b(sm_aat_[a-zA-Z0-9]{16})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "sm_aat"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "settlemint-personal-access-token",
      label: "Settlemint personal access token",
      provider: "settlemint",
      regex: `\\b(sm_pat_[a-zA-Z0-9]{16})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "sm_pat"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "settlemint-service-access-token",
      label: "Settlemint service access token",
      provider: "settlemint",
      regex: `\\b(sm_sat_[a-zA-Z0-9]{16})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "sm_sat"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "shippo-api-token",
      label: "Shippo API token",
      provider: "shippo",
      regex: `\\b(shippo_(?:live|test)_[a-fA-F0-9]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "shippo_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "shopify-access-token",
      label: "Shopify access token",
      provider: "shopify",
      regex: "shpat_[a-fA-F0-9]{32}",
      keywords: [
        "shpat_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "shopify-custom-access-token",
      label: "Shopify custom access token",
      provider: "shopify",
      regex: "shpca_[a-fA-F0-9]{32}",
      keywords: [
        "shpca_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "shopify-private-app-access-token",
      label: "Shopify private app access token",
      provider: "shopify",
      regex: "shppa_[a-fA-F0-9]{32}",
      keywords: [
        "shppa_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "shopify-shared-secret",
      label: "Shopify shared secret",
      provider: "shopify",
      regex: "shpss_[a-fA-F0-9]{32}",
      keywords: [
        "shpss_"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "sidekiq-secret",
      label: "Sidekiq secret",
      provider: "sidekiq",
      regex: `(?i)[\\w.-]{0,50}?(?:BUNDLE_ENTERPRISE__CONTRIBSYS__COM|BUNDLE_GEMS__CONTRIBSYS__COM)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-f0-9]{8}:[a-f0-9]{8})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "bundle_enterprise__contribsys__com",
        "bundle_gems__contribsys__com"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "sidekiq-sensitive-url",
      label: "Sidekiq sensitive URL",
      provider: "sidekiq",
      regex: "(?i)\\bhttps?://([a-f0-9]{8}:[a-f0-9]{8})@(?:gems.contribsys.com|enterprise.contribsys.com)(?:[\\/|\\#|\\?|:]|$)",
      keywords: [
        "gems.contribsys.com",
        "enterprise.contribsys.com"
      ],
      source: "gitleaks",
      confidence: "high"
    },
    {
      id: "slack-app-token",
      label: "Slack app token",
      provider: "slack",
      regex: "(?i)xapp-\\d-[A-Z0-9]+-\\d+-[a-z0-9]+",
      keywords: [
        "xapp"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "slack-bot-token",
      label: "Slack bot token",
      provider: "slack",
      regex: "xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
      keywords: [
        "xoxb"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "slack-config-access-token",
      label: "Slack config access token",
      provider: "slack",
      regex: "(?i)xoxe.xox[bp]-\\d-[A-Z0-9]{163,166}",
      keywords: [
        "xoxe.xoxb-",
        "xoxe.xoxp-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "slack-config-refresh-token",
      label: "Slack config refresh token",
      provider: "slack",
      regex: "(?i)xoxe-\\d-[A-Z0-9]{146}",
      keywords: [
        "xoxe-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "slack-legacy-bot-token",
      label: "Slack legacy bot token",
      provider: "slack",
      regex: "xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}",
      keywords: [
        "xoxb"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "slack-legacy-token",
      label: "Slack legacy token",
      provider: "slack",
      regex: "xox[os]-\\d+-\\d+-\\d+-[a-fA-F\\d]+",
      keywords: [
        "xoxo",
        "xoxs"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "slack-legacy-workspace-token",
      label: "Slack legacy workspace token",
      provider: "slack",
      regex: "xox[ar]-(?:\\d-)?[0-9a-zA-Z]{8,48}",
      keywords: [
        "xoxa",
        "xoxr"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "slack-user-token",
      label: "Slack user token",
      provider: "slack",
      regex: "xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}",
      keywords: [
        "xoxp-",
        "xoxe-"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "slack-webhook-url",
      label: "Slack webhook URL",
      provider: "slack",
      regex: "(?:https?://)?hooks.slack.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}",
      keywords: [
        "hooks.slack.com"
      ],
      source: "gitleaks",
      confidence: "high"
    },
    {
      id: "snyk-api-token",
      label: "Snyk API token",
      provider: "snyk",
      regex: `(?i)[\\w.-]{0,50}?(?:snyk[_.-]?(?:(?:api|oauth)[_.-]?)?(?:key|token))(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "snyk"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "sonar-api-token",
      label: "Sonar API token",
      provider: "sonar",
      regex: `(?i)[\\w.-]{0,50}?(?:sonar[_.-]?(login|token))(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}((?:squ_|sqp_|sqa_)?[a-z0-9=_\\-]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "sonar"
      ],
      source: "gitleaks",
      confidence: "medium",
      secretGroup: 2
    },
    {
      id: "sourcegraph-access-token",
      label: "Sourcegraph access token",
      provider: "sourcegraph",
      regex: `(?i)\\b(\\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40}|[a-fA-F0-9]{40})\\b)(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "sgp_",
        "sourcegraph"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "square-access-token",
      label: "Square access token",
      provider: "square",
      regex: `\\b((?:EAAA|sq0atp-)[\\w-]{22,60})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "sq0atp-",
        "eaaa"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "squarespace-access-token",
      label: "Squarespace access token",
      provider: "squarespace",
      regex: `(?i)[\\w.-]{0,50}?(?:squarespace)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "squarespace"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "stripe-access-token",
      label: "Stripe access token",
      provider: "stripe",
      regex: `\\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "sk_test",
        "sk_live",
        "sk_prod",
        "rk_test",
        "rk_live",
        "rk_prod"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 2
    },
    {
      id: "sumologic-access-id",
      label: "Sumologic access ID",
      provider: "sumologic",
      regex: `[\\w.-]{0,50}?(?i:[\\w.-]{0,50}?(?:(?-i:[Ss]umo|SUMO))(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(su[a-zA-Z0-9]{12})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "sumo"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "sumologic-access-token",
      label: "Sumologic access token",
      provider: "sumologic",
      regex: `(?i)[\\w.-]{0,50}?(?:(?-i:[Ss]umo|SUMO))(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "sumo"
      ],
      source: "gitleaks",
      confidence: "medium",
      entropy: 3
    },
    {
      id: "telegram-bot-api-token",
      label: "Telegram bot API token",
      provider: "telegram",
      regex: `(?i)[\\w.-]{0,50}?(?:telegr)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9]{5,16}:(?-i:A)[a-z0-9_\\-]{34})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "telegr"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "travisci-access-token",
      label: "Travisci access token",
      provider: "travisci",
      regex: `(?i)[\\w.-]{0,50}?(?:travis)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{22})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "travis"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "twilio-api-key",
      label: "Twilio API key",
      provider: "twilio",
      regex: "SK[0-9a-fA-F]{32}",
      keywords: [
        "sk"
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3
    },
    {
      id: "twitch-api-token",
      label: "Twitch API token",
      provider: "twitch",
      regex: `(?i)[\\w.-]{0,50}?(?:twitch)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{30})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "twitch"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "twitter-access-secret",
      label: "Twitter access secret",
      provider: "twitter",
      regex: `(?i)[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{45})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "twitter"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "twitter-access-token",
      label: "Twitter access token",
      provider: "twitter",
      regex: `(?i)[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([0-9]{15,25}-[a-zA-Z0-9]{20,40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "twitter"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "twitter-api-key",
      label: "Twitter API key",
      provider: "twitter",
      regex: `(?i)[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{25})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "twitter"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "twitter-api-secret",
      label: "Twitter API secret",
      provider: "twitter",
      regex: `(?i)[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{50})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "twitter"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "twitter-bearer-token",
      label: "Twitter bearer token",
      provider: "twitter",
      regex: `(?i)[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(A{22}[a-zA-Z0-9%]{80,100})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "twitter"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "typeform-api-token",
      label: "Typeform API token",
      provider: "typeform",
      regex: `(?i)[\\w.-]{0,50}?(?:typeform)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(tfp_[a-z0-9\\-_\\.=]{59})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "tfp_"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "vault-batch-token",
      label: "Vault batch token",
      provider: "vault",
      regex: `\\b(hvb\\.[\\w-]{138,300})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "hvb."
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 4
    },
    {
      id: "vault-service-token",
      label: "Vault service token",
      provider: "vault",
      regex: `\\b((?:hvs\\.[\\w-]{90,120}|s\\.(?i:[a-z0-9]{24})))(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "hvs.",
        "s."
      ],
      source: "gitleaks",
      confidence: "high",
      entropy: 3.5,
      allowlists: [
        {
          regexes: [
            "s\\.[A-Za-z]{24}"
          ]
        }
      ]
    },
    {
      id: "yandex-access-token",
      label: "Yandex access token",
      provider: "yandex",
      regex: `(?i)[\\w.-]{0,50}?(?:yandex)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(t1\\.[A-Z0-9a-z_-]+[=]{0,2}\\.[A-Z0-9a-z_-]{86}[=]{0,2})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "yandex"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "yandex-api-key",
      label: "Yandex API key",
      provider: "yandex",
      regex: `(?i)[\\w.-]{0,50}?(?:yandex)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(AQVN[A-Za-z0-9_\\-]{35,38})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "yandex"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "yandex-aws-access-token",
      label: "Yandex AWS access token",
      provider: "yandex",
      regex: `(?i)[\\w.-]{0,50}?(?:yandex)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}(YC[a-zA-Z0-9_\\-]{38})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "yandex"
      ],
      source: "gitleaks",
      confidence: "medium"
    },
    {
      id: "zendesk-secret-key",
      label: "Zendesk secret key",
      provider: "zendesk",
      regex: `(?i)[\\w.-]{0,50}?(?:zendesk)(?:[ \\t\\w.-]{0,20})[\\s'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'"\\s=]{0,5}([a-z0-9]{40})(?:[\\x60'"\\s;]|\\\\[nr]|$)`,
      keywords: [
        "zendesk"
      ],
      source: "gitleaks",
      confidence: "medium"
    }
  ]
};

// server/detect/rules/tripwire.ts
var rule = (r) => ({ ...r, source: "tripwire" });
var tripwirePack = {
  source: "tripwire",
  rules: [
    // Only a complete BEGIN..END block counts; a bare header in docs or a truncated example does not.
    rule({ id: "private-key", label: "Private key", provider: "ssh", multiline: true, regex: "-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\\w+/=:,.\\s-]{40,}?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----", keywords: ["private key"] }),
    rule({ id: "aws-access-key", label: "AWS access key ID", provider: "aws", regex: "\\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\\b", keywords: ["akia", "asia", "abia", "acca"] }),
    rule({ id: "aws-secret-key", label: "AWS secret access key", provider: "aws", regex: `(?i)aws_?secret_?(?:access_?)?key["']?\\s*[:=]\\s*["']?([A-Za-z0-9/+=]{40})\\b`, keywords: ["aws"] }),
    rule({ id: "github-pat", label: "GitHub token", provider: "github", regex: "\\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\\b", keywords: ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"], check: "github-checksum" }),
    rule({ id: "github-fine-grained", label: "GitHub fine-grained token", provider: "github", regex: "\\b(github_pat_[A-Za-z0-9_]{60,255})\\b", keywords: ["github_pat_"] }),
    rule({ id: "gitlab-pat", label: "GitLab token", provider: "gitlab", regex: "\\b(glpat-[A-Za-z0-9_-]{20,})\\b", keywords: ["glpat-"] }),
    rule({ id: "stripe-live", label: "Stripe live key", provider: "stripe", regex: "\\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\\b", keywords: ["sk_live_", "rk_live_"] }),
    rule({ id: "stripe-test", label: "Stripe test key", provider: "stripe-test", regex: "\\b((?:sk|rk)_test_[A-Za-z0-9]{20,})\\b", keywords: ["sk_test_", "rk_test_"] }),
    rule({ id: "slack-token", label: "Slack token", provider: "slack", regex: "\\b(xox[baprs]-[A-Za-z0-9-]{10,})\\b", keywords: ["xox"] }),
    rule({ id: "slack-webhook", label: "Slack webhook", provider: "slack", regex: "(https:\\/\\/hooks\\.slack\\.com\\/services\\/T[A-Za-z0-9_]+\\/B[A-Za-z0-9_]+\\/[A-Za-z0-9_]+)", keywords: ["hooks.slack.com"] }),
    rule({ id: "google-api-key", label: "Google API key", provider: "gcp", regex: "\\b(AIza[0-9A-Za-z_-]{35})\\b", keywords: ["aiza"] }),
    rule({ id: "anthropic-key", label: "Anthropic API key", provider: "anthropic", regex: "\\b(sk-ant-[A-Za-z0-9_-]{32,})\\b", keywords: ["sk-ant-"] }),
    rule({ id: "openai-key", label: "OpenAI API key", provider: "openai", regex: "\\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})\\b", keywords: ["t3blbkfj"] }),
    rule({ id: "sendgrid-key", label: "SendGrid API key", provider: "sendgrid", regex: "\\b(SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43})\\b", keywords: ["sg."] }),
    rule({ id: "twilio-key", label: "Twilio API key", provider: "twilio", regex: "\\b(SK[0-9a-f]{32})\\b", keywords: ["sk"] }),
    rule({ id: "npm-token", label: "npm access token", provider: "npm", regex: "\\b(npm_[A-Za-z0-9]{36})\\b", keywords: ["npm_"] }),
    // Same block as it appears inside a JSON string (GCP service-account files), with literal \n escapes instead of newlines.
    rule({ id: "private-key-escaped", label: "Private key (escaped in JSON)", provider: "ssh", regex: "-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[A-Za-z0-9+/=\\\\]{40,}?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----", keywords: ["private key"] }),
    rule({ id: "dockerhub-pat", label: "Docker Hub token", provider: "docker", regex: "\\b(dckr_pat_[A-Za-z0-9_-]{27,})\\b", keywords: ["dckr_pat_"] }),
    rule({ id: "replicate-token", label: "Replicate API token", provider: "replicate", regex: "\\b(r8_[A-Za-z0-9]{37})\\b", keywords: ["r8_"] }),
    rule({ id: "groq-key", label: "Groq API key", provider: "groq", regex: "\\b(gsk_[A-Za-z0-9]{52})\\b", keywords: ["gsk_"] }),
    rule({ id: "xai-key", label: "xAI API key", provider: "xai", regex: "\\b(xai-[A-Za-z0-9]{70,})\\b", keywords: ["xai-"] }),
    rule({ id: "supabase-token", label: "Supabase access token", provider: "supabase", regex: "\\b(sbp_[a-f0-9]{40})\\b", keywords: ["sbp_"] }),
    rule({ id: "figma-token", label: "Figma access token", provider: "figma", regex: "\\b(figd_[A-Za-z0-9_-]{40})\\b", keywords: ["figd_"] }),
    rule({ id: "neon-key", label: "Neon API key", provider: "neon", regex: "\\b(napi_[a-z0-9]{64})\\b", keywords: ["napi_"] }),
    rule({ id: "azure-storage-key", label: "Azure storage account key", provider: "azure", regex: "AccountKey=([A-Za-z0-9+/]{86}==)", keywords: ["accountkey="] }),
    // The password group is what gets checked; the whole URL is what gets reported.
    rule({ id: "db-url", label: "Database URL with password", provider: "database", regex: `\\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\\+srv)?|redis|rediss|amqps?):\\/\\/[^\\s:/@"']+:([^\\s@"'/]+)@[^\\s"']+)`, secretGroup: 2, reportGroup: 1, minLength: 6, check: "db-password", keywords: ["://"] }),
    rule({ id: "tripwire-demo", label: "Tripwire demo secret", provider: "demo", regex: "\\b(tw_fake_[a-z]+_[a-z0-9]{16,})\\b", keywords: ["tw_fake_"] })
  ]
};

// server/detect/index.ts
var shared;
function defaultEngine() {
  return shared ??= new Engine([tripwirePack, gitleaks_default]);
}

// server/real/rules.ts
var toMatch = (h) => ({ rule: h.rule, value: h.value, variable: h.variable, confidence: h.confidence, via: h.via });
function matchContent(content, path, startLine = 1) {
  return defaultEngine().scan(content, path, startLine).map((h) => ({ ...toMatch(h), line: h.line }));
}
function mask2(value, rule2) {
  if (rule2.id.startsWith("private-key")) return "-----BEGIN \u2026 PRIVATE KEY-----";
  if (rule2.id === "db-url") return value.replace(/:\/\/([^:/@\s]+):[^@\s]+@/, "://$1:\u2022\u2022\u2022\u2022@").slice(0, 48);
  if (rule2.id === "tripwire-demo") return value.length > 22 ? `${value.slice(0, 22)}\u2026` : value;
  const keep = Math.min(6, Math.floor(value.length / 4));
  return `${value.slice(0, keep)}${"\u2022".repeat(8)} (${value.length} chars)`;
}

// server/real/scan.ts
var run = promisify(execFile);
var SKIP_DIRS = /* @__PURE__ */ new Set([".git", "node_modules", "vendor", "dist", "build", ".next", "out", "coverage", "__pycache__", ".venv", "venv", "target"]);
var SKIP_FILE = /(?:^|\/)(?:\.tripwire-baseline\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|Gemfile\.lock|poetry\.lock|Cargo\.lock|go\.sum)$|\.(?:min\.js|map|png|jpe?g|gif|webp|ico|svg|pdf|zip|gz|woff2?|ttf|eot|mp4|mp3|lock)$/i;
var MANIFESTS = /* @__PURE__ */ new Set(["package.json", "Dockerfile", "requirements.txt", "pyproject.toml", "go.mod", "composer.json", "Gemfile", "pom.xml", "build.gradle", "Cargo.toml", "Procfile"]);
var CI_SERVICE = "CI (GitHub Actions)";
var HISTORY_COMMITS = Number(process.env.SCAN_HISTORY_COMMITS ?? 300);
function walk(dir, root = dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const full = join4(dir, name);
    const st = statSync(full, { throwIfNoEntry: false });
    if (!st) continue;
    if (st.isDirectory()) walk(full, root, out);
    else if (st.isFile() && st.size < 1e6) out.push(relative(root, full).split("\\").join("/"));
  }
  return out;
}
async function listFiles(dir) {
  if (!existsSync4(join4(dir, ".git"))) return walk(dir);
  try {
    const { stdout } = await run("git", ["-C", dir, "ls-files", "-z", "-co", "--exclude-standard"], { maxBuffer: 64 * 1024 * 1024 });
    return stdout.split("\0").filter((f) => f && !f.split("/").some((part) => SKIP_DIRS.has(part))).filter((f) => {
      const st = statSync(join4(dir, f), { throwIfNoEntry: false });
      return !!st?.isFile() && st.size < 1e6;
    });
  } catch {
    return walk(dir);
  }
}
function githubSlug(target) {
  const m = target.match(/github\.com[/:]([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/);
  return m ? `${m[1]}/${m[2]}` : void 0;
}
function normalizeTarget(input2) {
  const t = input2.trim();
  if (/^[\w.-]+\/[\w.-]+$/.test(t) && !existsSync4(t)) return `https://github.com/${t}.git`;
  return t;
}
async function cloneRepo(url, depth = HISTORY_COMMITS) {
  if (!/^(https?:\/\/|git@)/.test(url)) throw new Error("Enter a Git URL or owner/name");
  const tmp = mkdtempSync(join4(tmpdir(), "tripwire-real-"));
  const args = ["clone", "--quiet", "--single-branch", "--no-tags", "--depth", String(Math.max(1, depth)), url, tmp];
  const env = { ...process.env, GIT_TERMINAL_PROMPT: "0" };
  try {
    await run("git", args, { timeout: 9e4, env });
  } catch (err) {
    const token2 = process.env.GITHUB_TOKEN;
    if (!token2 || !url.includes("github.com")) {
      rmSync(tmp, { recursive: true, force: true });
      throw new Error(`Clone failed: ${err.message.split("\n")[0]}`);
    }
    rmSync(tmp, { recursive: true, force: true });
    const retry = mkdtempSync(join4(tmpdir(), "tripwire-real-"));
    const auth = Buffer.from(`x-access-token:${token2}`).toString("base64");
    try {
      await run("git", ["-c", `http.extraHeader=Authorization: Basic ${auth}`, ...args.slice(0, -1), retry], { timeout: 9e4, env });
    } catch {
      rmSync(retry, { recursive: true, force: true });
      throw new Error("Clone failed: repository not found or not accessible with this token");
    }
    return retry;
  }
  return tmp;
}
function manifestDirs(files) {
  const dirs = /* @__PURE__ */ new Set();
  for (const f of files) {
    const parts = f.split("/");
    if (parts.length <= 3 && MANIFESTS.has(parts[parts.length - 1])) dirs.add(parts.slice(0, -1).join("/"));
  }
  return dirs;
}
function serviceFor(file, dirs, repoName) {
  if (file.startsWith(".github/")) return CI_SERVICE;
  const parts = file.split("/");
  for (const depth of [2, 1]) {
    if (parts.length <= depth) continue;
    const dir = parts.slice(0, depth).join("/");
    if (dirs.has(dir)) return dir;
  }
  return repoName;
}
var IGNORE_MARK = /tripwire:ignore|gitleaks:allow/;
function findIn(content, file, startLine, service) {
  const lines = content.split(/\r?\n/);
  const out = [];
  for (const m of matchContent(content, file, startLine)) {
    if (IGNORE_MARK.test(lines[m.line - startLine] ?? "")) continue;
    const provider = m.rule.id === "tripwire-demo" ? m.value.split("_")[2] ?? "demo" : m.rule.provider;
    out.push({
      value: m.value,
      finding: { id: "", rule: m.rule.id, ruleLabel: m.rule.label, provider, variable: m.variable?.toUpperCase(), file, line: m.line, inHead: true, preview: mask2(m.value, m.rule), service, nodeId: "", confidence: m.confidence, via: m.via }
    });
  }
  return out;
}
function scanHead(dir, files, dirs, repoName) {
  const out = [];
  for (const file of files) {
    if (SKIP_FILE.test(file)) continue;
    const buf = readFileSync4(join4(dir, file));
    if (buf.includes(0)) continue;
    out.push(...findIn(buf.toString("utf8"), file, 1, serviceFor(file, dirs, repoName)));
  }
  return out;
}
function parsePatch(patch, dirs, repoName, inHead) {
  const raws = [];
  let commit = "";
  let file = "";
  let commits = 0;
  let hunk = [];
  let hunkStart = 0;
  const flush = () => {
    if (hunk.length && file && !SKIP_FILE.test(file))
      for (const r of findIn(hunk.join("\n"), file, hunkStart, serviceFor(file, dirs, repoName))) raws.push({ ...r, finding: { ...r.finding, commit: commit || void 0, inHead } });
    hunk = [];
  };
  for (const text of patch.split("\n")) {
    if (text.startsWith("__TW__")) {
      flush();
      commit = text.slice(6);
      commits++;
    } else if (text.startsWith("+++ ")) {
      flush();
      file = text.startsWith("+++ b/") ? text.slice(6) : "";
    } else if (text.startsWith("@@")) {
      flush();
      hunkStart = Number(text.match(/\+(\d+)/)?.[1] ?? 0);
    } else if (text.startsWith("+") && file) hunk.push(text.slice(1));
  }
  flush();
  return { raws, commits };
}
var GIT_BUF = { maxBuffer: 256 * 1024 * 1024, timeout: 6e4 };
async function scanHistory(dir, dirs, repoName, limit = HISTORY_COMMITS) {
  if (limit <= 0 || !existsSync4(join4(dir, ".git"))) return { raws: [], commits: 0 };
  const { stdout } = await run("git", ["-C", dir, "log", "-p", "-U0", "--no-merges", "--no-color", "--no-ext-diff", "--format=__TW__%h", "-n", String(limit)], GIT_BUF);
  return parsePatch(stdout, dirs, repoName, false);
}
async function scanDiff(dir, dirs, repoName, base2) {
  const diff = () => run("git", ["-C", dir, "diff", "-U0", "--no-color", "--no-ext-diff", base2, "HEAD"], GIT_BUF);
  let out;
  try {
    out = await diff();
  } catch {
    await run("git", ["-C", dir, "fetch", "--quiet", "--no-tags", "--depth=1", "origin", base2], { timeout: 6e4 });
    out = await diff();
  }
  return parsePatch(out.stdout, dirs, repoName, true).raws;
}
async function scanStaged(dir, dirs, repoName) {
  const { stdout } = await run("git", ["-C", dir, "diff", "--cached", "-U0", "--no-color", "--no-ext-diff", "--diff-filter=ACMR"], GIT_BUF);
  return parsePatch(stdout, dirs, repoName, true).raws;
}
function mergeFindings(head, history, added) {
  const byValue = /* @__PURE__ */ new Map();
  for (const r of head) if (!byValue.has(r.value)) byValue.set(r.value, r);
  for (const r of history) {
    const existing = byValue.get(r.value);
    if (existing) existing.finding.commit ??= r.finding.commit;
    else byValue.set(r.value, r);
  }
  const samples = /* @__PURE__ */ new Map();
  const values = /* @__PURE__ */ new Map();
  const findings = [...byValue.values()].map((r, i) => {
    r.finding.id = `f-${i}`;
    if (added) r.finding.isNew = added.has(r.value);
    if (r.finding.rule === "db-url") samples.set(r.finding.id, r.value);
    values.set(r.finding.id, r.value);
    return r.finding;
  });
  return { findings, samples, values };
}
function ciSecretRefs(dir, files) {
  const refs = /* @__PURE__ */ new Map();
  for (const file of files.filter((f) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(f))) {
    readFileSync4(join4(dir, file), "utf8").split(/\r?\n/).forEach((text, i) => {
      for (const m of text.matchAll(/secrets\.([A-Za-z_][A-Za-z0-9_]*)/g)) {
        if (m[1] === "GITHUB_TOKEN" || refs.has(m[1])) continue;
        refs.set(m[1], { name: m[1], file, line: i + 1 });
      }
    });
  }
  return [...refs.values()];
}
function ignoreMatcher(text) {
  const res = text.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#")).map((glob) => {
    const dirOnly = glob.endsWith("/");
    const g = glob.replace(/^\/|\/$/g, "");
    const body = g.split("**").map((part) => part.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]")).join(".*");
    const anchored = g.includes("/") ? `^${body}` : `(?:^|/)${body}`;
    return new RegExp(`${anchored}${dirOnly ? "/" : "(?:$|/)"}`);
  });
  return (file) => res.some((re) => re.test(file));
}
function loadIgnore(dir) {
  const p = join4(dir, ".tripwireignore");
  return ignoreMatcher(existsSync4(p) ? readFileSync4(p, "utf8") : "");
}
function repoNameOf(target, dir) {
  return githubSlug(target)?.split("/")[1] ?? basename(resolve2(dir));
}
async function currentBranch(dir) {
  if (!existsSync4(join4(dir, ".git"))) return void 0;
  return (await run("git", ["-C", dir, "rev-parse", "--abbrev-ref", "HEAD"])).stdout.trim();
}

// server/real/core.ts
var isRemote = (target) => /^(https?:\/\/|git@)/.test(target);
async function scanTarget(input2, opts = {}, onStage) {
  const started = Date.now();
  const target = normalizeTarget(input2);
  const remote = isRemote(target);
  const history = opts.history ?? Number(process.env.SCAN_HISTORY_COMMITS ?? 300);
  const warnings = [];
  let dir = remote ? "" : resolve3(target);
  onStage?.("cloning", {});
  try {
    if (remote) dir = await cloneRepo(target, history);
    else if (!existsSync5(dir)) throw new Error(`No such directory: ${target}`);
    const ignored = loadIgnore(dir);
    const files = (await listFiles(dir)).filter((f) => !ignored(f));
    const dirs = manifestDirs(files);
    const name = repoNameOf(target, dir);
    const branch = await currentBranch(dir).catch(() => void 0);
    onStage?.("secrets", { branch, filesScanned: files.length });
    const staged = opts.staged ? (await scanStaged(dir, dirs, name)).filter((r) => !ignored(r.finding.file)) : void 0;
    const head = staged ?? scanHead(dir, files, dirs, name);
    onStage?.("history", {});
    const past = staged ? { raws: [], commits: 0 } : await scanHistory(dir, dirs, name, history);
    let added = staged ? new Set(staged.map((r) => r.value)) : void 0;
    if (opts.diff && !staged) {
      try {
        added = new Set((await scanDiff(dir, dirs, name, opts.diff)).filter((r) => !ignored(r.finding.file)).map((r) => r.value));
      } catch (err) {
        warnings.push(`Could not diff against ${opts.diff} (${err.message.split("\n")[0]}); treating every secret in the code as blocking.`);
      }
    }
    const { findings, samples, values } = mergeFindings(head, past.raws.filter((r) => !ignored(r.finding.file)), added);
    const accepted = opts.baseline === false ? /* @__PURE__ */ new Set() : loadBaseline(dir);
    for (const f of findings) {
      f.fingerprint = fingerprint(f.rule, f.file, values.get(f.id) ?? "");
      if (accepted.has(f.fingerprint)) f.baselined = true;
    }
    if (opts.verify) {
      onStage?.("verify", { commitsScanned: past.commits, findings });
      await verifyFindings(findings, values, honeyKeyIds()).catch((err) => warnings.push(`Key verification failed: ${err.message}`));
    }
    opts.onValues?.(values);
    const graph = buildGraph(name, findings, ciSecretRefs(dir, files), samples);
    onStage?.("vulns", { commitsScanned: past.commits, findings, ...graph });
    let vulns = [];
    if (opts.vulns !== false && !staged) vulns = await findVulns(parseDeps(dir, files)).catch((err) => (warnings.push(`Vulnerability lookup failed: ${err.message}`), []));
    return { target, repo: githubSlug(target), name, branch, filesScanned: files.length, commitsScanned: past.commits, findings, ...graph, vulns, diffBase: staged ? "staged" : added ? opts.diff : void 0, warnings, durationMs: Date.now() - started };
  } finally {
    if (remote && dir) rmSync2(dir, { recursive: true, force: true });
  }
}

// server/detect/schema.ts
var CONFIDENCE_RANK = { low: 0, medium: 1, high: 2 };

// server/contain/index.ts
import { appendFileSync, mkdirSync as mkdirSync2 } from "node:fs";
import { homedir as homedir2 } from "node:os";
import { dirname as dirname3, join as join5 } from "node:path";

// server/graph.ts
function blastHops(edges, startIds) {
  const seen = new Set(startIds);
  const hops = [];
  let frontier = [...startIds];
  while (frontier.length) {
    const hop = { edges: [], nodes: [] };
    for (const id of frontier) {
      for (const e of edges) {
        if (e.from !== id || seen.has(e.to)) continue;
        seen.add(e.to);
        hop.edges.push(e.id);
        hop.nodes.push(e.to);
      }
    }
    if (!hop.nodes.length) break;
    hops.push(hop);
    frontier = hop.nodes;
  }
  return hops;
}

// server/contain/providers.ts
var TIMEOUT2 = Number(process.env.CONTAIN_TIMEOUT_MS ?? 1e4);
var signal = () => AbortSignal.timeout(TIMEOUT2);
var secretOf = (ctx) => ctx.values.get(ctx.finding.id) ?? "";
var github = async (ctx) => {
  const res = await fetch("https://api.github.com/credentials/revoke", {
    method: "POST",
    headers: { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json" },
    body: JSON.stringify({ credentials: [secretOf(ctx)] }),
    signal: signal()
  });
  return res.status === 202 ? { ok: true, note: "GitHub accepted the revocation." } : { ok: false, note: `GitHub returned ${res.status}.` };
};
var slack = async (ctx) => {
  const res = await fetch("https://slack.com/api/auth.revoke", { method: "POST", headers: { Authorization: `Bearer ${secretOf(ctx)}` }, signal: signal() });
  const data = await res.json().catch(() => ({}));
  return data.ok ? { ok: true, note: "Slack revoked the token." } : { ok: false, note: `Slack: ${data.error ?? res.status}.` };
};
var gitlab = async (ctx) => {
  const res = await fetch("https://gitlab.com/api/v4/personal_access_tokens/self", { method: "DELETE", headers: { "PRIVATE-TOKEN": secretOf(ctx) }, signal: signal() });
  return res.status === 204 ? { ok: true, note: "GitLab revoked the token." } : { ok: false, note: `GitLab returned ${res.status}.` };
};
var aws = async (ctx) => {
  const id = secretOf(ctx);
  const arn = ctx.finding.verify?.identity ?? "";
  const user = arn.includes(":user/") ? arn.split("/").pop() : void 0;
  if (!user) return { ok: false, note: "Only IAM user access keys can be deactivated this way (this key's identity is not an IAM user)." };
  const pair = awsSecretFor(ctx.findings, ctx.finding);
  const secret = pair ? ctx.values.get(pair.id) : void 0;
  if (!secret) return { ok: false, note: "No matching AWS secret access key was found next to this key ID." };
  const body = `Action=UpdateAccessKey&AccessKeyId=${encodeURIComponent(id)}&Status=Inactive&UserName=${encodeURIComponent(user)}&Version=2010-05-08`;
  const res = await fetch("https://iam.amazonaws.com/", { method: "POST", headers: sigV4({ id, secret, service: "iam", host: "iam.amazonaws.com", region: "us-east-1", body, now: /* @__PURE__ */ new Date() }), body, signal: signal() });
  if (!res.ok) {
    const code = (await res.text()).match(/<Code>([^<]*)<\/Code>/)?.[1] ?? res.status;
    return { ok: false, note: `AWS refused (${code}). The key may lack iam:UpdateAccessKey.` };
  }
  return { ok: true, note: `Deactivated ${id} for IAM user ${user}.`, reactivate: `aws iam update-access-key --access-key-id ${id} --status Active --user-name ${user}` };
};
var REVOKERS = { github, slack, gitlab, aws };
var GUIDES = {
  stripe: { url: "https://dashboard.stripe.com/apikeys", steps: ["Roll the key (Developers > API keys > Roll key). There is no API to do it for you.", "Deploy the new key.", "Check Developers > Logs for charges or refunds you do not recognise."] },
  "stripe-test": { url: "https://dashboard.stripe.com/test/apikeys", steps: ["Roll the test key; it cannot move real money, but it exposes test customer data."] },
  openai: { url: "https://platform.openai.com/api-keys", steps: ["Delete the key and create a new one.", "Check the usage dashboard for spend you do not recognise."] },
  anthropic: { url: "https://console.anthropic.com/settings/keys", steps: ["Delete the key and create a new one.", "Check usage for spend you do not recognise."] },
  sendgrid: { url: "https://app.sendgrid.com/settings/api_keys", steps: ["Delete the key, create a new one with the least scope it needs.", "Check Activity for mail you did not send."] },
  npm: { url: "https://www.npmjs.com/settings/~/tokens", steps: ["Revoke the token (or run `npm token revoke <id>`), then create a granular replacement.", "Check your packages for versions you did not publish."] },
  gcp: { url: "https://console.cloud.google.com/apis/credentials", steps: ["Delete or regenerate the API key and restrict the new one to the APIs and referrers it needs.", "Check API usage for spikes."] },
  twilio: { url: "https://console.twilio.com/us1/account/keys-credentials/api-keys", steps: ["Delete the API key and create a new one.", "Check the usage logs for messages or calls you did not make."] },
  database: { steps: ["Change the password: ALTER USER <user> WITH PASSWORD '<new>' (or the equivalent), then update the connection string wherever it is used.", "Restrict the database to the hosts that need it, and check its logs for unknown clients."] },
  ssh: { steps: ["Remove the matching public key from every server's authorized_keys and from GitHub/GitLab deploy keys.", "Generate a new key pair and install the new public key."] },
  github: { url: "https://github.com/settings/tokens", steps: ["Delete the token in Settings > Developer settings, then create a replacement with the least scope it needs."] },
  gitlab: { url: "https://gitlab.com/-/user_settings/personal_access_tokens", steps: ["Revoke the token, then create a replacement with the least scope it needs."] },
  slack: { url: "https://api.slack.com/apps", steps: ["Reinstall or rotate the app token, then revoke the old one."] },
  aws: { url: "https://console.aws.amazon.com/iam/home#/security_credentials", steps: ["Deactivate the access key (IAM > Users > Security credentials), create a new one, update the app, then delete the old key.", "Review CloudTrail for activity by the key since it leaked."] }
};
var GENERIC = { steps: ["Revoke or rotate the credential in the service that issued it.", "Deploy the replacement wherever the old one was used."] };
var TAIL = ["Review the provider's audit log for use of the old key since it leaked.", "Remove it from the code; if it is also in git history, the revocation is what protects you."];
function guideFor(provider) {
  const g = GUIDES[provider] ?? GENERIC;
  return { url: g.url, steps: [...g.steps, ...TAIL] };
}

// server/contain/plan.ts
var SENS = { low: 1, medium: 2, high: 3, production: 4 };
function reachOf(f, nodes, edges) {
  if (f.verify?.access?.length) {
    const sorted2 = [...f.verify.access].sort((a, b) => SENS[b.sensitivity] - SENS[a.sensitivity]);
    return { labels: sorted2.map((a) => a.label), rank: SENS[sorted2[0].sensitivity] * 10 + Math.min(sorted2.length, 9) };
  }
  if (!f.nodeId) return { labels: [], rank: 0 };
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const resources = blastHops(edges, [f.nodeId]).flatMap((h) => h.nodes).map((id) => byId.get(id)).filter((n) => n?.type === "resource").sort((a, b) => SENS[b.sensitivity ?? "low"] - SENS[a.sensitivity ?? "low"]);
  return { labels: resources.map((r) => r.label), rank: resources.length ? SENS[resources[0].sensitivity ?? "low"] * 10 + Math.min(resources.length, 9) : 0 };
}
function buildPlan(report) {
  const { findings, nodes, edges } = report;
  const steps = [];
  for (const f of findings) {
    if (f.verify?.status === "revoked" || f.verify?.status === "honey") continue;
    if (f.rule === "aws-secret-key" && findings.some((k) => k.rule === "aws-access-key" && awsSecretFor(findings, k)?.id === f.id)) continue;
    const live2 = f.verify?.status === "live";
    const reach2 = reachOf(f, nodes, edges);
    const auto2 = live2 && !!REVOKERS[f.provider];
    const guide = guideFor(f.provider);
    const reason = auto2 ? void 0 : live2 ? "Confirmed live, but Tripwire cannot revoke this provider's keys for you." : f.verify?.status === "unverified" ? "The provider could not confirm this key. Treat it as live until you have checked." : "Not checked against the provider (scan with key verification to confirm it is live).";
    steps.push({
      live: live2,
      rank: reach2.rank,
      step: {
        findingId: f.id,
        label: f.variable ?? f.ruleLabel,
        provider: f.provider,
        file: f.file,
        line: f.line,
        reach: reach2.labels,
        mode: auto2 ? "revoke" : "guided",
        reason,
        action: auto2 ? `Revoke through the ${f.provider} API, then check the provider now rejects it.` : "Revoke it yourself using the steps below.",
        guide
      }
    });
  }
  const auto = (s) => Number(s.step.mode === "revoke");
  return steps.sort((a, b) => Number(b.live) - Number(a.live) || b.rank - a.rank || auto(b) - auto(a) || a.step.label.localeCompare(b.step.label)).map((s) => s.step);
}

// server/contain/index.ts
var containLog = () => join5(process.env.TRIPWIRE_HOME ?? join5(homedir2(), ".tripwire"), "contain-log.jsonl");
var sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function record(file, entry) {
  if (file === false) return;
  const path = file ?? containLog();
  try {
    mkdirSync2(dirname3(path), { recursive: true });
    appendFileSync(path, JSON.stringify({ at: (/* @__PURE__ */ new Date()).toISOString(), ...entry }) + "\n", { mode: 384 });
  } catch {
  }
}
async function runContain(input2, opts) {
  const { findings, values } = input2;
  const plan = buildPlan(input2).filter((s) => !opts.only || opts.only.includes(s.findingId));
  const results = [];
  for (const step of plan) {
    const finding = findings.find((f) => f.id === step.findingId);
    if (step.mode === "guided") {
      results.push({ findingId: step.findingId, status: "guided", note: step.reason ?? "Follow the steps." });
      continue;
    }
    if (!opts.apply) {
      results.push({ findingId: step.findingId, status: "planned", note: "Dry run: nothing was changed." });
      continue;
    }
    const base2 = { provider: step.provider, fingerprint: finding.fingerprint, file: step.file };
    let revoked2;
    try {
      revoked2 = await REVOKERS[step.provider]({ finding, findings, values });
    } catch (err) {
      revoked2 = { ok: false, note: `Request failed: ${err.message}` };
    }
    if (!revoked2.ok) {
      results.push({ findingId: step.findingId, status: "failed", note: `${revoked2.note} Use the manual steps instead.` });
      record(opts.logFile, { ...base2, outcome: "failed", note: revoked2.note });
      continue;
    }
    await sleep(opts.delayMs ?? 1500);
    const value = values.get(finding.id) ?? "";
    const pair = finding.rule === "aws-access-key" ? awsSecretFor(findings, finding) : void 0;
    const context = new Map(pair ? [["aws-secret", values.get(pair.id) ?? ""]] : []);
    const after = await verifyOne(finding, value, context).catch(() => void 0);
    if (after) finding.verify = after;
    const still = after?.status === "live";
    const status2 = still ? "still-live" : "revoked";
    const note = still ? `${revoked2.note} But the provider still accepts the key. Revoke it manually.` : after?.status === "revoked" ? `${revoked2.note} The provider now rejects the key.` : `${revoked2.note} The provider could not be re-checked.`;
    results.push({ findingId: step.findingId, status: status2, note, reactivate: revoked2.reactivate });
    record(opts.logFile, { ...base2, outcome: status2, note: revoked2.note, reactivate: revoked2.reactivate });
  }
  return { plan, results, contained: !results.some((r) => r.status === "failed" || r.status === "still-live") };
}

// server/cli/contain.ts
var GLYPH = { planned: "WOULD REVOKE", guided: "YOU DO THIS", revoked: "REVOKED", failed: "FAILED", "still-live": "STILL LIVE" };
function formatContain(outcome, findings, apply, color) {
  const c = (code) => (s) => color ? `\x1B[${code}m${s}\x1B[0m` : s;
  const [red, yellow, green, dim, bold, cyan] = ["31", "33", "32", "2", "1", "36"].map(c);
  const tone = (s) => ({ planned: yellow, guided: cyan, revoked: green, failed: red, "still-live": red })[s];
  const byId = new Map(findings.map((f) => [f.id, f]));
  const out = ["", bold(apply ? "Containment" : "Containment plan (dry run: nothing has been changed)"), ""];
  if (!outcome.plan.length) out.push(dim("  No live or unconfirmed keys to contain."), "");
  outcome.plan.forEach((step, i) => {
    const r = outcome.results.find((x) => x.findingId === step.findingId);
    const f = byId.get(step.findingId);
    out.push(`${String(i + 1).padStart(2)}. ${tone(r.status)(GLYPH[r.status].padEnd(12))} ${bold(step.label)}  ${dim(`${step.provider} \xB7 ${step.file}:${step.line}${f?.verify?.identity ? ` \xB7 as ${f.verify.identity}` : ""}`)}`);
    if (step.reach.length) out.push(dim(`      reaches ${step.reach.slice(0, 4).join(", ")}${step.reach.length > 4 ? ", \u2026" : ""}`));
    out.push(`      ${r.note}`);
    if (r.reactivate) out.push(dim(`      undo: ${r.reactivate}`));
    if (r.status === "guided" || r.status === "failed" || r.status === "still-live") {
      if (step.guide.url) out.push(`      ${cyan(step.guide.url)}`);
      step.guide.steps.forEach((s, j) => out.push(dim(`      ${j + 1}) ${s}`)));
    }
    out.push("");
  });
  const n = (s) => outcome.results.filter((r) => r.status === s).length;
  if (apply) out.push(`${green(`${n("revoked")} revoked`)} \xB7 ${n("failed") + n("still-live") ? red(`${n("failed") + n("still-live")} need attention`) : "0 need attention"} \xB7 ${cyan(`${n("guided")} manual`)}`, "");
  else if (n("planned")) out.push(`${n("planned")} key${n("planned") === 1 ? "" : "s"} can be revoked automatically. Run again with ${bold("--apply")} to do it.`, "");
  return out.join("\n");
}
async function contain(target, apply, json2, log, err, quiet) {
  let values = /* @__PURE__ */ new Map();
  const report = await scanTarget(target, { vulns: false, verify: true, baseline: false, onValues: (v) => values = v }, (stage) => !quiet && err(`tripwire: ${stage}\u2026
`));
  const outcome = await runContain({ findings: report.findings, nodes: report.nodes, edges: report.edges, values }, { apply });
  if (json2) log(JSON.stringify({ target: report.target, apply, ...outcome }, null, 2) + "\n");
  else log(formatContain(outcome, report.findings, apply, !!process.stdout.isTTY && !process.env.NO_COLOR));
  if (!apply) return 0;
  const byId = new Map(report.findings.map((f) => [f.id, f]));
  const stillExposed = outcome.results.some((r) => r.status === "failed" || r.status === "still-live" || r.status === "guided" && byId.get(r.findingId)?.verify?.status === "live");
  return stillExposed ? 1 : 0;
}

// server/cli/hook.ts
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync as existsSync6, mkdirSync as mkdirSync3, readFileSync as readFileSync5, rmSync as rmSync3, writeFileSync as writeFileSync3 } from "node:fs";
import { dirname as dirname4, resolve as resolve4 } from "node:path";
var HOOK_MARKER = "# tripwire-hook";
var HOOK_SCRIPT = `#!/bin/sh
${HOOK_MARKER}: installed by \`tripwire install-hook\`. Remove with \`tripwire install-hook --remove\`.
[ "$TRIPWIRE_SKIP" = "1" ] && exit 0
if command -v tripwire >/dev/null 2>&1; then
  exec tripwire scan --staged
fi
exec npx --yes tripwire-scan scan --staged
`;
function hookPath(dir) {
  const rel = execFileSync("git", ["-C", dir, "rev-parse", "--git-path", "hooks/pre-commit"], { encoding: "utf8" }).trim();
  return resolve4(dir, rel);
}
function installHook(target, opts, log, err) {
  const dir = resolve4(target);
  let path;
  try {
    path = hookPath(dir);
  } catch {
    return err(`${dir} is not a git repository.
`), 2;
  }
  const existing = existsSync6(path) ? readFileSync5(path, "utf8") : void 0;
  const ours = existing?.includes(HOOK_MARKER);
  if (opts.remove) {
    if (!existing) return log("No pre-commit hook installed.\n"), 0;
    if (!ours) return err(`${path} was not installed by Tripwire; leaving it alone.
`), 2;
    rmSync3(path);
    return log(`Removed ${path}
`), 0;
  }
  if (existing && !ours && !opts.force) {
    return err(`A pre-commit hook already exists at ${path}.
Add \`tripwire scan --staged\` to it yourself, use the pre-commit framework (see README), or re-run with --force to replace it.
`), 2;
  }
  mkdirSync3(dirname4(path), { recursive: true });
  writeFileSync3(path, HOOK_SCRIPT, { mode: 493 });
  chmodSync(path, 493);
  log(`Installed ${path}
Commits now fail if they add a secret. Bypass once with \`git commit --no-verify\` or TRIPWIRE_SKIP=1.
`);
  return 0;
}

// server/cli/github.ts
import { appendFileSync as appendFileSync2, readFileSync as readFileSync6 } from "node:fs";

// server/cli/report.ts
var MARKER = "<!-- tripwire-report -->";
var RANK2 = { UNKNOWN: 0, LOW: 1, MODERATE: 2, HIGH: 3, CRITICAL: 4 };
function evaluate(r, policy) {
  const floor = CONFIDENCE_RANK[policy.minConfidence ?? "low"];
  const active = r.findings.filter((f) => f.verify?.status !== "revoked" && f.verify?.status !== "honey" && !f.baselined && CONFIDENCE_RANK[f.confidence ?? "high"] >= floor);
  const candidates = r.diffBase ? active.filter((f) => f.isNew) : active.filter((f) => f.inHead);
  const blocking = policy.secrets ? candidates : [];
  const blockingVulns = policy.vulns === "none" ? [] : r.vulns.filter((v) => RANK2[v.severity] >= RANK2[policy.vulns]);
  const reasons = [];
  const s = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;
  const liveN = blocking.filter((f) => f.verify?.status === "live").length;
  if (liveN) reasons.push(`${s(liveN, "live key")} confirmed by the provider`);
  if (blocking.length) reasons.push(r.diffBase ? `${s(blocking.length, "secret")} added in this change` : `${s(blocking.length, "secret")} in the code`);
  if (blockingVulns.length) reasons.push(`${s(blockingVulns.length, "vulnerable package")} at ${policy.vulns.toLowerCase()} or above`);
  return { failed: reasons.length > 0, reasons, blocking, blockingVulns };
}
function unlocks(r, f) {
  const byId = new Map(r.nodes.map((n) => [n.id, n]));
  return blastHops(r.edges, [f.nodeId]).flatMap((h) => h.nodes).map((id) => byId.get(id)).filter((n) => n?.type === "resource").map((n) => n.label);
}
var VSTAT = { live: "**LIVE**", revoked: "revoked", honey: "honey", unverified: "unverified" };
var status = (f) => [f.isNew ? "new" : f.inHead ? "in code" : "history", f.baselined ? "baselined" : "", f.confidence && f.confidence !== "high" ? `${f.confidence} confidence` : "", f.verify ? VSTAT[f.verify.status] : ""].filter(Boolean).join(" \xB7 ");
var reach = (r, f) => f.verify?.access?.length ? f.verify.access.map((a) => a.label) : f.verify?.status === "revoked" || f.verify?.status === "honey" ? [] : unlocks(r, f);
var order = (f) => f.isNew ? 0 : f.inHead ? 1 : 2;
var sorted = (fs) => [...fs].sort((a, b) => order(a) - order(b));
var cell = (s) => s.replace(/\|/g, "\\|").replace(/\n/g, " ");
function toMarkdown(r, v, maxVulns = 15) {
  const out = [MARKER, "## Tripwire", ""];
  out.push(v.failed ? `**Failed:** ${v.reasons.join(", ")}.` : "**Passed:** no blocking findings.", "");
  if (r.findings.length) {
    out.push(`### Secrets (${r.findings.length})`, "", "| Status | Secret | Location | Type | Unlocks |", "| --- | --- | --- | --- | --- |");
    for (const f of sorted(r.findings)) {
      const where = f.inHead ? `\`${f.file}:${f.line}\`` : `\`${f.file}:${f.line}\` (commit ${f.commit})`;
      out.push(`| ${status(f)} | \`${cell(f.variable ?? f.ruleLabel)}\` \`${cell(f.preview)}\` | ${where} | ${cell(f.ruleLabel)} | ${cell(reach(r, f).join(", ") || "-")}${f.verify?.identity ? ` (as \`${cell(f.verify.identity)}\`)` : ""} |`);
    }
    out.push("");
    if (r.findings.some((f) => !f.inHead)) out.push("> Secrets marked `history` were deleted from the code but are still in git history. Rotate them with the provider; removing the line does not revoke them.", "");
  } else out.push("No secrets found.", "");
  if (r.vulns.length) {
    const counts = ["CRITICAL", "HIGH", "MODERATE", "LOW"].map((s) => [s, r.vulns.filter((x) => x.severity === s).length]).filter(([, n]) => n);
    out.push(`### Vulnerable dependencies (${r.vulns.length})`, "", counts.map(([s, n]) => `${n} ${s.toLowerCase()}`).join(" \xB7 "), "", "| Package | Version | Fixed in | Severity | Advisory |", "| --- | --- | --- | --- | --- |");
    for (const x of r.vulns.slice(0, maxVulns)) out.push(`| \`${x.name}\` (${x.ecosystem}${x.direct ? "" : ", transitive"}) | ${x.version} | ${x.fixed ?? "-"} | ${x.severity.toLowerCase()} | ${x.advisories[0].id}: ${cell(x.advisories[0].summary).slice(0, 90)} |`);
    if (r.vulns.length > maxVulns) out.push("", `\u2026and ${r.vulns.length - maxVulns} more.`);
    out.push("");
  }
  for (const w of r.warnings) out.push(`> Warning: ${w}`, "");
  out.push(`<sub>Scanned ${r.filesScanned} files and ${r.commitsScanned} commits in ${(r.durationMs / 1e3).toFixed(1)}s. Silence a false positive with a \`tripwire:ignore\` comment on the line or a glob in \`.tripwireignore\`.</sub>`);
  return out.join("\n") + "\n";
}
function toText(r, v, color, maxVulns = 10) {
  const c = (code) => (s) => color ? `\x1B[${code}m${s}\x1B[0m` : s;
  const [red, yellow, green, dim, bold, cyan] = ["31", "33", "32", "2", "1", "36"].map(c);
  const tone = (f) => f.baselined ? dim("BASE") : f.isNew ? red("NEW ") : f.inHead ? red("CODE") : yellow("HIST");
  const vtag = (f) => !f.verify ? "" : f.verify.status === "live" ? ` ${red(bold("LIVE"))}` : f.verify.status === "revoked" ? ` ${green("revoked")}` : f.verify.status === "honey" ? ` ${cyan("honey")}` : ` ${dim("unverified")}`;
  const sev = (s) => (RANK2[s] >= 3 ? red : RANK2[s] === 2 ? yellow : dim)(s.padEnd(8));
  const out = ["", `${bold("Tripwire")}  ${r.repo ?? r.name}${r.branch ? dim(` (${r.branch})`) : ""}  ${dim(`${r.filesScanned} files \xB7 ${r.commitsScanned} commits \xB7 ${(r.durationMs / 1e3).toFixed(1)}s`)}`, ""];
  out.push(bold(`Secrets (${r.findings.length})`));
  if (!r.findings.length) out.push(dim("  none found"));
  for (const f of sorted(r.findings)) {
    out.push(`  ${tone(f)}  ${(f.variable ?? f.ruleLabel).padEnd(22)} ${cyan(`${f.file}:${f.line}`)}${f.inHead ? "" : dim(` @${f.commit}`)}  ${dim(f.ruleLabel)}${f.confidence && f.confidence !== "high" ? dim(` [${f.confidence}]`) : ""}${f.via ? dim(` (${f.via})`) : ""}${vtag(f)}`);
    const u = reach(r, f);
    out.push(dim(`        ${f.preview}${f.verify?.identity ? `  as ${f.verify.identity}` : ""}${u.length ? `  \u2192 unlocks ${u.join(", ")}` : ""}`));
    if (f.verify?.note && f.verify.status !== "live") out.push(dim(`        ${f.verify.note}`));
  }
  out.push("", bold(`Vulnerable dependencies (${r.vulns.length})`));
  if (!r.vulns.length) out.push(dim("  none found"));
  for (const x of r.vulns.slice(0, maxVulns)) out.push(`  ${sev(x.severity)} ${`${x.name}@${x.version}`.padEnd(30)} ${x.fixed ? green(`\u2192 ${x.fixed}`.padEnd(14)) : dim("no fix".padEnd(14))} ${dim(`${x.file}  ${x.advisories[0].id}`)}`);
  if (r.vulns.length > maxVulns) out.push(dim(`  \u2026and ${r.vulns.length - maxVulns} more (use --json for the full list)`));
  for (const w of r.warnings) out.push("", yellow(`warning: ${w}`));
  out.push("", v.failed ? `${red(bold("FAIL"))}  ${v.reasons.join(", ")}` : `${green(bold("PASS"))}  no blocking findings`, "");
  return out.join("\n");
}

// server/cli/github.ts
var esc = (s) => s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
var escProp = (s) => esc(s).replace(/:/g, "%3A").replace(/,/g, "%2C");
function githubReport(r, v, markdown) {
  const lines = [];
  const blocking = new Set(v.blocking.map((f) => f.id));
  for (const f of r.findings) {
    if (!f.inHead) continue;
    const level = blocking.has(f.id) ? "error" : "warning";
    lines.push(`::${level} file=${escProp(f.file)},line=${f.line},title=${escProp(`Tripwire: ${f.ruleLabel}`)}::${esc(`${f.variable ?? f.ruleLabel} looks like a real secret (${f.preview}). Remove it, rotate it with the provider and load it from a secret store.`)}`);
  }
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync2(process.env.GITHUB_STEP_SUMMARY, markdown);
  if (process.env.GITHUB_OUTPUT)
    appendFileSync2(process.env.GITHUB_OUTPUT, `secrets=${r.findings.length}
new-secrets=${r.findings.filter((f) => f.isNew).length}
vulns=${r.vulns.length}
failed=${v.failed}
`);
  return lines;
}
function pullRequestNumber() {
  const path = process.env.GITHUB_EVENT_PATH;
  if (!path) return void 0;
  try {
    return JSON.parse(readFileSync6(path, "utf8")).pull_request?.number;
  } catch {
    return void 0;
  }
}
async function upsertPrComment(body) {
  const repo = process.env.GITHUB_REPOSITORY;
  const pr = pullRequestNumber();
  if (!repo || !pr) return "not a pull request; skipped comment";
  if (!process.env.GITHUB_TOKEN) return "GITHUB_TOKEN not set; skipped comment";
  const comments = await gh(`/repos/${repo}/issues/${pr}/comments?per_page=100`);
  const mine = comments.find((c) => c.body?.includes(MARKER));
  if (mine) await gh(`/repos/${repo}/issues/comments/${mine.id}`, { method: "PATCH", body: { body } });
  else await gh(`/repos/${repo}/issues/${pr}/comments`, { method: "POST", body: { body } });
  return `${mine ? "updated" : "posted"} comment on #${pr}`;
}

// server/cli/main.ts
var HELP = `Usage: tripwire scan [path | git url | owner/repo] [options]
       tripwire honey create [--email you@x.com] [--plant owner/repo] [--file path]
       tripwire baseline [path]  accept every current finding in .tripwire-baseline.json
       tripwire contain [path]   plan how to kill every live key (--apply to revoke them)
       tripwire install-hook [path]  block commits that add a secret (--remove, --force)
       tripwire honey check      (exit 1 if any decoy was used)

Finds secrets in the code and git history, maps what each one unlocks,
and checks dependencies against OSV.dev. Exits 1 when something blocks.

Options:
  --diff <base>           Only secrets added since <base> block (for pull requests)
  --history <n>           Commits of history to scan (default 300, 0 = none)
  --fail-on-vulns <sev>   Also fail on vulnerable deps: low|moderate|high|critical (default: none)
  --no-fail-secrets       Report secrets without failing
  --skip-vulns            Skip the dependency check
  --min-confidence <c>    Only findings at this confidence or above block: low|medium|high (default: low)
  --staged                Scan only what is staged for commit (pre-commit hooks); fast, no history
  --apply                 contain: actually revoke live keys (default is a dry-run plan)
  --no-baseline           Ignore .tripwire-baseline.json
  --verify                Ask each provider (read-only) if found keys work and what they reach
  --json <file|->         Write the full report as JSON
  --markdown <file>       Write a Markdown report
  --github                GitHub Actions: annotations, job summary, outputs
  --comment               GitHub Actions: post/update a pull request comment
  -q, --quiet             No progress output
  -h, --help              Show this help

Silence a false positive with "tripwire:ignore" on the line, or globs in .tripwireignore.
`;
async function main(argv2, log = (s) => process.stdout.write(s), err = (s) => process.stderr.write(s)) {
  const { values, positionals } = parseArgs({
    args: argv2,
    allowPositionals: true,
    options: {
      diff: { type: "string" },
      history: { type: "string" },
      "fail-on-vulns": { type: "string", default: "none" },
      "no-fail-secrets": { type: "boolean" },
      "skip-vulns": { type: "boolean" },
      verify: { type: "boolean" },
      "min-confidence": { type: "string", default: "low" },
      "no-baseline": { type: "boolean" },
      apply: { type: "boolean" },
      staged: { type: "boolean" },
      remove: { type: "boolean" },
      force: { type: "boolean" },
      email: { type: "string" },
      plant: { type: "string" },
      file: { type: "string" },
      json: { type: "string" },
      markdown: { type: "string" },
      github: { type: "boolean" },
      comment: { type: "boolean" },
      quiet: { type: "boolean", short: "q" },
      help: { type: "boolean", short: "h" }
    }
  });
  const [cmd, target = "."] = positionals;
  if (values.help || !cmd) return log(HELP), 0;
  if (cmd === "honey") return honey(positionals[1], values, log, err);
  const minConfidence = values["min-confidence"].toLowerCase();
  if (!(minConfidence in CONFIDENCE_RANK)) return err("--min-confidence must be one of low, medium, high\n"), 2;
  if (cmd === "baseline") return baseline(target, log, err);
  if (cmd === "install-hook") return installHook(target, { remove: !!values.remove, force: !!values.force }, log, err);
  if (cmd === "contain") return contain(target, !!values.apply, values.json === "-", log, err, !!values.quiet);
  if (cmd !== "scan") return err(`Unknown command "${cmd}".

${HELP}`), 2;
  const failVulns = values["fail-on-vulns"].toUpperCase();
  if (failVulns !== "NONE" && !(failVulns in RANK2)) return err(`--fail-on-vulns must be one of low, moderate, high, critical, none
`), 2;
  const history = values.history === void 0 ? void 0 : Number(values.history);
  if (history !== void 0 && !(history >= 0)) return err("--history must be a number >= 0\n"), 2;
  const report = await scanTarget(target, { history, diff: values.diff, staged: !!values.staged, vulns: !values["skip-vulns"] && !values.staged, verify: !!values.verify, baseline: !values["no-baseline"] }, (stage) => !values.quiet && !values.staged && err(`tripwire: ${stage}\u2026
`));
  const verdict = evaluate(report, { secrets: !values["no-fail-secrets"], vulns: failVulns === "NONE" ? "none" : failVulns, minConfidence });
  const markdown = toMarkdown(report, verdict);
  if (values.json === "-") log(JSON.stringify(report, null, 2) + "\n");
  else log(toText(report, verdict, !!process.stdout.isTTY && !process.env.NO_COLOR));
  if (values.json && values.json !== "-") writeFileSync4(values.json, JSON.stringify(report, null, 2));
  if (values.markdown) writeFileSync4(values.markdown, markdown);
  if (values.github) for (const line of githubReport(report, verdict, markdown)) log(line + "\n");
  if (values.comment) {
    const note = await upsertPrComment(markdown).catch((e) => `could not comment (${e.message})`);
    err(`tripwire: ${note}
`);
  }
  return verdict.failed ? 1 : 0;
}
async function honey(sub, values, log, err) {
  if (sub === "create") {
    const r = await createHoney({ memo: `Tripwire honey secret${values.plant ? ` for ${values.plant}` : ""}`, email: values.email, repo: values.plant });
    log(`Created decoy AWS key ${r.accessKeyId} (stored in ${HONEY_FILE}).
`);
    if (values.plant) {
      const planted = await plantHoney(r.id, values.plant, values.file);
      log(`Planting PR: ${planted.prUrl}
`);
    } else log(`
Paste this somewhere an attacker would look (.env, CI config, backups):

${decoyFile(r)}
`);
    return 0;
  }
  if (sub === "check") {
    const { records } = await checkHoney();
    if (!records.length) return log("No honey secrets yet. Run `tripwire honey create` first.\n"), 0;
    let used = 0;
    for (const t of records.map(publicHoney)) {
      log(`${t.accessKeyPreview}  ${t.repo ?? "unplanted"}${t.file ? `:${t.file}` : ""}  ${t.hits.length ? `USED ${t.hits.length}x` : "quiet"}${t.checkError ? `  (check failed: ${t.checkError})` : ""}
`);
      for (const h of t.hits.slice(0, 5)) log(`    ${new Date(h.at).toISOString()}  ${h.ip ?? "?"}  ${[h.location, h.org].filter(Boolean).join(" \xB7 ")}  ${h.action ?? ""}
`);
      used += t.hits.length;
    }
    return used ? 1 : 0;
  }
  return err(`Usage: tripwire honey create|check
`), 2;
}
async function baseline(target, log, err) {
  if (isRemote(target)) return err("tripwire baseline needs a local checkout.\n"), 2;
  const report = await scanTarget(target, { vulns: false, baseline: false });
  const entries = report.findings.flatMap((f) => f.fingerprint ? [{ fingerprint: f.fingerprint, rule: f.rule, file: f.file }] : []);
  const path = writeBaseline(resolve5(target), entries);
  log(`Accepted ${entries.length} finding${entries.length === 1 ? "" : "s"} in ${path}.
Commit ${BASELINE_FILE}; those findings are still listed but no longer fail the check.
`);
  return 0;
}

// server/cli/action.ts
var input = (name, fallback = "") => (process.env[`INPUT_${name.toUpperCase()}`] ?? "").trim() || fallback;
function baseSha() {
  try {
    return JSON.parse(readFileSync7(process.env.GITHUB_EVENT_PATH ?? "", "utf8")).pull_request?.base?.sha;
  } catch {
    return void 0;
  }
}
var token = input("token");
if (token) process.env.GITHUB_TOKEN = token;
var argv = ["scan", input("path", "."), "--github", "--history", input("history", "300"), "--fail-on-vulns", input("fail-on-vulns", "none")];
var base = baseSha();
if (base) argv.push("--diff", base);
if (base && input("comment", "true") === "true") argv.push("--comment");
if (input("fail-on-secrets", "true") === "false") argv.push("--no-fail-secrets");
if (input("verify", "false") === "true") argv.push("--verify");
if (input("baseline", "true") === "false") argv.push("--no-baseline");
argv.push("--min-confidence", input("min-confidence", "low"));
main(argv).then(
  (code) => process.exit(code),
  (e) => {
    process.stdout.write(`::error title=Tripwire::${e.message}
`);
    process.exit(2);
  }
);
