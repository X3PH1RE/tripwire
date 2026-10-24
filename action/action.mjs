#!/usr/bin/env node

// server/cli/action.ts
import { readFileSync as readFileSync5 } from "node:fs";

// server/cli/main.ts
import { writeFileSync as writeFileSync2 } from "node:fs";
import { parseArgs } from "node:util";

// server/real/core.ts
import { existsSync as existsSync4, rmSync as rmSync2 } from "node:fs";
import { resolve as resolve2 } from "node:path";

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
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";

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
var HONEY_FILE = process.env.TRIPWIRE_HONEY_FILE ?? join(process.env.TRIPWIRE_HOME ?? join(homedir(), ".tripwire"), "honey.json");
var HONEY_BRANCH_PREFIX = "tripwire/honey-";
function loadHoney() {
  try {
    return existsSync(HONEY_FILE) ? JSON.parse(readFileSync(HONEY_FILE, "utf8")) : [];
  } catch {
    return [];
  }
}
function saveHoney(records) {
  mkdirSync(dirname(HONEY_FILE), { recursive: true });
  writeFileSync(HONEY_FILE, JSON.stringify(records, null, 2), { mode: 384 });
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
  const record = {
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
  saveHoney([...loadHoney(), record]);
  return record;
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
import { readFileSync as readFileSync2 } from "node:fs";
import { dirname as dirname2, join as join2 } from "node:path";
var json = (p) => {
  try {
    return JSON.parse(readFileSync2(p, "utf8"));
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
  const at = (f) => join2(dir, f);
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
      for (const l of readFileSync2(at(f), "utf8").split(/\r?\n/)) {
        const m = l.match(/^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)/);
        if (m) deps.push({ ecosystem: "PyPI", name: m[1], version: m[2], file: f, direct: true });
      }
    } else if (name === "go.mod") {
      let block = false;
      for (const l of readFileSync2(at(f), "utf8").split(/\r?\n/)) {
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
      const text = readFileSync2(at(f), "utf8");
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
import { createHmac, createHash } from "node:crypto";
var TIMEOUT = Number(process.env.VERIFY_TIMEOUT_MS ?? 8e3);
var CONCURRENCY = 6;
var get = async (url, headers, method = "GET", body) => fetch(url, { method, headers, body, signal: AbortSignal.timeout(TIMEOUT) });
var live = (identity, access = [], note) => ({ status: "live", identity, access, note });
var revoked = (note) => ({ status: "revoked", note });
var hmac = (key, data) => createHmac("sha256", key).update(data, "utf8").digest();
var sha256 = (s) => createHash("sha256").update(s, "utf8").digest("hex");
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
async function verifyFindings(findings, values, honeyIds = /* @__PURE__ */ new Set()) {
  const secrets = findings.filter((f) => f.rule === "aws-secret-key");
  const pairFor = (f) => {
    const near = secrets.filter((s) => s.file === f.file).sort((a, b) => Math.abs(a.line - f.line) - Math.abs(b.line - f.line))[0];
    return near ?? (secrets.length === 1 ? secrets[0] : void 0);
  };
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
import { existsSync as existsSync3, mkdtempSync, readdirSync, readFileSync as readFileSync3, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join as join3, relative, resolve } from "node:path";
import { promisify } from "node:util";

// server/real/rules.ts
function entropy(s) {
  const counts = /* @__PURE__ */ new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) h -= c / s.length * Math.log2(c / s.length);
  return h;
}
var RULES = [
  { id: "private-key", label: "Private key", provider: "ssh", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/ },
  { id: "aws-access-key", label: "AWS access key ID", provider: "aws", re: /\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b/ },
  { id: "aws-secret-key", label: "AWS secret access key", provider: "aws", re: /aws_?secret_?(?:access_?)?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})\b/i },
  { id: "github-pat", label: "GitHub token", provider: "github", re: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b/ },
  { id: "github-fine-grained", label: "GitHub fine-grained token", provider: "github", re: /\b(github_pat_[A-Za-z0-9_]{60,255})\b/ },
  { id: "gitlab-pat", label: "GitLab token", provider: "gitlab", re: /\b(glpat-[A-Za-z0-9_-]{20,})\b/ },
  { id: "stripe-live", label: "Stripe live key", provider: "stripe", re: /\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b/ },
  { id: "stripe-test", label: "Stripe test key", provider: "stripe-test", re: /\b((?:sk|rk)_test_[A-Za-z0-9]{20,})\b/ },
  { id: "slack-token", label: "Slack token", provider: "slack", re: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/ },
  { id: "slack-webhook", label: "Slack webhook", provider: "slack", re: /(https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9_]+)/ },
  { id: "google-api-key", label: "Google API key", provider: "gcp", re: /\b(AIza[0-9A-Za-z_-]{35})\b/ },
  { id: "anthropic-key", label: "Anthropic API key", provider: "anthropic", re: /\b(sk-ant-[A-Za-z0-9_-]{32,})\b/ },
  { id: "openai-key", label: "OpenAI API key", provider: "openai", re: /\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})\b/ },
  { id: "sendgrid-key", label: "SendGrid API key", provider: "sendgrid", re: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/ },
  { id: "twilio-key", label: "Twilio API key", provider: "twilio", re: /\b(SK[0-9a-f]{32})\b/ },
  { id: "npm-token", label: "npm access token", provider: "npm", re: /\b(npm_[A-Za-z0-9]{36})\b/ },
  { id: "db-url", label: "Database URL with password", provider: "database", re: /\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?):\/\/[^\s:/@"']+:([^\s@"'/]+)@[^\s"']+)/ },
  { id: "tripwire-demo", label: "Tripwire demo secret", provider: "demo", re: /\b(tw_fake_[a-z]+_[a-z0-9]{16,})\b/ }
];
var ASSIGN = /\b([A-Za-z][A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIALS?|AUTH|URL|URI|DSN))["']?\s*[:=]\s*["']?([^\s"'`,;]+)/i;
var PLACEHOLDER = /example|sample|dummy|placeholder|changeme|change_me|your[_-]|xxxx|\*\*\*|<|>|\$\{|\{\{|process\.env|os\.environ|getenv|secrets\.|redacted|todo|replace|insert|test123|password123|^true$|^false$|^null$/i;
var GENERIC = { id: "generic-assignment", label: "High-entropy secret", provider: "unknown", re: /$^/ };
function isPlaceholder(value) {
  return PLACEHOLDER.test(value) || /^(.)\1+$/.test(value);
}
function matchLine(text) {
  if (text.length > 2e3) return [];
  const variable = text.match(ASSIGN)?.[1];
  const out = [];
  for (const rule of RULES) {
    const m = text.match(rule.re);
    if (!m) continue;
    const value = rule.id === "db-url" ? m[2] : m[1] ?? m[0];
    if (rule.id !== "private-key" && isPlaceholder(value)) continue;
    if (rule.id === "db-url" && value.length < 6) continue;
    out.push({ rule, value: rule.id === "db-url" ? m[1] : value, variable });
  }
  if (out.length) return out.filter((m) => !out.some((o) => o !== m && o.value.length > m.value.length && o.value.includes(m.value)));
  const a = text.match(ASSIGN);
  if (a) {
    const value = a[2];
    if (value.length >= 16 && value.length <= 200 && !value.includes("://") && !/[\\()[\]{}^]/.test(value) && !isPlaceholder(value) && !/^[a-z]+(?:[._-][a-z]+)*$/i.test(value) && entropy(value) >= 3.8)
      out.push({ rule: GENERIC, value, variable: a[1] });
  }
  return out;
}
function mask2(value, rule) {
  if (rule.id === "private-key") return "-----BEGIN \u2026 PRIVATE KEY-----";
  if (rule.id === "db-url") return value.replace(/:\/\/([^:/@\s]+):[^@\s]+@/, "://$1:\u2022\u2022\u2022\u2022@").slice(0, 48);
  if (rule.id === "tripwire-demo") return value.length > 22 ? `${value.slice(0, 22)}\u2026` : value;
  const keep = Math.min(6, Math.floor(value.length / 4));
  return `${value.slice(0, keep)}${"\u2022".repeat(8)} (${value.length} chars)`;
}

// server/real/scan.ts
var run = promisify(execFile);
var SKIP_DIRS = /* @__PURE__ */ new Set([".git", "node_modules", "vendor", "dist", "build", ".next", "out", "coverage", "__pycache__", ".venv", "venv", "target"]);
var SKIP_FILE = /(?:^|\/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|Gemfile\.lock|poetry\.lock|Cargo\.lock|go\.sum)$|\.(?:min\.js|map|png|jpe?g|gif|webp|ico|svg|pdf|zip|gz|woff2?|ttf|eot|mp4|mp3|lock)$/i;
var MANIFESTS = /* @__PURE__ */ new Set(["package.json", "Dockerfile", "requirements.txt", "pyproject.toml", "go.mod", "composer.json", "Gemfile", "pom.xml", "build.gradle", "Cargo.toml", "Procfile"]);
var CI_SERVICE = "CI (GitHub Actions)";
var HISTORY_COMMITS = Number(process.env.SCAN_HISTORY_COMMITS ?? 300);
function walk(dir, root = dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const full = join3(dir, name);
    const st = statSync(full, { throwIfNoEntry: false });
    if (!st) continue;
    if (st.isDirectory()) walk(full, root, out);
    else if (st.isFile() && st.size < 1e6) out.push(relative(root, full).split("\\").join("/"));
  }
  return out;
}
async function listFiles(dir) {
  if (!existsSync3(join3(dir, ".git"))) return walk(dir);
  try {
    const { stdout } = await run("git", ["-C", dir, "ls-files", "-z", "-co", "--exclude-standard"], { maxBuffer: 64 * 1024 * 1024 });
    return stdout.split("\0").filter((f) => f && !f.split("/").some((part) => SKIP_DIRS.has(part))).filter((f) => {
      const st = statSync(join3(dir, f), { throwIfNoEntry: false });
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
  if (/^[\w.-]+\/[\w.-]+$/.test(t) && !existsSync3(t)) return `https://github.com/${t}.git`;
  return t;
}
async function cloneRepo(url, depth = HISTORY_COMMITS) {
  if (!/^(https?:\/\/|git@)/.test(url)) throw new Error("Enter a Git URL or owner/name");
  const tmp = mkdtempSync(join3(tmpdir(), "tripwire-real-"));
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
    const retry = mkdtempSync(join3(tmpdir(), "tripwire-real-"));
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
function makeFinding(file, line, text, service) {
  if (IGNORE_MARK.test(text)) return [];
  return matchLine(text).map((m) => {
    const provider = m.rule.id === "tripwire-demo" ? m.value.split("_")[2] ?? "demo" : m.rule.provider;
    return {
      value: m.value,
      finding: { id: "", rule: m.rule.id, ruleLabel: m.rule.label, provider, variable: m.variable?.toUpperCase(), file, line, inHead: true, preview: mask2(m.value, m.rule), service, nodeId: "" }
    };
  });
}
function scanHead(dir, files, dirs, repoName) {
  const out = [];
  for (const file of files) {
    if (SKIP_FILE.test(file)) continue;
    const buf = readFileSync3(join3(dir, file));
    if (buf.includes(0)) continue;
    const service = serviceFor(file, dirs, repoName);
    buf.toString("utf8").split(/\r?\n/).forEach((text, i) => out.push(...makeFinding(file, i + 1, text, service)));
  }
  return out;
}
function parsePatch(patch, dirs, repoName, inHead) {
  const raws = [];
  let commit = "";
  let file = "";
  let line = 0;
  let commits = 0;
  for (const text of patch.split("\n")) {
    if (text.startsWith("__TW__")) {
      commit = text.slice(6);
      commits++;
    } else if (text.startsWith("+++ ")) file = text.startsWith("+++ b/") ? text.slice(6) : "";
    else if (text.startsWith("@@")) line = Number(text.match(/\+(\d+)/)?.[1] ?? 0);
    else if (text.startsWith("+") && file && !SKIP_FILE.test(file)) {
      for (const r of makeFinding(file, line, text.slice(1), serviceFor(file, dirs, repoName))) raws.push({ ...r, finding: { ...r.finding, commit: commit || void 0, inHead } });
      line++;
    }
  }
  return { raws, commits };
}
var GIT_BUF = { maxBuffer: 256 * 1024 * 1024, timeout: 6e4 };
async function scanHistory(dir, dirs, repoName, limit = HISTORY_COMMITS) {
  if (limit <= 0 || !existsSync3(join3(dir, ".git"))) return { raws: [], commits: 0 };
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
    readFileSync3(join3(dir, file), "utf8").split(/\r?\n/).forEach((text, i) => {
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
  const p = join3(dir, ".tripwireignore");
  return ignoreMatcher(existsSync3(p) ? readFileSync3(p, "utf8") : "");
}
function repoNameOf(target, dir) {
  return githubSlug(target)?.split("/")[1] ?? basename(resolve(dir));
}
async function currentBranch(dir) {
  if (!existsSync3(join3(dir, ".git"))) return void 0;
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
  let dir = remote ? "" : resolve2(target);
  onStage?.("cloning", {});
  try {
    if (remote) dir = await cloneRepo(target, history);
    else if (!existsSync4(dir)) throw new Error(`No such directory: ${target}`);
    const ignored = loadIgnore(dir);
    const files = (await listFiles(dir)).filter((f) => !ignored(f));
    const dirs = manifestDirs(files);
    const name = repoNameOf(target, dir);
    const branch = await currentBranch(dir).catch(() => void 0);
    onStage?.("secrets", { branch, filesScanned: files.length });
    const head = scanHead(dir, files, dirs, name);
    onStage?.("history", {});
    const past = await scanHistory(dir, dirs, name, history);
    let added;
    if (opts.diff) {
      try {
        added = new Set((await scanDiff(dir, dirs, name, opts.diff)).filter((r) => !ignored(r.finding.file)).map((r) => r.value));
      } catch (err) {
        warnings.push(`Could not diff against ${opts.diff} (${err.message.split("\n")[0]}); treating every secret in the code as blocking.`);
      }
    }
    const { findings, samples, values } = mergeFindings(head, past.raws.filter((r) => !ignored(r.finding.file)), added);
    if (opts.verify) {
      onStage?.("verify", { commitsScanned: past.commits, findings });
      await verifyFindings(findings, values, honeyKeyIds()).catch((err) => warnings.push(`Key verification failed: ${err.message}`));
    }
    const graph = buildGraph(name, findings, ciSecretRefs(dir, files), samples);
    onStage?.("vulns", { commitsScanned: past.commits, findings, ...graph });
    let vulns = [];
    if (opts.vulns !== false) vulns = await findVulns(parseDeps(dir, files)).catch((err) => (warnings.push(`Vulnerability lookup failed: ${err.message}`), []));
    return { target, repo: githubSlug(target), name, branch, filesScanned: files.length, commitsScanned: past.commits, findings, ...graph, vulns, diffBase: added ? opts.diff : void 0, warnings, durationMs: Date.now() - started };
  } finally {
    if (remote && dir) rmSync2(dir, { recursive: true, force: true });
  }
}

// server/cli/github.ts
import { appendFileSync, readFileSync as readFileSync4 } from "node:fs";

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

// server/cli/report.ts
var MARKER = "<!-- tripwire-report -->";
var RANK2 = { UNKNOWN: 0, LOW: 1, MODERATE: 2, HIGH: 3, CRITICAL: 4 };
function evaluate(r, policy) {
  const active = r.findings.filter((f) => f.verify?.status !== "revoked" && f.verify?.status !== "honey");
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
var status = (f) => [f.isNew ? "new" : f.inHead ? "in code" : "history", f.verify ? VSTAT[f.verify.status] : ""].filter(Boolean).join(" \xB7 ");
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
  const tone = (f) => f.isNew ? red("NEW ") : f.inHead ? red("CODE") : yellow("HIST");
  const vtag = (f) => !f.verify ? "" : f.verify.status === "live" ? ` ${red(bold("LIVE"))}` : f.verify.status === "revoked" ? ` ${green("revoked")}` : f.verify.status === "honey" ? ` ${cyan("honey")}` : ` ${dim("unverified")}`;
  const sev = (s) => (RANK2[s] >= 3 ? red : RANK2[s] === 2 ? yellow : dim)(s.padEnd(8));
  const out = ["", `${bold("Tripwire")}  ${r.repo ?? r.name}${r.branch ? dim(` (${r.branch})`) : ""}  ${dim(`${r.filesScanned} files \xB7 ${r.commitsScanned} commits \xB7 ${(r.durationMs / 1e3).toFixed(1)}s`)}`, ""];
  out.push(bold(`Secrets (${r.findings.length})`));
  if (!r.findings.length) out.push(dim("  none found"));
  for (const f of sorted(r.findings)) {
    out.push(`  ${tone(f)}  ${(f.variable ?? f.ruleLabel).padEnd(22)} ${cyan(`${f.file}:${f.line}`)}${f.inHead ? "" : dim(` @${f.commit}`)}  ${dim(f.ruleLabel)}${vtag(f)}`);
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
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, markdown);
  if (process.env.GITHUB_OUTPUT)
    appendFileSync(process.env.GITHUB_OUTPUT, `secrets=${r.findings.length}
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
    return JSON.parse(readFileSync4(path, "utf8")).pull_request?.number;
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
       tripwire honey check      (exit 1 if any decoy was used)

Finds secrets in the code and git history, maps what each one unlocks,
and checks dependencies against OSV.dev. Exits 1 when something blocks.

Options:
  --diff <base>           Only secrets added since <base> block (for pull requests)
  --history <n>           Commits of history to scan (default 300, 0 = none)
  --fail-on-vulns <sev>   Also fail on vulnerable deps: low|moderate|high|critical (default: none)
  --no-fail-secrets       Report secrets without failing
  --skip-vulns            Skip the dependency check
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
  if (cmd !== "scan") return err(`Unknown command "${cmd}".

${HELP}`), 2;
  const failVulns = values["fail-on-vulns"].toUpperCase();
  if (failVulns !== "NONE" && !(failVulns in RANK2)) return err(`--fail-on-vulns must be one of low, moderate, high, critical, none
`), 2;
  const history = values.history === void 0 ? void 0 : Number(values.history);
  if (history !== void 0 && !(history >= 0)) return err("--history must be a number >= 0\n"), 2;
  const report = await scanTarget(target, { history, diff: values.diff, vulns: !values["skip-vulns"], verify: !!values.verify }, (stage) => !values.quiet && err(`tripwire: ${stage}\u2026
`));
  const verdict = evaluate(report, { secrets: !values["no-fail-secrets"], vulns: failVulns === "NONE" ? "none" : failVulns });
  const markdown = toMarkdown(report, verdict);
  if (values.json === "-") log(JSON.stringify(report, null, 2) + "\n");
  else log(toText(report, verdict, !!process.stdout.isTTY && !process.env.NO_COLOR));
  if (values.json && values.json !== "-") writeFileSync2(values.json, JSON.stringify(report, null, 2));
  if (values.markdown) writeFileSync2(values.markdown, markdown);
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

// server/cli/action.ts
var input = (name, fallback = "") => (process.env[`INPUT_${name.toUpperCase()}`] ?? "").trim() || fallback;
function baseSha() {
  try {
    return JSON.parse(readFileSync5(process.env.GITHUB_EVENT_PATH ?? "", "utf8")).pull_request?.base?.sha;
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
main(argv).then(
  (code) => process.exit(code),
  (e) => {
    process.stdout.write(`::error title=Tripwire::${e.message}
`);
    process.exit(2);
  }
);
