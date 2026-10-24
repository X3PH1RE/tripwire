import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { HoneyHit, HoneyToken } from "../../shared/types";
import { gh, hasToken, openMultiFilePr, repoInfo } from "../github";

const CANARY = process.env.CANARYTOKENS_URL ?? "https://canarytokens.org";
const API = `${CANARY}/d3aece8093b71007b5ccfedad91ebb11`;
export const HONEY_FILE = process.env.TRIPWIRE_HONEY_FILE ?? join(process.env.TRIPWIRE_HOME ?? join(homedir(), ".tripwire"), "honey.json");
export const HONEY_BRANCH_PREFIX = "tripwire/honey-";

/** Stored locally only (it holds the decoy secret and the Canarytokens auth token). */
export interface HoneyRecord {
  id: string;
  token: string;
  auth: string;
  accessKeyId: string;
  secretAccessKey: string;
  region: string;
  memo: string;
  createdAt: number;
  repo?: string;
  file?: string;
  prUrl?: string;
  lastCheck?: number;
  checkError?: string;
  hits: HoneyHit[];
}

export function loadHoney(): HoneyRecord[] {
  try {
    return existsSync(HONEY_FILE) ? (JSON.parse(readFileSync(HONEY_FILE, "utf8")) as HoneyRecord[]) : [];
  } catch {
    return [];
  }
}

export function saveHoney(records: HoneyRecord[]): void {
  mkdirSync(dirname(HONEY_FILE), { recursive: true });
  writeFileSync(HONEY_FILE, JSON.stringify(records, null, 2), { mode: 0o600 });
}

export const honeyKeyIds = () => new Set(loadHoney().flatMap((r) => [r.accessKeyId, r.secretAccessKey]));

const mask = (s: string) => `${s.slice(0, 8)}••••${s.slice(-4)}`;

export function publicHoney(r: HoneyRecord): HoneyToken {
  return {
    id: r.id,
    accessKeyPreview: mask(r.accessKeyId),
    memo: r.memo,
    createdAt: r.createdAt,
    repo: r.prUrl ? r.repo : undefined,
    file: r.prUrl ? r.file : undefined,
    prUrl: r.prUrl,
    snippet: r.prUrl ? undefined : decoyFile(r),
    historyUrl: `${CANARY}/history?token=${r.token}&auth=${r.auth}`,
    lastCheck: r.lastCheck,
    checkError: r.checkError,
    hits: r.hits,
  };
}

/** Creates a real AWS key on Canarytokens. It has no permissions; any use of it is reported. */
export async function createHoney(opts: { memo: string; email?: string; webhook?: string; repo?: string }): Promise<HoneyRecord> {
  const email = opts.email ?? process.env.HONEY_ALERT_EMAIL;
  const webhook = opts.webhook ?? process.env.HONEY_ALERT_WEBHOOK;
  if (!email && !webhook) throw new Error("Set HONEY_ALERT_EMAIL (or HONEY_ALERT_WEBHOOK) so Canarytokens knows where to send alerts.");
  const res = await fetch(`${API}/generate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token_type: "aws_keys", memo: opts.memo, email: email ?? "", webhook_url: webhook ?? "" }),
    signal: AbortSignal.timeout(20_000),
  });
  const data = (await res.json().catch(() => ({}))) as any;
  if (!res.ok || data.error || !data.aws_access_key_id) throw new Error(`Canarytokens: ${data.error_message ?? data.error ?? res.status}`);
  const record: HoneyRecord = {
    id: randomUUID().slice(0, 8),
    token: data.token,
    auth: data.auth_token,
    accessKeyId: data.aws_access_key_id,
    secretAccessKey: data.aws_secret_access_key,
    region: data.region ?? "us-east-1",
    memo: opts.memo,
    createdAt: Date.now(),
    repo: opts.repo,
    hits: [],
  };
  saveHoney([...loadHoney(), record]);
  return record;
}

const first = (v: unknown) => (Array.isArray(v) ? v[0] : v) as string | undefined;

export function parseHits(raw: any[]): HoneyHit[] {
  return raw
    .map((h) => {
      const geo = h.geo_info && typeof h.geo_info === "object" ? h.geo_info : {};
      const log = h.additional_info?.aws_key_log_data ?? h.additional_info?.["AWS Key Log Data"] ?? {};
      return {
        at: Math.round(Number(h.time_of_hit) * 1000),
        ip: h.src_ip || undefined,
        location: [geo.city, geo.country].filter(Boolean).join(", ") || undefined,
        org: geo.org || undefined,
        userAgent: h.useragent ?? h.user_agent ?? undefined,
        action: first(log.eventName) ?? first(log.service_used) ?? undefined,
      } satisfies HoneyHit;
    })
    .sort((a, b) => b.at - a.at);
}

/** Pulls the alert history for every decoy. Returns the hits that are new since the last check. */
export async function checkHoney(): Promise<{ records: HoneyRecord[]; fresh: { record: HoneyRecord; hit: HoneyHit }[] }> {
  const records = loadHoney();
  const fresh: { record: HoneyRecord; hit: HoneyHit }[] = [];
  for (const r of records) {
    try {
      const res = await fetch(`${API}/history?token=${encodeURIComponent(r.token)}&auth=${encodeURIComponent(r.auth)}`, { signal: AbortSignal.timeout(15_000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = (await res.json()) as any;
      const hits = parseHits(data?.history?.hits ?? []);
      const known = new Set(r.hits.map((h) => h.at));
      for (const hit of hits) if (!known.has(hit.at)) fresh.push({ record: r, hit });
      r.hits = hits;
      r.checkError = undefined;
    } catch (err) {
      r.checkError = (err as Error).message;
    }
    r.lastCheck = Date.now();
  }
  // Merge so a record created while we were polling is not lost.
  const latest = loadHoney();
  saveHoney(latest.map((l) => records.find((r) => r.id === l.id) ?? l));
  return { records, fresh };
}

export function decoyFile(r: HoneyRecord): string {
  return ["# Backup job credentials (read-only bucket). Rotated quarterly.", `AWS_ACCESS_KEY_ID=${r.accessKeyId}`, `AWS_SECRET_ACCESS_KEY=${r.secretAccessKey}`, `AWS_DEFAULT_REGION=${r.region}`, ""].join("\n");
}

/** Opens a PR that plants the decoy in the repo. It stays open for the owner to merge. */
export async function plantHoney(id: string, repo: string, file = "deploy/backup.env"): Promise<HoneyRecord> {
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
      "Merge it to arm the tripwire. Do not mention it elsewhere in the repo.",
    ].join("\n"),
  }).catch((err: Error) => {
    if (/Secret detected|push protection|rule violations/i.test(err.message))
      throw new Error("GitHub push protection blocked the decoy because it is a real AWS-format key (the same check would block a real leak). The decoy is saved; place it where GitHub doesn't scan: CI/CD variables, a server .env, an S3 backup, an internal wiki.");
    throw err;
  });
  Object.assign(r, { repo, file, prUrl: pr.url });
  saveHoney(records);
  return r;
}
