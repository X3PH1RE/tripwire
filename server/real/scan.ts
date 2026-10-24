import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, relative, resolve } from "node:path";
import { promisify } from "node:util";
import type { Finding } from "../../shared/types";
import type { CiSecretRef } from "./graph";
import { mask, matchLine } from "./rules";

const run = promisify(execFile);

const SKIP_DIRS = new Set([".git", "node_modules", "vendor", "dist", "build", ".next", "out", "coverage", "__pycache__", ".venv", "venv", "target"]);
const SKIP_FILE = /(?:^|\/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|Gemfile\.lock|poetry\.lock|Cargo\.lock|go\.sum)$|\.(?:min\.js|map|png|jpe?g|gif|webp|ico|svg|pdf|zip|gz|woff2?|ttf|eot|mp4|mp3|lock)$/i;
const MANIFESTS = new Set(["package.json", "Dockerfile", "requirements.txt", "pyproject.toml", "go.mod", "composer.json", "Gemfile", "pom.xml", "build.gradle", "Cargo.toml", "Procfile"]);
export const CI_SERVICE = "CI (GitHub Actions)";
const HISTORY_COMMITS = Number(process.env.SCAN_HISTORY_COMMITS ?? 300);

export function walk(dir: string, root = dir, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const full = join(dir, name);
    const st = statSync(full, { throwIfNoEntry: false });
    if (!st) continue;
    if (st.isDirectory()) walk(full, root, out);
    else if (st.isFile() && st.size < 1_000_000) out.push(relative(root, full).split("\\").join("/"));
  }
  return out;
}

/** Files git would track (tracked + untracked, minus .gitignore), falling back to a plain walk outside git. */
export async function listFiles(dir: string): Promise<string[]> {
  if (!existsSync(join(dir, ".git"))) return walk(dir);
  try {
    const { stdout } = await run("git", ["-C", dir, "ls-files", "-z", "-co", "--exclude-standard"], { maxBuffer: 64 * 1024 * 1024 });
    return stdout
      .split("\0")
      .filter((f) => f && !f.split("/").some((part) => SKIP_DIRS.has(part)))
      .filter((f) => {
        const st = statSync(join(dir, f), { throwIfNoEntry: false });
        return !!st?.isFile() && st.size < 1_000_000;
      });
  } catch {
    return walk(dir);
  }
}

export function githubSlug(target: string): string | undefined {
  const m = target.match(/github\.com[/:]([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/);
  return m ? `${m[1]}/${m[2]}` : undefined;
}

export function normalizeTarget(input: string): string {
  const t = input.trim();
  if (/^[\w.-]+\/[\w.-]+$/.test(t) && !existsSync(t)) return `https://github.com/${t}.git`;
  return t;
}

/** Clones a repo into a temp dir (falling back to GITHUB_TOKEN for private GitHub repos). */
export async function cloneRepo(url: string, depth = HISTORY_COMMITS): Promise<string> {
  if (!/^(https?:\/\/|git@)/.test(url)) throw new Error("Enter a Git URL or owner/name");
  const tmp = mkdtempSync(join(tmpdir(), "tripwire-real-"));
  const args = ["clone", "--quiet", "--single-branch", "--no-tags", "--depth", String(Math.max(1, depth)), url, tmp];
  const env = { ...process.env, GIT_TERMINAL_PROMPT: "0" };
  try {
    await run("git", args, { timeout: 90_000, env });
  } catch (err) {
    const token = process.env.GITHUB_TOKEN;
    if (!token || !url.includes("github.com")) {
      rmSync(tmp, { recursive: true, force: true });
      throw new Error(`Clone failed: ${(err as Error).message.split("\n")[0]}`);
    }
    rmSync(tmp, { recursive: true, force: true });
    const retry = mkdtempSync(join(tmpdir(), "tripwire-real-"));
    const auth = Buffer.from(`x-access-token:${token}`).toString("base64");
    try {
      await run("git", ["-c", `http.extraHeader=Authorization: Basic ${auth}`, ...args.slice(0, -1), retry], { timeout: 90_000, env });
    } catch {
      rmSync(retry, { recursive: true, force: true });
      throw new Error("Clone failed: repository not found or not accessible with this token");
    }
    return retry;
  }
  return tmp;
}

export function manifestDirs(files: string[]): Set<string> {
  const dirs = new Set<string>();
  for (const f of files) {
    const parts = f.split("/");
    if (parts.length <= 3 && MANIFESTS.has(parts[parts.length - 1])) dirs.add(parts.slice(0, -1).join("/"));
  }
  return dirs;
}

export function serviceFor(file: string, dirs: Set<string>, repoName: string): string {
  if (file.startsWith(".github/")) return CI_SERVICE;
  const parts = file.split("/");
  for (const depth of [2, 1]) {
    if (parts.length <= depth) continue;
    const dir = parts.slice(0, depth).join("/");
    if (dirs.has(dir)) return dir;
  }
  return repoName;
}

export interface Raw {
  finding: Finding;
  value: string;
}

const IGNORE_MARK = /tripwire:ignore|gitleaks:allow/;

function makeFinding(file: string, line: number, text: string, service: string): Raw[] {
  if (IGNORE_MARK.test(text)) return [];
  return matchLine(text).map((m) => {
    const provider = m.rule.id === "tripwire-demo" ? (m.value.split("_")[2] ?? "demo") : m.rule.provider;
    return {
      value: m.value,
      finding: { id: "", rule: m.rule.id, ruleLabel: m.rule.label, provider, variable: m.variable?.toUpperCase(), file, line, inHead: true, preview: mask(m.value, m.rule), service, nodeId: "" },
    };
  });
}

export function scanHead(dir: string, files: string[], dirs: Set<string>, repoName: string): Raw[] {
  const out: Raw[] = [];
  for (const file of files) {
    if (SKIP_FILE.test(file)) continue;
    const buf = readFileSync(join(dir, file));
    if (buf.includes(0)) continue;
    const service = serviceFor(file, dirs, repoName);
    buf.toString("utf8").split(/\r?\n/).forEach((text, i) => out.push(...makeFinding(file, i + 1, text, service)));
  }
  return out;
}

function parsePatch(patch: string, dirs: Set<string>, repoName: string, inHead: boolean): { raws: Raw[]; commits: number } {
  const raws: Raw[] = [];
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
      for (const r of makeFinding(file, line, text.slice(1), serviceFor(file, dirs, repoName))) raws.push({ ...r, finding: { ...r.finding, commit: commit || undefined, inHead } });
      line++;
    }
  }
  return { raws, commits };
}

const GIT_BUF = { maxBuffer: 256 * 1024 * 1024, timeout: 60_000 };

/** Scans lines added in recent commits so secrets that were deleted (but never rotated) still show up. */
export async function scanHistory(dir: string, dirs: Set<string>, repoName: string, limit = HISTORY_COMMITS): Promise<{ raws: Raw[]; commits: number }> {
  if (limit <= 0 || !existsSync(join(dir, ".git"))) return { raws: [], commits: 0 };
  const { stdout } = await run("git", ["-C", dir, "log", "-p", "-U0", "--no-merges", "--no-color", "--no-ext-diff", "--format=__TW__%h", "-n", String(limit)], GIT_BUF);
  return parsePatch(stdout, dirs, repoName, false);
}

/** Lines added between `base` and HEAD, i.e. what a pull request introduces. Fetches `base` if a shallow checkout lacks it. */
export async function scanDiff(dir: string, dirs: Set<string>, repoName: string, base: string): Promise<Raw[]> {
  const diff = () => run("git", ["-C", dir, "diff", "-U0", "--no-color", "--no-ext-diff", base, "HEAD"], GIT_BUF);
  let out: { stdout: string };
  try {
    out = await diff();
  } catch {
    await run("git", ["-C", dir, "fetch", "--quiet", "--no-tags", "--depth=1", "origin", base], { timeout: 60_000 });
    out = await diff();
  }
  return parsePatch(out.stdout, dirs, repoName, true).raws;
}

/** Merges HEAD and history hits: one finding per distinct secret value; history-only ones are flagged. */
export function mergeFindings(head: Raw[], history: Raw[], added?: Set<string>): { findings: Finding[]; samples: Map<string, string>; values: Map<string, string> } {
  const byValue = new Map<string, Raw>();
  for (const r of head) if (!byValue.has(r.value)) byValue.set(r.value, r);
  for (const r of history) {
    const existing = byValue.get(r.value);
    if (existing) existing.finding.commit ??= r.finding.commit;
    else byValue.set(r.value, r);
  }
  const samples = new Map<string, string>();
  const values = new Map<string, string>();
  const findings = [...byValue.values()].map((r, i) => {
    r.finding.id = `f-${i}`;
    if (added) r.finding.isNew = added.has(r.value);
    if (r.finding.rule === "db-url") samples.set(r.finding.id, r.value);
    values.set(r.finding.id, r.value);
    return r.finding;
  });
  return { findings, samples, values };
}

export function ciSecretRefs(dir: string, files: string[]): CiSecretRef[] {
  const refs = new Map<string, CiSecretRef>();
  for (const file of files.filter((f) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(f))) {
    readFileSync(join(dir, file), "utf8")
      .split(/\r?\n/)
      .forEach((text, i) => {
        for (const m of text.matchAll(/secrets\.([A-Za-z_][A-Za-z0-9_]*)/g)) {
          if (m[1] === "GITHUB_TOKEN" || refs.has(m[1])) continue;
          refs.set(m[1], { name: m[1], file, line: i + 1 });
        }
      });
  }
  return [...refs.values()];
}

/** `.tripwireignore`: one glob per line (`docs/**`, `*.test.ts`, `fixtures/`), `#` for comments. */
export function ignoreMatcher(text: string): (file: string) => boolean {
  const res = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"))
    .map((glob) => {
      const dirOnly = glob.endsWith("/");
      const g = glob.replace(/^\/|\/$/g, "");
      const body = g.split("**").map((part) => part.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]")).join(".*");
      const anchored = g.includes("/") ? `^${body}` : `(?:^|/)${body}`;
      return new RegExp(`${anchored}${dirOnly ? "/" : "(?:$|/)"}`);
    });
  return (file) => res.some((re) => re.test(file));
}

export function loadIgnore(dir: string): (file: string) => boolean {
  const p = join(dir, ".tripwireignore");
  return ignoreMatcher(existsSync(p) ? readFileSync(p, "utf8") : "");
}

export function repoNameOf(target: string, dir: string): string {
  return githubSlug(target)?.split("/")[1] ?? basename(resolve(dir));
}

export async function currentBranch(dir: string): Promise<string | undefined> {
  if (!existsSync(join(dir, ".git"))) return undefined;
  return (await run("git", ["-C", dir, "rev-parse", "--abbrev-ref", "HEAD"])).stdout.trim();
}

