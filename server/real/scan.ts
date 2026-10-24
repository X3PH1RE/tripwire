import { execFile } from "node:child_process";
import { existsSync, lstatSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, relative, resolve } from "node:path";
import { promisify } from "node:util";
import type { Finding } from "../../shared/types";
import type { CiSecretRef } from "./graph";
import { mask, matchContent } from "./rules";

const run = promisify(execFile);

/** Skipped only when walking a plain folder (no git): dependency and cache trees nobody commits. Inside a git repo every tracked file is scanned, so a directory name is never a hiding place. */
const WALK_SKIP = new Set([".git", "node_modules", "__pycache__", ".venv", "venv"]);
const MAX_FILE_BYTES = Number(process.env.MAX_FILE_BYTES ?? 20_000_000);
/** Binary and media formats, plus Tripwire's own baseline. Minified bundles, source maps and lockfiles are scanned: secrets end up in all of them. */
const SKIP_FILE = /(?:^|\/)\.tripwire-baseline\.json$|\.(?:png|jpe?g|gif|webp|ico|pdf|zip|gz|woff2?|ttf|eot|mp4|mp3)$/i;
const MANIFESTS = new Set(["package.json", "Dockerfile", "requirements.txt", "pyproject.toml", "go.mod", "composer.json", "Gemfile", "pom.xml", "build.gradle", "Cargo.toml", "Procfile"]);
export const CI_SERVICE = "CI (GitHub Actions)";
const HISTORY_COMMITS = Number(process.env.SCAN_HISTORY_COMMITS ?? 300);

export function walk(dir: string, root = dir, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (WALK_SKIP.has(name)) continue;
    const full = join(dir, name);
    // lstat: a symlink must never be followed out of the tree being scanned.
    const st = lstatSync(full, { throwIfNoEntry: false });
    if (!st || st.isSymbolicLink()) continue;
    if (st.isDirectory()) walk(full, root, out);
    else if (st.isFile() && st.size < MAX_FILE_BYTES) out.push(relative(root, full).split("\\").join("/"));
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
      .filter((f) => f && !f.split("/").includes(".git"))
      .filter((f) => {
        // lstat reports a symlink as a symlink, not as the file it points to, so links are dropped (they could point at ~/.aws/credentials).
        const st = lstatSync(join(dir, f), { throwIfNoEntry: false });
        return !!st?.isFile() && st.size < MAX_FILE_BYTES;
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

/** A token for private GitHub repos: GITHUB_TOKEN, else whatever the GitHub CLI is logged in with. */
async function githubToken(): Promise<string | undefined> {
  if (process.env.GITHUB_TOKEN) return process.env.GITHUB_TOKEN;
  try {
    return (await run("gh", ["auth", "token"], { timeout: 5_000 })).stdout.trim() || undefined;
  } catch {
    return undefined;
  }
}

/** The last meaningful line git printed, so the UI says why a clone failed instead of repeating the command. */
function gitReason(err: unknown): string {
  const e = err as { stderr?: string; killed?: boolean; signal?: string; message?: string };
  if (e.killed || e.signal === "SIGTERM") return "timed out";
  const lines = String(e.stderr ?? e.message ?? "").split("\n").map((l) => l.trim()).filter(Boolean);
  return (lines.reverse().find((l) => !/^(hint|error: )/i.test(l)) ?? lines[0] ?? "unknown error").replace(/^fatal:\s*/i, "");
}

/** Clones a repo into a temp dir. Private GitHub repos are retried with GITHUB_TOKEN or the `gh` login. */
export async function cloneRepo(url: string, depth = HISTORY_COMMITS): Promise<string> {
  if (!/^(https?:\/\/|git@)/.test(url)) throw new Error("Enter a Git URL or owner/name");
  const args = ["clone", "--quiet", "--single-branch", "--no-tags", "--depth", String(Math.max(1, depth)), url];
  // Never wait on a credential prompt (terminal or Git Credential Manager window): fail fast, then try a token.
  const env = { ...process.env, GIT_TERMINAL_PROMPT: "0", GCM_INTERACTIVE: "never", GIT_ASKPASS: "echo" };
  // Big repositories on a slow connection legitimately take minutes; only a stalled clone should be given up on.
  const timeout = Number(process.env.CLONE_TIMEOUT_MS ?? 600_000);
  const attempt = async (extra: string[]) => {
    const dest = mkdtempSync(join(tmpdir(), "tripwire-real-"));
    try {
      await run("git", [...extra, ...args, dest], { timeout, env, maxBuffer: 16 * 1024 * 1024 });
      return dest;
    } catch (err) {
      rmSync(dest, { recursive: true, force: true });
      throw err;
    }
  };
  try {
    return await attempt([]);
  } catch (first) {
    // A timeout is slowness, not missing credentials: a second download with a token would only take as long again.
    if (gitReason(first) === "timed out") throw new Error(`Clone failed: timed out after ${Math.round(timeout / 1000)}s. The repository is large or the connection is slow; raise CLONE_TIMEOUT_MS.`);
    if (!url.includes("github.com")) throw new Error(`Clone failed: ${gitReason(first)}`);
    const token = await githubToken();
    if (!token) throw new Error(`Clone failed: ${gitReason(first)}. If the repository is private, set GITHUB_TOKEN or run \`gh auth login\` and scan again.`);
    const auth = Buffer.from(`x-access-token:${token}`).toString("base64");
    try {
      return await attempt(["-c", `http.extraHeader=Authorization: Basic ${auth}`]);
    } catch (second) {
      if (gitReason(second) === "timed out") throw new Error(`Clone failed: timed out after ${Math.round(timeout / 1000)}s. The repository is large or the connection is slow; raise CLONE_TIMEOUT_MS.`);
      throw new Error(`Clone failed: ${gitReason(second)}. The repository was not found, or this token cannot read it.`);
    }
  }
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

/** A secret that an inline marker hid. Reported, so a reviewer sees what was waved through. */
export interface Suppressed {
  file: string;
  line: number;
  rule: string;
}

/** What inline markers do for one scan: hidden findings are collected here; with `honourInline: false` markers hide nothing. */
export interface IgnoreCtx {
  hidden: Suppressed[];
  honourInline: boolean;
}

/** Scans a file or diff hunk (`startLine` is its first line number) and turns each hit into a finding. */
function findIn(content: string, file: string, startLine: number, service: string, ctx?: IgnoreCtx): Raw[] {
  const lines = content.split(/\r?\n/);
  const out: Raw[] = [];
  for (const m of matchContent(content, file, startLine)) {
    if ((ctx?.honourInline ?? true) && IGNORE_MARK.test(lines[m.line - startLine] ?? "")) {
      ctx?.hidden.push({ file, line: m.line, rule: m.rule.label });
      continue;
    }
    const provider = m.rule.id === "tripwire-demo" ? (m.value.split("_")[2] ?? "demo") : m.rule.provider;
    out.push({
      value: m.value,
      finding: { id: "", rule: m.rule.id, ruleLabel: m.rule.label, provider, variable: m.variable?.toUpperCase(), file, line: m.line, inHead: true, preview: mask(m.value, m.rule), service, nodeId: "", confidence: m.confidence, via: m.via },
    });
  }
  return out;
}

export function scanHead(dir: string, files: string[], dirs: Set<string>, repoName: string, ctx?: IgnoreCtx): Raw[] {
  const out: Raw[] = [];
  for (const file of files) {
    if (SKIP_FILE.test(file)) continue;
    const buf = readFileSync(join(dir, file));
    if (buf.includes(0)) continue;
    out.push(...findIn(buf.toString("utf8"), file, 1, serviceFor(file, dirs, repoName), ctx));
  }
  return out;
}

function parsePatch(patch: string, dirs: Set<string>, repoName: string, inHead: boolean, ctx?: IgnoreCtx): { raws: Raw[]; commits: number } {
  const raws: Raw[] = [];
  let commit = "";
  let file = "";
  let commits = 0;
  // Consecutive added lines form one hunk, so multi-line rules (private keys) can match across them.
  let hunk: string[] = [];
  let hunkStart = 0;
  const flush = () => {
    if (hunk.length && file && !SKIP_FILE.test(file))
      for (const r of findIn(hunk.join("\n"), file, hunkStart, serviceFor(file, dirs, repoName), ctx)) raws.push({ ...r, finding: { ...r.finding, commit: commit || undefined, inHead } });
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

const GIT_BUF = { maxBuffer: 256 * 1024 * 1024, timeout: 60_000 };

/** Scans lines added in recent commits so secrets that were deleted (but never rotated) still show up. */
export async function scanHistory(dir: string, dirs: Set<string>, repoName: string, limit = HISTORY_COMMITS): Promise<{ raws: Raw[]; commits: number }> {
  if (limit <= 0 || !existsSync(join(dir, ".git"))) return { raws: [], commits: 0 };
  try {
    const { stdout } = await run("git", ["-C", dir, "log", "-p", "-U0", "--no-merges", "--no-color", "--no-ext-diff", "--format=__TW__%h", "-n", String(limit)], GIT_BUF);
    return parsePatch(stdout, dirs, repoName, false);
  } catch (err) {
    // A freshly `git init`ed repo has no commits, hence no history; that is not an error.
    if (/does not have any commits yet|bad default revision|unknown revision/i.test(String((err as { stderr?: string }).stderr ?? err))) return { raws: [], commits: 0 };
    throw err;
  }
}

/** Lines added between `base` and HEAD, i.e. what a pull request introduces. Fetches `base` if a shallow checkout lacks it. */
export async function scanDiff(dir: string, dirs: Set<string>, repoName: string, base: string, ctx?: IgnoreCtx): Promise<Raw[]> {
  const diff = () => run("git", ["-C", dir, "diff", "-U0", "--no-color", "--no-ext-diff", base, "HEAD"], GIT_BUF);
  let out: { stdout: string };
  try {
    out = await diff();
  } catch {
    await run("git", ["-C", dir, "fetch", "--quiet", "--no-tags", "--depth=1", "origin", base], { timeout: 60_000 });
    out = await diff();
  }
  return parsePatch(out.stdout, dirs, repoName, true, ctx).raws;
}

/** True when `ref` exists locally, fetching it first if a shallow checkout lacks it. */
export async function ensureRef(dir: string, ref: string): Promise<boolean> {
  const has = () => run("git", ["-C", dir, "cat-file", "-e", `${ref}^{commit}`]).then(() => true, () => false);
  if (await has()) return true;
  await run("git", ["-C", dir, "fetch", "--quiet", "--no-tags", "--depth=1", "origin", ref], { timeout: 60_000 }).catch(() => undefined);
  return has();
}

/** A file as it was at `ref`, or undefined if it did not exist there. */
export async function readAtRef(dir: string, ref: string, path: string): Promise<string | undefined> {
  try {
    return (await run("git", ["-C", dir, "show", `${ref}:${path}`], { maxBuffer: 16 * 1024 * 1024 })).stdout;
  } catch {
    return undefined;
  }
}

/** Lines added to the index (`git add`ed, not yet committed): what a pre-commit hook must stop. */
export async function scanStaged(dir: string, dirs: Set<string>, repoName: string, ctx?: IgnoreCtx): Promise<Raw[]> {
  const { stdout } = await run("git", ["-C", dir, "diff", "--cached", "-U0", "--no-color", "--no-ext-diff", "--diff-filter=ACMR"], GIT_BUF);
  return parsePatch(stdout, dirs, repoName, true, ctx).raws;
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

