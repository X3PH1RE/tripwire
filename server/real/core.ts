import { existsSync, readFileSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import type { Finding, GraphEdge, GraphNode, VulnPackage } from "../../shared/types";
import { BASELINE_FILE, baselineFromText, loadBaseline } from "../detect/baseline";
import { fingerprint } from "../detect/filters";
import { buildGraph } from "./graph";
import { honeyKeyIds } from "./honey";
import { findVulns, parseDeps } from "./osv";
import { verifyFindings } from "./verify";
import { ciSecretRefs, cloneRepo, currentBranch, ensureRef, githubSlug, ignoreMatcher, listFiles, loadIgnore, manifestDirs, mergeFindings, normalizeTarget, readAtRef, repoNameOf, scanDiff, scanHead, scanHistory, scanStaged, type IgnoreCtx, type Suppressed } from "./scan";

export type Stage = "cloning" | "secrets" | "history" | "verify" | "vulns";

export interface ScanOptions {
  /** Commits of history to scan (0 = none). */
  history?: number;
  /** Base ref/SHA: findings added between it and HEAD are flagged `isNew`. */
  diff?: string;
  vulns?: boolean;
  /** Ask each provider whether found keys still work and what they can reach. */
  verify?: boolean;
  /** Scan only what is staged for commit (a pre-commit hook): no history, no dependency lookup, nothing outside the index. */
  staged?: boolean;
  /** Honour inline `tripwire:ignore` / `gitleaks:allow` markers (default true). Off, they hide nothing: for CI that must not trust the change under review. */
  inlineIgnore?: boolean;
  /** Apply `.tripwire-baseline.json` when present (default true). */
  baseline?: boolean;
  /**
   * Receives each finding id's secret value, in memory only, for callers that act on the secrets (containment).
   * Values are never part of the returned report.
   */
  onValues?: (values: Map<string, string>) => void;
}

export interface ScanReport {
  target: string;
  repo?: string;
  name: string;
  branch?: string;
  filesScanned: number;
  commitsScanned: number;
  findings: Finding[];
  nodes: GraphNode[];
  edges: GraphEdge[];
  vulns: VulnPackage[];
  /** Set when `diff` was requested and the diff could be computed. */
  diffBase?: string;
  warnings: string[];
  durationMs: number;
}

export const isRemote = (target: string) => /^(https?:\/\/|git@)/.test(target);

export async function scanTarget(input: string, opts: ScanOptions = {}, onStage?: (stage: Stage, partial: Partial<ScanReport>) => void): Promise<ScanReport> {
  const started = Date.now();
  const target = normalizeTarget(input);
  const remote = isRemote(target);
  const history = opts.history ?? Number(process.env.SCAN_HISTORY_COMMITS ?? 300);
  const warnings: string[] = [];
  let dir = remote ? "" : resolve(target);
  onStage?.("cloning", {});
  try {
    if (remote) dir = await cloneRepo(target, history);
    else if (!existsSync(dir)) throw new Error(`No such directory: ${target}`);
    // In diff mode the ignore rules and the baseline come from the base ref. The change under review must not be able to
    // switch the check off by editing the files that configure it.
    const baseRef = opts.diff && !opts.staged && (await ensureRef(dir, opts.diff)) ? opts.diff : undefined;
    let ignored = loadIgnore(dir);
    let accepted = new Set<string>();
    if (baseRef) {
      ignored = ignoreMatcher((await readAtRef(dir, baseRef, ".tripwireignore")) ?? "");
      if (opts.baseline !== false) accepted = baselineFromText((await readAtRef(dir, baseRef, BASELINE_FILE)) ?? "");
      for (const p of [".tripwireignore", BASELINE_FILE]) {
        const now = existsSync(join(dir, p)) ? readFileSync(join(dir, p), "utf8") : "";
        if (now !== ((await readAtRef(dir, baseRef, p)) ?? "")) warnings.push(`This change edits ${p}. Tripwire used the version from ${opts.diff}, so the change cannot switch the check off.`);
      }
    } else if (opts.baseline !== false) accepted = loadBaseline(dir);
    const suppressedHead: Suppressed[] = [];
    const suppressedChange: Suppressed[] = [];
    const honourInline = opts.inlineIgnore !== false;
    const ctxHead: IgnoreCtx = { hidden: suppressedHead, honourInline };
    const ctxChange: IgnoreCtx = { hidden: suppressedChange, honourInline };
    const files = (await listFiles(dir)).filter((f) => !ignored(f));
    const dirs = manifestDirs(files);
    const name = repoNameOf(target, dir);
    const branch = await currentBranch(dir).catch(() => undefined);
    onStage?.("secrets", { branch, filesScanned: files.length });
    const staged = opts.staged ? (await scanStaged(dir, dirs, name, ctxChange)).filter((r) => !ignored(r.finding.file)) : undefined;
    const head = staged ?? scanHead(dir, files, dirs, name, ctxHead);
    onStage?.("history", {});
    const past = staged ? { raws: [], commits: 0 } : await scanHistory(dir, dirs, name, history);
    let added: Set<string> | undefined = staged ? new Set(staged.map((r) => r.value)) : undefined;
    if (opts.diff && !staged) {
      try {
        added = new Set((await scanDiff(dir, dirs, name, opts.diff, ctxChange)).filter((r) => !ignored(r.finding.file)).map((r) => r.value));
      } catch (err) {
        warnings.push(`Could not diff against ${opts.diff} (${(err as Error).message.split("\n")[0]}); treating every secret in the code as blocking.`);
      }
    }
    const { findings, samples, values } = mergeFindings(head, past.raws.filter((r) => !ignored(r.finding.file)), added);
    // Anything an inline marker hid is listed, so a reviewer can see what was waved through (in a change, only what the change added).
    const hidden = opts.staged || opts.diff ? suppressedChange : suppressedHead;
    if (hidden.length) {
      const where = hidden.slice(0, 8).map((s) => `${s.file}:${s.line} (${s.rule})`).join(", ");
      warnings.push(`${hidden.length} secret${hidden.length === 1 ? "" : "s"} hidden by an inline tripwire:ignore / gitleaks:allow marker${opts.diff ? " in this change" : ""}: ${where}${hidden.length > 8 ? ", …" : ""}`);
    }
    for (const f of findings) {
      f.fingerprint = fingerprint(f.rule, f.file, values.get(f.id) ?? "");
      if (accepted.has(f.fingerprint)) f.baselined = true;
    }
    if (opts.verify) {
      onStage?.("verify", { commitsScanned: past.commits, findings });
      await verifyFindings(findings, values, honeyKeyIds()).catch((err: Error) => warnings.push(`Key verification failed: ${err.message}`));
    }
    opts.onValues?.(values);
    const graph = buildGraph(name, findings, ciSecretRefs(dir, files), samples);
    onStage?.("vulns", { commitsScanned: past.commits, findings, ...graph });
    let vulns: VulnPackage[] = [];
    if (opts.vulns !== false && !staged) vulns = await findVulns(parseDeps(dir, files)).catch((err: Error) => (warnings.push(`Vulnerability lookup failed: ${err.message}`), []));
    return { target, repo: githubSlug(target), name, branch, filesScanned: files.length, commitsScanned: past.commits, findings, ...graph, vulns, diffBase: staged ? "staged" : added ? opts.diff : undefined, warnings, durationMs: Date.now() - started };
  } finally {
    if (remote && dir) rmSync(dir, { recursive: true, force: true });
  }
}
