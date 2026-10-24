import { existsSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import type { Finding, GraphEdge, GraphNode, VulnPackage } from "../../shared/types";
import { loadBaseline } from "../detect/baseline";
import { fingerprint } from "../detect/filters";
import { buildGraph } from "./graph";
import { honeyKeyIds } from "./honey";
import { findVulns, parseDeps } from "./osv";
import { verifyFindings } from "./verify";
import { ciSecretRefs, cloneRepo, currentBranch, githubSlug, listFiles, loadIgnore, manifestDirs, mergeFindings, normalizeTarget, repoNameOf, scanDiff, scanHead, scanHistory } from "./scan";

export type Stage = "cloning" | "secrets" | "history" | "verify" | "vulns";

export interface ScanOptions {
  /** Commits of history to scan (0 = none). */
  history?: number;
  /** Base ref/SHA: findings added between it and HEAD are flagged `isNew`. */
  diff?: string;
  vulns?: boolean;
  /** Ask each provider whether found keys still work and what they can reach. */
  verify?: boolean;
  /** Apply `.tripwire-baseline.json` when present (default true). */
  baseline?: boolean;
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
    const ignored = loadIgnore(dir);
    const files = (await listFiles(dir)).filter((f) => !ignored(f));
    const dirs = manifestDirs(files);
    const name = repoNameOf(target, dir);
    const branch = await currentBranch(dir).catch(() => undefined);
    onStage?.("secrets", { branch, filesScanned: files.length });
    const head = scanHead(dir, files, dirs, name);
    onStage?.("history", {});
    const past = await scanHistory(dir, dirs, name, history);
    let added: Set<string> | undefined;
    if (opts.diff) {
      try {
        added = new Set((await scanDiff(dir, dirs, name, opts.diff)).filter((r) => !ignored(r.finding.file)).map((r) => r.value));
      } catch (err) {
        warnings.push(`Could not diff against ${opts.diff} (${(err as Error).message.split("\n")[0]}); treating every secret in the code as blocking.`);
      }
    }
    const { findings, samples, values } = mergeFindings(head, past.raws.filter((r) => !ignored(r.finding.file)), added);
    const accepted = opts.baseline === false ? new Set<string>() : loadBaseline(dir);
    for (const f of findings) {
      f.fingerprint = fingerprint(f.rule, f.file, values.get(f.id) ?? "");
      if (accepted.has(f.fingerprint)) f.baselined = true;
    }
    if (opts.verify) {
      onStage?.("verify", { commitsScanned: past.commits, findings });
      await verifyFindings(findings, values, honeyKeyIds()).catch((err: Error) => warnings.push(`Key verification failed: ${err.message}`));
    }
    const graph = buildGraph(name, findings, ciSecretRefs(dir, files), samples);
    onStage?.("vulns", { commitsScanned: past.commits, findings, ...graph });
    let vulns: VulnPackage[] = [];
    if (opts.vulns !== false) vulns = await findVulns(parseDeps(dir, files)).catch((err: Error) => (warnings.push(`Vulnerability lookup failed: ${err.message}`), []));
    return { target, repo: githubSlug(target), name, branch, filesScanned: files.length, commitsScanned: past.commits, findings, ...graph, vulns, diffBase: added ? opts.diff : undefined, warnings, durationMs: Date.now() - started };
  } finally {
    if (remote && dir) rmSync(dir, { recursive: true, force: true });
  }
}
