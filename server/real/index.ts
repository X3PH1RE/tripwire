import { existsSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import type { RealScan } from "../../shared/types";
import { ROOT } from "../paths";
import { broadcast, state } from "../state";
import { emptyScan } from "./empty";
import { openFixPr } from "./fix";
import { buildGraph } from "./graph";
import { findVulns, parseDeps } from "./osv";
import { ciSecretRefs, cloneRepo, currentBranch, githubSlug, manifestDirs, mergeFindings, normalizeTarget, repoNameOf, scanHead, scanHistory, walk } from "./scan";

let scanGen = 0;

export function clearScan(): void {
  scanGen++;
  state.scan = emptyScan();
  broadcast();
}

export function startScan(input: string): void {
  const gen = ++scanGen;
  const target = normalizeTarget(input);
  state.scan = { ...emptyScan(), status: "cloning", target, repo: githubSlug(target), startedAt: Date.now() };
  broadcast();
  const live = () => gen === scanGen;
  const update = (patch: Partial<RealScan>) => {
    if (!live()) return;
    Object.assign(state.scan, patch);
    broadcast();
  };

  (async () => {
    const remote = /^(https?:\/\/|git@)/.test(target);
    let dir = remote ? "" : resolve(ROOT, target);
    try {
      if (remote) dir = await cloneRepo(target);
      else if (!existsSync(dir)) throw new Error(`No such directory: ${target}`);
      if (!live()) return;
      const files = walk(dir);
      const dirs = manifestDirs(files);
      const name = repoNameOf(target, dir);
      update({ status: "secrets", branch: await currentBranch(dir), filesScanned: files.length });
      const head = scanHead(dir, files, dirs, name);
      update({ status: "history" });
      const history = await scanHistory(dir, dirs, name);
      const { findings, samples } = mergeFindings(head, history.raws);
      const graph = buildGraph(name, findings, ciSecretRefs(dir, files), samples);
      update({ status: "vulns", commitsScanned: history.commits, findings, ...graph });
      let vulnError: string | undefined;
      const vulns = await findVulns(parseDeps(dir, files)).catch((err: Error) => ((vulnError = `Vulnerability lookup failed: ${err.message}`), []));
      update({ status: "done", vulns, error: vulnError, finishedAt: Date.now() });
    } catch (err) {
      update({ status: "failed", error: (err as Error).message, finishedAt: Date.now() });
    } finally {
      if (remote && dir) rmSync(dir, { recursive: true, force: true });
    }
  })();
}

export function startFix(keys?: string[]): void {
  const gen = scanGen;
  const scan = state.scan;
  if (scan.status !== "done" || scan.fix.status === "running") return;
  scan.fix = { status: "running" };
  broadcast();
  openFixPr(scan, keys)
    .then((pr) => gen === scanGen && (scan.fix = { status: "done", prUrl: pr.url, prNumber: pr.number, packages: pr.packages }))
    .catch((err: Error) => gen === scanGen && (scan.fix = { status: "failed", note: err.message }))
    .finally(broadcast);
}
