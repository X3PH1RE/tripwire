import { resolve } from "node:path";
import type { RealScan } from "../../shared/types";
import { ROOT } from "../paths";
import { broadcast, state } from "../state";
import { emptyScan } from "./empty";
import { openFixPr } from "./fix";
import { isRemote, scanTarget } from "./core";
import { githubSlug, normalizeTarget } from "./scan";

let scanGen = 0;

export function clearScan(): void {
  scanGen++;
  state.scan = emptyScan();
  broadcast();
}

export function startScan(input: string): void {
  const gen = ++scanGen;
  const normalized = normalizeTarget(input);
  const target = isRemote(normalized) ? normalized : resolve(ROOT, normalized);
  state.scan = { ...emptyScan(), status: "cloning", target: normalized, repo: githubSlug(normalized), startedAt: Date.now() };
  broadcast();
  const update = (patch: Partial<RealScan>) => {
    if (gen !== scanGen) return;
    Object.assign(state.scan, patch);
    broadcast();
  };
  scanTarget(target, {}, (status, partial) => update({ status, ...partial }))
    .then((r) => update({ status: "done", vulns: r.vulns, error: r.warnings[0], finishedAt: Date.now() }))
    .catch((err: Error) => update({ status: "failed", error: err.message, finishedAt: Date.now() }));
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
