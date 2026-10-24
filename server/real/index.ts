import { resolve } from "node:path";
import type { RealScan } from "../../shared/types";
import { ROOT } from "../paths";
import { addIncident, broadcast, state } from "../state";
import { checkHoney, createHoney, loadHoney, plantHoney, publicHoney } from "./honey";
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

export function startScan(input: string, verify = false): void {
  const gen = ++scanGen;
  const normalized = normalizeTarget(input);
  const target = isRemote(normalized) ? normalized : resolve(ROOT, normalized);
  state.scan = { ...emptyScan(), status: "cloning", target: normalized, repo: githubSlug(normalized), startedAt: Date.now(), verify };
  broadcast();
  const update = (patch: Partial<RealScan>) => {
    if (gen !== scanGen) return;
    Object.assign(state.scan, patch);
    broadcast();
  };
  scanTarget(target, { verify }, (status, partial) => update({ status, ...partial }))
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

const syncHoney = () => {
  state.honeyTokens = loadHoney().map(publicHoney).reverse();
};

/** Polls Canarytokens and raises an incident for every new use of a decoy. */
export async function pollHoney(): Promise<void> {
  if (!loadHoney().length) return syncHoney();
  const { fresh } = await checkHoney();
  for (const { record, hit } of fresh)
    addIncident({
      kind: "honey",
      title: "Honey secret used",
      summary: `Someone used the decoy AWS key ${record.accessKeyId.slice(0, 8)}… ${record.repo ? `planted in ${record.repo}` : ""}${hit.ip ? ` from ${hit.ip}` : ""}.`,
      details: [
        { label: "When", value: new Date(hit.at).toISOString() },
        ...(hit.location ? [{ label: "Location", value: hit.location }] : []),
        ...(hit.org ? [{ label: "Network", value: hit.org }] : []),
        ...(hit.action ? [{ label: "Tried", value: hit.action }] : []),
        ...(hit.userAgent ? [{ label: "Client", value: hit.userAgent.slice(0, 120) }] : []),
      ],
      affectedNodeIds: [],
    });
  syncHoney();
  broadcast();
}

export async function honeyAction(fn: () => Promise<unknown>, label: string): Promise<void> {
  state.honeyBusy = label;
  broadcast();
  try {
    await fn();
  } finally {
    state.honeyBusy = undefined;
    syncHoney();
    broadcast();
  }
}

export function startHoneyPolling(): void {
  syncHoney();
  const every = Number(process.env.HONEY_POLL_MS ?? 60_000);
  const tick = () => pollHoney().catch((err) => console.error("honey poll failed", err.message)).finally(() => setTimeout(tick, every));
  setTimeout(tick, 2_000);
}

export { createHoney, plantHoney };
