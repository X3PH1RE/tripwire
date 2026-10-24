import { appendFileSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { ContainResult, ContainStep, Finding, GraphEdge, GraphNode } from "../../shared/types";
import { awsSecretFor, verifyOne } from "../real/verify";
import { buildPlan } from "./plan";
import { REVOKERS } from "./providers";

export { buildPlan } from "./plan";

export const CONTAIN_LOG = join(process.env.TRIPWIRE_HOME ?? join(homedir(), ".tripwire"), "contain-log.jsonl");

export interface ContainInput {
  findings: Finding[];
  nodes: GraphNode[];
  edges: GraphEdge[];
  /** Finding id -> secret value. Never logged, never returned. */
  values: Map<string, string>;
}

export interface ContainOptions {
  /** Without this nothing is written to any provider. */
  apply: boolean;
  /** Only act on these finding ids (the UI's per-key confirm). */
  only?: string[];
  /** Wait before re-checking a revoked key, for providers that apply revocation a moment later. */
  delayMs?: number;
  /** Where actions are recorded; defaults to ~/.tripwire/contain-log.jsonl. Pass `false` to skip. */
  logFile?: string | false;
}

export interface ContainOutcome {
  plan: ContainStep[];
  results: ContainResult[];
  /** True when every key that could be live is now rejected or still needs the user (nothing failed, nothing still works). */
  contained: boolean;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function record(file: string | false | undefined, entry: Record<string, unknown>): void {
  if (file === false) return;
  const path = file ?? CONTAIN_LOG;
  try {
    mkdirSync(dirname(path), { recursive: true });
    appendFileSync(path, JSON.stringify({ at: new Date().toISOString(), ...entry }) + "\n", { mode: 0o600 });
  } catch {
    // The log is a convenience; failing to write it must not stop a revocation that already happened.
  }
}

/** Plans containment and, with `apply`, revokes every live key it can and checks that the provider now rejects it. */
export async function runContain(input: ContainInput, opts: ContainOptions): Promise<ContainOutcome> {
  const { findings, values } = input;
  const plan = buildPlan(input).filter((s) => !opts.only || opts.only.includes(s.findingId));
  const results: ContainResult[] = [];

  for (const step of plan) {
    const finding = findings.find((f) => f.id === step.findingId)!;
    if (step.mode === "guided") {
      results.push({ findingId: step.findingId, status: "guided", note: step.reason ?? "Follow the steps." });
      continue;
    }
    if (!opts.apply) {
      results.push({ findingId: step.findingId, status: "planned", note: "Dry run: nothing was changed." });
      continue;
    }

    const base = { provider: step.provider, fingerprint: finding.fingerprint, file: step.file };
    let revoked;
    try {
      revoked = await REVOKERS[step.provider]({ finding, findings, values });
    } catch (err) {
      revoked = { ok: false, note: `Request failed: ${(err as Error).message}` };
    }
    if (!revoked.ok) {
      results.push({ findingId: step.findingId, status: "failed", note: `${revoked.note} Use the manual steps instead.` });
      record(opts.logFile, { ...base, outcome: "failed", note: revoked.note });
      continue;
    }

    // The revoke call returning OK is not proof; ask the provider whether the key still works.
    await sleep(opts.delayMs ?? 1500);
    const value = values.get(finding.id) ?? "";
    const pair = finding.rule === "aws-access-key" ? awsSecretFor(findings, finding) : undefined;
    const context = new Map<string, string>(pair ? [["aws-secret", values.get(pair.id) ?? ""]] : []);
    const after = await verifyOne(finding, value, context).catch(() => undefined);
    if (after) finding.verify = after;

    const still = after?.status === "live";
    const status: ContainResult["status"] = still ? "still-live" : "revoked";
    const note = still ? `${revoked.note} But the provider still accepts the key. Revoke it manually.` : after?.status === "revoked" ? `${revoked.note} The provider now rejects the key.` : `${revoked.note} The provider could not be re-checked.`;
    results.push({ findingId: step.findingId, status, note, reactivate: revoked.reactivate });
    record(opts.logFile, { ...base, outcome: status, note: revoked.note, reactivate: revoked.reactivate });
  }

  return { plan, results, contained: !results.some((r) => r.status === "failed" || r.status === "still-live") };
}
