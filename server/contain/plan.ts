import type { ContainStep, Finding, GraphEdge, GraphNode } from "../../shared/types";
import { blastHops } from "../graph";
import { awsSecretFor } from "../real/verify";
import { guideFor, REVOKERS } from "./providers";

type Sensitivity = NonNullable<GraphNode["sensitivity"]>;
const SENS: Record<Sensitivity, number> = { low: 1, medium: 2, high: 3, production: 4 };

interface Reach {
  labels: string[];
  rank: number;
}

/** What a key reaches: the provider's own answer when we have it, otherwise the graph. */
function reachOf(f: Finding, nodes: GraphNode[], edges: GraphEdge[]): Reach {
  if (f.verify?.access?.length) {
    const sorted = [...f.verify.access].sort((a, b) => SENS[b.sensitivity] - SENS[a.sensitivity]);
    return { labels: sorted.map((a) => a.label), rank: SENS[sorted[0].sensitivity] * 10 + Math.min(sorted.length, 9) };
  }
  if (!f.nodeId) return { labels: [], rank: 0 };
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const resources = blastHops(edges, [f.nodeId])
    .flatMap((h) => h.nodes)
    .map((id) => byId.get(id))
    .filter((n): n is GraphNode => n?.type === "resource")
    .sort((a, b) => SENS[b.sensitivity ?? "low"] - SENS[a.sensitivity ?? "low"]);
  return { labels: resources.map((r) => r.label), rank: resources.length ? SENS[resources[0].sensitivity ?? "low"] * 10 + Math.min(resources.length, 9) : 0 };
}

/**
 * One step per credential, most dangerous first. Keys the provider already rejects and Tripwire's own decoys are left out.
 * A key is only revoked automatically when the provider confirmed it is live.
 */
export function buildPlan(report: { findings: Finding[]; nodes: GraphNode[]; edges: GraphEdge[] }): ContainStep[] {
  const { findings, nodes, edges } = report;
  const steps: { step: ContainStep; live: boolean; rank: number }[] = [];
  for (const f of findings) {
    if (f.verify?.status === "revoked" || f.verify?.status === "honey") continue;
    // The secret half of an AWS key pair is covered by the key ID's step.
    if (f.rule === "aws-secret-key" && findings.some((k) => k.rule === "aws-access-key" && awsSecretFor(findings, k)?.id === f.id)) continue;

    const live = f.verify?.status === "live";
    const reach = reachOf(f, nodes, edges);
    const auto = live && !!REVOKERS[f.provider];
    const guide = guideFor(f.provider);
    const reason = auto
      ? undefined
      : live
        ? "Confirmed live, but Tripwire cannot revoke this provider's keys for you."
        : f.verify?.status === "unverified"
          ? "The provider could not confirm this key. Treat it as live until you have checked."
          : "Not checked against the provider (scan with key verification to confirm it is live).";
    steps.push({
      live,
      rank: reach.rank,
      step: {
        findingId: f.id,
        label: f.variable ?? f.ruleLabel,
        provider: f.provider,
        file: f.file,
        line: f.line,
        reach: reach.labels,
        mode: auto ? "revoke" : "guided",
        reason,
        action: auto ? `Revoke through the ${f.provider} API, then check the provider now rejects it.` : "Revoke it yourself using the steps below.",
        guide,
      },
    });
  }
  // Live before unconfirmed, then by blast radius, then keys Tripwire can revoke now before ones the user must handle, then by name.
  const auto = (s: { step: ContainStep }) => Number(s.step.mode === "revoke");
  return steps.sort((a, b) => Number(b.live) - Number(a.live) || b.rank - a.rank || auto(b) - auto(a) || a.step.label.localeCompare(b.step.label)).map((s) => s.step);
}
