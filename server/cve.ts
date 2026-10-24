import type { CveStep } from "../shared/types";
import { cleanupPatchPrs, openPatchPr } from "./github";
import { generate } from "./llm";
import { addIncident, broadcast, script, sleep, state } from "./state";

const CVE = {
  id: "CVE-2026-99999",
  summary: "PHP remote code execution via crafted request arguments (simulated advisory)",
  runtime: "php",
  introduced: "8.1.0",
  fixed: "8.1.29",
};

const parse = (v: string) => v.split(".").map(Number);
function lessThan(a: string, b: string): boolean {
  const [x, y] = [parse(a), parse(b)];
  for (let i = 0; i < 3; i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) < (y[i] ?? 0);
  return false;
}
const affected = (version: string) => !lessThan(version, CVE.introduced) && lessThan(version, CVE.fixed);

function step(key: CveStep["key"]): CveStep {
  return state.cve.steps.find((s) => s.key === key)!;
}

const cannedBody = (service: string, from: string) =>
  `## Security patch for ${CVE.id}\n\n${CVE.summary}.\n\n- **Affected:** ${service} runs PHP ${from}, inside the vulnerable range ${CVE.introduced} to <${CVE.fixed}.\n- **Fix:** bump the base image to \`php:${CVE.fixed}-apache\`.\n- **Risk of change:** patch release, no API changes expected.\n\nOpened automatically by Tripwire. A human reviews and merges.`;

export function simulateCve(): void {
  if (state.cve.status === "running") return;
  state.cve = {
    status: "running",
    cveId: CVE.id,
    summary: CVE.summary,
    steps: [
      { key: "disclosed", label: "Disclosed", at: Date.now() },
      { key: "found", label: "Found affected services" },
      { key: "pr", label: "Patch PR opened" },
      { key: "ready", label: "Patch ready for review" },
    ],
  };
  addIncident({ kind: "cve", title: `New CVE: ${CVE.id}`, summary: `${CVE.summary}. Affects ${CVE.runtime} ${CVE.introduced} to <${CVE.fixed}.`, affectedNodeIds: [] });
  broadcast();

  script(async (alive) => {
    await sleep(1200);
    if (!alive()) return;
    const vulnerable = state.nodes.filter((n) => {
      const [runtime, version] = (n.version ?? "").split(" ");
      return n.type === "service" && runtime === CVE.runtime && affected(version);
    });
    for (const n of vulnerable) n.status = "attacked";
    step("found").at = Date.now();
    addIncident({
      kind: "cve",
      title: `${vulnerable.length} service affected`,
      summary: vulnerable.map((n) => `${n.label} runs ${n.version}`).join(", "),
      affectedNodeIds: vulnerable.map((n) => n.id),
    });
    broadcast();

    const svc = vulnerable[0];
    if (!svc) return;
    const from = svc.version!.split(" ")[1];
    const [title, body] = await Promise.all([
      generate(`Write a one-line PR title for bumping PHP ${from} to ${CVE.fixed} to fix ${CVE.id}.`, `fix(api): bump PHP ${from} → ${CVE.fixed} for ${CVE.id}`),
      generate(`Write a short PR description for bumping the API service's PHP base image from ${from} to ${CVE.fixed} to fix ${CVE.id} (${CVE.summary}).`, cannedBody(svc.label, from)),
    ]);
    try {
      const pr = await openPatchPr({ file: svc.file!, from: `php:${from}-apache`, to: `php:${CVE.fixed}-apache`, title: title.text.replace(/^"|"$/g, ""), body: body.text });
      if (!alive()) return;
      Object.assign(state.cve, { prUrl: pr.url, prNumber: pr.number });
    } catch (err) {
      if (!alive()) return;
      console.error("patch PR failed, using fallback", err);
      const fallback = process.env.FALLBACK_PR_URL;
      Object.assign(state.cve, { replayed: true, prUrl: fallback, prNumber: fallback ? Number(fallback.split("/").pop()) : undefined, note: fallback ? "GitHub API failed, showing a PR from a dry run" : "GitHub API failed, patch prepared locally" });
    }
    step("pr").at = Date.now();
    broadcast();
    await sleep(1000);
    if (!alive()) return;
    step("ready").at = Date.now();
    svc.status = "patched";
    svc.version = `php ${from} → ${CVE.fixed}`;
    svc.badge = state.cve.prNumber ? `PR #${state.cve.prNumber}` : "patch ready";
    state.cve.status = "done";
    addIncident({
      kind: "cve",
      title: "Patch ready for review",
      summary: `${svc.label}: PHP ${from} → ${CVE.fixed}${state.cve.prUrl ? ` in PR #${state.cve.prNumber}` : ""}. Left open for a human to merge.`,
      affectedNodeIds: [svc.id],
    });
    broadcast();
  });
}

export function cleanupInBackground(): void {
  cleanupPatchPrs()
    .then((n) => n && console.log(`closed ${n} old patch PR(s)`))
    .catch((err) => console.error("PR cleanup failed", err.message));
}
