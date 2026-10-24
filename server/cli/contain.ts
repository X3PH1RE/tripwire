import type { ContainResult, ContainStep, Finding } from "../../shared/types";
import { runContain, type ContainOutcome } from "../contain";
import { scanTarget } from "../real/core";

const GLYPH: Record<ContainResult["status"], string> = { planned: "WOULD REVOKE", guided: "YOU DO THIS", revoked: "REVOKED", failed: "FAILED", "still-live": "STILL LIVE" };

/** Renders a plan (dry run) or its results (apply). Never prints a secret. */
export function formatContain(outcome: ContainOutcome, findings: Finding[], apply: boolean, color: boolean): string {
  const c = (code: string) => (s: string) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const [red, yellow, green, dim, bold, cyan] = ["31", "33", "32", "2", "1", "36"].map(c);
  const tone = (s: ContainResult["status"]) => ({ planned: yellow, guided: cyan, revoked: green, failed: red, "still-live": red })[s];
  const byId = new Map(findings.map((f) => [f.id, f]));
  const out = ["", bold(apply ? "Containment" : "Containment plan (dry run: nothing has been changed)"), ""];
  if (!outcome.plan.length) out.push(dim("  No live or unconfirmed keys to contain."), "");

  outcome.plan.forEach((step: ContainStep, i) => {
    const r = outcome.results.find((x) => x.findingId === step.findingId)!;
    const f = byId.get(step.findingId);
    out.push(`${String(i + 1).padStart(2)}. ${tone(r.status)(GLYPH[r.status].padEnd(12))} ${bold(step.label)}  ${dim(`${step.provider} · ${step.file}:${step.line}${f?.verify?.identity ? ` · as ${f.verify.identity}` : ""}`)}`);
    if (step.reach.length) out.push(dim(`      reaches ${step.reach.slice(0, 4).join(", ")}${step.reach.length > 4 ? ", …" : ""}`));
    out.push(`      ${r.note}`);
    if (r.reactivate) out.push(dim(`      undo: ${r.reactivate}`));
    if (r.status === "guided" || r.status === "failed" || r.status === "still-live") {
      if (step.guide.url) out.push(`      ${cyan(step.guide.url)}`);
      step.guide.steps.forEach((s, j) => out.push(dim(`      ${j + 1}) ${s}`)));
    }
    out.push("");
  });

  const n = (s: ContainResult["status"]) => outcome.results.filter((r) => r.status === s).length;
  if (apply) out.push(`${green(`${n("revoked")} revoked`)} · ${n("failed") + n("still-live") ? red(`${n("failed") + n("still-live")} need attention`) : "0 need attention"} · ${cyan(`${n("guided")} manual`)}`, "");
  else if (n("planned")) out.push(`${n("planned")} key${n("planned") === 1 ? "" : "s"} can be revoked automatically. Run again with ${bold("--apply")} to do it.`, "");
  return out.join("\n");
}

/** Scans with key verification, then plans (and with `apply` performs) containment. Exit 1 if a live key is left standing. */
export async function contain(target: string, apply: boolean, json: boolean, log: (s: string) => void, err: (s: string) => void, quiet: boolean): Promise<number> {
  let values = new Map<string, string>();
  const report = await scanTarget(target, { vulns: false, verify: true, baseline: false, onValues: (v) => (values = v) }, (stage) => !quiet && err(`tripwire: ${stage}…\n`));
  const outcome = await runContain({ findings: report.findings, nodes: report.nodes, edges: report.edges, values }, { apply });
  if (json) log(JSON.stringify({ target: report.target, apply, ...outcome }, null, 2) + "\n");
  else log(formatContain(outcome, report.findings, apply, (!!process.stdout.isTTY || !!process.env.FORCE_COLOR) && !process.env.NO_COLOR));
  if (!apply) return 0;
  const byId = new Map(report.findings.map((f) => [f.id, f]));
  const stillExposed = outcome.results.some((r) => r.status === "failed" || r.status === "still-live" || (r.status === "guided" && byId.get(r.findingId)?.verify?.status === "live"));
  return stillExposed ? 1 : 0;
}
