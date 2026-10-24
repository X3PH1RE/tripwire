import type { Finding, Severity, VulnPackage } from "../../shared/types";
import { blastHops } from "../graph";
import type { ScanReport } from "../real/core";

export const MARKER = "<!-- tripwire-report -->";
export const RANK: Record<Severity, number> = { UNKNOWN: 0, LOW: 1, MODERATE: 2, HIGH: 3, CRITICAL: 4 };

export interface Policy {
  secrets: boolean;
  vulns: Severity | "none";
}

export interface Verdict {
  failed: boolean;
  reasons: string[];
  blocking: Finding[];
  blockingVulns: VulnPackage[];
}

/** In diff mode only secrets the change adds block; otherwise every secret still in the code does. */
export function evaluate(r: ScanReport, policy: Policy): Verdict {
  const candidates = r.diffBase ? r.findings.filter((f) => f.isNew) : r.findings.filter((f) => f.inHead);
  const blocking = policy.secrets ? candidates : [];
  const blockingVulns = policy.vulns === "none" ? [] : r.vulns.filter((v) => RANK[v.severity] >= RANK[policy.vulns as Severity]);
  const reasons: string[] = [];
  const s = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"}`;
  if (blocking.length) reasons.push(r.diffBase ? `${s(blocking.length, "secret")} added in this change` : `${s(blocking.length, "secret")} in the code`);
  if (blockingVulns.length) reasons.push(`${s(blockingVulns.length, "vulnerable package")} at ${(policy.vulns as string).toLowerCase()} or above`);
  return { failed: reasons.length > 0, reasons, blocking, blockingVulns };
}

export function unlocks(r: ScanReport, f: Finding): string[] {
  const byId = new Map(r.nodes.map((n) => [n.id, n]));
  return blastHops(r.edges, [f.nodeId])
    .flatMap((h) => h.nodes)
    .map((id) => byId.get(id))
    .filter((n) => n?.type === "resource")
    .map((n) => n!.label);
}

const status = (f: Finding) => (f.isNew ? "new" : f.inHead ? "in code" : "history");
const order = (f: Finding) => (f.isNew ? 0 : f.inHead ? 1 : 2);
const sorted = (fs: Finding[]) => [...fs].sort((a, b) => order(a) - order(b));
const cell = (s: string) => s.replace(/\|/g, "\\|").replace(/\n/g, " ");

export function toMarkdown(r: ScanReport, v: Verdict, maxVulns = 15): string {
  const out = [MARKER, "## Tripwire", ""];
  out.push(v.failed ? `**Failed:** ${v.reasons.join(", ")}.` : "**Passed:** no blocking findings.", "");
  if (r.findings.length) {
    out.push(`### Secrets (${r.findings.length})`, "", "| Status | Secret | Location | Type | Unlocks |", "| --- | --- | --- | --- | --- |");
    for (const f of sorted(r.findings)) {
      const where = f.inHead ? `\`${f.file}:${f.line}\`` : `\`${f.file}:${f.line}\` (commit ${f.commit})`;
      out.push(`| ${status(f)} | \`${cell(f.variable ?? f.ruleLabel)}\` \`${cell(f.preview)}\` | ${where} | ${cell(f.ruleLabel)} | ${cell(unlocks(r, f).join(", ") || "-")} |`);
    }
    out.push("");
    if (r.findings.some((f) => !f.inHead)) out.push("> Secrets marked `history` were deleted from the code but are still in git history. Rotate them with the provider; removing the line does not revoke them.", "");
  } else out.push("No secrets found.", "");
  if (r.vulns.length) {
    const counts = (["CRITICAL", "HIGH", "MODERATE", "LOW"] as Severity[]).map((s) => [s, r.vulns.filter((x) => x.severity === s).length] as const).filter(([, n]) => n);
    out.push(`### Vulnerable dependencies (${r.vulns.length})`, "", counts.map(([s, n]) => `${n} ${s.toLowerCase()}`).join(" · "), "", "| Package | Version | Fixed in | Severity | Advisory |", "| --- | --- | --- | --- | --- |");
    for (const x of r.vulns.slice(0, maxVulns)) out.push(`| \`${x.name}\` (${x.ecosystem}${x.direct ? "" : ", transitive"}) | ${x.version} | ${x.fixed ?? "-"} | ${x.severity.toLowerCase()} | ${x.advisories[0].id}: ${cell(x.advisories[0].summary).slice(0, 90)} |`);
    if (r.vulns.length > maxVulns) out.push("", `…and ${r.vulns.length - maxVulns} more.`);
    out.push("");
  }
  for (const w of r.warnings) out.push(`> Warning: ${w}`, "");
  out.push(`<sub>Scanned ${r.filesScanned} files and ${r.commitsScanned} commits in ${(r.durationMs / 1000).toFixed(1)}s. Silence a false positive with a \`tripwire:ignore\` comment on the line or a glob in \`.tripwireignore\`.</sub>`);
  return out.join("\n") + "\n";
}

export function toText(r: ScanReport, v: Verdict, color: boolean, maxVulns = 10): string {
  const c = (code: string) => (s: string) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const [red, yellow, green, dim, bold, cyan] = ["31", "33", "32", "2", "1", "36"].map(c);
  const tone = (f: Finding) => (f.isNew ? red("NEW ") : f.inHead ? red("CODE") : yellow("HIST"));
  const sev = (s: Severity) => (RANK[s] >= 3 ? red : RANK[s] === 2 ? yellow : dim)(s.padEnd(8));
  const out = ["", `${bold("Tripwire")}  ${r.repo ?? r.name}${r.branch ? dim(` (${r.branch})`) : ""}  ${dim(`${r.filesScanned} files · ${r.commitsScanned} commits · ${(r.durationMs / 1000).toFixed(1)}s`)}`, ""];
  out.push(bold(`Secrets (${r.findings.length})`));
  if (!r.findings.length) out.push(dim("  none found"));
  for (const f of sorted(r.findings)) {
    out.push(`  ${tone(f)}  ${(f.variable ?? f.ruleLabel).padEnd(22)} ${cyan(`${f.file}:${f.line}`)}${f.inHead ? "" : dim(` @${f.commit}`)}  ${dim(f.ruleLabel)}`);
    const u = unlocks(r, f);
    out.push(dim(`        ${f.preview}${u.length ? `  → unlocks ${u.join(", ")}` : ""}`));
  }
  out.push("", bold(`Vulnerable dependencies (${r.vulns.length})`));
  if (!r.vulns.length) out.push(dim("  none found"));
  for (const x of r.vulns.slice(0, maxVulns)) out.push(`  ${sev(x.severity)} ${`${x.name}@${x.version}`.padEnd(30)} ${x.fixed ? green(`→ ${x.fixed}`.padEnd(14)) : dim("no fix".padEnd(14))} ${dim(`${x.file}  ${x.advisories[0].id}`)}`);
  if (r.vulns.length > maxVulns) out.push(dim(`  …and ${r.vulns.length - maxVulns} more (use --json for the full list)`));
  for (const w of r.warnings) out.push("", yellow(`warning: ${w}`));
  out.push("", v.failed ? `${red(bold("FAIL"))}  ${v.reasons.join(", ")}` : `${green(bold("PASS"))}  no blocking findings`, "");
  return out.join("\n");
}
