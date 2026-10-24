import type { Finding, Severity, VulnPackage } from "../../shared/types";
import { CONFIDENCE_RANK, type Confidence } from "../detect/schema";
import { blastHops } from "../graph";
import type { ScanReport } from "../real/core";

export const MARKER = "<!-- tripwire-report -->";
export const RANK: Record<Severity, number> = { UNKNOWN: 0, LOW: 1, MODERATE: 2, HIGH: 3, CRITICAL: 4 };

export interface Policy {
  secrets: boolean;
  vulns: Severity | "none";
  /** Findings below this confidence are reported but never block (default: everything blocks). */
  minConfidence?: Confidence;
}

export interface Verdict {
  failed: boolean;
  reasons: string[];
  blocking: Finding[];
  blockingVulns: VulnPackage[];
}

/** A key the provider confirmed live is high-confidence by definition, wherever it was found (a test fixture holding a real key is still a leak). */
const effectiveConfidence = (f: Finding): Confidence => (f.verify?.status === "live" ? "high" : (f.confidence ?? "high"));

/** In diff mode only secrets the change adds block; otherwise every secret still in the code does. Baselined findings and findings below `minConfidence` are reported but never block. */
export function evaluate(r: ScanReport, policy: Policy): Verdict {
  const floor = CONFIDENCE_RANK[policy.minConfidence ?? "low"];
  const active = r.findings.filter((f) => f.verify?.status !== "revoked" && f.verify?.status !== "honey" && !f.baselined && CONFIDENCE_RANK[effectiveConfidence(f)] >= floor);
  const candidates = r.diffBase ? active.filter((f) => f.isNew) : active.filter((f) => f.inHead);
  const blocking = policy.secrets ? candidates : [];
  const blockingVulns = policy.vulns === "none" ? [] : r.vulns.filter((v) => RANK[v.severity] >= RANK[policy.vulns as Severity]);
  const reasons: string[] = [];
  const s = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"}`;
  const liveN = blocking.filter((f) => f.verify?.status === "live").length;
  if (liveN) reasons.push(`${s(liveN, "live key")} confirmed by the provider`);
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

const VSTAT: Record<string, string> = { live: "**LIVE**", revoked: "revoked", honey: "honey", unverified: "unverified" };
const status = (f: Finding) => [f.isNew ? "new" : f.inHead ? "in code" : "history", f.baselined ? "baselined" : "", f.confidence && f.confidence !== "high" ? `${f.confidence} confidence` : "", f.verify ? VSTAT[f.verify.status] : ""].filter(Boolean).join(" · ");
const reach = (r: ScanReport, f: Finding) => (f.verify?.access?.length ? f.verify.access.map((a) => a.label) : f.verify?.status === "revoked" || f.verify?.status === "honey" ? [] : unlocks(r, f));
const order = (f: Finding) => (f.isNew ? 0 : f.inHead ? 1 : 2);
const sorted = (fs: Finding[]) => [...fs].sort((a, b) => order(a) - order(b));
/**
 * Text from the scanned repository (file names, variable names) ends up in a PR comment. A backtick would close the code
 * span it sits in and let a hostile repo inject links and @mentions into the bot's comment, so backticks are neutralised
 * along with the table delimiter and line breaks.
 */
const cell = (s: string) => s.replace(/\|/g, "\\|").replace(/`/g, "'").replace(/\r?\n|\r/g, " ");

export function toMarkdown(r: ScanReport, v: Verdict, maxVulns = 15): string {
  const out = [MARKER, "## Tripwire", ""];
  out.push(v.failed ? `**Failed:** ${v.reasons.join(", ")}.` : "**Passed:** no blocking findings.", "");
  if (r.findings.length) {
    out.push(`### Secrets (${r.findings.length})`, "", "| Status | Secret | Location | Type | Unlocks |", "| --- | --- | --- | --- | --- |");
    for (const f of sorted(r.findings)) {
      const where = f.inHead ? `\`${cell(f.file)}:${f.line}\`` : `\`${cell(f.file)}:${f.line}\` (commit ${cell(String(f.commit))})`;
      out.push(`| ${status(f)} | \`${cell(f.variable ?? f.ruleLabel)}\` \`${cell(f.preview)}\` | ${where} | ${cell(f.ruleLabel)} | ${cell(reach(r, f).join(", ") || "-")}${f.verify?.identity ? ` (as \`${cell(f.verify.identity)}\`)` : ""} |`);
    }
    out.push("");
    if (r.findings.some((f) => !f.inHead)) out.push("> Secrets marked `history` were deleted from the code but are still in git history. Rotate them with the provider; removing the line does not revoke them.", "");
  } else out.push("No secrets found.", "");
  if (r.vulns.length) {
    const counts = (["CRITICAL", "HIGH", "MODERATE", "LOW"] as Severity[]).map((s) => [s, r.vulns.filter((x) => x.severity === s).length] as const).filter(([, n]) => n);
    out.push(`### Vulnerable dependencies (${r.vulns.length})`, "", counts.map(([s, n]) => `${n} ${s.toLowerCase()}`).join(" · "), "", "| Package | Version | Fixed in | Severity | Advisory |", "| --- | --- | --- | --- | --- |");
    for (const x of r.vulns.slice(0, maxVulns)) out.push(`| \`${cell(x.name)}\` (${x.ecosystem}${x.direct ? "" : ", transitive"}) | ${x.version} | ${x.fixed ?? "-"} | ${x.severity.toLowerCase()} | ${x.advisories[0].id}: ${cell(x.advisories[0].summary).slice(0, 90)} |`);
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
  const tone = (f: Finding) => (f.baselined ? dim("BASE") : f.isNew ? red("NEW ") : f.inHead ? red("CODE") : yellow("HIST"));
  const vtag = (f: Finding) => (!f.verify ? "" : f.verify.status === "live" ? ` ${red(bold("LIVE"))}` : f.verify.status === "revoked" ? ` ${green("revoked")}` : f.verify.status === "honey" ? ` ${cyan("honey")}` : ` ${dim("unverified")}`);
  const sev = (s: Severity) => (RANK[s] >= 3 ? red : RANK[s] === 2 ? yellow : dim)(s.padEnd(8));
  const out = ["", `${bold("Tripwire")}  ${r.repo ?? r.name}${r.branch ? dim(` (${r.branch})`) : ""}  ${dim(`${r.filesScanned} files · ${r.commitsScanned} commits · ${(r.durationMs / 1000).toFixed(1)}s`)}`, ""];
  out.push(bold(`Secrets (${r.findings.length})`));
  if (!r.findings.length) out.push(dim("  none found"));
  for (const f of sorted(r.findings)) {
    out.push(`  ${tone(f)}  ${(f.variable ?? f.ruleLabel).padEnd(22)} ${cyan(`${f.file}:${f.line}`)}${f.inHead ? "" : dim(` @${f.commit}`)}  ${dim(f.ruleLabel)}${f.confidence && f.confidence !== "high" ? dim(` [${f.confidence}]`) : ""}${f.via ? dim(` (${f.via})`) : ""}${vtag(f)}`);
    const u = reach(r, f);
    out.push(dim(`        ${f.preview}${f.verify?.identity ? `  as ${f.verify.identity}` : ""}${u.length ? `  → unlocks ${u.join(", ")}` : ""}`));
    if (f.verify?.note && f.verify.status !== "live") out.push(dim(`        ${f.verify.note}`));
  }
  // A pre-commit scan does not look at dependencies, so do not claim there are none.
  const showVulns = r.diffBase !== "staged";
  if (showVulns) out.push("", bold(`Vulnerable dependencies (${r.vulns.length})`));
  if (showVulns && !r.vulns.length) out.push(dim("  none found"));
  for (const x of showVulns ? r.vulns.slice(0, maxVulns) : []) out.push(`  ${sev(x.severity)} ${`${x.name}@${x.version}`.padEnd(30)} ${x.fixed ? green(`→ ${x.fixed}`.padEnd(14)) : dim("no fix".padEnd(14))} ${dim(`${x.file}  ${x.advisories[0].id}`)}`);
  if (showVulns && r.vulns.length > maxVulns) out.push(dim(`  …and ${r.vulns.length - maxVulns} more (use --json for the full list)`));
  for (const w of r.warnings) out.push("", yellow(`warning: ${w}`));
  out.push("", v.failed ? `${red(bold("FAIL"))}  ${v.reasons.join(", ")}` : `${green(bold("PASS"))}  no blocking findings`, "");
  return out.join("\n");
}
