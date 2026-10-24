import { appendFileSync, readFileSync } from "node:fs";
import { gh } from "../github";
import type { ScanReport } from "../real/core";
import { MARKER, type Verdict } from "./report";

const esc = (s: string) => s.replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
const escProp = (s: string) => esc(s).replace(/:/g, "%3A").replace(/,/g, "%2C");

/** Workflow commands: inline annotations on the diff, job summary and step outputs. */
export function githubReport(r: ScanReport, v: Verdict, markdown: string): string[] {
  const lines: string[] = [];
  const blocking = new Set(v.blocking.map((f) => f.id));
  for (const f of r.findings) {
    if (!f.inHead) continue;
    const level = blocking.has(f.id) ? "error" : "warning";
    lines.push(`::${level} file=${escProp(f.file)},line=${f.line},title=${escProp(`Tripwire: ${f.ruleLabel}`)}::${esc(`${f.variable ?? f.ruleLabel} looks like a real secret (${f.preview}). Remove it, rotate it with the provider and load it from a secret store.`)}`);
  }
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, markdown);
  if (process.env.GITHUB_OUTPUT)
    appendFileSync(process.env.GITHUB_OUTPUT, `secrets=${r.findings.length}\nnew-secrets=${r.findings.filter((f) => f.isNew).length}\nvulns=${r.vulns.length}\nfailed=${v.failed}\n`);
  return lines;
}

export function pullRequestNumber(): number | undefined {
  const path = process.env.GITHUB_EVENT_PATH;
  if (!path) return undefined;
  try {
    return JSON.parse(readFileSync(path, "utf8")).pull_request?.number;
  } catch {
    return undefined;
  }
}

/** Creates or updates a single Tripwire comment on the current pull request. */
export async function upsertPrComment(body: string): Promise<string> {
  const repo = process.env.GITHUB_REPOSITORY;
  const pr = pullRequestNumber();
  if (!repo || !pr) return "not a pull request; skipped comment";
  if (!process.env.GITHUB_TOKEN) return "GITHUB_TOKEN not set; skipped comment";
  const comments = await gh<{ id: number; body?: string }[]>(`/repos/${repo}/issues/${pr}/comments?per_page=100`);
  const mine = comments.find((c) => c.body?.includes(MARKER));
  if (mine) await gh(`/repos/${repo}/issues/comments/${mine.id}`, { method: "PATCH", body: { body } });
  else await gh(`/repos/${repo}/issues/${pr}/comments`, { method: "POST", body: { body } });
  return `${mine ? "updated" : "posted"} comment on #${pr}`;
}
