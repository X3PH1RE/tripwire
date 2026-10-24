// Scores Tripwire (and Gitleaks, when bench/.cache has it) on the labeled corpus.
//   npm run bench:fetch   # once: downloads Gitleaks
//   npm run bench         # prints the table and writes bench/RESULTS.md
//   npm run bench -- --gate  # exit 1 if Tripwire falls below the thresholds (regression check)
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { scanTarget } from "../server/real/core";
import { buildCorpus, type Case } from "./corpus.mts";
import { gitleaksPath, VERSION } from "./fetch-gitleaks.mts";

const here = fileURLToPath(new URL(".", import.meta.url));
const root = join(here, "out", "corpus");
const GATE = { recall: 0.95, precision: 0.95 };

interface Result {
  tool: string;
  version: string;
  flagged: Map<string, string[]>; // case id -> rule ids
  ms: number;
}

function write(cases: Case[]): void {
  rmSync(root, { recursive: true, force: true });
  for (const c of cases) {
    const file = join(root, c.id, c.path);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, c.content);
  }
}

async function runTripwire(): Promise<Result> {
  const t0 = Date.now();
  const report = await scanTarget(root, { vulns: false, history: 0, baseline: false });
  const flagged = new Map<string, string[]>();
  for (const f of report.findings) {
    const id = f.file.split("/")[0];
    flagged.set(id, [...(flagged.get(id) ?? []), f.rule]);
  }
  return { tool: "Tripwire", version: "this repo", flagged, ms: Date.now() - t0 };
}

function runGitleaks(): Result | undefined {
  const bin = gitleaksPath();
  if (!bin) return undefined;
  const out = join(here, "out", "gitleaks.json");
  const t0 = Date.now();
  execFileSync(bin, ["dir", root, "--no-banner", "--exit-code", "0", "--report-format", "json", "--report-path", out, "--log-level", "error"], { stdio: "ignore" });
  const flagged = new Map<string, string[]>();
  for (const f of JSON.parse(readFileSync(out, "utf8")) as { File: string; RuleID: string }[]) {
    const id = relative(root, f.File).split(/[\\/]/)[0];
    flagged.set(id, [...(flagged.get(id) ?? []), f.RuleID]);
  }
  return { tool: "Gitleaks", version: VERSION, flagged, ms: Date.now() - t0 };
}

function score(cases: Case[], r: Result) {
  const pos = cases.filter((c) => c.kind === "positive");
  const neg = cases.filter((c) => c.kind === "negative");
  const missed = pos.filter((c) => !r.flagged.has(c.id));
  const falsePos = neg.filter((c) => r.flagged.has(c.id));
  const tp = pos.length - missed.length;
  const precision = tp + falsePos.length ? tp / (tp + falsePos.length) : 1;
  const recall = tp / pos.length;
  return { tp, fn: missed.length, fp: falsePos.length, tn: neg.length - falsePos.length, precision, recall, f1: (2 * precision * recall) / (precision + recall || 1), missed, falsePos };
}

const pct = (x: number) => `${(x * 100).toFixed(1)}%`;

const cases = buildCorpus();
write(cases);
const results = [await runTripwire(), runGitleaks()].filter((r): r is Result => !!r);
const pos = cases.filter((c) => c.kind === "positive").length;
const neg = cases.length - pos;

const lines = [
  "# Detection benchmark",
  "",
  `${pos} positive cases (real provider token formats with synthetic values, several contexts each, plus encoded and multi-line secrets) and ${neg} negative cases (placeholders, hashes, UUIDs, env references, lockfiles, docs, identifiers).`,
  "A case counts as detected when the tool reports anything in its file. A negative case that gets any finding is a false positive.",
  "",
  "| Tool | Version | Precision | Recall | F1 | Missed | False positives | Time |",
  "| --- | --- | --- | --- | --- | --- | --- | --- |",
];
const scored = results.map((r) => ({ r, s: score(cases, r) }));
for (const { r, s } of scored) lines.push(`| ${r.tool} | ${r.version} | ${pct(s.precision)} | ${pct(s.recall)} | ${pct(s.f1)} | ${s.fn}/${pos} | ${s.fp}/${neg} | ${r.ms} ms |`);
if (results.length === 1) lines.push("", "_Gitleaks was not found; run `npm run bench:fetch` to compare._");
for (const { r, s } of scored) {
  lines.push("", `## ${r.tool}`, "");
  lines.push(s.missed.length ? `Missed: ${s.missed.map((c) => `${c.name} (${c.id})`).join("; ")}` : "Missed: none");
  lines.push("", s.falsePos.length ? `False positives: ${s.falsePos.map((c) => `${c.name} (${c.id}: ${[...new Set(r.flagged.get(c.id))].join(", ")})`).join("; ")}` : "False positives: none");
}
lines.push("", "## Caveat", "", "The corpus is written by the Tripwire authors, so it favours Tripwire's own rules. Treat the numbers as a regression gate and a parity check against Gitleaks, not as an independent ranking. Add cases to `bench/corpus.mts` whenever a real-world miss or false positive turns up.", "");
const md = lines.join("\n");
writeFileSync(join(here, "RESULTS.md"), md);
console.log(md);

if (process.argv.includes("--gate")) {
  const tw = scored[0].s;
  if (tw.recall < GATE.recall || tw.precision < GATE.precision) {
    console.error(`\nGate failed: need recall >= ${pct(GATE.recall)} and precision >= ${pct(GATE.precision)}.`);
    process.exit(1);
  }
}
