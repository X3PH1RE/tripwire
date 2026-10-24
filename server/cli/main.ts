import { writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import type { Severity } from "../../shared/types";
import { resolve } from "node:path";
import { isRemote, scanTarget } from "../real/core";
import { BASELINE_FILE, writeBaseline } from "../detect/baseline";
import { CONFIDENCE_RANK, type Confidence } from "../detect/schema";
import { contain } from "./contain";
import { checkHoney, createHoney, decoyFile, HONEY_FILE, plantHoney, publicHoney } from "../real/honey";
import { githubReport, upsertPrComment } from "./github";
import { evaluate, RANK, toMarkdown, toText } from "./report";

export const HELP = `Usage: tripwire scan [path | git url | owner/repo] [options]
       tripwire honey create [--email you@x.com] [--plant owner/repo] [--file path]
       tripwire baseline [path]  accept every current finding in .tripwire-baseline.json
       tripwire contain [path]   plan how to kill every live key (--apply to revoke them)
       tripwire honey check      (exit 1 if any decoy was used)

Finds secrets in the code and git history, maps what each one unlocks,
and checks dependencies against OSV.dev. Exits 1 when something blocks.

Options:
  --diff <base>           Only secrets added since <base> block (for pull requests)
  --history <n>           Commits of history to scan (default 300, 0 = none)
  --fail-on-vulns <sev>   Also fail on vulnerable deps: low|moderate|high|critical (default: none)
  --no-fail-secrets       Report secrets without failing
  --skip-vulns            Skip the dependency check
  --min-confidence <c>    Only findings at this confidence or above block: low|medium|high (default: low)
  --apply                 contain: actually revoke live keys (default is a dry-run plan)
  --no-baseline           Ignore .tripwire-baseline.json
  --verify                Ask each provider (read-only) if found keys work and what they reach
  --json <file|->         Write the full report as JSON
  --markdown <file>       Write a Markdown report
  --github                GitHub Actions: annotations, job summary, outputs
  --comment               GitHub Actions: post/update a pull request comment
  -q, --quiet             No progress output
  -h, --help              Show this help

Silence a false positive with "tripwire:ignore" on the line, or globs in .tripwireignore.
`;

export async function main(argv: string[], log: (s: string) => void = (s) => process.stdout.write(s), err: (s: string) => void = (s) => process.stderr.write(s)): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      diff: { type: "string" },
      history: { type: "string" },
      "fail-on-vulns": { type: "string", default: "none" },
      "no-fail-secrets": { type: "boolean" },
      "skip-vulns": { type: "boolean" },
      verify: { type: "boolean" },
      "min-confidence": { type: "string", default: "low" },
      "no-baseline": { type: "boolean" },
      apply: { type: "boolean" },
      email: { type: "string" },
      plant: { type: "string" },
      file: { type: "string" },
      json: { type: "string" },
      markdown: { type: "string" },
      github: { type: "boolean" },
      comment: { type: "boolean" },
      quiet: { type: "boolean", short: "q" },
      help: { type: "boolean", short: "h" },
    },
  });
  const [cmd, target = "."] = positionals;
  if (values.help || !cmd) return log(HELP), 0;
  if (cmd === "honey") return honey(positionals[1], values, log, err);
  const minConfidence = values["min-confidence"]!.toLowerCase();
  if (!(minConfidence in CONFIDENCE_RANK)) return err("--min-confidence must be one of low, medium, high\n"), 2;
  if (cmd === "baseline") return baseline(target, log, err);
  if (cmd === "contain") return contain(target, !!values.apply, values.json === "-", log, err, !!values.quiet);
  if (cmd !== "scan") return err(`Unknown command "${cmd}".\n\n${HELP}`), 2;
  const failVulns = values["fail-on-vulns"]!.toUpperCase();
  if (failVulns !== "NONE" && !(failVulns in RANK)) return err(`--fail-on-vulns must be one of low, moderate, high, critical, none\n`), 2;
  const history = values.history === undefined ? undefined : Number(values.history);
  if (history !== undefined && !(history >= 0)) return err("--history must be a number >= 0\n"), 2;

  const report = await scanTarget(target, { history, diff: values.diff, vulns: !values["skip-vulns"], verify: !!values.verify, baseline: !values["no-baseline"] }, (stage) => !values.quiet && err(`tripwire: ${stage}…\n`));
  const verdict = evaluate(report, { secrets: !values["no-fail-secrets"], vulns: failVulns === "NONE" ? "none" : (failVulns as Severity), minConfidence: minConfidence as Confidence });
  const markdown = toMarkdown(report, verdict);

  if (values.json === "-") log(JSON.stringify(report, null, 2) + "\n");
  else log(toText(report, verdict, !!process.stdout.isTTY && !process.env.NO_COLOR));
  if (values.json && values.json !== "-") writeFileSync(values.json, JSON.stringify(report, null, 2));
  if (values.markdown) writeFileSync(values.markdown, markdown);
  if (values.github) for (const line of githubReport(report, verdict, markdown)) log(line + "\n");
  if (values.comment) {
    const note = await upsertPrComment(markdown).catch((e: Error) => `could not comment (${e.message})`);
    err(`tripwire: ${note}\n`);
  }
  return verdict.failed ? 1 : 0;
}

async function honey(sub: string | undefined, values: { email?: string; plant?: string; file?: string }, log: (s: string) => void, err: (s: string) => void): Promise<number> {
  if (sub === "create") {
    const r = await createHoney({ memo: `Tripwire honey secret${values.plant ? ` for ${values.plant}` : ""}`, email: values.email, repo: values.plant });
    log(`Created decoy AWS key ${r.accessKeyId} (stored in ${HONEY_FILE}).\n`);
    if (values.plant) {
      const planted = await plantHoney(r.id, values.plant, values.file);
      log(`Planting PR: ${planted.prUrl}\n`);
    } else log(`\nPaste this somewhere an attacker would look (.env, CI config, backups):\n\n${decoyFile(r)}\n`);
    return 0;
  }
  if (sub === "check") {
    const { records } = await checkHoney();
    if (!records.length) return log("No honey secrets yet. Run `tripwire honey create` first.\n"), 0;
    let used = 0;
    for (const t of records.map(publicHoney)) {
      log(`${t.accessKeyPreview}  ${t.repo ?? "unplanted"}${t.file ? `:${t.file}` : ""}  ${t.hits.length ? `USED ${t.hits.length}x` : "quiet"}${t.checkError ? `  (check failed: ${t.checkError})` : ""}\n`);
      for (const h of t.hits.slice(0, 5)) log(`    ${new Date(h.at).toISOString()}  ${h.ip ?? "?"}  ${[h.location, h.org].filter(Boolean).join(" · ")}  ${h.action ?? ""}\n`);
      used += t.hits.length;
    }
    return used ? 1 : 0;
  }
  return err(`Usage: tripwire honey create|check\n`), 2;
}

async function baseline(target: string, log: (s: string) => void, err: (s: string) => void): Promise<number> {
  if (isRemote(target)) return err("tripwire baseline needs a local checkout.\n"), 2;
  const report = await scanTarget(target, { vulns: false, baseline: false });
  const entries = report.findings.flatMap((f) => (f.fingerprint ? [{ fingerprint: f.fingerprint, rule: f.rule, file: f.file }] : []));
  const path = writeBaseline(resolve(target), entries);
  log(`Accepted ${entries.length} finding${entries.length === 1 ? "" : "s"} in ${path}.\nCommit ${BASELINE_FILE}; those findings are still listed but no longer fail the check.\n`);
  return 0;
}
