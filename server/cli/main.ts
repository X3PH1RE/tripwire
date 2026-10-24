import { writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import type { Severity } from "../../shared/types";
import { scanTarget } from "../real/core";
import { githubReport, upsertPrComment } from "./github";
import { evaluate, RANK, toMarkdown, toText } from "./report";

export const HELP = `Usage: tripwire scan [path | git url | owner/repo] [options]

Finds secrets in the code and git history, maps what each one unlocks,
and checks dependencies against OSV.dev. Exits 1 when something blocks.

Options:
  --diff <base>           Only secrets added since <base> block (for pull requests)
  --history <n>           Commits of history to scan (default 300, 0 = none)
  --fail-on-vulns <sev>   Also fail on vulnerable deps: low|moderate|high|critical (default: none)
  --no-fail-secrets       Report secrets without failing
  --skip-vulns            Skip the dependency check
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
  if (cmd !== "scan") return err(`Unknown command "${cmd}".\n\n${HELP}`), 2;
  const failVulns = values["fail-on-vulns"]!.toUpperCase();
  if (failVulns !== "NONE" && !(failVulns in RANK)) return err(`--fail-on-vulns must be one of low, moderate, high, critical, none\n`), 2;
  const history = values.history === undefined ? undefined : Number(values.history);
  if (history !== undefined && !(history >= 0)) return err("--history must be a number >= 0\n"), 2;

  const report = await scanTarget(target, { history, diff: values.diff, vulns: !values["skip-vulns"] }, (stage) => !values.quiet && err(`tripwire: ${stage}…\n`));
  const verdict = evaluate(report, { secrets: !values["no-fail-secrets"], vulns: failVulns === "NONE" ? "none" : (failVulns as Severity) });
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
