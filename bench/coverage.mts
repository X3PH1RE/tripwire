// Provider coverage on data this project did not write.
//
// TruffleHog keeps a unit test per detector (800+ providers), each with an example credential for that provider. For every
// such folder this asks: does the tool report *anything* in it? That says how many providers a tool recognises at all.
// It is a coarse proxy, not a recall figure: a hit is any finding in the folder, and the example strings are TruffleHog's.
// The source is fetched at run time into bench/.cache (sparse, ~25 MB) and never committed (AGPL-3.0).
//
//   npm run bench:coverage
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { defaultEngine } from "../server/detect/index.ts";
import { listFiles } from "../server/real/scan.ts";
import { gitleaksPath, VERSION } from "./fetch-gitleaks.mts";

const here = fileURLToPath(new URL(".", import.meta.url));
const SRC = join(here, ".cache", "trufflehog-src");
const ROOT = join(SRC, "pkg", "detectors");

if (!existsSync(ROOT)) {
  mkdirSync(join(here, ".cache"), { recursive: true });
  console.log("fetching TruffleHog's detector tests (sparse clone)…");
  execFileSync("git", ["clone", "--quiet", "--depth", "1", "--filter=blob:none", "--sparse", "https://github.com/trufflesecurity/trufflehog.git", SRC], { stdio: "inherit" });
  execFileSync("git", ["-C", SRC, "sparse-checkout", "set", "pkg/detectors"], { stdio: "inherit" });
}

// Denominator: detector folders whose unit tests carry example credential strings.
const folders = readdirSync(ROOT, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name);
const withExamples = folders.filter((d) =>
  readdirSync(join(ROOT, d)).some((f) => f.endsWith("_test.go") && !f.includes("integration") && /valid[Pp]attern|\binput:\s*[`"]/.test(readFileSync(join(ROOT, d, f), "utf8"))),
);
const universe = new Set(withExamples);

const folderOf = (file: string) => file.split("\\").join("/").split("pkg/detectors/").pop()!.split("/")[0];

// Tripwire: the engine on every file, no de-duplication across files.
const engine = defaultEngine();
const tripwire = new Set<string>();
for (const f of await listFiles(ROOT)) {
  let text = "";
  try {
    text = readFileSync(join(ROOT, f), "utf8");
  } catch {
    continue;
  }
  if (engine.scan(text, f).length) tripwire.add(folderOf(f));
}

const gitleaks = new Set<string>();
const gl = gitleaksPath();
if (gl) {
  const out = join(here, "out", "gitleaks-coverage.json");
  mkdirSync(join(here, "out"), { recursive: true });
  spawnSync(gl, ["dir", ROOT, "--no-banner", "--exit-code", "0", "--report-format", "json", "--report-path", out, "--log-level", "error", "--max-target-megabytes", "5"]);
  for (const f of JSON.parse(readFileSync(out, "utf8")) as { File: string }[]) gitleaks.add(folderOf(f.File));
}

const covered = (s: Set<string>) => [...universe].filter((d) => s.has(d));
const t = covered(tripwire);
const g = covered(gitleaks);
const neither = [...universe].filter((d) => !tripwire.has(d) && !gitleaks.has(d));
const pct = (n: number) => `${((100 * n) / universe.size).toFixed(1)}%`;

const lines = [
  "# Provider coverage",
  "",
  `For each of ${universe.size} providers that TruffleHog has a detector and example credentials for, does the tool report anything in that provider's test folder? Example strings are TruffleHog's, so this measures breadth of recognised providers, not accuracy. TruffleHog itself recognises all of them by construction and is not scored here.`,
  "",
  "| Tool | Providers recognised | Share |",
  "| --- | --- | --- |",
  `| Tripwire | ${t.length} | ${pct(t.length)} |`,
  gl ? `| Gitleaks ${VERSION} | ${g.length} | ${pct(g.length)} |` : "| Gitleaks | not installed (`npm run bench:fetch`) | |",
  "",
  `Recognised only by Tripwire: ${t.filter((d) => !gitleaks.has(d)).length}. Recognised only by Gitleaks: ${g.filter((d) => !tripwire.has(d)).length}. Recognised by neither: ${neither.length}.`,
  "",
  `Neither tool recognises (first 40): ${neither.slice(0, 40).join(", ")}${neither.length > 40 ? ", …" : ""}`,
  "",
  "Read this as: Tripwire is level with Gitleaks (it ships Gitleaks' rules) and well short of TruffleHog's breadth. Many of the unrecognised providers use bare, context-free token formats that no pattern scanner can tell apart from random text without a verification call; TruffleHog covers them by calling the provider.",
  "",
];
writeFileSync(join(here, "COVERAGE.md"), lines.join("\n"));
console.log(lines.join("\n"));
