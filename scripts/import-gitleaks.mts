// Regenerates server/detect/rules/gitleaks.json from the Gitleaks default config (MIT).
// Usage: npm run import:gitleaks [path-or-url]
import { readFileSync, writeFileSync } from "node:fs";
import { importGitleaks } from "../server/detect/gitleaks";
import { compileRegex } from "../server/detect/filters";

const DEFAULT = "https://raw.githubusercontent.com/gitleaks/gitleaks/v8.30.1/config/gitleaks.toml";
const src = process.argv[2] ?? DEFAULT;
const toml = /^https?:/.test(src) ? await (await fetch(src)).text() : readFileSync(src, "utf8");

const pack = importGitleaks(toml);
let broken = 0;
for (const r of pack.rules) {
  try {
    compileRegex(r.regex, "g");
  } catch (err) {
    broken++;
    console.error(`cannot compile ${r.id}: ${(err as Error).message}`);
  }
}
writeFileSync(new URL("../server/detect/rules/gitleaks.json", import.meta.url), JSON.stringify(pack, null, 1) + "\n");
console.log(`imported ${pack.rules.length} rules from ${src} (${broken} failed to compile)`);
if (broken) process.exit(1);
