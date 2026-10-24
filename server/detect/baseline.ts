import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const BASELINE_FILE = ".tripwire-baseline.json";

export interface BaselineEntry {
  fingerprint: string;
  rule: string;
  file: string;
}

export interface Baseline {
  version: 1;
  /** Hashes only: the file is safe to commit and never contains a secret. */
  entries: BaselineEntry[];
}

export function loadBaseline(dir: string): Set<string> {
  const path = join(dir, BASELINE_FILE);
  if (!existsSync(path)) return new Set();
  try {
    const doc = JSON.parse(readFileSync(path, "utf8")) as Baseline;
    return new Set((doc.entries ?? []).map((e) => e.fingerprint));
  } catch {
    return new Set();
  }
}

export function writeBaseline(dir: string, entries: BaselineEntry[]): string {
  const unique = new Map(entries.map((e) => [e.fingerprint, e]));
  const doc: Baseline = { version: 1, entries: [...unique.values()].sort((a, b) => a.file.localeCompare(b.file) || a.rule.localeCompare(b.rule)) };
  const path = join(dir, BASELINE_FILE);
  writeFileSync(path, JSON.stringify(doc, null, 2) + "\n");
  return path;
}
