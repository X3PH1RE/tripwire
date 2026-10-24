import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import type { GraphEdge, GraphNode, ScanHit } from "../shared/types";
import { reachableNodes } from "./graph";
import { ROOT, RUNTIME_DIR } from "./paths";

const PREFIX = /tw_fake_[a-z]+_[a-z0-9]{16,}/;
const ASSIGN = /^\s*(?:export\s+)?([A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|URL))\s*[:=]\s*["']?([^\s"']+)/;
const URL_PASSWORD = /^[a-z][a-z0-9+.-]*:\/\/[^:/@\s]+:([^@\s]+)@/i;
const LONG_TOKEN = /[A-Za-z0-9_\-]{24,}/g;
const SKIP_DIRS = new Set([".git", "node_modules"]);

export function entropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of counts.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function looksSecret(value: string): boolean {
  return PREFIX.test(value) || (value.length >= 20 && entropy(value) >= 3.5);
}

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) out.push(...walk(full));
    else if (st.size < 1_000_000) out.push(full);
  }
  return out;
}

function preview(value: string): string {
  const m = value.match(PREFIX);
  const v = m ? m[0] : value;
  return v.length > 18 ? `${v.slice(0, 18)}…` : v;
}

function scanLine(text: string): Omit<ScanHit, "file" | "line" | "kind" | "reaches">[] {
  const assign = text.match(ASSIGN);
  if (assign) {
    const [, variable, value] = assign;
    const urlPw = value.match(URL_PASSWORD);
    if (value.includes("://") && !urlPw) return [];
    const candidate = urlPw ? urlPw[1] : value;
    if (!looksSecret(candidate)) return [];
    return [{ variable, rule: PREFIX.test(candidate) ? "prefix" : "assignment", preview: preview(candidate), entropy: +entropy(candidate).toFixed(2) }];
  }
  const prefixed = text.match(PREFIX);
  if (prefixed) return [{ rule: "prefix", preview: preview(prefixed[0]), entropy: +entropy(prefixed[0]).toFixed(2) }];
  return (text.match(LONG_TOKEN) ?? [])
    .filter((t) => entropy(t) >= 4.2)
    .map((t) => ({ rule: "entropy" as const, preview: preview(t), entropy: +entropy(t).toFixed(2) }));
}

export function scanDir(dir: string, nodes: GraphNode[], edges: GraphEdge[]): ScanHit[] {
  const hits: ScanHit[] = [];
  for (const full of walk(dir)) {
    const buf = readFileSync(full);
    if (buf.includes(0)) continue;
    const file = relative(dir, full).split("\\").join("/");
    buf.toString("utf8").split(/\r?\n/).forEach((text, i) => {
      for (const h of scanLine(text)) {
        const node = nodes.find((n) => (n.type === "secret" || n.type === "decoy") && n.file === file && n.label === h.variable);
        hits.push({
          ...h,
          file,
          line: i + 1,
          nodeId: node?.id,
          provider: node?.provider,
          kind: node ? (node.type as "secret" | "decoy") : "unknown",
          reaches: node
            ? reachableNodes(nodes, edges, node.id)
                .filter((r) => r.type === "resource")
                .map((r) => ({ id: r.id, label: r.label, sensitivity: r.sensitivity }))
            : [],
        });
      }
    });
  }
  return hits;
}

export function scanTarget(target: string | undefined, nodes: GraphNode[], edges: GraphEdge[]): { target: string; hits: ScanHit[] } {
  if (!target) return { target: "runtime/acme-shop", hits: scanDir(RUNTIME_DIR, nodes, edges) };
  if (/^(https?:\/\/|git@)/.test(target)) {
    const tmp = mkdtempSync(join(tmpdir(), "tripwire-scan-"));
    try {
      execFileSync("git", ["clone", "--depth", "1", "--quiet", target, tmp], { stdio: "pipe", timeout: 30_000 });
      return { target, hits: scanDir(tmp, nodes, edges) };
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  }
  return { target, hits: scanDir(resolve(ROOT, target), nodes, edges) };
}
