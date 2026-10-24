import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { Severity, VulnPackage } from "../../shared/types";

export interface Dep {
  ecosystem: "npm" | "PyPI" | "Go" | "Packagist" | "RubyGems";
  name: string;
  version: string;
  file: string;
  direct: boolean;
}

const json = (p: string) => {
  try {
    return JSON.parse(readFileSync(p, "utf8"));
  } catch {
    return undefined;
  }
};

const LOCKS = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json"];

/** True when this package.json or any parent directory (npm/yarn/pnpm workspaces) has a lockfile. */
function lockedByAncestor(files: string[], pkgFile: string): boolean {
  const set = new Set(files);
  const parts = pkgFile.split("/").slice(0, -1);
  for (let i = parts.length; i >= 0; i--) {
    const prefix = parts.slice(0, i).join("/");
    if (LOCKS.some((l) => set.has(prefix ? `${prefix}/${l}` : l))) return true;
  }
  return false;
}

export function parseDeps(dir: string, files: string[]): Dep[] {
  const deps: Dep[] = [];
  const at = (f: string) => join(dir, f);
  for (const f of files) {
    const name = f.split("/").pop()!;
    const sib = (n: string) => (dirname(f) === "." ? n : `${dirname(f)}/${n}`);
    if (name === "package-lock.json") {
      const lock = json(at(f));
      const pkg = json(at(sib("package.json"))) ?? {};
      const direct = new Set(Object.keys({ ...pkg.dependencies, ...pkg.devDependencies, ...pkg.optionalDependencies }));
      if (lock?.packages) {
        for (const [key, v] of Object.entries<any>(lock.packages)) {
          if (!key || !v?.version || v.link) continue;
          const n = key.slice(key.lastIndexOf("node_modules/") + 13);
          deps.push({ ecosystem: "npm", name: n, version: v.version, file: f, direct: key === `node_modules/${n}` && direct.has(n) });
        }
      } else if (lock?.dependencies) {
        for (const [n, v] of Object.entries<any>(lock.dependencies)) if (v?.version) deps.push({ ecosystem: "npm", name: n, version: v.version, file: f, direct: direct.has(n) });
      }
    } else if (name === "package.json" && !lockedByAncestor(files, f)) {
      // Without a lockfile only exact pins say what actually gets installed; ranges like ^1.2.3 resolve to newer versions.
      const pkg = json(at(f)) ?? {};
      for (const [n, spec] of Object.entries<any>({ ...pkg.dependencies, ...pkg.devDependencies })) {
        const m = typeof spec === "string" && spec.match(/^=?v?(\d+\.\d+\.\d+(?:-[\w.]+)?)$/);
        if (m) deps.push({ ecosystem: "npm", name: n, version: m[1], file: f, direct: true });
      }
    } else if (/^requirements.*\.txt$/.test(name)) {
      for (const l of readFileSync(at(f), "utf8").split(/\r?\n/)) {
        const m = l.match(/^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)/);
        if (m) deps.push({ ecosystem: "PyPI", name: m[1], version: m[2], file: f, direct: true });
      }
    } else if (name === "go.mod") {
      let block = false;
      for (const l of readFileSync(at(f), "utf8").split(/\r?\n/)) {
        if (/^require\s*\($/.test(l.trim())) block = true;
        else if (l.trim() === ")") block = false;
        const m = (block ? l : l.replace(/^require\s+/, "")).trim().match(/^([\w./-]+\.[\w./-]+)\s+v([\w.+-]+)(\s*\/\/ indirect)?/);
        if (m && (block || l.startsWith("require"))) deps.push({ ecosystem: "Go", name: m[1], version: m[2], file: f, direct: !m[3] });
      }
    } else if (name === "composer.lock") {
      const lock = json(at(f));
      const req = Object.keys((json(at(sib("composer.json"))) ?? {}).require ?? {});
      for (const p of [...(lock?.packages ?? []), ...(lock?.["packages-dev"] ?? [])]) deps.push({ ecosystem: "Packagist", name: p.name, version: String(p.version).replace(/^v/, ""), file: f, direct: req.includes(p.name) });
    } else if (name === "Gemfile.lock") {
      const text = readFileSync(at(f), "utf8");
      const direct = new Set([...(text.split(/^DEPENDENCIES$/m)[1] ?? "").matchAll(/^\s{2}([\w.-]+)/gm)].map((m) => m[1]));
      for (const m of text.matchAll(/^ {4}([\w.-]+) \(([\d.]+)\)$/gm)) deps.push({ ecosystem: "RubyGems", name: m[1], version: m[2], file: f, direct: direct.has(m[1]) });
    }
  }
  const seen = new Set<string>();
  return deps.filter((d) => {
    const k = `${d.ecosystem}|${d.name}|${d.version}|${d.file}`;
    return seen.has(k) ? false : (seen.add(k), true);
  });
}

export function compareVersions(a: string, b: string): number {
  const pa = a.replace(/^v/, "").split(/[.+-]/);
  const pb = b.replace(/^v/, "").split(/[.+-]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? "0";
    const y = pb[i] ?? "0";
    const nx = Number(x);
    const ny = Number(y);
    if (!Number.isNaN(nx) && !Number.isNaN(ny)) {
      if (nx !== ny) return nx - ny;
    } else if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  database_specific?: { severity?: string };
  affected?: { package?: { name: string; ecosystem: string }; ranges?: { type: string; events: Record<string, string>[] }[] }[];
}

const RANK: Record<Severity, number> = { CRITICAL: 4, HIGH: 3, MODERATE: 2, LOW: 1, UNKNOWN: 0 };
const OSV = process.env.OSV_API ?? "https://api.osv.dev/v1";

function severityOf(v: OsvVuln): Severity {
  const s = v.database_specific?.severity?.toUpperCase();
  if (s === "MEDIUM") return "MODERATE";
  return s && s in RANK ? (s as Severity) : "UNKNOWN";
}

/** Smallest fixed version above `version` from the advisory's affected ranges. */
const pkgName = (name: string, eco: string) => (eco === "PyPI" ? name.toLowerCase().replace(/[-_.]+/g, "-") : name);

export function fixedFor(v: OsvVuln, dep: Dep): string | undefined {
  const candidates: string[] = [];
  for (const a of v.affected ?? []) {
    if (!a.package || a.package.ecosystem !== dep.ecosystem || pkgName(a.package.name, dep.ecosystem) !== pkgName(dep.name, dep.ecosystem)) continue;
    for (const r of a.ranges ?? []) {
      if (r.type === "GIT") continue;
      for (const e of r.events) if (e.fixed && compareVersions(e.fixed, dep.version) > 0) candidates.push(e.fixed);
    }
  }
  return candidates.sort(compareVersions)[0];
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${OSV}${path}`, { method: "POST", body: JSON.stringify(body), headers: { "Content-Type": "application/json" }, signal: AbortSignal.timeout(20_000) });
  if (!res.ok) throw new Error(`OSV ${path}: ${res.status}`);
  return res.json() as Promise<T>;
}

export async function findVulns(deps: Dep[]): Promise<VulnPackage[]> {
  const ids: string[][] = [];
  for (let i = 0; i < deps.length; i += 500) {
    const chunk = deps.slice(i, i + 500);
    const res = await post<{ results: { vulns?: { id: string }[] }[] }>("/querybatch", { queries: chunk.map((d) => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version })) });
    res.results.forEach((r) => ids.push((r.vulns ?? []).map((v) => v.id)));
  }
  const unique = [...new Set(ids.flat())].slice(0, 200);
  const details = new Map<string, OsvVuln>();
  for (let i = 0; i < unique.length; i += 10) {
    await Promise.all(
      unique.slice(i, i + 10).map(async (id) => {
        const res = await fetch(`${OSV}/vulns/${id}`, { signal: AbortSignal.timeout(15_000) });
        if (res.ok) details.set(id, (await res.json()) as OsvVuln);
      }),
    );
  }
  const out: VulnPackage[] = [];
  deps.forEach((dep, i) => {
    const advisories = ids[i].map((id) => details.get(id)).filter((v): v is OsvVuln => !!v);
    if (!advisories.length) return;
    const fixes = advisories.map((v) => fixedFor(v, dep));
    const fixed = fixes.filter((f): f is string => !!f).sort(compareVersions).pop();
    const list = advisories.map((v) => ({ id: v.aliases?.find((a) => a.startsWith("CVE-")) ?? v.id, summary: v.summary ?? v.details?.slice(0, 140) ?? v.id, severity: severityOf(v) }));
    list.sort((a, b) => RANK[b.severity] - RANK[a.severity]);
    // Transitive npm deps are pinned through `overrides`, which is only safe within the same major version.
    const sameMajor = !!fixed && fixed.split(".")[0] === dep.version.split(".")[0];
    const fixable = !!fixed && ((dep.ecosystem === "npm" && /package(-lock)?\.json$/.test(dep.file) && (dep.direct || sameMajor)) || (dep.ecosystem === "PyPI" && dep.direct));
    out.push({ key: `${dep.ecosystem}:${dep.name}@${dep.version}:${dep.file}`, ecosystem: dep.ecosystem, name: dep.name, version: dep.version, file: dep.file, direct: dep.direct, severity: list[0].severity, advisories: list, fixed, fixable });
  });
  return out.sort((a, b) => RANK[b.severity] - RANK[a.severity] || Number(b.direct) - Number(a.direct) || b.advisories.length - a.advisories.length);
}
