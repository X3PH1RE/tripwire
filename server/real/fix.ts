import type { RealScan, VulnPackage } from "../../shared/types";
import { getFile, hasToken, openMultiFilePr, repoInfo } from "../github";

export const FIX_BRANCH_PREFIX = "tripwire/deps-";
const DEP_FIELDS = ["dependencies", "devDependencies", "optionalDependencies"] as const;

const dirOf = (f: string) => (f.includes("/") ? f.slice(0, f.lastIndexOf("/") + 1) : "");
const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Bumps direct npm deps in place and pins vulnerable transitive ones through npm `overrides`. */
export function patchPackageJson(text: string, vulns: VulnPackage[]): string {
  const pkg = JSON.parse(text);
  const indent = text.match(/^[ \t]+(?=")/m)?.[0] ?? "  ";
  for (const v of vulns) {
    const field = DEP_FIELDS.find((f) => pkg[f]?.[v.name] !== undefined);
    if (field) pkg[field][v.name] = `^${v.fixed}`;
    else (pkg.overrides ??= {})[v.name] = `^${v.fixed}`;
  }
  return `${JSON.stringify(pkg, null, indent)}\n`;
}

export function patchRequirements(text: string, vulns: VulnPackage[]): string {
  let out = text;
  for (const v of vulns) out = out.replace(new RegExp(`^(\\s*${escape(v.name)}(?:\\[[^\\]]*\\])?\\s*==\\s*)${escape(v.version)}`, "im"), `$1${v.fixed}`);
  return out;
}

export function targetFile(v: VulnPackage): string {
  return v.ecosystem === "npm" ? `${dirOf(v.file)}package.json` : v.file;
}

export async function openFixPr(scan: RealScan, keys?: string[]): Promise<{ url: string; number: number; packages: string[] }> {
  if (!scan.repo) throw new Error("Fix PRs need a GitHub repository");
  if (!hasToken()) throw new Error("GITHUB_TOKEN is not set");
  const picked = scan.vulns.filter((v) => v.fixable && (!keys?.length || keys.includes(v.key)));
  if (!picked.length) throw new Error("Nothing auto-fixable was selected");
  const info = await repoInfo(scan.repo).catch(() => undefined);
  if (!info) throw new Error(`Cannot read ${scan.repo} with this token`);
  if (!info.permissions?.push) throw new Error(`Token has no write access to ${scan.repo}; fork it or grant access`);

  const byFile = new Map<string, VulnPackage[]>();
  for (const v of picked) {
    const f = targetFile(v);
    const list = byFile.get(f) ?? [];
    if (!list.some((x) => x.name === v.name)) list.push(v);
    byFile.set(f, list);
  }
  const files: { path: string; content: string }[] = [];
  for (const [path, vulns] of byFile) {
    const text = await getFile(scan.repo, path, info.default_branch);
    const content = path.endsWith("package.json") ? patchPackageJson(text, vulns) : patchRequirements(text, vulns);
    if (content !== text) files.push({ path, content });
  }
  if (!files.length) throw new Error("Manifests already up to date");

  const packages = [...byFile.values()].flat().map((v) => `${v.name}@${v.fixed}`);
  const rows = [...byFile.values()]
    .flat()
    .map((v) => `| \`${v.name}\` | ${v.version} → **${v.fixed}** | ${v.direct ? "direct" : "transitive (npm override)"} | ${v.severity} | ${v.advisories.slice(0, 3).map((a) => a.id).join(", ")} |`);
  const npm = [...byFile.keys()].some((p) => p.endsWith("package.json"));
  const body = [
    "Tripwire found dependencies with known vulnerabilities (source: [OSV.dev](https://osv.dev)) and bumped each to the lowest version that fixes every listed advisory.",
    "",
    "| Package | Version | Kind | Severity | Advisories |",
    "| --- | --- | --- | --- | --- |",
    ...rows,
    "",
    npm ? "Run `npm install` on this branch to refresh `package-lock.json` before merging." : "",
    "Left open for human review.",
  ].join("\n");
  const pr = await openMultiFilePr(scan.repo, {
    base: info.default_branch,
    branch: `${FIX_BRANCH_PREFIX}${Date.now()}`,
    files,
    message: `fix(deps): patch ${packages.length} vulnerable dependenc${packages.length === 1 ? "y" : "ies"}`,
    title: `Tripwire: patch ${packages.length} vulnerable dependenc${packages.length === 1 ? "y" : "ies"}`,
    body,
  });
  return { ...pr, packages };
}
