import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

export const HOOK_MARKER = "# tripwire-hook";

/** Prefers a `tripwire` on PATH (fast); otherwise fetches the published package. TRIPWIRE_SKIP=1 bypasses it; `git commit --no-verify` always can. */
export const HOOK_SCRIPT = `#!/bin/sh
${HOOK_MARKER}: installed by \`tripwire install-hook\`. Remove with \`tripwire install-hook --remove\`.
[ "$TRIPWIRE_SKIP" = "1" ] && exit 0
if command -v tripwire >/dev/null 2>&1; then
  exec tripwire scan --staged
fi
exec npx --yes tripwire-scan scan --staged
`;

function hookPath(dir: string): string {
  // Respects core.hooksPath and worktrees, unlike assuming .git/hooks.
  const rel = execFileSync("git", ["-C", dir, "rev-parse", "--git-path", "hooks/pre-commit"], { encoding: "utf8" }).trim();
  return resolve(dir, rel);
}

/** Installs (or with `remove`, deletes) the pre-commit hook. Never overwrites a hook it did not write unless `force`. */
export function installHook(target: string, opts: { remove?: boolean; force?: boolean }, log: (s: string) => void, err: (s: string) => void): number {
  const dir = resolve(target);
  let path: string;
  try {
    path = hookPath(dir);
  } catch {
    return err(`${dir} is not a git repository.\n`), 2;
  }
  const existing = existsSync(path) ? readFileSync(path, "utf8") : undefined;
  const ours = existing?.includes(HOOK_MARKER);
  if (opts.remove) {
    if (!existing) return log("No pre-commit hook installed.\n"), 0;
    if (!ours) return err(`${path} was not installed by Tripwire; leaving it alone.\n`), 2;
    rmSync(path);
    return log(`Removed ${path}\n`), 0;
  }
  if (existing && !ours && !opts.force) {
    return err(`A pre-commit hook already exists at ${path}.\nAdd \`tripwire scan --staged\` to it yourself, use the pre-commit framework (see README), or re-run with --force to replace it.\n`), 2;
  }
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, HOOK_SCRIPT, { mode: 0o755 });
  chmodSync(path, 0o755);
  log(`Installed ${path}\nCommits now fail if they add a secret. Bypass once with \`git commit --no-verify\` or TRIPWIRE_SKIP=1.\n`);
  return 0;
}
