// Downloads the pinned Gitleaks release into bench/.cache so the benchmark can run it next to Tripwire.
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export const VERSION = "8.30.1";
const cache = join(fileURLToPath(new URL(".", import.meta.url)), ".cache");
const exe = join(cache, process.platform === "win32" ? "gitleaks.exe" : "gitleaks");

export function gitleaksPath(): string | undefined {
  return existsSync(exe) ? exe : undefined;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  if (gitleaksPath()) {
    console.log(`already present: ${exe}`);
    process.exit(0);
  }
  const os = { win32: "windows", darwin: "darwin", linux: "linux" }[process.platform as string];
  const arch = { x64: "x64", arm64: "arm64" }[process.arch as string];
  if (!os || !arch) throw new Error(`no Gitleaks build for ${process.platform}/${process.arch}`);
  const ext = os === "windows" ? "zip" : "tar.gz";
  const url = `https://github.com/gitleaks/gitleaks/releases/download/v${VERSION}/gitleaks_${VERSION}_${os}_${arch}.${ext}`;
  mkdirSync(cache, { recursive: true });
  const archive = join(cache, `gitleaks.${ext}`);
  // curl follows GitHub's release redirect more reliably than Node's fetch does behind some proxies.
  execFileSync("curl", ["-fsSL", "--retry", "3", "-o", archive, url], { stdio: "inherit" });
  // Windows ships bsdtar (reads zip); Git Bash's GNU tar does not, so call the system one explicitly.
  const tar = process.platform === "win32" ? join(process.env.SystemRoot ?? "C:\\Windows", "System32", "tar.exe") : "tar";
  execFileSync(tar, ["-xf", archive, "-C", cache], { stdio: "inherit" });
  rmSync(archive);
  console.log(`installed ${exe}`);
}
