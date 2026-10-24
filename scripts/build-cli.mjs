// Bundles the CLI and the GitHub Action into action/ (committed, so `npx github:...` and `uses: ./` need no build step).
import { build } from "esbuild";
import { renameSync } from "node:fs";

await build({
  entryPoints: ["server/cli/bin.ts", "server/cli/action.ts"],
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node20",
  outdir: "action",
  outExtension: { ".js": ".mjs" },
  entryNames: "[name]",
  banner: { js: "#!/usr/bin/env node" },
  logLevel: "error",
});
renameSync("action/bin.mjs", "action/tripwire.mjs");
console.log("built action/tripwire.mjs and action/action.mjs");
