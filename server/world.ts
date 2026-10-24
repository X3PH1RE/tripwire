import { cpSync, readFileSync, rmSync } from "node:fs";
import type { World } from "../shared/types";
import { RUNTIME_DIR, TEMPLATE_DIR, WORLD_FILE } from "./paths";

export function loadWorld(): World {
  return JSON.parse(readFileSync(WORLD_FILE, "utf8")) as World;
}

export function resetRuntime(): void {
  rmSync(RUNTIME_DIR, { recursive: true, force: true });
  cpSync(TEMPLATE_DIR, RUNTIME_DIR, { recursive: true });
}
