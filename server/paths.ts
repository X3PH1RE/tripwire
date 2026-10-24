import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const TEMPLATE_DIR = resolve(ROOT, "demo-world/acme-shop");
export const RUNTIME_DIR = resolve(ROOT, "runtime/acme-shop");
export const WORLD_FILE = resolve(ROOT, "demo-world/world.json");
