import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { GraphNode } from "../shared/types";
import { blastHops } from "./graph";
import { RUNTIME_DIR } from "./paths";
import { addIncident, boosts, broadcast, node, script, sleep, state } from "./state";

const randomToken = (n = 32) => Array.from({ length: n }, () => "abcdefghijklmnopqrstuvwxyz0123456789"[Math.floor(Math.random() * 36)]).join("");
export const fakeValue = (provider: string) => `tw_fake_${provider}_${randomToken()}`;

const DECOYS = [
  { id: "dec-api", label: "BACKUP_DB_PASSWORD", file: "api/.env", service: "svc-api", position: { x: 240, y: 320 } },
  { id: "dec-web", label: "ADMIN_API_TOKEN", file: "web/.env", service: "svc-web", position: { x: 240, y: 120 } },
  { id: "dec-worker", label: "PAYOUTS_SECRET", file: "worker/.env", service: "svc-worker", position: { x: 240, y: 520 } },
  { id: "dec-ci", label: "PROD_SSH_KEY", file: ".github/workflows/deploy.yml", service: "svc-ci", position: { x: 240, y: 680 } },
];

const ATTACKERS = [
  { ip: "203.0.113.42", city: "Frankfurt, DE", agent: "python-requests/2.31" },
  { ip: "198.51.100.7", city: "Singapore, SG", agent: "curl/8.4.0" },
  { ip: "192.0.2.199", city: "São Paulo, BR", agent: "aws-cli/2.15" },
  { ip: "203.0.113.88", city: "Amsterdam, NL", agent: "Go-http-client/2.0" },
];

function plantLine(file: string, label: string, value: string): number {
  const path = join(RUNTIME_DIR, file);
  const lines = readFileSync(path, "utf8").replace(/\n$/, "").split("\n");
  if (file.endsWith(".yml")) {
    const at = lines.findIndex((l) => l.includes("DEPLOY_TOKEN:")) + 1;
    const indent = lines[at - 1].match(/^\s*/)![0];
    lines.splice(at, 0, `${indent}${label}: ${value}`);
    writeFileSync(path, lines.join("\n") + "\n");
    return at + 1;
  }
  lines.push(`${label}=${value}`);
  writeFileSync(path, lines.join("\n") + "\n");
  return lines.length;
}

export function plantTripwires(): void {
  if (state.honey.planted) return;
  for (const d of DECOYS) {
    const line = plantLine(d.file, d.label, fakeValue("honey"));
    state.nodes.push({ id: d.id, type: "decoy", label: d.label, provider: "honey", file: d.file, line, status: "ok", position: d.position });
    state.edges.push({ id: `${d.service}--stored_in--${d.id}`, from: d.service, to: d.id, kind: "stored_in" });
  }
  state.honey.planted = true;
  addIncident({
    kind: "info",
    title: "Tripwires planted",
    summary: `${DECOYS.length} decoy secrets written into env and CI files. Any use of them is an attack.`,
    affectedNodeIds: DECOYS.map((d) => d.id),
  });
  broadcast();
}

export function simulateAttacker(): void {
  if (!state.honey.planted) plantTripwires();
  const i = state.honey.attacks % DECOYS.length;
  const decoy = node(DECOYS[i].id);
  const who = ATTACKERS[i];
  state.honey.attacks++;
  decoy.status = "attacked";
  const neighbours = state.nodes.filter((n) => n.type === "secret" && n.file === decoy.file && n.status !== "rotated");
  for (const n of neighbours) {
    boosts[n.id] = (boosts[n.id] ?? 0) + 10;
    if (n.status === "ok") n.status = "exposed";
  }
  addIncident({
    kind: "honey",
    title: `Tripwire fired: ${decoy.label}`,
    summary: `Someone used a decoy key. ${neighbours.length ? `Real secrets in the same file are now presumed leaked: ${neighbours.map((n) => n.label).join(", ")}.` : ""}`,
    details: [
      { label: "Decoy", value: decoy.label },
      { label: "Planted in", value: `${decoy.file}:${decoy.line}` },
      { label: "Used at", value: new Date().toLocaleTimeString() },
      { label: "Source", value: `${who.ip} · ${who.city}` },
      { label: "Client", value: who.agent },
    ],
    affectedNodeIds: [decoy.id, ...neighbours.map((n) => n.id)],
  });
  broadcast();
}

export const PROVIDERS = ["railway", "stripe", "cloud", "github"];

export function simulateBreach(provider: string): void {
  const leaked = state.nodes.filter((n) => n.type === "secret" && n.provider === provider && n.status !== "rotated");
  if (!leaked.length) return;
  state.breach = { provider, startedAt: state.breach.startedAt ?? Date.now() };
  for (const n of leaked) n.status = "exposed";
  addIncident({
    kind: "breach",
    title: `${provider[0].toUpperCase()}${provider.slice(1)} breach (simulated)`,
    summary: `Provider reports credential exposure. ${leaked.map((n) => n.label).join(", ")} must be treated as leaked.`,
    affectedNodeIds: leaked.map((n) => n.id),
  });
  broadcast();
  script(async (alive) => {
    for (const hop of blastHops(state.edges, leaked.map((n) => n.id))) {
      await sleep(600);
      if (!alive()) return;
      for (const id of hop.nodes) {
        const n: GraphNode = node(id);
        if (n.type !== "decoy" && n.status === "ok") n.status = "attacked";
      }
      broadcast();
    }
  });
}
