import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fakeValue } from "./incidents";
import { RUNTIME_DIR } from "./paths";
import { withDanger } from "./scoring";
import { addIncident, boosts, broadcast, script, sleep, state } from "./state";

const PREFIX = /tw_fake_[a-z]+_[a-z0-9]{16,}/;
const short = (v: string) => (v.length > 26 ? `${v.slice(0, 26)}…` : v);

function rewrite(file: string, line: number, provider: string): { before: string; after: string } {
  const path = join(RUNTIME_DIR, file);
  const lines = readFileSync(path, "utf8").split("\n");
  const before = lines[line - 1].match(PREFIX)?.[0] ?? "";
  const after = fakeValue(provider);
  lines[line - 1] = lines[line - 1].replace(PREFIX, after);
  writeFileSync(path, lines.join("\n"));
  return { before, after };
}

export function contain(): void {
  if (state.containment.status === "running") return;
  const scored = withDanger(state.nodes, state.edges, boosts);
  const targets = scored
    .filter((n) => n.type === "secret" && (n.status === "exposed" || n.status === "attacked"))
    .sort((a, b) => (b.danger ?? 0) - (a.danger ?? 0));
  if (!targets.length) return;
  state.containment = { status: "running", startedAt: Date.now(), total: targets.length, done: 0, rotations: [] };
  broadcast();
  script(async (alive) => {
    for (const t of targets) {
      const live = state.nodes.find((n) => n.id === t.id)!;
      live.status = "rotating";
      broadcast();
      await sleep(900);
      if (!alive()) return;
      const { before, after } = rewrite(live.file!, live.line!, live.provider ?? "key");
      if (state.containment.rotations.length < 2) state.containment.rotations.push({ nodeId: live.id, label: live.label, before: short(before), after: short(after) });
      live.status = "rotated";
      delete boosts[live.id];
      state.containment.done++;
      broadcast();
      await sleep(250);
      if (!alive()) return;
    }
    for (const n of state.nodes) if (n.type !== "decoy" && n.type !== "secret" && n.status === "attacked") n.status = "rotated";
    state.containment.status = "done";
    state.containment.finishedAt = Date.now();
    const secs = ((state.containment.finishedAt - state.containment.startedAt!) / 1000).toFixed(1);
    addIncident({
      kind: "contain",
      title: "Contained",
      summary: `Rotated ${targets.length} secrets in ${secs}s, highest danger first: ${targets.map((t) => t.label).join(" → ")}.`,
      affectedNodeIds: targets.map((t) => t.id),
    });
    broadcast();
  });
}
