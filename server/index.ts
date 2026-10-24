import { config } from "dotenv";
import express from "express";
import { resolve } from "node:path";
import { ROOT } from "./paths";
import type { BlastResult } from "../shared/types";
import { blastHops } from "./graph";
import { cannedBlast, generate } from "./llm";
import { scanTarget } from "./scanner";
import { resetState, snapshot, state, subscribe, world } from "./state";

config({ path: resolve(ROOT, ".env.local"), quiet: true });
resetState();

const app = express();
app.use(express.json());

app.get("/api/state", (_req, res) => {
  res.json(snapshot());
});

app.get("/api/events", (_req, res) => {
  subscribe(res);
});

app.post("/api/reset", (_req, res) => {
  resetState();
  res.json({ ok: true });
});

app.get("/api/blast/:id", async (req, res) => {
  const start = state.nodes.find((n) => n.id === req.params.id);
  if (!start) return void res.status(404).json({ error: "unknown node" });
  const hops = blastHops(state.edges, [start.id]);
  const canned = cannedBlast(start.id, state.nodes, state.edges, world.notes);
  const chain = hops.flatMap((h) => h.nodes).map((id) => state.nodes.find((n) => n.id === id)?.label).join(" -> ");
  const ai = await generate(
    `Explain to a developer what an attacker can reach if ${start.label} leaks. Chain: ${start.label} -> ${chain}. Notes: ${JSON.stringify(world.notes)}`,
    canned.explanation,
  );
  const result: BlastResult = { nodeId: start.id, hops, explanation: ai.text, worstCase: canned.worstCase, source: ai.source };
  res.json(result);
});

app.get("/api/scan", (req, res) => {
  try {
    const target = typeof req.query.target === "string" ? req.query.target : undefined;
    res.json(scanTarget(target, state.nodes, state.edges));
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

const port = Number(process.env.PORT ?? 3001);
app.listen(port, () => console.log(`tripwire server on http://localhost:${port}`));
