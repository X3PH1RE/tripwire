import { config } from "dotenv";
import express from "express";
import { resolve } from "node:path";
import { ROOT } from "./paths";
import type { BlastResult } from "../shared/types";
import { cleanupInBackground, simulateCve } from "./cve";
import { blastHops } from "./graph";
import { PROVIDERS, plantTripwires, simulateAttacker, simulateBreach } from "./incidents";
import { guard } from "./guard";
import { cannedBlast, generate } from "./llm";
import { clearScan, createHoney, honeyAction, plantHoney, pollHoney, startContain, startFix, startHoneyPolling, startScan } from "./real/index";
import { contain } from "./rotation";
import { scanTarget } from "./scanner";
import { resetState, snapshot, state, subscribe, world } from "./state";

config({ path: resolve(ROOT, ".env.local"), quiet: true });
resetState();
cleanupInBackground();
startHoneyPolling();

const app = express();
app.disable("x-powered-by");
app.use(guard());
app.use(express.json());

app.get("/api/state", (_req, res) => {
  res.json(snapshot());
});

app.get("/api/events", (_req, res) => {
  subscribe(res);
});

app.post("/api/reset", (_req, res) => {
  resetState();
  cleanupInBackground();
  res.json({ ok: true });
});

app.post("/api/honey/plant", (_req, res) => {
  plantTripwires();
  res.json({ ok: true });
});

app.post("/api/honey/attack", (_req, res) => {
  simulateAttacker();
  res.json({ ok: true });
});

app.get("/api/providers", (_req, res) => {
  res.json(PROVIDERS);
});

app.post("/api/breach", (req, res) => {
  const provider = String(req.body?.provider ?? "railway");
  if (!PROVIDERS.includes(provider)) return void res.status(400).json({ error: "unknown provider" });
  simulateBreach(provider);
  res.json({ ok: true });
});

app.post("/api/contain", (_req, res) => {
  contain();
  res.json({ ok: true });
});

app.post("/api/cve", (_req, res) => {
  simulateCve();
  res.json({ ok: true });
});

app.get("/api/blast/:id", async (req, res) => {
  const real = req.params.id.startsWith("r-");
  const { nodes, edges } = real ? state.scan : state;
  const notes = real ? {} : world.notes;
  const start = nodes.find((n) => n.id === req.params.id);
  if (!start) return void res.status(404).json({ error: "unknown node" });
  const hops = blastHops(edges, [start.id]);
  const canned = cannedBlast(start.id, nodes, edges, notes);
  const chain = hops.flatMap((h) => h.nodes).map((id) => nodes.find((n) => n.id === id)?.label).join(" -> ");
  const ai = await generate(
    `Explain to a developer what an attacker can reach if ${start.label} leaks. Chain: ${start.label} -> ${chain}. Notes: ${JSON.stringify(notes)}`,
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

app.post("/api/real/scan", (req, res) => {
  const target = typeof req.body?.target === "string" ? req.body.target.trim() : "";
  if (!target) return void res.status(400).json({ error: "target required" });
  startScan(target, req.body?.verify === true);
  res.json({ ok: true });
});

app.post("/api/real/fix", (req, res) => {
  const keys = Array.isArray(req.body?.keys) ? req.body.keys.map(String) : undefined;
  startFix(keys);
  res.json({ ok: true });
});

app.post("/api/real/contain", (req, res) => {
  // Nothing is revoked unless the caller says so explicitly; anything else is a dry run.
  const ids = Array.isArray(req.body?.ids) ? req.body.ids.map(String) : undefined;
  startContain(req.body?.apply === true, ids);
  res.json({ ok: true });
});

app.post("/api/real/clear", (_req, res) => {
  clearScan();
  res.json({ ok: true });
});

app.post("/api/real/honey", async (req, res) => {
  const repo = typeof req.body?.repo === "string" ? req.body.repo : state.scan.repo;
  const plant = req.body?.plant !== false && !!repo;
  try {
    await honeyAction(async () => {
      const r = await createHoney({ memo: `Tripwire honey secret${repo ? ` for ${repo}` : ""}`, email: req.body?.email || undefined, repo });
      if (plant) await plantHoney(r.id, repo!, req.body?.file || undefined);
    }, plant ? "Creating and planting decoy…" : "Creating decoy…");
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

app.post("/api/real/honey/check", async (_req, res) => {
  await honeyAction(pollHoney, "Checking for use…").catch(() => undefined);
  res.json({ ok: true });
});

const port = Number(process.env.PORT ?? 3001);
// Loopback only by default: the API is unauthenticated and can scan this machine and revoke keys. HOST=0.0.0.0 (plus ALLOWED_HOSTS) is opt-in.
const host = process.env.HOST ?? "127.0.0.1";
app.listen(port, host, () => console.log(`tripwire server on http://localhost:${port} (listening on ${host})`));
