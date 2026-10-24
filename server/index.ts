import { config } from "dotenv";
import express from "express";
import { resolve } from "node:path";
import { ROOT } from "./paths";
import { scanTarget } from "./scanner";
import { resetState, snapshot, state, subscribe } from "./state";

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
