import { config } from "dotenv";
import express from "express";
import { resolve } from "node:path";
import { ROOT } from "./paths";
import { scanTarget } from "./scanner";
import { loadWorld, resetRuntime } from "./world";

config({ path: resolve(ROOT, ".env.local"), quiet: true });

const world = loadWorld();
resetRuntime();

const app = express();
app.use(express.json());

app.get("/api/scan", (req, res) => {
  try {
    const target = typeof req.query.target === "string" ? req.query.target : undefined;
    res.json(scanTarget(target, world.nodes, world.edges));
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

const port = Number(process.env.PORT ?? 3001);
app.listen(port, () => console.log(`tripwire server on http://localhost:${port}`));
