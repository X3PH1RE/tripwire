import type { Response } from "express";
import type { DemoState, GraphNode, Incident } from "../shared/types";
import { withDanger } from "./scoring";
import { loadWorld, resetRuntime } from "./world";

export const world = loadWorld();

function freshState(): DemoState {
  return {
    nodes: structuredClone(world.nodes),
    edges: structuredClone(world.edges),
    incidents: [],
    breach: {},
    honey: { planted: false, attacks: 0 },
    containment: { status: "idle", total: 0, done: 0, rotations: [] },
    cve: { status: "idle", steps: [] },
  };
}

export let state = freshState();
export let boosts: Record<string, number> = {};
let generation = 0;

export function currentGeneration(): number {
  return generation;
}

export function resetState(): void {
  generation++;
  resetRuntime();
  state = freshState();
  boosts = {};
  broadcast();
}

export function node(id: string): GraphNode {
  const n = state.nodes.find((x) => x.id === id);
  if (!n) throw new Error(`unknown node ${id}`);
  return n;
}

export function setStatus(ids: string[], status: GraphNode["status"]): void {
  for (const id of ids) node(id).status = status;
}

export function addIncident(incident: Omit<Incident, "id" | "at">): Incident {
  const full = { ...incident, id: `inc-${Date.now()}-${state.incidents.length}`, at: Date.now() };
  state.incidents.unshift(full);
  return full;
}

export function snapshot(): DemoState {
  return { ...state, nodes: withDanger(state.nodes, state.edges, boosts) };
}

const clients = new Set<Response>();

export function subscribe(res: Response): void {
  res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" });
  res.write(`data: ${JSON.stringify(snapshot())}\n\n`);
  clients.add(res);
  const ping = setInterval(() => res.write(": ping\n\n"), 15_000);
  res.on("close", () => {
    clearInterval(ping);
    clients.delete(res);
  });
}

export function broadcast(): void {
  const payload = `data: ${JSON.stringify(snapshot())}\n\n`;
  for (const c of clients) c.write(payload);
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Runs a scripted sequence; returns false from `step` once a reset has happened so the script can stop. */
export function script(fn: (alive: () => boolean) => Promise<void>): void {
  const gen = generation;
  fn(() => gen === generation).catch((err) => console.error("script failed", err));
}
