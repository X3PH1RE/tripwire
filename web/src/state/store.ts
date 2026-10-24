import { create } from "zustand";
import type { BlastResult, DemoState } from "../../../shared/types";
import { get } from "../api";

const HOP_MS = 400;

export type Mode = "demo" | "real";

interface Store {
  mode: Mode;
  setMode: (mode: Mode) => void;
  demo: DemoState | null;
  connected: boolean;
  selectedId: string | null;
  blast: BlastResult | null;
  litEdges: Set<string>;
  litNodes: Set<string>;
  connect: () => void;
  showBlast: (id: string) => Promise<void>;
  clearBlast: () => void;
}

let animation = 0;

export const useStore = create<Store>((set) => ({
  mode: "demo",
  setMode: (mode) => {
    animation++;
    set({ mode, selectedId: null, blast: null, litEdges: new Set(), litNodes: new Set() });
  },
  demo: null,
  connected: false,
  selectedId: null,
  blast: null,
  litEdges: new Set(),
  litNodes: new Set(),
  connect: () => {
    const es = new EventSource("/api/events");
    es.onopen = () => set({ connected: true });
    es.onerror = () => set({ connected: false });
    es.onmessage = (e) => set({ demo: JSON.parse(e.data) as DemoState });
  },
  showBlast: async (id) => {
    const run = ++animation;
    set({ selectedId: id, blast: null, litEdges: new Set(), litNodes: new Set([id]) });
    const blast = await get<BlastResult>(`/blast/${id}`);
    if (run !== animation) return;
    set({ blast });
    const edges = new Set<string>();
    const nodes = new Set<string>([id]);
    for (const hop of blast.hops) {
      await new Promise((r) => setTimeout(r, HOP_MS));
      if (run !== animation) return;
      hop.edges.forEach((e) => edges.add(e));
      hop.nodes.forEach((n) => nodes.add(n));
      set({ litEdges: new Set(edges), litNodes: new Set(nodes) });
    }
  },
  clearBlast: () => {
    animation++;
    set({ selectedId: null, blast: null, litEdges: new Set(), litNodes: new Set() });
  },
}));
