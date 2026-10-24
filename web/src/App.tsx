import { useEffect, useState } from "react";
import type { GraphNode } from "../../shared/types";
import { post } from "./api";
import { Graph } from "./components/Graph";
import { useStore } from "./state/store";

const EMPTY = new Set<string>();

export default function App() {
  const { demo, connected, connect } = useStore();
  const [selected, setSelected] = useState<GraphNode | null>(null);

  useEffect(() => connect(), [connect]);

  if (!demo) return <div className="p-10 text-2xl text-slate-400">Connecting to Tripwire…</div>;

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center gap-4 border-b border-slate-800 px-6 py-3">
        <h1 className="text-3xl font-black tracking-tight text-slate-50">
          Trip<span className="text-red-500">wire</span>
        </h1>
        <span className={`h-3 w-3 rounded-full ${connected ? "bg-emerald-400" : "bg-red-500"}`} />
        <button className="ml-auto rounded-lg bg-slate-800 px-4 py-2 text-lg hover:bg-slate-700" onClick={() => post("/reset")}>
          Reset
        </button>
      </header>
      <main className="flex min-h-0 flex-1">
        <div className="min-w-0 flex-1">
          <Graph demo={demo} litEdges={EMPTY} litNodes={EMPTY} selectedId={selected?.id ?? null} onSelect={setSelected} />
        </div>
      </main>
    </div>
  );
}
