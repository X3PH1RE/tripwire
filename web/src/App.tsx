import { useEffect, useState } from "react";
import { post } from "./api";
import { AlertFeed } from "./components/AlertFeed";
import { BlastPanel } from "./components/BlastPanel";
import { ContainPanel } from "./components/ContainPanel";
import { ControlBar } from "./components/ControlBar";
import { Graph } from "./components/Graph";
import { Timeline } from "./components/Timeline";
import { useStore } from "./state/store";

const LEGEND = [
  ["bg-zinc-600", "Healthy"],
  ["bg-rose-500", "Exposed"],
  ["bg-amber-400", "Rotating"],
  ["bg-emerald-400", "Secured"],
  ["bg-violet-400", "Honey secret"],
];

function Legend() {
  return (
    <div className="pointer-events-none absolute left-5 top-4 z-10 flex items-center gap-4 rounded-lg border border-line bg-ink-900/90 px-3 py-2 text-[11px] text-zinc-400 backdrop-blur">
      {LEGEND.map(([c, l]) => (
        <span key={l} className="flex items-center gap-1.5">
          <span className={`h-2 w-2 rounded-sm ${c}`} />
          {l}
        </span>
      ))}
      <span className="text-zinc-600">Click a secret to trace its blast radius</span>
    </div>
  );
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function until(check: () => boolean, timeoutMs = 30_000) {
  const start = Date.now();
  while (!check() && Date.now() - start < timeoutMs) await wait(200);
}

export default function App() {
  const { demo, connected, connect, selectedId, blast, litEdges, litNodes, showBlast, clearBlast } = useStore();
  const [running, setRunning] = useState(false);

  useEffect(() => connect(), [connect]);

  const reset = async () => {
    clearBlast();
    await post("/reset");
  };

  const runDemo = async () => {
    setRunning(true);
    try {
      await reset();
      await wait(1500);
      await post("/breach", { provider: "railway" });
      await wait(4500);
      await showBlast("sec-database-url");
      await wait(4500);
      clearBlast();
      await post("/honey/plant");
      await wait(1500);
      await post("/honey/attack");
      await wait(4000);
      await post("/contain");
      await until(() => useStore.getState().demo?.containment.status === "done");
      await wait(2500);
      await post("/cve");
      await until(() => useStore.getState().demo?.cve.status === "done");
    } finally {
      setRunning(false);
    }
  };

  if (!demo) return <div className="flex h-full items-center justify-center text-sm text-zinc-500">Connecting to Tripwire…</div>;

  return (
    <div className="flex h-full flex-col">
      <ControlBar demo={demo} connected={connected} onReset={reset} onRunDemo={runDemo} running={running} />
      <main className="flex min-h-0 flex-1">
        <div className="relative min-w-0 flex-1">
          <Legend />
          <Graph
            demo={demo}
            litEdges={litEdges}
            litNodes={litNodes}
            selectedId={selectedId}
            onSelect={(n) => (n.type === "secret" ? showBlast(n.id) : clearBlast())}
          />
        </div>
        <aside className="scroll-thin flex w-[420px] shrink-0 flex-col gap-3 overflow-y-auto border-l border-line bg-ink-950 p-4">
          {blast && <BlastPanel blast={blast} demo={demo} onClose={clearBlast} />}
          <Timeline cve={demo.cve} />
          <ContainPanel demo={demo} />
          <AlertFeed incidents={demo.incidents} />
        </aside>
      </main>
    </div>
  );
}
