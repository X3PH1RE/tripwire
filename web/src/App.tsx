import { useEffect, useState } from "react";
import { post } from "./api";
import { AlertFeed } from "./components/AlertFeed";
import { BlastPanel } from "./components/BlastPanel";
import { ContainPanel } from "./components/ContainPanel";
import { ControlBar } from "./components/ControlBar";
import { FindingsPanel, HoneyPanel, ScanPanel, VulnPanel } from "./components/RealPanels";
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
const REAL_LEGEND = [
  ["bg-rose-500", "Exposed secret / reachable resource"],
  ["bg-amber-400", "history = deleted but still in git"],
  ["bg-violet-400", "live / revoked / honey = checked with provider"],
  ["bg-zinc-600", "CI secret reachable through repo access"],
];

function Legend({ items = LEGEND }: { items?: string[][] }) {
  return (
    <div className="pointer-events-none absolute left-5 top-4 z-10 flex items-center gap-4 rounded-lg border border-line bg-ink-900/90 px-3 py-2 text-[11px] text-zinc-400 backdrop-blur">
      {items.map(([c, l]) => (
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
  const { demo, connected, connect, selectedId, blast, litEdges, litNodes, showBlast, clearBlast, mode, setMode } = useStore();
  const [running, setRunning] = useState(false);

  useEffect(() => connect(), [connect]);
  const scanStarted = demo?.scan.startedAt;
  useEffect(() => {
    if (scanStarted) clearBlast();
  }, [scanStarted, clearBlast]);

  const reset = async () => {
    clearBlast();
    await post("/reset");
  };

  const runDemo = async () => {
    setMode("demo");
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

  const real = mode === "real";
  const scan = demo.scan;
  const graph = real ? scan : demo;
  const clearScan = async () => {
    clearBlast();
    await post("/real/clear");
  };

  return (
    <div className="flex h-full flex-col">
      <ControlBar demo={demo} connected={connected} onReset={reset} onRunDemo={runDemo} running={running} mode={mode} setMode={setMode} onClearScan={clearScan} />
      <main className="flex min-h-0 flex-1">
        <div className="relative min-w-0 flex-1">
          {(!real || scan.nodes.length > 0) && <Legend items={real ? REAL_LEGEND : LEGEND} />}
          {real && !scan.nodes.length && (
            <div className="absolute inset-0 z-10 flex items-center justify-center p-8">
              <div className="max-w-md rounded-xl border border-line bg-ink-900/90 p-6 text-center backdrop-blur">
                <div className="text-[15px] font-semibold text-zinc-100">{scan.status === "idle" ? "Scan a real repository" : scan.status === "failed" ? "Scan failed" : scan.status === "done" ? "No secrets to map" : "Scanning…"}</div>
                <p className="mt-2 text-[13px] leading-relaxed text-zinc-400">
                  {scan.status === "idle"
                    ? "Paste a GitHub URL above. Tripwire finds secrets in the code and its git history, maps what each one unlocks, and checks every dependency for known vulnerabilities."
                    : scan.status === "failed"
                      ? scan.error
                      : scan.status === "done"
                        ? "No secrets were found, so there is no attack graph. Check the dependency results on the right."
                        : "Cloning and scanning. Results appear here as soon as the secret scan finishes."}
                </p>
              </div>
            </div>
          )}
          <Graph
            graph={graph}
            secured={!real && demo.containment.status === "done"}
            fitKey={real ? `real:${scan.target}:${scan.nodes.length}` : "demo"}
            litEdges={litEdges}
            litNodes={litNodes}
            selectedId={selectedId}
            onSelect={(n) => (n.type === "secret" ? showBlast(n.id) : clearBlast())}
          />
        </div>
        <aside className="scroll-thin flex w-[420px] shrink-0 flex-col gap-3 overflow-y-auto border-l border-line bg-ink-950 p-4">
          {blast && <BlastPanel blast={blast} nodes={graph.nodes} onClose={clearBlast} />}
          {real ? (
            <>
              {scan.status !== "idle" && <ScanPanel scan={scan} />}
              {scan.nodes.length > 0 || scan.status === "done" || scan.status === "vulns" ? <FindingsPanel scan={scan} onSelect={showBlast} /> : null}
              <HoneyPanel demo={demo} />
              {scan.status === "done" && <VulnPanel scan={scan} />}
              {demo.incidents.some((i) => i.kind === "honey") && <AlertFeed incidents={demo.incidents.filter((i) => i.kind === "honey")} />}
            </>
          ) : (
            <>
              <Timeline cve={demo.cve} />
              <ContainPanel demo={demo} />
              <AlertFeed incidents={demo.incidents} />
            </>
          )}
        </aside>
      </main>
    </div>
  );
}
