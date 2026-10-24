import { useState } from "react";
import type { DemoState } from "../../../shared/types";
import { post } from "../api";
import { fmt, useNow } from "./useNow";

const PROVIDERS = ["railway", "stripe", "cloud", "github"];

function Button({ onClick, children, tone = "slate", disabled }: { onClick: () => void; children: React.ReactNode; tone?: string; disabled?: boolean }) {
  const tones: Record<string, string> = {
    slate: "bg-slate-800 hover:bg-slate-700",
    red: "bg-red-600 hover:bg-red-500",
    fuchsia: "bg-fuchsia-700 hover:bg-fuchsia-600",
    emerald: "bg-emerald-600 hover:bg-emerald-500",
    sky: "bg-sky-600 hover:bg-sky-500",
  };
  return (
    <button disabled={disabled} onClick={onClick} className={`rounded-lg px-4 py-2 text-base font-semibold text-white transition disabled:opacity-40 ${tones[tone]}`}>
      {children}
    </button>
  );
}

export function ControlBar({ demo, connected, onReset, onRunDemo, running }: { demo: DemoState; connected: boolean; onReset: () => void; onRunDemo: () => void; running: boolean }) {
  const [provider, setProvider] = useState("railway");
  const c = demo.containment;
  const breachLive = !!demo.breach.startedAt && c.status !== "done";
  const now = useNow(breachLive || c.status === "running");
  const sinceBreach = demo.breach.startedAt ? (c.finishedAt ?? now) - demo.breach.startedAt : null;
  const containTime = c.startedAt ? (c.finishedAt ?? now) - c.startedAt : null;

  return (
    <header className="flex flex-wrap items-center gap-2.5 border-b border-slate-800 px-5 py-3">
      <h1 className="mr-2 text-3xl font-black tracking-tight text-slate-50">
        Trip<span className="text-red-500">wire</span>
      </h1>
      <span title={connected ? "live" : "disconnected"} className={`h-3 w-3 rounded-full ${connected ? "bg-emerald-400" : "bg-red-500"}`} />
      <div className="flex items-center overflow-hidden rounded-lg border border-red-700">
        <select value={provider} onChange={(e) => setProvider(e.target.value)} className="bg-slate-900 px-2 py-2 text-base text-slate-100 outline-none">
          {PROVIDERS.map((p) => (
            <option key={p}>{p}</option>
          ))}
        </select>
        <button onClick={() => post("/breach", { provider })} className="bg-red-600 px-4 py-2 text-base font-semibold text-white hover:bg-red-500">
          Simulate breach
        </button>
      </div>
      <Button tone="fuchsia" onClick={() => post("/honey/plant")} disabled={demo.honey.planted}>
        Plant tripwires
      </Button>
      <Button tone="fuchsia" onClick={() => post("/honey/attack")}>
        Simulate attacker
      </Button>
      <Button tone="emerald" onClick={() => post("/contain")} disabled={c.status === "running"}>
        Contain
      </Button>
      <Button tone="sky" onClick={() => post("/cve")} disabled={demo.cve.status === "running"}>
        Simulate new CVE
      </Button>
      <div className="ml-auto flex items-center gap-5">
        {sinceBreach !== null && (
          <div className="text-right">
            <div className="text-xs uppercase tracking-widest text-slate-400">Breach → contained</div>
            <div className={`font-mono text-3xl font-bold ${c.status === "done" ? "text-emerald-400" : "text-red-400"}`}>{fmt(sinceBreach)}</div>
          </div>
        )}
        {containTime !== null && (
          <div className="text-right">
            <div className="text-xs uppercase tracking-widest text-slate-400">Rotation {c.done}/{c.total}</div>
            <div className={`font-mono text-3xl font-bold ${c.status === "done" ? "text-emerald-400" : "text-amber-300"}`}>{fmt(containTime)}</div>
          </div>
        )}
        <Button onClick={onRunDemo} disabled={running}>
          {running ? "Running…" : "Run full demo"}
        </Button>
        <Button onClick={onReset}>Reset</Button>
      </div>
    </header>
  );
}
