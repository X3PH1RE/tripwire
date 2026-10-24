import { useState, type ReactNode } from "react";
import type { DemoState } from "../../../shared/types";
import { post } from "../api";
import { fmt, useNow } from "./useNow";

const PROVIDERS = ["railway", "stripe", "cloud", "github"];

function Btn({ onClick, children, dot, disabled, variant = "ghost" }: { onClick: () => void; children: ReactNode; dot?: string; disabled?: boolean; variant?: "ghost" | "primary" }) {
  const base = "inline-flex h-9 items-center gap-2 rounded-lg px-3.5 text-[13px] font-medium transition disabled:cursor-not-allowed disabled:opacity-40";
  const look = variant === "primary" ? "bg-zinc-100 text-zinc-900 hover:bg-white" : "border border-line bg-ink-850 text-zinc-200 hover:border-line-strong hover:bg-ink-800";
  return (
    <button disabled={disabled} onClick={onClick} className={`${base} ${look}`}>
      {dot && <span className={`h-1.5 w-1.5 rounded-full ${dot}`} />}
      {children}
    </button>
  );
}

function Group({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-zinc-500">{label}</span>
      <div className="flex items-center gap-2">{children}</div>
    </div>
  );
}

function Metric({ label, value, tone }: { label: string; value: string; tone: string }) {
  return (
    <div className="min-w-[96px] text-right">
      <div className="text-[10px] font-medium uppercase tracking-[0.14em] text-zinc-500">{label}</div>
      <div className={`font-mono text-[22px] font-medium leading-tight tabular-nums ${tone}`}>{value}</div>
    </div>
  );
}

export function ControlBar({ demo, connected, onReset, onRunDemo, running }: { demo: DemoState; connected: boolean; onReset: () => void; onRunDemo: () => void; running: boolean }) {
  const [provider, setProvider] = useState("railway");
  const c = demo.containment;
  const breachLive = !!demo.breach.startedAt && c.status !== "done";
  const now = useNow(breachLive || c.status === "running");
  const sinceBreach = demo.breach.startedAt ? (c.finishedAt ?? now) - demo.breach.startedAt : null;
  const containTime = c.startedAt ? (c.finishedAt ?? now) - c.startedAt : null;
  const exposed = demo.nodes.filter((n) => n.type === "secret" && (n.status === "exposed" || n.status === "attacked")).length;

  return (
    <header className="border-b border-line bg-ink-950/80 backdrop-blur">
      <div className="flex items-center gap-4 px-6 pt-4">
        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-rose-500 to-rose-700 shadow-[0_0_0_1px_rgba(255,255,255,0.1)_inset]">
            <svg viewBox="0 0 24 24" className="h-4 w-4 text-white" fill="none" stroke="currentColor" strokeWidth={2.2} strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z" />
              <path d="M8 12h8" />
            </svg>
          </div>
          <div className="leading-tight">
            <div className="text-[17px] font-semibold tracking-tight text-zinc-50">Tripwire</div>
            <div className="text-[11px] text-zinc-500">Secret exposure &amp; response</div>
          </div>
        </div>
        <div className="mx-2 h-8 w-px bg-line" />
        <div className="flex items-center gap-2 font-mono text-[12px] text-zinc-400">
          <span>acme-shop</span>
          <span className="text-zinc-600">/</span>
          <span>main</span>
        </div>
        <span className={`ml-1 inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] ${connected ? "border-emerald-500/25 text-emerald-300" : "border-rose-500/30 text-rose-300"}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${connected ? "animate-pulse bg-emerald-400" : "bg-rose-400"}`} />
          {connected ? "Live" : "Offline"}
        </span>
        <div className="ml-auto flex items-center gap-6">
          <Metric label="Exposed" value={String(exposed)} tone={exposed ? "text-rose-300" : "text-zinc-300"} />
          <Metric label="Time to contain" value={sinceBreach !== null ? fmt(sinceBreach) : "—"} tone={c.status === "done" ? "text-emerald-300" : sinceBreach !== null ? "text-rose-300" : "text-zinc-500"} />
          <Metric label={`Rotated ${c.done}/${c.total || 0}`} value={containTime !== null ? fmt(containTime) : "—"} tone={c.status === "done" ? "text-emerald-300" : containTime !== null ? "text-amber-300" : "text-zinc-500"} />
        </div>
      </div>
      <div className="flex flex-wrap items-end gap-6 px-6 pb-4 pt-3">
        <Group label="Incident">
          <div className="flex h-9 items-center overflow-hidden rounded-lg border border-line bg-ink-850">
            <select value={provider} onChange={(e) => setProvider(e.target.value)} className="h-full cursor-pointer bg-transparent pl-3 pr-1 font-mono text-[12px] text-zinc-300 outline-none">
              {PROVIDERS.map((p) => (
                <option key={p} className="bg-ink-900">
                  {p}
                </option>
              ))}
            </select>
            <button onClick={() => post("/breach", { provider })} className="flex h-full items-center gap-2 border-l border-line px-3.5 text-[13px] font-medium text-zinc-200 hover:bg-ink-800">
              <span className="h-1.5 w-1.5 rounded-full bg-rose-500" />
              Simulate provider breach
            </button>
          </div>
        </Group>
        <Group label="Deception">
          <Btn dot="bg-violet-400" onClick={() => post("/honey/plant")} disabled={demo.honey.planted}>
            Plant tripwires
          </Btn>
          <Btn dot="bg-violet-400" onClick={() => post("/honey/attack")}>
            Simulate attacker
          </Btn>
        </Group>
        <Group label="Response">
          <Btn dot="bg-emerald-400" onClick={() => post("/contain")} disabled={c.status === "running"}>
            Contain &amp; rotate
          </Btn>
          <Btn dot="bg-sky-400" onClick={() => post("/cve")} disabled={demo.cve.status === "running"}>
            Simulate new CVE
          </Btn>
        </Group>
        <div className="ml-auto flex items-center gap-2">
          <Btn onClick={onReset}>Reset</Btn>
          <Btn variant="primary" onClick={onRunDemo} disabled={running}>
            {running ? "Running demo…" : "Run full demo"}
          </Btn>
        </div>
      </div>
    </header>
  );
}
