import { useState, type ReactNode } from "react";
import type { DemoState } from "../../../shared/types";
import type { Mode } from "../state/store";
import { post } from "../api";
import { fmt, useNow } from "./useNow";

const PROVIDERS = ["railway", "stripe", "cloud", "github"];

function Btn({ onClick, children, dot, disabled, variant = "ghost", type = "button" }: { onClick: () => void; children: ReactNode; dot?: string; disabled?: boolean; variant?: "ghost" | "primary"; type?: "button" | "submit" }) {
  const base = "inline-flex h-9 items-center gap-2 rounded-lg px-3.5 text-[13px] font-medium transition disabled:cursor-not-allowed disabled:opacity-40";
  const look = variant === "primary" ? "bg-zinc-100 text-zinc-900 hover:bg-white" : "border border-line bg-ink-850 text-zinc-200 hover:border-line-strong hover:bg-ink-800";
  return (
    <button type={type} disabled={disabled} onClick={onClick} className={`${base} ${look}`}>
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

function ModeToggle({ mode, setMode }: { mode: Mode; setMode: (m: Mode) => void }) {
  return (
    <div className="flex h-8 items-center rounded-lg border border-line bg-ink-850 p-0.5 text-[12px]">
      {(["demo", "real"] as const).map((m) => (
        <button key={m} onClick={() => setMode(m)} className={`h-full rounded-md px-3 font-medium transition ${mode === m ? "bg-zinc-100 text-zinc-900" : "text-zinc-400 hover:text-zinc-200"}`}>
          {m === "demo" ? "Live demo" : "Scan a repo"}
        </button>
      ))}
    </div>
  );
}

function RealControls({ demo, onClear }: { demo: DemoState; onClear: () => void }) {
  const scan = demo.scan;
  const [target, setTarget] = useState(scan.target ?? "");
  const busy = !["idle", "done", "failed"].includes(scan.status);
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (target.trim()) post("/real/scan", { target: target.trim() });
  };
  return (
    <form onSubmit={submit} className="flex flex-1 flex-wrap items-end gap-3">
      <Group label="Repository">
        <div className="flex h-9 w-[440px] items-center gap-2 rounded-lg border border-line bg-ink-850 px-3 focus-within:border-line-strong">
          <svg viewBox="0 0 24 24" className="h-4 w-4 shrink-0 text-zinc-500" fill="none" stroke="currentColor" strokeWidth={2}><circle cx="11" cy="11" r="7" /><path d="M20 20l-3.5-3.5" /></svg>
          <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://github.com/owner/repo  or  owner/repo" className="h-full flex-1 bg-transparent font-mono text-[12px] text-zinc-200 outline-none placeholder:text-zinc-600" />
        </div>
        <Btn variant="primary" onClick={() => undefined} disabled={busy || !target.trim()} type="submit">
          {busy ? "Scanning…" : "Scan repository"}
        </Btn>
      </Group>
      <p className="max-w-[420px] pb-2 text-[11px] leading-relaxed text-zinc-500">Clones the repo, scans files and the last 300 commits for secrets, maps what each one unlocks and checks dependencies against OSV.dev.</p>
      <div className="ml-auto">
        <Btn onClick={onClear} disabled={scan.status === "idle"}>
          Clear
        </Btn>
      </div>
    </form>
  );
}

export function ControlBar({ demo, connected, onReset, onRunDemo, running, mode, setMode, onClearScan }: { demo: DemoState; connected: boolean; onReset: () => void; onRunDemo: () => void; running: boolean; mode: Mode; setMode: (m: Mode) => void; onClearScan: () => void }) {
  const [provider, setProvider] = useState("railway");
  const scan = demo.scan;
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
        <ModeToggle mode={mode} setMode={setMode} />
        <div className="flex items-center gap-2 font-mono text-[12px] text-zinc-400">
          <span>{mode === "demo" ? "acme-shop" : (scan.repo ?? scan.target ?? "no repository")}</span>
          {(mode === "demo" || scan.branch) && <span className="text-zinc-600">/</span>}
          {(mode === "demo" || scan.branch) && <span>{mode === "demo" ? "main" : scan.branch}</span>}
        </div>
        <span className={`ml-1 inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] ${connected ? "border-emerald-500/25 text-emerald-300" : "border-rose-500/30 text-rose-300"}`}>
          <span className={`h-1.5 w-1.5 rounded-full ${connected ? "animate-pulse bg-emerald-400" : "bg-rose-400"}`} />
          {connected ? "Live" : "Offline"}
        </span>
        {mode === "real" ? (
          <div className="ml-auto flex items-center gap-6">
            <Metric label="Secrets" value={scan.status === "idle" ? "—" : String(scan.findings.length)} tone={scan.findings.length ? "text-rose-300" : "text-zinc-300"} />
            <Metric label="Only in history" value={scan.status === "idle" ? "—" : String(scan.findings.filter((f) => !f.inHead).length)} tone={scan.findings.some((f) => !f.inHead) ? "text-amber-300" : "text-zinc-300"} />
            <Metric label="Vulnerable deps" value={scan.status === "done" ? String(scan.vulns.length) : "—"} tone={scan.vulns.length ? "text-sky-300" : "text-zinc-300"} />
          </div>
        ) : (
        <div className="ml-auto flex items-center gap-6">
          <Metric label="Exposed" value={String(exposed)} tone={exposed ? "text-rose-300" : "text-zinc-300"} />
          <Metric label="Time to contain" value={sinceBreach !== null ? fmt(sinceBreach) : "—"} tone={c.status === "done" ? "text-emerald-300" : sinceBreach !== null ? "text-rose-300" : "text-zinc-500"} />
          <Metric label={`Rotated ${c.done}/${c.total || 0}`} value={containTime !== null ? fmt(containTime) : "—"} tone={c.status === "done" ? "text-emerald-300" : containTime !== null ? "text-amber-300" : "text-zinc-500"} />
        </div>
        )}
      </div>
      <div className="flex flex-wrap items-end gap-6 px-6 pb-4 pt-3">
        {mode === "real" ? <RealControls demo={demo} onClear={onClearScan} /> : <>
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
        </>}
      </div>
    </header>
  );
}
