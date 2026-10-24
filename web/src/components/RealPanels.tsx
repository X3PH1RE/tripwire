import { motion } from "framer-motion";
import type { Finding, RealScan, Severity, VulnPackage } from "../../../shared/types";
import { post } from "../api";
import { Panel } from "./ui";
import { fmt } from "./useNow";

const SEV: Record<Severity, string> = {
  CRITICAL: "bg-rose-500/15 text-rose-300 ring-rose-500/30",
  HIGH: "bg-orange-500/15 text-orange-300 ring-orange-500/30",
  MODERATE: "bg-amber-500/10 text-amber-200 ring-amber-500/25",
  LOW: "bg-zinc-500/10 text-zinc-300 ring-zinc-500/25",
  UNKNOWN: "bg-zinc-500/10 text-zinc-400 ring-zinc-500/20",
};

const pill = "rounded-md px-1.5 py-0.5 font-mono text-[10px] font-medium ring-1 ring-inset";

const STEPS: { key: RealScan["status"]; label: string }[] = [
  { key: "cloning", label: "Clone repository" },
  { key: "secrets", label: "Scan files for secrets" },
  { key: "history", label: "Scan git history" },
  { key: "vulns", label: "Check dependencies (OSV.dev)" },
];
const ORDER = ["cloning", "secrets", "history", "vulns", "done"];

export function ScanPanel({ scan }: { scan: RealScan }) {
  const at = ORDER.indexOf(scan.status);
  const failedAt = scan.filesScanned ? 1 : 0;
  const detail = (k: RealScan["status"]) =>
    k === "secrets" && scan.filesScanned ? `${scan.filesScanned} files` : k === "history" && scan.commitsScanned ? `${scan.commitsScanned} commits` : k === "vulns" && scan.status === "done" ? `${scan.vulns.length} vulnerable` : "";
  return (
    <Panel
      eyebrow="Repository scan"
      accent={scan.status === "failed" ? "bg-rose-500" : scan.status === "done" ? "bg-emerald-400" : "bg-sky-400 animate-pulse"}
      title={<span className="font-mono text-[15px]">{scan.repo ?? scan.target}</span>}
      right={scan.finishedAt && scan.startedAt ? <span className="font-mono text-[11px] text-zinc-500">{fmt(scan.finishedAt - scan.startedAt)}</span> : undefined}
    >
      <ol className="mt-3 space-y-2">
        {STEPS.map((s, i) => {
          const done = scan.status === "done" || (at > i && scan.status !== "failed") || (scan.status === "failed" && i < failedAt);
          const active = scan.status === s.key;
          return (
            <li key={s.key} className="flex items-center gap-2.5 text-[13px]">
              <span className={`flex h-4 w-4 items-center justify-center rounded-full ${done ? "bg-emerald-500/15 text-emerald-300" : active ? "bg-sky-500/15" : "bg-white/5"}`}>
                {done ? (
                  <svg viewBox="0 0 24 24" className="h-2.5 w-2.5" fill="none" stroke="currentColor" strokeWidth={3}><path d="M5 12l5 5L20 7" /></svg>
                ) : (
                  <span className={`h-1.5 w-1.5 rounded-full ${active ? "animate-pulse bg-sky-400" : "bg-zinc-600"}`} />
                )}
              </span>
              <span className={done || active ? "text-zinc-200" : "text-zinc-500"}>{s.label}</span>
              <span className="ml-auto font-mono text-[11px] text-zinc-500">{detail(s.key)}</span>
            </li>
          );
        })}
      </ol>
      {scan.error && <div className="mt-3 rounded-lg border border-rose-500/20 bg-rose-500/5 px-3 py-2 text-[12px] text-rose-200/90">{scan.error}</div>}
    </Panel>
  );
}

function FindingRow({ f, onSelect }: { f: Finding; onSelect: (id: string) => void }) {
  return (
    <button
      onClick={() => f.nodeId && onSelect(f.nodeId)}
      className="w-full rounded-lg border border-line bg-ink-850 p-3 text-left transition hover:border-line-strong disabled:cursor-default"
      disabled={!f.nodeId}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="truncate font-mono text-[13px] font-medium text-zinc-100">{f.variable ?? f.ruleLabel}</span>
        <span className={`${pill} shrink-0 ${f.inHead ? "bg-rose-500/10 text-rose-300 ring-rose-500/25" : "bg-amber-500/10 text-amber-300 ring-amber-500/25"}`}>{f.inHead ? "in code" : "history"}</span>
      </div>
      <div className="mt-1 flex items-center justify-between gap-2 text-[11px] text-zinc-500">
        <span className="truncate font-mono">
          {f.file}:{f.line}
        </span>
        <span className="shrink-0">{f.ruleLabel}</span>
      </div>
      <div className="mt-1.5 truncate font-mono text-[11px] text-zinc-400">{f.preview}</div>
      {!f.inHead && <div className="mt-1.5 text-[11px] leading-relaxed text-amber-200/80">Deleted from the code but still in commit {f.commit}. Anyone who clones the repo has it. Rotate it.</div>}
    </button>
  );
}

export function FindingsPanel({ scan, onSelect }: { scan: RealScan; onSelect: (id: string) => void }) {
  const history = scan.findings.filter((f) => !f.inHead).length;
  return (
    <Panel
      eyebrow="Secrets found"
      accent={scan.findings.length ? "bg-rose-500" : "bg-emerald-400"}
      title={scan.findings.length ? `${scan.findings.length} exposed secret${scan.findings.length === 1 ? "" : "s"}` : "No secrets found"}
      right={history ? <span className={`${pill} bg-amber-500/10 text-amber-300 ring-amber-500/25`}>{history} only in history</span> : undefined}
    >
      {scan.findings.length > 0 && (
        <div className="mt-3 flex flex-col gap-2">
          {scan.findings.slice(0, 30).map((f) => (
            <FindingRow key={f.id} f={f} onSelect={onSelect} />
          ))}
          {scan.findings.length > 30 && <div className="text-center text-[12px] text-zinc-500">+{scan.findings.length - 30} more</div>}
        </div>
      )}
      {!scan.findings.length && <p className="mt-2 text-[13px] text-zinc-400">No known token formats or high-entropy assignments in the files or the last {scan.commitsScanned} commits.</p>}
    </Panel>
  );
}

function VulnRow({ v }: { v: VulnPackage }) {
  return (
    <div className="rounded-lg border border-line bg-ink-850 p-3">
      <div className="flex items-center justify-between gap-2">
        <span className="truncate font-mono text-[13px] text-zinc-100">
          {v.name}
          <span className="text-zinc-500">@{v.version}</span>
        </span>
        <span className={`${pill} shrink-0 ${SEV[v.severity]}`}>{v.severity.toLowerCase()}</span>
      </div>
      <div className="mt-1 flex items-center justify-between gap-2 text-[11px] text-zinc-500">
        <span className="truncate">
          {v.ecosystem} · {v.direct ? "direct" : "transitive"} · {v.advisories.length} advisor{v.advisories.length === 1 ? "y" : "ies"}
        </span>
        {v.fixed && <span className={`shrink-0 font-mono ${v.fixable ? "text-emerald-300" : "text-zinc-400"}`}>→ {v.fixed}</span>}
      </div>
      <div className="mt-1.5 truncate text-[12px] text-zinc-400">
        <span className="font-mono text-zinc-500">{v.advisories[0].id}</span> {v.advisories[0].summary}
      </div>
    </div>
  );
}

export function VulnPanel({ scan }: { scan: RealScan }) {
  const fixable = scan.vulns.filter((v) => v.fixable);
  const counts = (["CRITICAL", "HIGH", "MODERATE", "LOW"] as Severity[]).map((s) => [s, scan.vulns.filter((v) => v.severity === s).length] as const).filter(([, n]) => n);
  const fix = scan.fix;
  return (
    <Panel eyebrow="Vulnerable dependencies" accent={scan.vulns.length ? "bg-sky-400" : "bg-emerald-400"} title={scan.vulns.length ? `${scan.vulns.length} vulnerable package${scan.vulns.length === 1 ? "" : "s"}` : "No known vulnerabilities"}>
      {counts.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {counts.map(([s, n]) => (
            <span key={s} className={`${pill} ${SEV[s]}`}>
              {n} {s.toLowerCase()}
            </span>
          ))}
        </div>
      )}
      {scan.vulns.length > 0 && (
        <div className="mt-3">
          {fix.status === "done" && fix.prUrl ? (
            <motion.a initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} href={fix.prUrl} target="_blank" rel="noreferrer" className="flex items-center gap-3 rounded-lg border border-emerald-500/25 bg-emerald-500/5 px-3 py-2.5 hover:border-emerald-500/40">
              <svg viewBox="0 0 24 24" className="h-4 w-4 text-emerald-300" fill="none" stroke="currentColor" strokeWidth={2}><circle cx="6" cy="6" r="2" /><circle cx="6" cy="18" r="2" /><circle cx="18" cy="18" r="2" /><path d="M6 8v8M18 16V9a3 3 0 0 0-3-3h-4" /></svg>
              <span className="text-[13px] text-zinc-100">Fix PR #{fix.prNumber}</span>
              <span className="text-[12px] text-zinc-500">{fix.packages?.length} packages</span>
              <span className="ml-auto text-[12px] text-emerald-300">Open on GitHub ↗</span>
            </motion.a>
          ) : (
            <button
              disabled={!fixable.length || !scan.repo || fix.status === "running"}
              onClick={() => post("/real/fix")}
              className="flex h-9 w-full items-center justify-center gap-2 rounded-lg bg-zinc-100 text-[13px] font-medium text-zinc-900 transition hover:bg-white disabled:cursor-not-allowed disabled:opacity-40"
            >
              {fix.status === "running" ? "Opening PR…" : fixable.length ? `Open fix PR · ${new Set(fixable.map((v) => v.name)).size} packages` : "No automatic fixes available"}
            </button>
          )}
          {fix.status === "failed" && <div className="mt-2 rounded-lg border border-rose-500/20 bg-rose-500/5 px-3 py-2 text-[12px] text-rose-200/90">{fix.note}</div>}
          {!scan.repo && <div className="mt-2 text-[11px] text-zinc-500">Fix PRs are available for GitHub repositories.</div>}
        </div>
      )}
      {scan.vulns.length > 0 && (
        <div className="mt-3 flex flex-col gap-2">
          {scan.vulns.slice(0, 8).map((v) => (
            <VulnRow key={v.key} v={v} />
          ))}
          {scan.vulns.length > 8 && <div className="text-center text-[12px] text-zinc-500">+{scan.vulns.length - 8} more</div>}
        </div>
      )}
    </Panel>
  );
}
