import { motion } from "framer-motion";
import type { CveState } from "../../../shared/types";
import { Panel } from "./ui";

export function Timeline({ cve }: { cve: CveState }) {
  if (cve.status === "idle") return null;
  const t0 = cve.steps[0]?.at ?? 0;
  return (
    <motion.div initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }}>
      <Panel eyebrow="Zero-day response" accent="bg-sky-400" title={<span className="font-mono">{cve.cveId}</span>}>
        <p className="mt-1 text-[13px] leading-relaxed text-zinc-400">{cve.summary}</p>
        <ol className="mt-4 space-y-3">
          {cve.steps.map((s, i) => (
            <li key={s.key} className="relative flex items-center gap-3 text-[13px]">
              {i < cve.steps.length - 1 && <span className={`absolute left-[9px] top-5 h-4 w-px ${s.at ? "bg-sky-400/40" : "bg-line"}`} />}
              <span className={`flex h-[19px] w-[19px] shrink-0 items-center justify-center rounded-full ${s.at ? "bg-sky-400/15 text-sky-300 ring-1 ring-sky-400/40" : "ring-1 ring-line-strong"}`}>
                {s.at && (
                  <svg viewBox="0 0 24 24" className="h-3 w-3" fill="none" stroke="currentColor" strokeWidth={3}><path d="M5 12l5 5L20 7" /></svg>
                )}
              </span>
              <span className={s.at ? "text-zinc-200" : "text-zinc-500"}>{s.label}</span>
              <span className="ml-auto font-mono text-[11px] tabular-nums text-zinc-500">{s.at ? `+${((s.at - t0) / 1000).toFixed(1)}s` : ""}</span>
            </li>
          ))}
        </ol>
        {cve.prUrl && (
          <a href={cve.prUrl} target="_blank" rel="noreferrer" className="mt-4 flex items-center justify-between rounded-lg border border-line bg-ink-850 px-3 py-2.5 text-[13px] text-zinc-200 transition hover:border-sky-400/40 hover:bg-ink-800">
            <span className="flex items-center gap-2">
              <svg viewBox="0 0 24 24" className="h-4 w-4 text-emerald-400" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round"><circle cx="6" cy="6" r="2.5" /><circle cx="6" cy="18" r="2.5" /><circle cx="18" cy="18" r="2.5" /><path d="M6 8.5v7M18 15.5V9a3 3 0 0 0-3-3h-4" /></svg>
              Pull request <span className="font-mono text-zinc-400">#{cve.prNumber}</span>
            </span>
            <span className="text-zinc-500">Open on GitHub ↗</span>
          </a>
        )}
        {cve.replayed && <p className="mt-2 text-[12px] text-amber-300/90">{cve.note}</p>}
      </Panel>
    </motion.div>
  );
}
