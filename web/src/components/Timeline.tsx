import { motion } from "framer-motion";
import type { CveState } from "../../../shared/types";

export function Timeline({ cve }: { cve: CveState }) {
  if (cve.status === "idle") return null;
  const t0 = cve.steps[0]?.at ?? 0;
  return (
    <motion.section initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} className="rounded-xl border border-sky-500/40 bg-slate-900 p-4">
      <div className="text-xs uppercase tracking-widest text-sky-300">Zero-day responder</div>
      <h3 className="text-xl font-bold text-slate-50">{cve.cveId}</h3>
      <p className="text-sm text-slate-400">{cve.summary}</p>
      <ol className="mt-3 space-y-2">
        {cve.steps.map((s) => (
          <li key={s.key} className="flex items-center gap-3 text-base">
            <span className={`flex h-6 w-6 items-center justify-center rounded-full text-sm font-bold ${s.at ? "bg-sky-500 text-slate-950" : "border-2 border-slate-600 text-transparent"}`}>✓</span>
            <span className={s.at ? "text-slate-100" : "text-slate-500"}>{s.label}</span>
            <span className="ml-auto font-mono text-sm text-slate-400">{s.at ? `+${((s.at - t0) / 1000).toFixed(1)}s` : ""}</span>
          </li>
        ))}
      </ol>
      {cve.prUrl && (
        <a href={cve.prUrl} target="_blank" rel="noreferrer" className="mt-3 block rounded-lg bg-sky-600 px-3 py-2 text-center text-lg font-bold text-white hover:bg-sky-500">
          Open PR #{cve.prNumber} on GitHub ↗
        </a>
      )}
      {cve.replayed && <p className="mt-2 text-sm text-amber-300">Replayed: {cve.note}</p>}
    </motion.section>
  );
}
