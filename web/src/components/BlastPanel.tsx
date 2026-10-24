import { motion } from "framer-motion";
import type { BlastResult, DemoState } from "../../../shared/types";

export function BlastPanel({ blast, demo, onClose }: { blast: BlastResult; demo: DemoState; onClose: () => void }) {
  const label = (id: string) => demo.nodes.find((n) => n.id === id)?.label ?? id;
  return (
    <motion.section initial={{ opacity: 0, x: 40 }} animate={{ opacity: 1, x: 0 }} className="rounded-xl border border-orange-500/40 bg-slate-900 p-4">
      <div className="flex items-start justify-between">
        <div>
          <div className="text-xs uppercase tracking-widest text-orange-300">Blast radius</div>
          <h2 className="text-2xl font-bold text-slate-50">{label(blast.nodeId)}</h2>
        </div>
        <button className="text-2xl text-slate-500 hover:text-slate-200" onClick={onClose} aria-label="Close">
          ×
        </button>
      </div>
      <ol className="mt-3 space-y-1">
        {blast.hops.map((h, i) => (
          <motion.li key={i} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.4 * (i + 1) }} className="flex gap-2 text-base">
            <span className="w-14 shrink-0 font-mono text-orange-300">hop {i + 1}</span>
            <span className="text-slate-200">{h.nodes.map(label).join(", ")}</span>
          </motion.li>
        ))}
      </ol>
      <p className="mt-3 text-[15px] leading-snug text-slate-300">{blast.explanation}</p>
      <div className="mt-3 rounded-lg bg-red-950/70 p-3 text-[15px] text-red-200">
        <span className="font-semibold text-red-300">Worst case: </span>
        {blast.worstCase}
      </div>
      <div className="mt-2 text-right text-xs text-slate-500">{blast.source === "llm" ? "explained by LLM" : "canned explanation"}</div>
    </motion.section>
  );
}
