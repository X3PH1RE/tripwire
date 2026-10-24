import { motion } from "framer-motion";
import type { DemoState } from "../../../shared/types";

export function ContainPanel({ demo }: { demo: DemoState }) {
  const c = demo.containment;
  if (c.status === "idle") return null;
  const pct = c.total ? (100 * c.done) / c.total : 0;
  return (
    <motion.section initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} className="rounded-xl border border-emerald-500/40 bg-slate-900 p-4">
      <div className="flex items-baseline justify-between">
        <h3 className="text-xl font-bold text-slate-50">{c.status === "done" ? "Contained" : "Containing…"}</h3>
        <span className="font-mono text-2xl font-bold text-emerald-300">
          {c.done} of {c.total}
        </span>
      </div>
      <div className="mt-2 h-3 overflow-hidden rounded-full bg-slate-800">
        <motion.div className="h-full bg-emerald-500" animate={{ width: `${pct}%` }} transition={{ duration: 0.4 }} />
      </div>
      {c.rotations.map((r) => (
        <div key={r.nodeId} className="mt-3 rounded-lg bg-slate-950 p-2 font-mono text-xs">
          <div className="mb-1 font-sans text-sm font-semibold text-slate-200">{r.label}</div>
          <div className="text-red-400 line-through">{r.before}</div>
          <div className="text-emerald-400">{r.after}</div>
        </div>
      ))}
    </motion.section>
  );
}
