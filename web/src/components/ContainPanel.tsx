import { motion } from "framer-motion";
import type { DemoState } from "../../../shared/types";
import { Panel } from "./ui";

export function ContainPanel({ demo }: { demo: DemoState }) {
  const c = demo.containment;
  if (c.status === "idle") return null;
  const pct = c.total ? (100 * c.done) / c.total : 0;
  return (
    <motion.div initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }}>
      <Panel
        eyebrow="Containment"
        accent={c.status === "done" ? "bg-emerald-400" : "bg-amber-400"}
        title={c.status === "done" ? "All exposed secrets rotated" : "Rotating, highest risk first"}
        right={<span className="font-mono text-[13px] tabular-nums text-zinc-400">{c.done}/{c.total}</span>}
      >
        <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-ink-800">
          <motion.div className={`h-full ${c.status === "done" ? "bg-emerald-400" : "bg-amber-400"}`} animate={{ width: `${pct}%` }} transition={{ duration: 0.4 }} />
        </div>
        <div className="mt-3 space-y-2">
          {c.rotations.map((r) => (
            <div key={r.nodeId} className="rounded-lg border border-line bg-ink-950/60 px-3 py-2 font-mono text-[11px]">
              <div className="mb-1 font-sans text-[12px] font-medium text-zinc-300">{r.label}</div>
              <div className="flex gap-2 text-zinc-500 line-through decoration-rose-400/60"><span className="text-rose-400/80 no-underline">−</span>{r.before}</div>
              <div className="flex gap-2 text-emerald-300"><span>+</span>{r.after}</div>
            </div>
          ))}
        </div>
      </Panel>
    </motion.div>
  );
}
