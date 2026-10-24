import { motion } from "framer-motion";
import type { BlastResult, GraphNode } from "../../../shared/types";
import { Panel } from "./ui";

export function BlastPanel({ blast, nodes, onClose }: { blast: BlastResult; nodes: GraphNode[]; onClose: () => void }) {
  const label = (id: string) => nodes.find((n) => n.id === id)?.label ?? id;
  return (
    <motion.div initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }}>
      <Panel
        eyebrow="Blast radius"
        accent="bg-amber-400"
        title={<span className="font-mono">{label(blast.nodeId)}</span>}
        right={
          <button className="rounded-md p-1 text-zinc-500 hover:bg-white/5 hover:text-zinc-200" onClick={onClose} aria-label="Close">
            <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth={2}><path d="M6 6l12 12M18 6L6 18" /></svg>
          </button>
        }
      >
        <ol className="relative mt-4 space-y-2.5 border-l border-line pl-4">
          {blast.hops.map((h, i) => (
            <motion.li key={i} initial={{ opacity: 0, x: -4 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.4 * (i + 1) }} className="relative text-[13px]">
              <span className="absolute -left-[21px] top-1.5 h-2 w-2 rounded-full bg-amber-400 ring-4 ring-ink-900" />
              <span className="mr-2 font-mono text-[11px] text-zinc-500">{String(i + 1).padStart(2, "0")}</span>
              <span className="text-zinc-200">{h.nodes.map(label).join(", ")}</span>
            </motion.li>
          ))}
        </ol>
        <p className="mt-4 text-[13px] leading-relaxed text-zinc-400">{blast.explanation}</p>
        <div className="mt-3 rounded-lg border border-rose-500/20 bg-rose-500/5 px-3 py-2.5 text-[13px] leading-relaxed text-rose-200/90">
          <span className="font-medium text-rose-300">Worst case. </span>
          {blast.worstCase}
        </div>
        <div className="mt-2 text-right font-mono text-[10px] uppercase tracking-wider text-zinc-600">{blast.source === "llm" ? "LLM explanation" : "deterministic explanation"}</div>
      </Panel>
    </motion.div>
  );
}
