import type { GraphNode } from "../../shared/types";

export function dangerColor(danger: number): string {
  if (danger >= 70) return "bg-rose-500/15 text-rose-300 ring-rose-500/30";
  if (danger >= 40) return "bg-amber-500/15 text-amber-300 ring-amber-500/30";
  return "bg-emerald-500/10 text-emerald-300 ring-emerald-500/25";
}

/** Accent colour of the status stripe on the left edge of each node. */
export function stripe(n: GraphNode, secured = false): string {
  if (n.type === "decoy") return n.status === "attacked" ? "bg-violet-400" : "bg-violet-500/60";
  switch (n.status) {
    case "exposed":
    case "attacked":
      return "bg-rose-500";
    case "rotating":
      return "bg-amber-400 animate-pulse";
    case "rotated":
    case "patched":
      return "bg-emerald-400";
    default:
      return secured ? "bg-emerald-500/50" : "bg-zinc-600";
  }
}

export function statusClasses(n: GraphNode, secured = false): string {
  if (n.type === "decoy")
    return n.status === "attacked"
      ? "bg-violet-950/60 border-violet-400/70 border-dashed shadow-[0_0_0_4px_rgba(139,92,246,0.15)]"
      : "bg-ink-900 border-violet-500/40 border-dashed";
  switch (n.status) {
    case "exposed":
      return "bg-rose-950/50 border-rose-500/70 shadow-[0_0_0_4px_rgba(244,63,94,0.14)]";
    case "attacked":
      return "bg-rose-950/30 border-rose-500/45";
    case "rotating":
      return "bg-amber-950/30 border-amber-400/60";
    case "rotated":
    case "patched":
      return "bg-emerald-950/30 border-emerald-500/50";
    default:
      return secured ? "bg-ink-900 border-emerald-500/25" : "bg-ink-900 border-line-strong";
  }
}

export const HOT_STATUSES: GraphNode["status"][] = ["exposed", "attacked"];
