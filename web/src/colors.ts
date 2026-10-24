import type { GraphNode } from "../../shared/types";

export function dangerColor(danger: number): string {
  if (danger >= 70) return "bg-red-500 text-white";
  if (danger >= 40) return "bg-amber-400 text-slate-950";
  return "bg-emerald-500 text-slate-950";
}

export function statusClasses(n: GraphNode): string {
  if (n.type === "decoy") return "bg-fuchsia-950/60 border-fuchsia-400 border-dashed";
  switch (n.status) {
    case "exposed":
      return "bg-red-900 border-red-400 shadow-[0_0_28px_rgba(239,68,68,0.75)]";
    case "attacked":
      return "bg-red-950 border-red-500 shadow-[0_0_18px_rgba(239,68,68,0.55)]";
    case "rotating":
      return "bg-amber-900 border-amber-300 animate-pulse";
    case "rotated":
    case "patched":
      return "bg-emerald-900 border-emerald-400 shadow-[0_0_14px_rgba(16,185,129,0.45)]";
    default:
      return "bg-slate-800 border-slate-600";
  }
}

export const HOT_STATUSES: GraphNode["status"][] = ["exposed", "attacked"];
