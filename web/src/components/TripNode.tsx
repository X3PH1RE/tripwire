import { Handle, Position, type NodeProps, type Node } from "@xyflow/react";
import { motion } from "framer-motion";
import type { GraphNode } from "../../../shared/types";
import { dangerColor, statusClasses, stripe } from "../colors";

export type TripNodeData = { node: GraphNode; lit: boolean; selected: boolean; secured: boolean };
export type TripFlowNode = Node<TripNodeData, "trip">;

const ICON_PATH: Record<GraphNode["type"], string> = {
  repo: "M4 4h16v16H4z M4 9h16",
  service: "M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z M12 2v3 M12 19v3 M2 12h3 M19 12h3 M5 5l2 2 M17 17l2 2 M5 19l2-2 M17 7l2-2",
  resource: "M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3z M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6 M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3",
  secret: "M14 10a4 4 0 1 0-3.5 3.97L10 14v3h3v3h3v-3l-2.5-2.5A4 4 0 0 0 14 10z M7.5 9.5h.01",
  decoy: "M3 17h18 M5 17l3-9 4 5 4-5 3 9 M12 4v3",
};

function Icon({ type }: { type: GraphNode["type"] }) {
  return (
    <svg viewBox="0 0 24 24" className="h-3.5 w-3.5 shrink-0" fill="none" stroke="currentColor" strokeWidth={1.75} strokeLinecap="round" strokeLinejoin="round">
      <path d={ICON_PATH[type]} />
    </svg>
  );
}

function subtitle(n: GraphNode): string {
  if (n.type === "secret" || n.type === "decoy") {
    const file = n.file && n.file.length > 16 ? n.file.split("/").pop() : n.file;
    return `${file}:${n.line}`;
  }
  if (n.type === "service") return n.version ?? "";
  if (n.type === "resource") return n.sensitivity === "production" ? "production" : `${n.sensitivity} sensitivity`;
  return "repository";
}

const hidden = { opacity: 0, width: 6, height: 6 };

export function TripNode({ data }: NodeProps<TripFlowNode>) {
  const { node: n, lit, selected, secured } = data;
  const clickable = n.type === "secret";
  const typeLabel = n.type === "decoy" ? "honey secret" : n.type;
  return (
    <div
      className={`tw-node relative ${n.type === "decoy" ? "w-[215px] py-2" : "w-[230px] py-2.5"} overflow-hidden rounded-lg border pl-4 pr-3 ${statusClasses(n, secured)} ${
        lit ? "shadow-[0_0_0_2px_rgba(251,191,36,0.7)]" : ""
      } ${selected ? "outline outline-1 outline-offset-4 outline-zinc-300/70" : ""} ${clickable ? "cursor-pointer hover:border-zinc-400/60" : ""}`}
    >
      <span className={`absolute inset-y-0 left-0 w-[3px] ${stripe(n, secured)}`} />
      {(["Top", "Right", "Bottom", "Left"] as const).map((side) => (
        <Handle key={`s-${side}`} id={`s-${side}`} type="source" position={Position[side]} style={hidden} isConnectable={false} />
      ))}
      {(["Top", "Right", "Bottom", "Left"] as const).map((side) => (
        <Handle key={`t-${side}`} id={`t-${side}`} type="target" position={Position[side]} style={hidden} isConnectable={false} />
      ))}
      <div className={`items-center justify-between gap-2 ${n.type === "decoy" ? "hidden" : "flex"}`}>
        <div className="flex items-center gap-1.5 text-[10px] font-medium uppercase tracking-[0.12em] text-zinc-500">
          <Icon type={n.type} />
          {typeLabel}
        </div>
        {n.type === "secret" && n.danger !== undefined && (
          <motion.span
            key={`${n.danger}-${n.status}`}
            initial={{ scale: 1.5, opacity: 0.4 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ type: "spring", stiffness: 300, damping: 18 }}
            className={`rounded-md px-1.5 py-0.5 font-mono text-[11px] font-medium ring-1 ring-inset ${
              n.status === "rotated" ? "bg-emerald-500/10 text-emerald-300 ring-emerald-500/25" : dangerColor(n.danger)
            }`}
          >
            {n.status === "rotated" ? "rotated" : `risk ${n.danger}`}
          </motion.span>
        )}
        {n.badge && <span className="rounded-md bg-emerald-500/10 px-1.5 py-0.5 font-mono text-[11px] text-emerald-300 ring-1 ring-inset ring-emerald-500/25">{n.badge}</span>}
      </div>
      <div className={`flex items-center gap-1.5 truncate font-semibold tracking-tight text-zinc-50 ${n.type === "decoy" ? "text-[13px]" : "mt-1 text-[14px]"}`}>
        {n.type === "decoy" && <span className="text-violet-300"><Icon type="decoy" /></span>}
        <span className="truncate">{n.label}</span>
      </div>
      <div className="mt-0.5 flex items-center justify-between gap-2 text-[11px] text-zinc-400">
        <span className="truncate font-mono">{subtitle(n)}</span>
        {n.provider && <span className="font-mono text-zinc-500">{n.provider}</span>}
      </div>
    </div>
  );
}
