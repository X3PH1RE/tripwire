import { Background, BackgroundVariant, MarkerType, ReactFlow, type Edge } from "@xyflow/react";
import { useMemo } from "react";
import type { DemoState, GraphNode } from "../../../shared/types";
import { HOT_STATUSES } from "../colors";
import { TripNode, type TripFlowNode } from "./TripNode";

const nodeTypes = { trip: TripNode };

function handlesFor(a: GraphNode, b: GraphNode): [string, string, "default" | "smoothstep"] {
  const dx = b.position.x - a.position.x;
  const dy = b.position.y - a.position.y;
  if (Math.abs(dx) < 60) return dy > 0 ? ["s-Bottom", "t-Top", "smoothstep"] : ["s-Top", "t-Bottom", "smoothstep"];
  if (dx > 0) return ["s-Right", "t-Left", "default"];
  return ["s-Bottom", "t-Top", "smoothstep"];
}

interface Props {
  demo: DemoState;
  litEdges: Set<string>;
  litNodes: Set<string>;
  selectedId: string | null;
  onSelect: (node: GraphNode) => void;
}

export function Graph({ demo, litEdges, litNodes, selectedId, onSelect }: Props) {
  const nodes: TripFlowNode[] = useMemo(
    () =>
      demo.nodes.map((n) => ({
        id: n.id,
        type: "trip",
        position: n.position,
        data: { node: n, lit: litNodes.has(n.id), selected: n.id === selectedId, secured: demo.containment.status === "done" },
        draggable: false,
        selectable: false,
      })),
    [demo.nodes, demo.containment.status, litNodes, selectedId],
  );

  const edges: Edge[] = useMemo(() => {
    const byId = new Map(demo.nodes.map((n) => [n.id, n]));
    return demo.edges.map((e) => {
      const a = byId.get(e.from)!;
      const b = byId.get(e.to)!;
      const [sourceHandle, targetHandle, type] = handlesFor(a, b);
      const lit = litEdges.has(e.id);
      const hot = HOT_STATUSES.includes(a.status) && HOT_STATUSES.includes(b.status);
      const green = !lit && !hot && (a.status === "rotated" || a.status === "patched") && (b.status === "rotated" || b.status === "patched");
      const color = lit ? "#fbbf24" : hot ? "#f43f5e" : green ? "#34d399" : e.kind === "unlocks" ? "#52525b" : "#3f3f46";
      return {
        id: e.id,
        source: e.from,
        target: e.to,
        sourceHandle,
        targetHandle,
        type,
        animated: lit || hot,
        className: lit ? "edge-lit" : hot ? "edge-hot" : "",
        style: { stroke: color, strokeWidth: lit ? 2.5 : hot ? 2 : 1.25, strokeDasharray: e.kind === "stored_in" && !lit && !hot ? "4 4" : undefined },
        markerEnd: { type: MarkerType.ArrowClosed, color, width: 14, height: 14 },
        label: e.kind === "unlocks" ? "unlocks" : undefined,
        labelStyle: { fill: "#71717a", fontSize: 10, fontFamily: "JetBrains Mono" },
        labelBgStyle: { fill: "#0a0a0c" },
        labelBgPadding: [4, 2] as [number, number],
      };
    });
  }, [demo.edges, demo.nodes, litEdges]);

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      fitView
      fitViewOptions={{ padding: 0.12 }}
      nodesDraggable={false}
      nodesConnectable={false}
      elementsSelectable={false}
      zoomOnScroll={false}
      zoomOnDoubleClick={false}
      proOptions={{ hideAttribution: true }}
      colorMode="dark"
      style={{ background: "transparent" }}
      onNodeClick={(_, n) => onSelect((n as TripFlowNode).data.node)}
    >
      <Background variant={BackgroundVariant.Dots} color="#27272a" gap={22} size={1.2} />
    </ReactFlow>
  );
}
