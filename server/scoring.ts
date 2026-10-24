import type { GraphEdge, GraphNode } from "../shared/types";
import { reachableNodes } from "./graph";

const SENSITIVITY_SCORE = { production: 40, high: 30, medium: 15, low: 5 } as const;

export function dangerScore(node: GraphNode, nodes: GraphNode[], edges: GraphEdge[], boost = 0): number {
  if (node.status === "rotated" || node.status === "rotating") return 0;
  const resources = reachableNodes(nodes, edges, node.id).filter((n) => n.type === "resource");
  if (!resources.length) return Math.min(100, boost);
  const base = Math.max(...resources.map((r) => SENSITIVITY_SCORE[r.sensitivity ?? "low"]));
  const breadth = Math.min(30, 10 * (resources.length - 1));
  const production = resources.some((r) => r.sensitivity === "production") ? 20 : 0;
  const exposed = node.status === "exposed" || node.status === "attacked" ? 15 : 0;
  return Math.min(100, base + breadth + production + exposed + boost);
}

export function withDanger(nodes: GraphNode[], edges: GraphEdge[], boosts: Record<string, number>): GraphNode[] {
  return nodes.map((n) => (n.type === "secret" ? { ...n, danger: dangerScore(n, nodes, edges, boosts[n.id] ?? 0) } : n));
}
