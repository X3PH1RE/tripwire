import type { GraphEdge, GraphNode } from "../shared/types";

export interface Hop {
  edges: string[];
  nodes: string[];
}

export function blastHops(edges: GraphEdge[], startIds: string[]): Hop[] {
  const seen = new Set(startIds);
  const hops: Hop[] = [];
  let frontier = [...startIds];
  while (frontier.length) {
    const hop: Hop = { edges: [], nodes: [] };
    for (const id of frontier) {
      for (const e of edges) {
        if (e.from !== id || seen.has(e.to)) continue;
        seen.add(e.to);
        hop.edges.push(e.id);
        hop.nodes.push(e.to);
      }
    }
    if (!hop.nodes.length) break;
    hops.push(hop);
    frontier = hop.nodes;
  }
  return hops;
}

export function reachableNodes(nodes: GraphNode[], edges: GraphEdge[], startId: string): GraphNode[] {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  return blastHops(edges, [startId])
    .flatMap((h) => h.nodes)
    .map((id) => byId.get(id))
    .filter((n): n is GraphNode => !!n);
}
