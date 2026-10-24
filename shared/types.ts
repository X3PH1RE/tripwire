export type NodeType = "repo" | "service" | "resource" | "secret" | "decoy";

export type NodeStatus = "ok" | "exposed" | "attacked" | "rotating" | "rotated" | "patched";

export interface GraphNode {
  id: string;
  type: NodeType;
  label: string;
  provider?: string;
  sensitivity?: "low" | "medium" | "high" | "production";
  file?: string;
  line?: number;
  version?: string;
  status: NodeStatus;
  danger?: number;
  position: { x: number; y: number };
}

export interface GraphEdge {
  id: string;
  from: string;
  to: string;
  kind: "stored_in" | "unlocks";
}

export interface Incident {
  id: string;
  kind: "breach" | "honey" | "cve";
  at: number;
  summary: string;
  affectedNodeIds: string[];
}

export interface World {
  company: string;
  root: string;
  notes: Record<string, string>;
  heroPath: string[];
  nodes: GraphNode[];
  edges: GraphEdge[];
}
