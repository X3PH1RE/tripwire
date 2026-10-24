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
  badge?: string;
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
  kind: "breach" | "honey" | "cve" | "contain" | "info";
  at: number;
  title: string;
  summary: string;
  details?: { label: string; value: string }[];
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

export interface ScanHit {
  file: string;
  line: number;
  variable?: string;
  rule: "prefix" | "assignment" | "entropy";
  preview: string;
  entropy: number;
  kind: "secret" | "decoy" | "unknown";
  nodeId?: string;
  provider?: string;
  reaches: { id: string; label: string; sensitivity?: GraphNode["sensitivity"] }[];
}

export interface Rotation {
  nodeId: string;
  label: string;
  before: string;
  after: string;
}

export interface CveStep {
  key: "disclosed" | "found" | "pr" | "ready";
  label: string;
  at?: number;
}

export interface CveState {
  status: "idle" | "running" | "done" | "failed";
  cveId?: string;
  summary?: string;
  steps: CveStep[];
  prUrl?: string;
  prNumber?: number;
  replayed?: boolean;
  note?: string;
}

export interface DemoState {
  nodes: GraphNode[];
  edges: GraphEdge[];
  incidents: Incident[];
  breach: { provider?: string; startedAt?: number };
  honey: { planted: boolean; attacks: number };
  containment: {
    status: "idle" | "running" | "done";
    startedAt?: number;
    finishedAt?: number;
    total: number;
    done: number;
    rotations: Rotation[];
  };
  cve: CveState;
}

export interface BlastResult {
  nodeId: string;
  hops: { edges: string[]; nodes: string[] }[];
  explanation: string;
  worstCase: string;
  source: "llm" | "canned";
}
