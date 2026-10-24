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
  scan: RealScan;
  honeyTokens: HoneyToken[];
  honeyBusy?: string;
}

export interface BlastResult {
  nodeId: string;
  hops: { edges: string[]; nodes: string[] }[];
  explanation: string;
  worstCase: string;
  source: "llm" | "canned";
}

export interface Finding {
  id: string;
  rule: string;
  ruleLabel: string;
  provider: string;
  variable?: string;
  file: string;
  line: number;
  /** Short SHA of the commit that introduced it when it only survives in git history. */
  commit?: string;
  inHead: boolean;
  /** Added by the change being checked (`--diff <base>`). */
  isNew?: boolean;
  preview: string;
  service: string;
  nodeId: string;
  /** How sure the rule is: fixed-format provider tokens are high, name-based matches are medium or low. */
  confidence?: "high" | "medium" | "low";
  /** Set when the value was found inside an encoded string, e.g. "base64". */
  via?: string;
  /** Accepted in the baseline file: reported, but never blocks. */
  baselined?: boolean;
  /** Hash of rule + file + value (never the value itself); what the baseline file stores. */
  fingerprint?: string;
  /** Result of asking the provider whether the key works (`--verify`). */
  verify?: Verification;
}

export interface Access {
  label: string;
  sensitivity: NonNullable<GraphNode["sensitivity"]>;
  detail?: string;
}

export interface Verification {
  status: "live" | "revoked" | "unverified" | "honey";
  /** Who the key authenticates as, e.g. an AWS ARN or GitHub login. */
  identity?: string;
  note?: string;
  /** What the provider says the key can reach. */
  access?: Access[];
}

export interface HoneyHit {
  at: number;
  ip?: string;
  location?: string;
  org?: string;
  userAgent?: string;
  /** AWS API call or service the attacker tried. */
  action?: string;
}

/** A real decoy credential (Canarytokens AWS key). Safe to expose to the UI: no secret or auth token. */
export interface HoneyToken {
  id: string;
  accessKeyPreview: string;
  memo: string;
  createdAt: number;
  repo?: string;
  file?: string;
  prUrl?: string;
  historyUrl: string;
  /** Decoy env lines to place by hand when it was not planted through a PR. A decoy unlocks nothing. */
  snippet?: string;
  lastCheck?: number;
  checkError?: string;
  hits: HoneyHit[];
}

export type Severity = "CRITICAL" | "HIGH" | "MODERATE" | "LOW" | "UNKNOWN";

export interface VulnPackage {
  key: string;
  ecosystem: string;
  name: string;
  version: string;
  file: string;
  direct: boolean;
  severity: Severity;
  advisories: { id: string; summary: string; severity: Severity }[];
  fixed?: string;
  fixable: boolean;
}

export interface RealFix {
  status: "idle" | "running" | "done" | "failed";
  prUrl?: string;
  prNumber?: number;
  packages?: string[];
  note?: string;
}

export interface RealScan {
  status: "idle" | "cloning" | "secrets" | "history" | "verify" | "vulns" | "done" | "failed";
  verify?: boolean;
  target?: string;
  repo?: string;
  branch?: string;
  startedAt?: number;
  finishedAt?: number;
  error?: string;
  filesScanned: number;
  commitsScanned: number;
  nodes: GraphNode[];
  edges: GraphEdge[];
  findings: Finding[];
  vulns: VulnPackage[];
  fix: RealFix;
}
