export type Confidence = "high" | "medium" | "low";

export const CONFIDENCE_RANK: Record<Confidence, number> = { low: 0, medium: 1, high: 2 };

/** Gitleaks-compatible allowlist: a finding is dropped when it matches (any, or all with condition AND) of the populated criteria. */
export interface AllowlistDef {
  description?: string;
  condition?: "OR" | "AND";
  /** What `regexes` are tested against. Default `secret`. */
  regexTarget?: "secret" | "match" | "line";
  regexes?: string[];
  stopwords?: string[];
  paths?: string[];
}

/** Structure checks that go beyond what a regex can say. */
export type CheckId = "github-checksum" | "jwt";

export interface RuleDef {
  id: string;
  label: string;
  provider: string;
  /** JS regex source. A leading `(?i)`-style group is peeled into real flags. */
  regex: string;
  /** 1-based group holding the secret; default is the first non-empty group, else the whole match. */
  secretGroup?: number;
  /** Group reported to the user when it differs from the secret (e.g. the whole URL for a database password). */
  reportGroup?: number;
  /** A line is only tested when it contains one of these (case-insensitive). */
  keywords: string[];
  /** Reject secrets shorter than this. */
  minLength?: number;
  /** Reject secrets whose Shannon entropy is not above this. */
  entropy?: number;
  /** Run over the whole file/hunk instead of a single line. */
  multiline?: boolean;
  confidence?: Confidence;
  check?: CheckId;
  /** Only run on files whose path matches. */
  path?: string;
  allowlists?: AllowlistDef[];
  source: "tripwire" | "gitleaks";
}

export interface Pack {
  source: string;
  license?: string;
  allowlist?: AllowlistDef;
  rules: RuleDef[];
}
