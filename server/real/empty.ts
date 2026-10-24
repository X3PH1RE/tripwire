import type { RealScan } from "../../shared/types";

export function emptyScan(): RealScan {
  return { status: "idle", filesScanned: 0, commitsScanned: 0, nodes: [], edges: [], findings: [], vulns: [], fix: { status: "idle" }, contain: { status: "idle", plan: [], results: [] } };
}
