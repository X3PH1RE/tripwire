import type { GraphEdge, GraphNode } from "../shared/types";
import { blastHops } from "./graph";

export interface Generated {
  text: string;
  source: "llm" | "canned";
}

/** Canned text is the default. The LLM is only asked when LLM_ENABLED=1 and a key is set, and any failure falls back. */
export async function generate(prompt: string, fallback: string): Promise<Generated> {
  const key = process.env.LLM_API_KEY;
  if (process.env.LLM_ENABLED !== "1" || !key) return { text: fallback, source: "canned" };
  try {
    const res = await fetch(`${process.env.LLM_BASE_URL ?? "https://api.openai.com/v1"}/chat/completions`, {
      method: "POST",
      headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: process.env.LLM_MODEL ?? "gpt-4o-mini",
        max_tokens: 300,
        messages: [
          { role: "system", content: "You are a concise security engineer. Plain language, no markdown headings, under 90 words." },
          { role: "user", content: prompt },
        ],
      }),
      signal: AbortSignal.timeout(Number(process.env.LLM_TIMEOUT_MS ?? 3000)),
    });
    if (!res.ok) throw new Error(`LLM ${res.status}`);
    const json = (await res.json()) as { choices?: { message?: { content?: string } }[] };
    const text = json.choices?.[0]?.message?.content?.trim();
    return text ? { text, source: "llm" } : { text: fallback, source: "canned" };
  } catch {
    return { text: fallback, source: "canned" };
  }
}

const HERO_EXPLANATION =
  "DATABASE_URL opens the customers Postgres database. Inside it, the integrations.cloud_credentials table holds CLOUD_ACCESS_KEY, which unlocks the uploads bucket. That bucket keeps ci/deploy.env with DEPLOY_TOKEN, which can push code to production. One leaked connection string reaches production in five hops.";

export function cannedBlast(
  startId: string,
  nodes: GraphNode[],
  edges: GraphEdge[],
  notes: Record<string, string>,
): { explanation: string; worstCase: string } {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const edgeById = new Map(edges.map((e) => [e.id, e]));
  const start = byId.get(startId)!;
  const hops = blastHops(edges, [startId]);
  const reached = hops.flatMap((h) => h.nodes).map((id) => byId.get(id)!);
  const resources = reached.filter((n) => n.type === "resource");

  let worstCase = `${start.label} does not unlock anything sensitive on its own.`;
  const prod = resources.find((r) => r.sensitivity === "production");
  const high = resources.filter((r) => r.sensitivity === "high");
  if (prod) worstCase = `An attacker ships their own code to ${prod.label.toLowerCase()}${high.length ? ` and reads ${high.map((r) => r.label).join(", ")} on the way` : ""}.`;
  else if (high.length) worstCase = `An attacker reads or changes everything in ${high.map((r) => r.label).join(" and ")}.`;
  else if (resources.length) worstCase = `An attacker gets into ${resources.map((r) => r.label).join(" and ")}.`;

  if (startId === "sec-database-url") return { explanation: HERO_EXPLANATION, worstCase };

  const sentences = hops.flatMap((h) =>
    h.edges.map((id) => {
      const e = edgeById.get(id)!;
      const a = byId.get(e.from)!;
      const b = byId.get(e.to)!;
      if (e.kind === "unlocks") return `${a.label} unlocks ${b.label}.`;
      return `${a.label} stores ${b.label}${notes[a.id] ? ` (${notes[a.id]})` : ""}.`;
    }),
  );
  const explanation = sentences.length
    ? `${sentences.join(" ")} Reach: ${resources.length} resource${resources.length === 1 ? "" : "s"} in ${hops.length} hop${hops.length === 1 ? "" : "s"}.`
    : `${start.label} is not connected to anything else in the graph.`;
  return { explanation, worstCase };
}
