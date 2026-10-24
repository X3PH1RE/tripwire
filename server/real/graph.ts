import type { Finding, GraphEdge, GraphNode } from "../../shared/types";

type Sensitivity = NonNullable<GraphNode["sensitivity"]>;
interface ResourceGuess {
  key: string;
  label: string;
  sensitivity: Sensitivity;
  provider: string;
}

const DB_LABEL: Record<string, string> = { postgres: "Postgres database", postgresql: "Postgres database", mysql: "MySQL database", mariadb: "MySQL database", mongodb: "MongoDB database", "mongodb+srv": "MongoDB database", redis: "Redis", rediss: "Redis", amqp: "Message queue", amqps: "Message queue" };

/** Guesses what a secret unlocks from its provider and variable name. */
export function resourceFor(provider: string, variable = "", sample = ""): ResourceGuess {
  const v = variable.toUpperCase();
  const scheme = sample.match(/^([a-z+]+):\/\//)?.[1];
  if (scheme && DB_LABEL[scheme]) return { key: `db-${DB_LABEL[scheme]}`, label: DB_LABEL[scheme], sensitivity: "high", provider: scheme.replace(/ql$|\+srv$/, "") };
  if (/DATABASE|POSTGRES|PG_|MYSQL|MONGO|DB_|_DB\b/.test(v)) return { key: "db", label: "Database", sensitivity: "high", provider: "database" };
  if (/REDIS/.test(v)) return { key: "db-Redis", label: "Redis", sensitivity: "high", provider: "redis" };
  if (/DEPLOY|VERCEL|NETLIFY|HEROKU|RAILWAY|FLY_|RENDER_|CLOUDFLARE/.test(v) || provider === "deploy") return { key: "deploy", label: "Production deploy", sensitivity: "production", provider: "deploy" };
  switch (provider) {
    case "github":
    case "gitlab":
      return { key: "scm", label: "Source code (write access)", sensitivity: "production", provider };
    case "npm":
      return { key: "npm", label: "npm package publishing", sensitivity: "production", provider };
    case "aws":
      return { key: "aws", label: "AWS account", sensitivity: "high", provider };
    case "gcp":
      return { key: "gcp", label: "Google Cloud APIs", sensitivity: "medium", provider };
    case "stripe":
      return { key: "stripe", label: "Payments (Stripe live)", sensitivity: "high", provider };
    case "stripe-test":
      return { key: "stripe-test", label: "Stripe test mode", sensitivity: "low", provider: "stripe" };
    case "slack":
      return { key: "slack", label: "Slack workspace", sensitivity: "medium", provider };
    case "openai":
    case "anthropic":
      return { key: "llm", label: "AI API billing", sensitivity: "medium", provider };
    case "sendgrid":
    case "twilio":
      return { key: `msg-${provider}`, label: provider === "twilio" ? "SMS sending (Twilio)" : "Email sending", sensitivity: "medium", provider };
    case "ssh":
      return { key: "ssh", label: "Servers (private key)", sensitivity: "high", provider };
  }
  if (/AWS|S3_|BUCKET|STORAGE|CLOUD/.test(v)) return { key: "cloud", label: "Cloud storage", sensitivity: "high", provider: "cloud" };
  if (/STRIPE|PAYPAL|PAYMENT|BRAINTREE/.test(v)) return { key: "payments", label: "Payments", sensitivity: "high", provider: "payments" };
  if (/SMTP|MAIL|SENDGRID/.test(v)) return { key: "mail", label: "Email sending", sensitivity: "medium", provider: "mail" };
  if (/JWT|SESSION|COOKIE|SIGNING|ENCRYPT/.test(v)) return { key: "auth", label: "User sessions (forge logins)", sensitivity: "high", provider: "app" };
  if (/ADMIN|ROOT|MASTER/.test(v)) return { key: "admin", label: "Admin access", sensitivity: "high", provider: "app" };
  return { key: "unknown", label: "Unclassified access", sensitivity: "low", provider: "unknown" };
}

export interface CiSecretRef {
  name: string;
  file: string;
  line: number;
}

const COL = { repo: -60, service: 240, secret: 560, resource: 880, ciSecret: 1200, ciResource: 1520 };
const ROW = 105;
const MAX_SECRET_NODES = 24;

const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

/** Spreads nodes in one column so each sits near `want` without overlapping the previous one. */
function settle(items: { want: number; node: GraphNode }[]): void {
  items.sort((a, b) => a.want - b.want);
  let last = -Infinity;
  for (const it of items) {
    const y = Math.max(it.want, last + ROW);
    it.node.position.y = y;
    last = y;
  }
}

export function buildGraph(repoName: string, findings: Finding[], ciRefs: CiSecretRef[], samples: Map<string, string>): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const byId = new Map<string, GraphNode>();
  const add = (n: GraphNode) => {
    if (!byId.has(n.id)) {
      byId.set(n.id, n);
      nodes.push(n);
    }
    return byId.get(n.id)!;
  };
  const link = (from: string, to: string, kind: GraphEdge["kind"]) => {
    const id = `r-e-${from}-${to}`;
    if (!edges.some((e) => e.id === id)) edges.push({ id, from, to, kind });
  };

  const repo = add({ id: "r-repo", type: "repo", label: repoName, status: "ok", position: { x: COL.repo, y: 0 } });

  // One node per (service, name); further findings of the same secret only appear in the findings list.
  const ordered = [...findings].sort((a, b) => a.service.localeCompare(b.service) || Number(b.inHead) - Number(a.inHead));
  const secretRows: { want: number; node: GraphNode }[] = [];
  let row = 0;
  for (const f of ordered) {
    const name = f.variable ?? f.ruleLabel;
    const id = `r-sec-${slug(f.service)}-${slug(name)}`;
    f.nodeId = id;
    if (byId.has(id)) {
      const existing = byId.get(id)!;
      if (f.inHead && existing.badge === "history") Object.assign(existing, { file: f.file, line: f.line, badge: undefined });
      continue;
    }
    if (secretRows.length >= MAX_SECRET_NODES) {
      f.nodeId = "";
      continue;
    }
    const serviceId = `r-svc-${slug(f.service)}`;
    add({ id: serviceId, type: "service", label: f.service, version: f.service === "CI (GitHub Actions)" ? "workflows" : undefined, status: "ok", position: { x: COL.service, y: 0 } });
    const node = add({ id, type: "secret", label: name, file: f.file, line: f.line, provider: f.provider, status: "exposed", badge: f.inHead ? undefined : "history", position: { x: COL.secret, y: 0 } });
    secretRows.push({ want: row++ * ROW, node });
    link(serviceId, id, "stored_in");
    const r = resourceFor(f.provider, f.variable, samples.get(f.id));
    const rid = `r-res-${slug(r.key)}`;
    add({ id: rid, type: "resource", label: r.label, sensitivity: r.sensitivity, provider: r.provider, status: "exposed", position: { x: COL.resource, y: 0 } });
    link(id, rid, "unlocks");
  }
  settle(secretRows);

  // A token with write access to the repo can add a workflow that prints every CI secret.
  const scm = byId.get("r-res-scm");
  if (scm && ciRefs.length) {
    const ciRows: { want: number; node: GraphNode }[] = [];
    const resRows: { want: number; node: GraphNode }[] = [];
    for (const [i, ref] of ciRefs.slice(0, 12).entries()) {
      const id = `r-ci-${slug(ref.name)}`;
      const node = add({ id, type: "secret", label: ref.name, file: ref.file, line: ref.line, provider: "gh secret", status: "ok", position: { x: COL.ciSecret, y: 0 } });
      ciRows.push({ want: i * ROW, node });
      link(scm.id, id, "unlocks");
      const r = resourceFor("", ref.name);
      if (r.key === "unknown") continue;
      const rid = `r-res-${slug(r.key)}`;
      const res = add({ id: rid, type: "resource", label: r.label, sensitivity: r.sensitivity, provider: r.provider, status: "ok", position: { x: COL.ciResource, y: 0 } });
      if (res.position.x === COL.ciResource) resRows.push({ want: i * ROW, node: res });
      link(id, rid, "unlocks");
    }
    settle(ciRows);
    settle(resRows.filter((r, i, a) => a.findIndex((x) => x.node === r.node) === i));
  }

  const avgY = (ids: string[]) => {
    const ys = ids.map((i) => byId.get(i)?.position.y).filter((y): y is number => y !== undefined);
    return ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : 0;
  };
  const services = nodes.filter((n) => n.type === "service");
  settle(services.map((s) => ({ want: avgY(edges.filter((e) => e.from === s.id).map((e) => e.to)), node: s })));
  settle(nodes.filter((n) => n.type === "resource" && n.position.x === COL.resource).map((r) => ({ want: avgY(edges.filter((e) => e.to === r.id).map((e) => e.from)), node: r })));
  for (const s of services) link(repo.id, s.id, "stored_in");
  repo.position.y = avgY(services.map((s) => s.id));
  return { nodes, edges };
}
