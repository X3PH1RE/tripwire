import { createHmac, createHash } from "node:crypto";
import type { Access, Finding, Verification } from "../../shared/types";

const TIMEOUT = Number(process.env.VERIFY_TIMEOUT_MS ?? 8000);
const CONCURRENCY = 6;

const get = async (url: string, headers: Record<string, string>, method = "GET", body?: string) =>
  fetch(url, { method, headers, body, signal: AbortSignal.timeout(TIMEOUT) });

const live = (identity: string, access: Access[] = [], note?: string): Verification => ({ status: "live", identity, access, note });
const revoked = (note: string): Verification => ({ status: "revoked", note });

// ---- AWS SigV4 (STS GetCallerIdentity, then IAM policies when the key may read them) ----

const hmac = (key: Buffer | string, data: string) => createHmac("sha256", key).update(data, "utf8").digest();
const sha256 = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");

export function sigV4(opts: { id: string; secret: string; service: string; host: string; region: string; body: string; now: Date }): Record<string, string> {
  const amzDate = opts.now.toISOString().replace(/[-:]|\.\d{3}/g, "");
  const date = amzDate.slice(0, 8);
  const headers = `content-type:application/x-www-form-urlencoded; charset=utf-8\nhost:${opts.host}\nx-amz-date:${amzDate}\n`;
  const signed = "content-type;host;x-amz-date";
  const canonical = ["POST", "/", "", headers, signed, sha256(opts.body)].join("\n");
  const scope = `${date}/${opts.region}/${opts.service}/aws4_request`;
  const toSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256(canonical)].join("\n");
  const kDate = hmac(`AWS4${opts.secret}`, date);
  const signature = createHmac("sha256", hmac(hmac(hmac(kDate, opts.region), opts.service), "aws4_request")).update(toSign, "utf8").digest("hex");
  return {
    "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
    "X-Amz-Date": amzDate,
    Authorization: `AWS4-HMAC-SHA256 Credential=${opts.id}/${scope}, SignedHeaders=${signed}, Signature=${signature}`,
  };
}

const xml = (text: string, tag: string) => text.match(new RegExp(`<${tag}>([^<]*)</${tag}>`))?.[1];
const xmlAll = (text: string, tag: string) => [...text.matchAll(new RegExp(`<${tag}>([^<]*)</${tag}>`, "g"))].map((m) => m[1]);

async function awsCall(id: string, secret: string, service: string, host: string, body: string): Promise<string | undefined> {
  const res = await get(`https://${host}/`, sigV4({ id, secret, service, host, region: "us-east-1", body, now: new Date() }), "POST", body);
  const text = await res.text();
  return res.ok ? text : undefined;
}

/** STS says whether the key works; IAM says what it can do. Both are read-only calls. */
export async function verifyAws(id: string, secret: string): Promise<Verification> {
  const res = await get("https://sts.amazonaws.com/", sigV4({ id, secret, service: "sts", host: "sts.amazonaws.com", region: "us-east-1", body: "Action=GetCallerIdentity&Version=2011-06-15", now: new Date() }), "POST", "Action=GetCallerIdentity&Version=2011-06-15");
  const text = await res.text();
  if (!res.ok) {
    const code = xml(text, "Code") ?? String(res.status);
    if (/InvalidClientTokenId|SignatureDoesNotMatch|AccessDenied/.test(code)) return revoked(`AWS rejected the key (${code}).`);
    return { status: "unverified", note: `AWS returned ${code}.` };
  }
  const arn = xml(text, "Arn") ?? "unknown";
  const account = xml(text, "Account");
  const user = arn.split("/").pop();
  const access: Access[] = [{ label: `AWS account ${account}`, sensitivity: "high", detail: arn }];
  if (user && arn.includes(":user/")) {
    const attached = await awsCall(id, secret, "iam", "iam.amazonaws.com", `Action=ListAttachedUserPolicies&UserName=${encodeURIComponent(user)}&Version=2010-05-08`).catch(() => undefined);
    const inline = await awsCall(id, secret, "iam", "iam.amazonaws.com", `Action=ListUserPolicies&UserName=${encodeURIComponent(user)}&Version=2010-05-08`).catch(() => undefined);
    const names = [...(attached ? xmlAll(attached, "PolicyName") : []), ...(inline ? xmlAll(inline, "member") : [])];
    for (const n of new Set(names)) access.push({ label: n === "AdministratorAccess" ? "Full AWS admin" : `IAM policy ${n}`, sensitivity: /Admin|FullAccess|PowerUser/.test(n) ? "production" : "high", detail: `attached to ${user}` });
    if (!names.length && (attached || inline)) access.push({ label: "No IAM policies attached", sensitivity: "low" });
  }
  return live(arn, access, `Live key for ${arn}.`);
}

// ---- Other providers ----

async function verifyGithub(token: string): Promise<Verification> {
  const res = await get("https://api.github.com/user", { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json" });
  if (res.status === 401) return revoked("GitHub rejected the token (401).");
  if (!res.ok) return { status: "unverified", note: `GitHub returned ${res.status}.` };
  const user = (await res.json()) as { login: string };
  const scopes = (res.headers.get("x-oauth-scopes") ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const access: Access[] = [];
  if (scopes.length) for (const s of scopes) access.push({ label: `GitHub scope ${s}`, sensitivity: /^(repo|admin|workflow|write)/.test(s) ? "production" : "medium" });
  else access.push({ label: "GitHub account (fine-grained token)", sensitivity: "production", detail: "scopes not reported by the API" });
  const repos = await get("https://api.github.com/user/repos?per_page=100&affiliation=owner,collaborator,organization_member", { Authorization: `Bearer ${token}` }).catch(() => undefined);
  if (repos?.ok) {
    const list = (await repos.json()) as { full_name: string; private: boolean; permissions?: { push?: boolean } }[];
    const writable = list.filter((r) => r.permissions?.push);
    if (writable.length) access.push({ label: `Write access to ${writable.length} repo${writable.length === 1 ? "" : "s"}`, sensitivity: "production", detail: writable.slice(0, 5).map((r) => r.full_name).join(", ") });
    const priv = list.filter((r) => r.private).length;
    if (priv) access.push({ label: `${priv} private repo${priv === 1 ? "" : "s"} readable`, sensitivity: "high" });
  }
  return live(user.login, access, `Live token for @${user.login}.`);
}

async function verifyStripe(key: string): Promise<Verification> {
  const res = await get("https://api.stripe.com/v1/account", { Authorization: `Bearer ${key}` });
  const data = (await res.json().catch(() => ({}))) as any;
  if (res.status === 401) return revoked("Stripe rejected the key (401).");
  if (!res.ok && res.status !== 403) return { status: "unverified", note: `Stripe returned ${res.status}.` };
  const test = key.includes("_test_");
  const name = data?.settings?.dashboard?.display_name ?? data?.business_profile?.name ?? data?.id ?? "Stripe account";
  const access: Access[] = [{ label: test ? "Stripe test mode" : "Stripe live payments", sensitivity: test ? "low" : "production", detail: data?.id }];
  if (!test) {
    const charges = await get("https://api.stripe.com/v1/charges?limit=1", { Authorization: `Bearer ${key}` });
    if (charges.ok) access.push({ label: "Read customer payment history", sensitivity: "high" });
  }
  return live(name, access, res.status === 403 ? "Live but restricted key." : undefined);
}

async function verifySlack(token: string): Promise<Verification> {
  const res = await get("https://slack.com/api/auth.test", { Authorization: `Bearer ${token}` });
  const data = (await res.json().catch(() => ({}))) as any;
  if (!data?.ok) return /invalid_auth|token_revoked|account_inactive/.test(data?.error ?? "") ? revoked(`Slack rejected the token (${data.error}).`) : { status: "unverified", note: `Slack: ${data?.error ?? res.status}.` };
  const scopes = (res.headers.get("x-oauth-scopes") ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const access: Access[] = [{ label: `Slack workspace ${data.team}`, sensitivity: "high", detail: data.url }];
  for (const s of scopes.slice(0, 8)) access.push({ label: `Slack scope ${s}`, sensitivity: /admin|channels:history|files|users:read.email/.test(s) ? "high" : "medium" });
  return live(`${data.user ?? "bot"}@${data.team}`, access);
}

async function verifyBearer(name: string, url: string, key: string, headers: Record<string, string>, label: string, sensitivity: Access["sensitivity"]): Promise<Verification> {
  const res = await get(url, headers);
  if (res.status === 401 || res.status === 403) return revoked(`${name} rejected the key (${res.status}).`);
  if (!res.ok && res.status !== 400) return { status: "unverified", note: `${name} returned ${res.status}.` };
  return live(`${name} key`, [{ label, sensitivity }], `Live ${name} key — it can spend on the owner's account.`);
}

async function verifyNpm(token: string): Promise<Verification> {
  const res = await get("https://registry.npmjs.org/-/whoami", { Authorization: `Bearer ${token}` });
  if (res.status === 401) return revoked("npm rejected the token (401).");
  if (!res.ok) return { status: "unverified", note: `npm returned ${res.status}.` };
  const who = ((await res.json()) as { username: string }).username;
  return live(who, [{ label: "Publish npm packages", sensitivity: "production", detail: `as ${who}` }]);
}

/** Read-only "who am I" call per provider. Only runs when the user asks for it. */
export async function verifyOne(f: Finding, value: string, context: Map<string, string>): Promise<Verification | undefined> {
  switch (f.provider) {
    case "aws": {
      if (f.rule === "aws-secret-key") return undefined; // verified together with the key ID
      const secret = context.get("aws-secret");
      if (!secret) return { status: "unverified", note: "No matching AWS secret access key was found next to this key ID." };
      return verifyAws(value, secret);
    }
    case "github":
      return verifyGithub(value);
    case "stripe":
    case "stripe-test":
      return verifyStripe(value);
    case "slack":
      return f.rule === "slack-webhook" ? undefined : verifySlack(value);
    case "openai":
      return verifyBearer("OpenAI", "https://api.openai.com/v1/models", value, { Authorization: `Bearer ${value}` }, "OpenAI API billing", "medium");
    case "anthropic":
      return verifyBearer("Anthropic", "https://api.anthropic.com/v1/models", value, { "x-api-key": value, "anthropic-version": "2023-06-01" }, "Anthropic API billing", "medium");
    case "sendgrid":
      return verifyBearer("SendGrid", "https://api.sendgrid.com/v3/scopes", value, { Authorization: `Bearer ${value}` }, "Send email as the owner's domain", "high");
    case "npm":
      return verifyNpm(value);
    default:
      return undefined;
  }
}

export const VERIFIABLE = new Set(["aws", "github", "stripe", "stripe-test", "slack", "openai", "anthropic", "sendgrid", "npm"]);

/** Fills in `finding.verify` in place. `honeyIds` are Tripwire's own decoys, which must never be used. */
export async function verifyFindings(findings: Finding[], values: Map<string, string>, honeyIds: Set<string> = new Set()): Promise<void> {
  const secrets = findings.filter((f) => f.rule === "aws-secret-key");
  // Pair each AWS key ID with the closest secret in the same file, else the only secret in the repo.
  const pairFor = (f: Finding) => {
    const near = secrets.filter((s) => s.file === f.file).sort((a, b) => Math.abs(a.line - f.line) - Math.abs(b.line - f.line))[0];
    return near ?? (secrets.length === 1 ? secrets[0] : undefined);
  };
  const queue = findings.filter((f) => VERIFIABLE.has(f.provider));
  let i = 0;
  const worker = async () => {
    while (i < queue.length) {
      const f = queue[i++];
      const value = values.get(f.id);
      if (!value) continue;
      if (honeyIds.has(value)) {
        f.verify = { status: "honey", identity: "Tripwire decoy", note: "This is a Tripwire honey secret. Using it alerts you; it unlocks nothing." };
        continue;
      }
      const context = new Map<string, string>();
      const pair = f.rule === "aws-access-key" ? pairFor(f) : undefined;
      if (pair) context.set("aws-secret", values.get(pair.id)!);
      f.verify = await verifyOne(f, value, context).catch((err: Error) => ({ status: "unverified", note: `Check failed: ${err.message}` }) as const);
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, queue.length) }, worker));
  for (const f of findings) {
    if (f.rule !== "aws-access-key" || !f.verify) continue;
    const pair = pairFor(f);
    if (pair && !pair.verify) pair.verify = f.verify;
  }
}
