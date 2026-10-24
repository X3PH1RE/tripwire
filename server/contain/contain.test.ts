import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";
import type { Finding, Verification } from "../../shared/types";
import { buildPlan, runContain } from "./index";

// Token-shaped values are built at run time so nothing provider-shaped is committed.
const GH = ["ghp", "Zq8Xw3Rt6Yu1Io4Pa7Sd0Fg2Hj5Kl9Mn3Bv"].join("_");
const AWS_ID = ["AKIA", "Q3MXR7ZB2KD4WT6N"].join("");
const AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYsecretsx00";
const ARN = "arn:aws:iam::123456789012:user/deploy-bot";

let n = 0;
const finding = (over: Partial<Finding> & { verify?: Verification }): Finding => ({
  id: `f-${n++}`,
  rule: "github-pat",
  ruleLabel: "GitHub token",
  provider: "github",
  file: ".env",
  line: 1,
  inHead: true,
  preview: "ghp_Zq••••",
  service: "app",
  nodeId: "",
  fingerprint: `fp-${n}`,
  ...over,
});
const live = (access: Verification["access"] = []): Verification => ({ status: "live", identity: "octocat", access });

interface Call {
  method: string;
  url: string;
  body?: string;
}
const realFetch = globalThis.fetch;
const calls: Call[] = [];

/** Replaces fetch with a router; any URL the router does not know fails the test loudly. */
function stub(routes: (c: Call) => { status: number; body?: string | object } | undefined): void {
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const call: Call = { method: init?.method ?? "GET", url: String(input), body: typeof init?.body === "string" ? init.body : undefined };
    calls.push(call);
    const r = routes(call);
    if (!r) throw new Error(`unexpected request: ${call.method} ${call.url}`);
    const text = typeof r.body === "string" ? r.body : JSON.stringify(r.body ?? {});
    return new Response(text, { status: r.status });
  }) as typeof fetch;
}
afterEach(() => {
  globalThis.fetch = realFetch;
  calls.length = 0;
});

const input = (findings: Finding[], values: Record<string, string>) => ({ findings, nodes: [], edges: [], values: new Map(Object.entries(values)) });

test("plan: live revocable keys first, by reach; revoked keys and decoys left out; AWS pair is one step", () => {
  const gh = finding({ provider: "github", verify: live([{ label: "Write access to 3 repos", sensitivity: "production" }]) });
  const stripe = finding({ provider: "stripe", rule: "stripe-live", ruleLabel: "Stripe live key", verify: live([{ label: "Stripe live payments", sensitivity: "production" }]) });
  const slack = finding({ provider: "slack", rule: "slack-token", ruleLabel: "Slack token", verify: live([{ label: "Slack workspace", sensitivity: "high" }]) });
  const openai = finding({ provider: "openai", rule: "openai-key", verify: { status: "unverified", note: "timeout" } });
  const dead = finding({ provider: "slack", verify: { status: "revoked" } });
  const decoy = finding({ provider: "aws", verify: { status: "honey" } });
  const awsKey = finding({ provider: "aws", rule: "aws-access-key", ruleLabel: "AWS access key ID", verify: live([{ label: "AWS account", sensitivity: "high" }]) });
  const awsSecret = finding({ provider: "aws", rule: "aws-secret-key", ruleLabel: "AWS secret access key", verify: awsKey.verify });
  const plan = buildPlan({ findings: [openai, slack, dead, decoy, stripe, awsSecret, awsKey, gh], nodes: [], edges: [] });

  assert.deepEqual(plan.map((s) => s.findingId), [gh.id, stripe.id, awsKey.id, slack.id, openai.id], "live first, then by reach; unverified last");
  assert.equal(plan.find((s) => s.findingId === gh.id)!.mode, "revoke");
  assert.equal(plan.find((s) => s.findingId === stripe.id)!.mode, "guided", "no safe API for Stripe");
  assert.match(plan.find((s) => s.findingId === stripe.id)!.reason!, /cannot revoke/);
  assert.equal(plan.find((s) => s.findingId === openai.id)!.mode, "guided");
  assert.ok(plan.every((s) => s.guide.steps.length > 1));
});

test("dry run makes no request at all", async () => {
  stub(() => undefined);
  const gh = finding({ verify: live() });
  const out = await runContain(input([gh], { [gh.id]: GH }), { apply: false, logFile: false });
  assert.equal(calls.length, 0);
  assert.deepEqual(out.results.map((r) => r.status), ["planned"]);
  assert.equal(out.contained, true);
});

test("apply: revokes via GitHub, confirms the provider now rejects the key, and logs without the secret", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tw-contain-"));
  const logFile = join(dir, "log.jsonl");
  try {
    stub((c) => {
      if (c.url === "https://api.github.com/credentials/revoke") return { status: 202 };
      if (c.url === "https://api.github.com/user") return { status: 401, body: { message: "Bad credentials" } };
    });
    const gh = finding({ verify: live([{ label: "Write access", sensitivity: "production" }]) });
    const out = await runContain(input([gh], { [gh.id]: GH }), { apply: true, delayMs: 0, logFile });
    assert.equal(out.results[0].status, "revoked");
    assert.match(out.results[0].note, /now rejects/);
    assert.equal(gh.verify?.status, "revoked", "finding updated in place");
    assert.deepEqual(JSON.parse(calls[0].body!), { credentials: [GH] });
    const log = readFileSync(logFile, "utf8");
    assert.ok(!log.includes(GH) && !log.includes(GH.slice(8)), "the log never holds the secret");
    assert.equal(JSON.parse(log.trim()).outcome, "revoked");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a revoke the provider accepts but does not honour is reported as still-live", async () => {
  stub((c) => {
    if (c.url.endsWith("/credentials/revoke")) return { status: 202 };
    if (c.url === "https://api.github.com/user") return { status: 200, body: { login: "octocat" } };
    if (c.url.includes("/user/repos")) return { status: 200, body: [] };
  });
  const gh = finding({ verify: live() });
  const out = await runContain(input([gh], { [gh.id]: GH }), { apply: true, delayMs: 0, logFile: false });
  assert.equal(out.results[0].status, "still-live");
  assert.equal(out.contained, false);
});

test("a failing revoker is recorded, does not stop the run, and points to the manual steps", async () => {
  stub((c) => {
    if (c.url === "https://slack.com/api/auth.revoke") return { status: 200, body: { ok: false, error: "not_allowed_token_type" } };
    if (c.url.endsWith("/credentials/revoke")) return { status: 202 };
    if (c.url === "https://api.github.com/user") return { status: 401 };
  });
  const slack = finding({ provider: "slack", rule: "slack-token", verify: live([{ label: "Slack workspace", sensitivity: "high" }]) });
  const gh = finding({ verify: live([{ label: "Write access", sensitivity: "production" }]) });
  const out = await runContain(input([slack, gh], { [slack.id]: "xoxb-1", [gh.id]: GH }), { apply: true, delayMs: 0, logFile: false });
  assert.deepEqual(out.results.map((r) => r.status), ["revoked", "failed"], "GitHub (higher reach) first; Slack failed after");
  assert.match(out.results[1].note, /not_allowed_token_type/);
  assert.match(out.results[1].note, /manual steps/);
  assert.equal(out.contained, false);
});

test("AWS: deactivates the key (reversible), signs the IAM call, and logs how to turn it back on", async () => {
  stub((c) => {
    if (c.url === "https://iam.amazonaws.com/") return { status: 200, body: "<UpdateAccessKeyResponse/>" };
    if (c.url === "https://sts.amazonaws.com/") return { status: 403, body: "<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>" };
  });
  const key = finding({ provider: "aws", rule: "aws-access-key", file: ".env", line: 1, verify: { status: "live", identity: ARN, access: [{ label: "AWS account", sensitivity: "high" }] } });
  const secret = finding({ provider: "aws", rule: "aws-secret-key", file: ".env", line: 2, verify: key.verify });
  const out = await runContain(input([key, secret], { [key.id]: AWS_ID, [secret.id]: AWS_SECRET }), { apply: true, delayMs: 0, logFile: false });
  assert.equal(out.plan.length, 1);
  assert.equal(out.results[0].status, "revoked");
  assert.match(out.results[0].reactivate!, /update-access-key --access-key-id AKIA\w+ --status Active --user-name deploy-bot/);
  const iam = new URLSearchParams(calls[0].body);
  assert.equal(iam.get("Action"), "UpdateAccessKey");
  assert.equal(iam.get("Status"), "Inactive");
  assert.equal(iam.get("UserName"), "deploy-bot");
  assert.ok(!calls[0].body!.includes(AWS_SECRET), "the secret key is only used to sign, never sent");
});

test("AWS without iam:UpdateAccessKey falls back to manual steps", async () => {
  stub((c) => {
    if (c.url === "https://iam.amazonaws.com/") return { status: 403, body: "<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>" };
  });
  const key = finding({ provider: "aws", rule: "aws-access-key", verify: { status: "live", identity: ARN, access: [] } });
  const secret = finding({ provider: "aws", rule: "aws-secret-key", line: 2, verify: key.verify });
  const out = await runContain(input([key, secret], { [key.id]: AWS_ID, [secret.id]: AWS_SECRET }), { apply: true, delayMs: 0, logFile: false });
  assert.equal(out.results[0].status, "failed");
  assert.match(out.results[0].note, /AccessDenied/);
});

test("keys that are not confirmed live are never revoked, even with apply", async () => {
  stub(() => undefined);
  const unverified = finding({ verify: { status: "unverified" } });
  const unchecked = finding({});
  const out = await runContain(input([unverified, unchecked], { [unverified.id]: GH, [unchecked.id]: GH }), { apply: true, delayMs: 0, logFile: false });
  assert.equal(calls.length, 0);
  assert.deepEqual(out.results.map((r) => r.status), ["guided", "guided"]);
});

test("`only` limits which keys are acted on", async () => {
  stub((c) => {
    if (c.url.endsWith("/credentials/revoke")) return { status: 202 };
    if (c.url === "https://api.github.com/user") return { status: 401 };
  });
  const a = finding({ verify: live([{ label: "x", sensitivity: "production" }]) });
  const b = finding({ verify: live([{ label: "y", sensitivity: "high" }]) });
  const out = await runContain(input([a, b], { [a.id]: GH, [b.id]: `${GH}x` }), { apply: true, only: [b.id], delayMs: 0, logFile: false });
  assert.deepEqual(out.plan.map((s) => s.findingId), [b.id]);
  assert.equal(calls.filter((c) => c.url.endsWith("/credentials/revoke")).length, 1);
  assert.equal(a.verify?.status, "live", "the other key was left alone");
});
