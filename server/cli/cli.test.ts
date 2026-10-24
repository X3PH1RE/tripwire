import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { scanTarget } from "../real/core";
import { ignoreMatcher } from "../real/scan";
import { evaluate, toMarkdown, unlocks } from "./report";
import { installHook } from "./hook";
import { main } from "./main";

// Built at runtime so no provider-format token is ever committed.
const STRIPE = ["sk", "live", "Zq8Xw3Rt6Yu1Io4Pa7Sd0Fg2Hj5"].join("_");
const DB = "DATABASE_URL=postgres://app:Pw9xQ2mZ7vL4@db.internal:5432/app";

function repo(): string {
  const dir = mkdtempSync(join(tmpdir(), "tw-cli-"));
  const git = (...a: string[]) => execFileSync("git", ["-C", dir, "-c", "user.name=t", "-c", "user.email=t@t", ...a], { stdio: "ignore" });
  git("init", "-q", "-b", "main");
  mkdirSync(join(dir, "api"));
  writeFileSync(join(dir, "api/package.json"), "{}");
  writeFileSync(join(dir, "api/.env"), `${DB}\n`);
  git("add", "-A");
  git("commit", "-qm", "base");
  writeFileSync(join(dir, "api/pay.js"), `const key = "${STRIPE}";\nconst other = "${STRIPE.replace("Zq", "Aa")}"; // tripwire:ignore\n`);
  mkdirSync(join(dir, "fixtures"));
  writeFileSync(join(dir, "fixtures/sample.env"), `STRIPE_KEY=${STRIPE.replace("Zq", "Bb")}\n`);
  writeFileSync(join(dir, ".tripwireignore"), "# test data\nfixtures/\n");
  git("add", "-A");
  git("commit", "-qm", "add payments");
  return dir;
}

test("ignore globs", () => {
  const m = ignoreMatcher("fixtures/\n*.test.ts\ndocs/**/*.md\n# c\n");
  assert.ok(m("fixtures/a.env"));
  assert.ok(m("src/x.test.ts"));
  assert.ok(m("docs/a/b.md"));
  assert.ok(!m("src/fixtures.ts"));
  assert.ok(!m("api/.env"));
});

test("diff mode blocks only secrets the change adds; ignore rules apply", async () => {
  const dir = repo();
  try {
    const r = await scanTarget(dir, { diff: "HEAD~1", vulns: false });
    assert.equal(r.diffBase, "HEAD~1");
    assert.deepEqual(r.findings.map((f) => [f.file, !!f.isNew]).sort(), [["api/.env", false], ["api/pay.js", true]]);
    const v = evaluate(r, { secrets: true, vulns: "none" });
    assert.equal(v.failed, true);
    assert.equal(v.blocking.length, 1);
    assert.match(v.reasons[0], /1 secret added/);
    const db = r.findings.find((f) => f.file === "api/.env")!;
    assert.ok(unlocks(r, db).length > 0);

    const full = evaluate(await scanTarget(dir, { vulns: false }), { secrets: true, vulns: "none" });
    assert.equal(full.blocking.length, 2);
    assert.equal(evaluate(r, { secrets: false, vulns: "none" }).failed, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("reports never contain secret values", async () => {
  const dir = repo();
  try {
    const r = await scanTarget(dir, { vulns: false });
    const md = toMarkdown(r, evaluate(r, { secrets: true, vulns: "none" }));
    let out = "";
    const code = await main(["scan", dir, "--skip-vulns", "-q"], (s) => (out += s), () => undefined);
    assert.equal(code, 1);
    for (const text of [md, out, JSON.stringify(r)]) {
      assert.ok(!text.includes(STRIPE));
      assert.ok(!text.includes("Pw9xQ2mZ7vL4"));
    }
    assert.match(md, /tripwire-report/);
    assert.match(out, /FAIL/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("cli argument errors exit 2", async () => {
  const quiet = () => undefined;
  assert.equal(await main(["nope"], quiet, quiet), 2);
  assert.equal(await main(["scan", ".", "--fail-on-vulns", "bad"], quiet, quiet), 2);
  assert.equal(await main(["--help"], quiet, quiet), 0);
});

test("sigV4 matches the AWS reference signature", async () => {
  const { sigV4 } = await import("../real/verify");
  const h = sigV4({ id: "AKIDEXAMPLE", secret: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", service: "sts", host: "sts.amazonaws.com", region: "us-east-1", body: "Action=GetCallerIdentity&Version=2011-06-15", now: new Date("2015-08-30T12:36:00Z") });
  assert.equal(h["X-Amz-Date"], "20150830T123600Z");
  assert.match(h.Authorization, /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE\/20150830\/us-east-1\/sts\/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=[0-9a-f]{64}$/);
});

test("verified keys reshape the graph and the verdict", async () => {
  const { buildGraph } = await import("../real/graph");
  const base = { rule: "x", ruleLabel: "x", file: "a.env", line: 1, inHead: true, preview: "p", service: "api", nodeId: "" };
  const findings = [
    { ...base, id: "f-0", provider: "github", variable: "GH", verify: { status: "live" as const, identity: "octo", access: [{ label: "Write access to 3 repos", sensitivity: "production" as const }] } },
    { ...base, id: "f-1", provider: "stripe", variable: "STRIPE", verify: { status: "revoked" as const } },
    { ...base, id: "f-2", provider: "aws", variable: "AWS", verify: { status: "honey" as const } },
  ];
  const g = buildGraph("repo", findings, [], new Map());
  const labels = g.nodes.filter((n) => n.type === "resource").map((n) => n.label);
  assert.deepEqual(labels, ["Write access to 3 repos"]);
  assert.equal(g.nodes.find((n) => n.label === "AWS")?.type, "decoy");
  assert.equal(g.nodes.find((n) => n.label === "STRIPE")?.badge, "revoked");
  const report = { findings, nodes: g.nodes, edges: g.edges, vulns: [], warnings: [], target: ".", name: "repo", filesScanned: 1, commitsScanned: 0, durationMs: 1 };
  const v = evaluate(report, { secrets: true, vulns: "none" });
  assert.deepEqual(v.blocking.map((f) => f.id), ["f-0"]);
  assert.match(v.reasons[0], /1 live key/);
});

test("canarytokens hits are parsed newest first", async () => {
  const { parseHits } = await import("../real/honey");
  const hits = parseHits([
    { time_of_hit: 1700000000.5, src_ip: "1.2.3.4", geo_info: { city: "Kochi", country: "IN", org: "AS1 Example" }, useragent: "aws-cli/2", additional_info: { aws_key_log_data: { eventName: ["ListBuckets"] } } },
    { time_of_hit: 1700000100, src_ip: "", geo_info: "" },
  ]);
  assert.equal(hits[0].at, 1700000100000);
  assert.deepEqual(hits[1], { at: 1700000000500, ip: "1.2.3.4", location: "Kochi, IN", org: "AS1 Example", userAgent: "aws-cli/2", action: "ListBuckets" });
});

test("baseline accepts current findings; new ones still block; hashes only", async () => {
  const dir = repo();
  try {
    let out = "";
    assert.equal(await main(["baseline", dir], (s) => (out += s), () => undefined), 0);
    assert.match(out, /Accepted 2 findings/);
    const file = readFileSync(join(dir, ".tripwire-baseline.json"), "utf8");
    assert.ok(!file.includes(STRIPE) && !file.includes("Pw9xQ2mZ7vL4"), "baseline stores hashes, never secrets");

    const r = await scanTarget(dir, { vulns: false });
    assert.equal(r.findings.every((f) => f.baselined), true);
    assert.equal(evaluate(r, { secrets: true, vulns: "none" }).failed, false);
    assert.equal(await main(["scan", dir, "--skip-vulns", "-q"], () => undefined, () => undefined), 0);
    assert.equal(await main(["scan", dir, "--skip-vulns", "-q", "--no-baseline"], () => undefined, () => undefined), 1);

    writeFileSync(join(dir, "api/new.js"), `const k = "${STRIPE.replace("Zq", "Cc")}";\n`);
    const again = await scanTarget(dir, { vulns: false });
    assert.equal(evaluate(again, { secrets: true, vulns: "none" }).blocking.length, 1, "a new secret is not baselined");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("min-confidence lets low-confidence findings through without hiding them", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tw-conf-"));
  try {
    writeFileSync(join(dir, "app.env"), `SESSION_SECRET=Hq8zTn3Lw9Rk2Vb7Xc4Mp6Ds1Fg5Jy0\n`);
    const r = await scanTarget(dir, { vulns: false });
    assert.equal(r.findings.length, 1);
    assert.notEqual(r.findings[0].confidence, "high");
    assert.equal(evaluate(r, { secrets: true, vulns: "none" }).failed, true);
    assert.equal(evaluate(r, { secrets: true, vulns: "none", minConfidence: "high" }).failed, false);
    assert.equal(await main(["scan", dir, "--skip-vulns", "-q", "--min-confidence", "high"], () => undefined, () => undefined), 0);
    assert.equal(await main(["scan", dir, "--min-confidence", "nope"], () => undefined, () => undefined), 2);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("contain: dry run plans without touching the provider; --apply revokes and re-checks", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tw-contain-cli-"));
  const home = mkdtempSync(join(tmpdir(), "tw-home-"));
  const realFetch = globalThis.fetch;
  const token = ["ghp", "Zq8Xw3Rt6Yu1Io4Pa7Sd0Fg2Hj5Kl9Mn3BvQ7"].join("_");
  const seen: string[] = [];
  let revoked = false;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    seen.push(`${init?.method ?? "GET"} ${url}`);
    if (url.endsWith("/credentials/revoke")) return (revoked = true), new Response("{}", { status: 202 });
    if (url === "https://api.github.com/user") return revoked ? new Response("{}", { status: 401 }) : new Response(JSON.stringify({ login: "octocat" }), { status: 200 });
    if (url.includes("/user/repos")) return new Response("[]", { status: 200 });
    throw new Error(`unexpected request ${url}`);
  }) as typeof fetch;
  process.env.TRIPWIRE_HOME = home;
  try {
    writeFileSync(join(dir, ".env"), `GITHUB_TOKEN=${token}\n`);
    let out = "";
    assert.equal(await main(["contain", dir, "-q"], (s) => (out += s), () => undefined), 0);
    assert.match(out, /dry run/);
    assert.match(out, /WOULD REVOKE/);
    assert.ok(!out.includes(token) && !out.includes(token.slice(8)), "the plan never prints the secret");
    assert.ok(!seen.some((s) => s.includes("credentials/revoke")), "dry run makes no write call");

    out = "";
    assert.equal(await main(["contain", dir, "--apply", "-q"], (s) => (out += s), () => undefined), 0);
    assert.match(out, /REVOKED/);
    assert.match(out, /1 revoked/);
    assert.ok(seen.some((s) => s === "POST https://api.github.com/credentials/revoke"));
    assert.ok(!readFileSync(join(home, "contain-log.jsonl"), "utf8").includes(token.slice(8)), "log has no secret");
  } finally {
    globalThis.fetch = realFetch;
    delete process.env.TRIPWIRE_HOME;
    rmSync(dir, { recursive: true, force: true });
    rmSync(home, { recursive: true, force: true });
  }
});

test("--staged blocks only what is staged for commit", async () => {
  const dir = mkdtempSync(join(tmpdir(), "tw-staged-"));
  const git = (...a: string[]) => execFileSync("git", ["-C", dir, "-c", "user.name=t", "-c", "user.email=t@t", ...a], { stdio: "ignore" });
  const run = async (...args: string[]) => {
    let out = "";
    const code = await main(["scan", dir, "--staged", ...args], (s) => (out += s), () => undefined);
    return { code, out };
  };
  try {
    git("init", "-q", "-b", "main");
    writeFileSync(join(dir, "README.md"), "hello\n");
    git("add", "-A");
    git("commit", "-qm", "base");

    // A secret that is in the working tree but not staged does not block the commit.
    writeFileSync(join(dir, "pay.js"), `const key = "${STRIPE}";\n`);
    assert.equal((await run()).code, 0);

    git("add", "pay.js");
    const blocked = await run();
    assert.equal(blocked.code, 1);
    assert.match(blocked.out, /pay\.js:1/);
    assert.ok(!blocked.out.includes(STRIPE), "never prints the secret");

    // Ignore marker, ignore file and baseline all still apply.
    writeFileSync(join(dir, "pay.js"), `const key = "${STRIPE}"; // tripwire:ignore\n`);
    git("add", "pay.js");
    assert.equal((await run()).code, 0);

    // Editing a line that already holds a committed secret is not "adding" one in a way that hides it: it is still caught.
    writeFileSync(join(dir, "pay.js"), `const key = "${STRIPE}";\n`);
    git("add", "pay.js");
    git("commit", "-qm", "bypass", "--no-verify");
    writeFileSync(join(dir, "other.js"), "// unrelated\n");
    git("add", "other.js");
    assert.equal((await run()).code, 0, "a secret already committed is not this commit's problem");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("install-hook writes a pre-commit hook, refuses to clobber someone else's, and removes only its own", () => {
  const dir = mkdtempSync(join(tmpdir(), "tw-hook-"));
  let out = "";
  let errs = "";
  const log = (s: string) => (out += s);
  const err = (s: string) => (errs += s);
  try {
    execFileSync("git", ["-C", dir, "init", "-q"], { stdio: "ignore" });
    const hook = join(dir, ".git", "hooks", "pre-commit");
    assert.equal(installHook(dir, {}, log, err), 0);
    const body = readFileSync(hook, "utf8");
    assert.match(body, /^#!\/bin\/sh/);
    assert.match(body, /tripwire scan --staged/);
    assert.equal(installHook(dir, {}, log, err), 0, "re-installing our own hook is fine");

    assert.equal(installHook(dir, { remove: true }, log, err), 0);
    assert.equal(existsSync(hook), false);

    writeFileSync(hook, "#!/bin/sh\necho mine\n");
    assert.equal(installHook(dir, {}, log, err), 2, "someone else's hook is left alone");
    assert.match(errs, /already exists/);
    assert.equal(readFileSync(hook, "utf8"), "#!/bin/sh\necho mine\n");
    assert.equal(installHook(dir, { remove: true }, log, err), 2);
    assert.equal(installHook(dir, { force: true }, log, err), 0);
    assert.match(readFileSync(hook, "utf8"), /tripwire-hook/);

    assert.equal(installHook(tmpdir(), {}, log, err), 2, "not a git repo");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
