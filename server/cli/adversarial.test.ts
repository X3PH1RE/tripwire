// Regression tests from an adversarial review: each one is an attack that used to work.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { defaultEngine } from "../detect";
import { writeBaseline } from "../detect/baseline";
import { fingerprint } from "../detect/filters";
import { guard, hostAllowed, originAllowed } from "../guard";
import { scanTarget } from "../real/core";
import { evaluate, toMarkdown } from "./report";

// Token-shaped values are built at run time so nothing provider-shaped is committed.
const pad = (n: number) => Array.from({ length: n }, (_, i) => "AbCdEfGhJkLmNpQrStUvWxYz23456789"[(i * 7 + 3) % 32]).join("");
const STRIPE = ["sk", "live", pad(24)].join("_");
const AWS = ["AKIA", "Q3MXR7ZB2KD4WT6N"].join("");
const POLICY = { secrets: true, vulns: "none" as const };

function gitRepo(): { dir: string; git: (...a: string[]) => string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "tw-adv-"));
  const git = (...a: string[]) => execFileSync("git", ["-C", dir, "-c", "user.name=t", "-c", "user.email=t@t", "-c", "core.autocrlf=false", ...a], { encoding: "utf8", stdio: "pipe" });
  git("init", "-q", "-b", "main");
  writeFileSync(join(dir, "README.md"), "hi\n");
  git("add", "-A");
  git("commit", "-qm", "base");
  return { dir, git, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

/** A pull request: branch off the base, apply `change`, commit, and run the diff check the way CI does. */
async function pr(change: (dir: string) => void) {
  const { dir, git, cleanup } = gitRepo();
  try {
    const base = git("rev-parse", "HEAD").trim();
    git("checkout", "-q", "-b", "pr");
    change(dir);
    git("add", "-A");
    git("commit", "-qm", "pr");
    const r = await scanTarget(dir, { diff: base, vulns: false, history: 0 });
    return { r, verdict: evaluate(r, POLICY) };
  } finally {
    cleanup();
  }
}

test("a pull request cannot switch the check off with its own .tripwireignore or baseline", async () => {
  const plain = await pr((d) => writeFileSync(join(d, "pay.js"), `const k="${STRIPE}";\n`));
  assert.equal(plain.verdict.failed, true);

  const ignoreAll = await pr((d) => (writeFileSync(join(d, ".tripwireignore"), "*\n"), writeFileSync(join(d, "pay.js"), `const k="${STRIPE}";\n`)));
  assert.equal(ignoreAll.verdict.failed, true, "an ignore file added by the PR is not honoured");
  assert.ok(ignoreAll.r.warnings.some((w) => /edits \.tripwireignore/.test(w)), "and the attempt is called out");

  const ignoreFile = await pr((d) => (writeFileSync(join(d, ".tripwireignore"), "pay.js\n"), writeFileSync(join(d, "pay.js"), `const k="${STRIPE}";\n`)));
  assert.equal(ignoreFile.verdict.failed, true);

  // A baseline that already accepts the secret, shipped inside the PR.
  const accepted = await pr((d) => {
    writeFileSync(join(d, "pay.js"), `const k="${STRIPE}";
`);
    writeBaseline(d, [{ fingerprint: fingerprint("stripe-live", "pay.js", STRIPE), rule: "stripe-live", file: "pay.js" }]);
  });
  assert.equal(accepted.verdict.failed, true, "a baseline added by the PR is not honoured");
  assert.ok(accepted.r.warnings.some((w) => /edits \.tripwire-baseline\.json/.test(w)));
});

test("an inline ignore marker still works, but the change reports what it hid", async () => {
  const { r, verdict } = await pr((d) => writeFileSync(join(d, "pay.js"), `const k="${STRIPE}"; // tripwire:ignore\n`));
  assert.equal(verdict.failed, false);
  const note = r.warnings.find((w) => /hidden by an inline/.test(w));
  assert.ok(note, "reviewers are told");
  assert.match(note!, /pay\.js:1/);
  assert.ok(!note!.includes(STRIPE), "never the secret itself");
});

test("a secret cannot hide behind a directory or file name", async () => {
  const { dir, cleanup } = gitRepo();
  try {
    const where = ["build/a.env", "dist/app.js", "vendor/a.env", "out/a.env", "target/a.env", "src/app.min.js", "src/app.js.map", "src/deps.lock"];
    where.forEach((p, i) => {
      mkdirSync(join(dir, p.split("/").slice(0, -1).join("/")), { recursive: true });
      // A different key per file: identical values are (correctly) merged into one finding.
      writeFileSync(join(dir, p), `KEY${i}=AKIAQ3MXR7ZB2KD4WT6${"ABCDEFGH"[i]}\n`);
    });
    const found = (await scanTarget(dir, { vulns: false, history: 0 })).findings.map((f) => f.file).sort();
    assert.deepEqual(found, [...where].sort());
  } finally {
    cleanup();
  }
});

test("secrets on very long lines and in large files are found", async () => {
  const e = defaultEngine();
  const line = (n: number) => `${"x ".repeat(n)}${AWS} ${"y ".repeat(n)}`;
  assert.equal(e.scan(line(1500), "app.min.js").length, 1, "6 KB line");
  assert.equal(e.scan(line(50_000), "bundle.js").length, 1, "200 KB line");
  assert.equal(e.scan(line(1500), "app.min.js")[0].value, AWS, "not cut in half at a window boundary");

  const { dir, cleanup } = gitRepo();
  try {
    writeFileSync(join(dir, "big.json"), `{"pad":"${"x".repeat(1_500_000)}","k":"${AWS}"}\n`);
    const r = await scanTarget(dir, { vulns: false, history: 0 });
    assert.equal(r.findings.length, 1, "file over 1 MB");
  } finally {
    cleanup();
  }
});

test("a symlink is never followed out of the repository", async (t) => {
  const { dir, cleanup } = gitRepo();
  const outside = mkdtempSync(join(tmpdir(), "tw-outside-"));
  try {
    writeFileSync(join(outside, "private.env"), `KEY=${AWS}\n`);
    try {
      symlinkSync(join(outside, "private.env"), join(dir, "innocent.env"), "file");
    } catch {
      t.skip("cannot create symlinks on this machine");
      return;
    }
    const r = await scanTarget(dir, { vulns: false, history: 0 });
    assert.equal(r.findings.length, 0, "the link's target is outside the repo and must not be read");
  } finally {
    cleanup();
    rmSync(outside, { recursive: true, force: true });
  }
});

test("a file full of BEGIN headers cannot stall the scanner", () => {
  const e = defaultEngine();
  const hostile = "-----BEGIN RSA PRIVATE KEY-----\n".repeat(20_000);
  const t0 = Date.now();
  e.scan(hostile, "x.txt");
  assert.ok(Date.now() - t0 < 3000, `took ${Date.now() - t0} ms (was 22 s when the key rule was quadratic)`);
  const real = ["-----BEGIN RSA PRIVATE KEY-----", pad(64), pad(64), "-----END RSA PRIVATE KEY-----"].join("\n");
  assert.equal(e.scan(`${hostile}${real}`, "x.txt").filter((h) => h.rule.id === "private-key").length, 1, "a real key after the noise is still found");
});

test("credentials in a URL are found; tutorial passwords rank low", () => {
  const e = defaultEngine();
  assert.equal(e.scan("remote = https://deploy:Xq7mT2vL9wR4kB8z@git.internal.example/app.git", "config")[0].confidence, "medium");
  assert.equal(e.scan("see https://admin:admin@demo.example.com/", "notes.txt")[0].confidence, "low");
  assert.deepEqual(e.scan("curl https://${USER}:${PASS}@host.example.com/", "run.sh").filter((h) => h.rule.id === "url-basic-auth"), []);
});

test("the API only answers the local app", () => {
  assert.ok(hostAllowed("localhost:3001"));
  assert.ok(hostAllowed("127.0.0.1:5173"));
  assert.ok(hostAllowed("[::1]:3001"));
  assert.ok(!hostAllowed("evil.example"), "DNS rebinding sends the attacker's host");
  assert.ok(!hostAllowed("localhost.evil.example"));
  assert.ok(!hostAllowed("192.168.1.20:3001"), "a LAN address is not loopback");
  assert.ok(!hostAllowed(undefined));
  assert.ok(hostAllowed("tripwire.internal", ["tripwire.internal"]), "opt-in via ALLOWED_HOSTS");

  assert.ok(originAllowed(undefined), "curl and the CLI send no Origin");
  assert.ok(originAllowed("http://localhost:5173"));
  assert.ok(!originAllowed("http://evil.example"));
  assert.ok(!originAllowed("null"), "sandboxed iframes send Origin: null");

  const run = (headers: Record<string, string>, method = "POST") => {
    let status = 200;
    let passed = false;
    guard([])({ method, headers } as never, { status: (s: number) => ((status = s), { json: () => undefined }) } as never, () => (passed = true));
    return { status, passed };
  };
  assert.equal(run({ host: "localhost:3001", origin: "http://localhost:5173" }).passed, true);
  assert.equal(run({ host: "localhost:3001", origin: "http://evil.example" }).status, 403);
  assert.equal(run({ host: "localhost:3001", "sec-fetch-site": "cross-site" }).status, 403, "cross-site write");
  assert.equal(run({ host: "evil.example" }, "GET").status, 403);
});

test("with inline-ignore off, a marker in the change hides nothing", async () => {
  const { dir, git, cleanup } = gitRepo();
  try {
    const base = git("rev-parse", "HEAD").trim();
    git("checkout", "-q", "-b", "pr");
    writeFileSync(join(dir, "pay.js"), `const k="${STRIPE}"; // tripwire:ignore\n`);
    git("add", "-A");
    git("commit", "-qm", "pr");
    const lenient = evaluate(await scanTarget(dir, { diff: base, vulns: false, history: 0 }), POLICY);
    const strict = evaluate(await scanTarget(dir, { diff: base, vulns: false, history: 0, inlineIgnore: false }), POLICY);
    assert.equal(lenient.failed, false, "default: markers are honoured (and reported)");
    assert.equal(strict.failed, true, "strict: the same change is blocked");
  } finally {
    cleanup();
  }
});

test("a key in an SVG is found (Gitleaks' default allowlist skips them)", async () => {
  const { dir, cleanup } = gitRepo();
  try {
    writeFileSync(join(dir, "logo.svg"), `<svg xmlns="http://www.w3.org/2000/svg"><!-- ${AWS} --></svg>\n`);
    assert.equal((await scanTarget(dir, { vulns: false, history: 0 })).findings.length, 1);
  } finally {
    cleanup();
  }
});

test("untrusted file and variable names cannot break out of the PR comment's code spans", () => {
  const hostile = "a`](https://evil.example) @octocat `b.env";
  const finding = { id: "f-0", rule: "stripe-live", ruleLabel: "Stripe live key", provider: "stripe", variable: hostile, file: hostile, line: 1, inHead: true, preview: "sk_liv", service: "app", nodeId: "" };
  const report = { findings: [finding], nodes: [], edges: [], vulns: [{ key: "k", ecosystem: "npm", name: hostile, version: "1.0.0", file: "package-lock.json", direct: true, severity: "HIGH", advisories: [{ id: "X", summary: "s", severity: "HIGH" }], fixable: false }], warnings: [], filesScanned: 1, commitsScanned: 0, durationMs: 1 } as never;
  const md = toMarkdown(report, { failed: true, reasons: [], blocking: [], blockingVulns: [] });
  assert.ok(!md.includes("`](https://evil.example)"), "the backtick that would close the span is neutralised");
  const outsideCode = md.replace(/`[^`\n]*`/g, "");
  assert.ok(!outsideCode.includes("@octocat"), "no live @mention outside a code span");
  assert.ok(!outsideCode.includes("evil.example"), "no live link outside a code span");
});
