import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { scanTarget } from "../real/core";
import { ignoreMatcher } from "../real/scan";
import { evaluate, toMarkdown, unlocks } from "./report";
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
