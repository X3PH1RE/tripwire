import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import type { VulnPackage } from "../../shared/types";
import { patchPackageJson, patchRequirements } from "./fix";
import { buildGraph } from "./graph";
import { compareVersions, fixedFor } from "./osv";
import { mask, matchLine } from "./rules";
import { ciSecretRefs, manifestDirs, mergeFindings, scanHead, scanHistory, walk } from "./scan";

// Token-shaped strings are assembled at runtime so no provider-format secret is ever committed.
const ALPHA = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
let seed = 7;
const rand = (n: number) => Array.from({ length: n }, () => ALPHA[(seed = (seed * 1103515245 + 12345) % 2147483648) % ALPHA.length]).join("");
const GH = ["ghp", rand(36)].join("_");
const AWS = ["AKIA", "Q3MXR7ZB2KD4WT6N"].join("");
const STRIPE = ["sk", "live", rand(24)].join("_");

test("provider rules find real token formats", () => {
  assert.equal(matchLine(`GH_TOKEN=${GH}`)[0].rule.id, "github-pat");
  assert.equal(matchLine(`aws_access_key_id = ${AWS}`)[0].rule.id, "aws-access-key");
  assert.equal(matchLine(`const stripe = "${STRIPE}"`)[0].rule.id, "stripe-live");
  assert.equal(matchLine("-----BEGIN OPENSSH PRIVATE KEY-----")[0].rule.id, "private-key");
  const db = matchLine("DATABASE_URL=postgres://app:s3cr3tP4ss@db.internal:5432/app")[0];
  assert.equal(db.rule.id, "db-url");
  assert.equal(db.variable, "DATABASE_URL");
});

test("placeholders and plain words are ignored", () => {
  assert.deepEqual(matchLine("API_KEY=your_api_key_here"), []);
  assert.deepEqual(matchLine("SECRET_KEY=${SECRET_KEY}"), []);
  assert.deepEqual(matchLine("token: process.env.GITHUB_TOKEN"), []);
  assert.deepEqual(matchLine("DATABASE_URL=postgres://user:password@localhost/db").length, 1);
  assert.deepEqual(matchLine("PASSWORD_RESET_URL=https://example.com/reset"), []);
  assert.equal(matchLine("SESSION_SECRET=Hq8zTn3Lw9Rk2Vb7Xc4Mp6Ds1Fg5Jy0")[0].rule.id, "generic-assignment");
  // A token embedded in a database URL is reported once, as the URL.
  const embedded = matchLine(`DATABASE_URL=postgres://app:tw_fake_db_${"k3j9x2m8q7w1z5v4"}@db/app`);
  assert.equal(embedded.length, 1);
  assert.equal(embedded[0].rule.id, "db-url");
});

test("previews never contain the full secret", () => {
  const m = matchLine(`GH_TOKEN=${GH}`)[0];
  const p = mask(m.value, m.rule);
  assert.ok(!p.includes(GH.slice(8)));
  const db = matchLine("DATABASE_URL=postgres://app:s3cr3tP4ss@db/app")[0];
  assert.ok(!mask(db.value, db.rule).includes("s3cr3tP4ss"));
});

test("version compare and OSV fixed version", () => {
  assert.ok(compareVersions("4.17.21", "4.17.15") > 0);
  assert.ok(compareVersions("1.10.0", "1.9.9") > 0);
  const v: Parameters<typeof fixedFor>[0] = { id: "X", affected: [{ package: { name: "lodash", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }] };
  assert.equal(fixedFor(v, { ecosystem: "npm", name: "lodash", version: "4.17.15", file: "package-lock.json", direct: true }), "4.17.21");
  assert.equal(fixedFor(v, { ecosystem: "npm", name: "lodash", version: "4.17.21", file: "package-lock.json", direct: true }), undefined);
});

test("manifest patches bump direct deps and override transitive ones", () => {
  const vp = (name: string, direct: boolean): VulnPackage => ({ key: name, ecosystem: "npm", name, version: "1.0.0", file: "package-lock.json", direct, severity: "HIGH", advisories: [], fixed: "1.2.3", fixable: true });
  const out = JSON.parse(patchPackageJson(JSON.stringify({ dependencies: { lodash: "^1.0.0" } }, null, 2), [vp("lodash", true), vp("minimist", false)]));
  assert.equal(out.dependencies.lodash, "^1.2.3");
  assert.equal(out.overrides.minimist, "^1.2.3");
  assert.equal(patchRequirements("flask==1.0.0\nDjango[argon2]==1.0.0\n", [{ ...vp("django", true), ecosystem: "PyPI", file: "requirements.txt" }]), "flask==1.0.0\nDjango[argon2]==1.2.3\n");
});

test("history scan finds a secret that was deleted from HEAD and the graph chains through repo write access", () => {
  const dir = mkdtempSync(join(tmpdir(), "tw-test-"));
  const git = (...args: string[]) => execFileSync("git", ["-C", dir, "-c", "user.name=t", "-c", "user.email=t@t", ...args], { stdio: "pipe" });
  try {
    git("init", "-q");
    writeFileSync(join(dir, "package.json"), "{}");
    writeFileSync(join(dir, ".env"), `GH_TOKEN=${GH}\n`);
    execFileSync("mkdir", ["-p", join(dir, ".github/workflows")]);
    writeFileSync(join(dir, ".github/workflows/ci.yml"), "env:\n  NPM_TOKEN: ${{ secrets.NPM_TOKEN }}\n  DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}\n");
    git("add", "-A");
    git("commit", "-qm", "init");
    writeFileSync(join(dir, ".env"), "GH_TOKEN=\n");
    git("commit", "-qam", "remove token");
    const files = walk(dir);
    const dirs = manifestDirs(files);
    return scanHistory(dir, dirs, "app").then(({ raws, commits }) => {
      assert.equal(commits, 2);
      const { findings, samples } = mergeFindings(scanHead(dir, files, dirs, "app"), raws);
      assert.equal(findings.length, 1);
      assert.equal(findings[0].inHead, false);
      assert.ok(findings[0].commit);
      const refs = ciSecretRefs(dir, files);
      assert.deepEqual(refs.map((r) => r.name), ["NPM_TOKEN", "DEPLOY_KEY"]);
      const g = buildGraph("app", findings, refs, samples);
      const scm = g.nodes.find((n) => n.id === "r-res-scm");
      assert.ok(scm, "github token unlocks source code");
      assert.ok(g.edges.some((e) => e.from === scm!.id && e.to === "r-ci-deploy-key"));
      assert.ok(g.edges.some((e) => e.from === "r-ci-deploy-key" && e.to === "r-res-deploy"));
      assert.equal(g.nodes.find((n) => n.type === "secret" && n.status === "exposed")?.badge, "history");
    });
  } finally {
    setTimeout(() => rmSync(dir, { recursive: true, force: true }), 2000);
  }
});
