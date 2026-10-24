import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { defaultEngine, Engine } from "./index";
import { allowed, compileAllowlist, compileRegex, crc32, githubChecksumOk, isPlaceholder, looksBenign, toBase62 } from "./filters";
import { importGitleaks, translateGoRegex } from "./gitleaks";
import type { Pack } from "./schema";
import gitleaks from "./rules/gitleaks.json";

// Token-shaped strings are assembled at runtime so no provider-format secret is ever committed.
const B62 = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
let counter = 0;
const rand = (n: number) => {
  let out = "";
  while (out.length < n) out += [...createHash("sha256").update(`tw-test-${counter++}`).digest()].map((b) => B62[b % B62.length]).join("");
  return out.slice(0, n);
};
const validGithub = () => {
  const body = rand(30);
  return ["ghp", body + toBase62(crc32(body), 6)].join("_");
};

test("go regex translation: scoped flags, POSIX classes, end anchors", () => {
  const ci = compileRegex(translateGoRegex("\\b(p8e-(?i)[a-z0-9]{4})(?:\\s|$)"));
  assert.ok(ci.test("p8e-AbC1 "));
  assert.ok(!ci.test("P8E-abcd "), "the flag only applies after the (?i)");
  assert.ok(compileRegex(translateGoRegex("^[[:alnum:]]{3}\\z$")).test("a1B"));
  assert.ok(!compileRegex(translateGoRegex("^[[:alnum:]]{3}\\z")).test("a1B\n"), "\\z is absolute end");
  assert.ok(compileRegex(translateGoRegex("(?i)token")).test("TOKEN"));
});

test("the gitleaks pack imports and every rule compiles", () => {
  const pack = gitleaks as Pack;
  assert.ok(pack.rules.length >= 200, `only ${pack.rules.length} rules`);
  for (const r of pack.rules) compileRegex(r.regex, "g");
  assert.ok(!pack.rules.some((r) => r.id === "generic-api-key"), "replaced by Tripwire's own generic rule");
  assert.ok(pack.allowlist?.paths?.length, "global path allowlist is imported");
  const small = importGitleaks('[[rules]]\nid = "x-token"\ndescription = "d"\nregex = \'\'\'\\bxt_[a-z]{8}\\b\'\'\'\nkeywords = ["xt_"]\n');
  assert.equal(small.rules[0].provider, "x");
  assert.equal(small.rules[0].label, "X token");
});

test("imported rules detect tokens their patterns describe", () => {
  const e = defaultEngine();
  const do_ = ["dop", "v1", "0123456789abcdef".repeat(4)].join("_");
  assert.equal(e.scan(`DO_TOKEN = "${do_}"`, "a.env")[0].rule.id, "digitalocean-pat");
  const ali = ["LTAI", rand(20)].join("");
  assert.equal(e.scan(`id = "${ali}"`, "a.env")[0].rule.id, "alibaba-access-key-id");
});

test("tripwire rules win over imported ones on the same value", () => {
  const aws = ["AKIA", "Q3MXR7ZB2KD4WT6N"].join("");
  const hits = defaultEngine().scan(`aws_access_key_id = ${aws}`, "a.env");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].rule.id, "aws-access-key");
});

test("github checksum separates real tokens from look-alikes", () => {
  assert.ok(githubChecksumOk(validGithub()));
  assert.ok(!githubChecksumOk(["ghp", rand(36)].join("_")));
  const e = defaultEngine();
  assert.equal(e.scan(`T=${validGithub()}`)[0].confidence, "high");
  assert.equal(e.scan(`T=${["ghp", rand(36)].join("_")}`)[0].confidence, "low");
});

test("placeholders match whole words only for weak terms", () => {
  assert.ok(isPlaceholder("your_api_key_here"));
  assert.ok(isPlaceholder("todo"));
  assert.ok(isPlaceholder("<token>"));
  assert.ok(!isPlaceholder("Qx7TodoMk29Lp4Zr8Vn3Bw6Yc1Hd5Gs0"), "a random token containing 'todo' is kept");
});

test("generic rule ignores hashes, uuids, versions and paths but keeps random secrets", () => {
  const e = defaultEngine();
  assert.deepEqual(e.scan("API_TOKEN=550e8400-e29b-41d4-a716-446655440000"), []);
  assert.deepEqual(e.scan(`CACHE_KEY=${"a1b2c3d4e5f60718".repeat(4)}`), []);
  assert.deepEqual(e.scan("SECRET_VERSION=12.4.1-beta.3"), []);
  assert.deepEqual(e.scan("AUTH_KEY_PATH=/etc/ssl/private/server-key.pem"), []);
  assert.deepEqual(e.scan(`SESSION_SECRET=${rand(32)}`, "package-lock.json"), []);
  assert.equal(e.scan(`SESSION_SECRET=${rand(32)}`, ".env")[0].rule.id, "generic-assignment");
});

test("jwt look-alikes are rejected", () => {
  const e = new Engine([{ source: "t", rules: [{ id: "jwt", label: "JWT", provider: "jwt", regex: "\\b(ey[A-Za-z0-9]{10,}\\.ey[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,})\\b", keywords: ["ey"], check: "jwt", source: "tripwire" }] }]);
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
  assert.equal(e.scan(`t=${b64({ alg: "HS256", typ: "JWT" })}.${b64({ sub: "1234567890abc" })}.${rand(20)}`).length, 1);
  assert.equal(e.scan(`t=eyJ${rand(12)}.eyJ${rand(12)}.${rand(20)}`).length, 0);
});

test("allowlists: OR any criterion, AND needs all, target picks what regexes see", () => {
  const ctx = { secret: "abc-fixture-123", match: "key=abc-fixture-123", line: "key=abc-fixture-123", path: "src/a.test.ts" };
  assert.ok(allowed(compileAllowlist({ stopwords: ["fixture"] }), ctx));
  assert.ok(allowed(compileAllowlist({ regexes: ["^key="], regexTarget: "line" }), ctx));
  assert.ok(!allowed(compileAllowlist({ regexes: ["^key="], regexTarget: "secret" }), ctx));
  assert.ok(allowed(compileAllowlist({ condition: "AND", stopwords: ["fixture"], paths: ["\\.test\\.ts$"] }), ctx));
  assert.ok(!allowed(compileAllowlist({ condition: "AND", stopwords: ["fixture"], paths: ["\\.spec\\.ts$"] }), ctx));
});

test("benign shapes", () => {
  assert.ok(looksBenign("550e8400-e29b-41d4-a716-446655440000"));
  assert.ok(looksBenign("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"));
  assert.ok(looksBenign("v1.2.3"));
  assert.ok(!looksBenign(rand(32)));
});

test("private keys need the full block and report the line they start on", () => {
  const e = defaultEngine();
  const pem = ["-----BEGIN RSA PRIVATE KEY-----", rand(64), rand(64), "-----END RSA PRIVATE KEY-----"].join("\n");
  const hits = e.scan(`# deploy\nKEY=1\n${pem}\nafter`, "deploy.sh");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].rule.id, "private-key");
  assert.equal(hits[0].line, 3);
  assert.equal(e.scan("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----").length, 0, "truncated example");
  assert.equal(e.scan("-----BEGIN RSA PRIVATE KEY-----").length, 0, "header only");
  assert.equal(e.scan(pem, "package-lock.json").length, 0, "globally allowlisted path");
});
