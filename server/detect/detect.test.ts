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

test("secrets hidden in base64, url-encoding and hex are found and labelled", () => {
  const e = defaultEngine();
  const aws = ["AKIA", "Q3MXR7ZB2KD4WT6N"].join("");
  const b64 = (s: string) => Buffer.from(s).toString("base64");

  const k8s = e.scan(`  token: ${b64(aws)}`, "secret.yaml");
  assert.equal(k8s[0].rule.id, "aws-access-key");
  assert.equal(k8s[0].via, "base64");
  assert.equal(k8s[0].value, aws);

  const plainSecret = `${rand(22)}7q`; // digits keep it from reading as an identifier
  const named = e.scan(`password: ${b64(plainSecret)}`, "secret.yaml");
  assert.equal(named.length, 1);
  assert.equal(named[0].via, "base64");
  assert.equal(named[0].variable, "password");

  const pct = (s: string) => [...s].map((c) => "%" + c.charCodeAt(0).toString(16).padStart(2, "0")).join("");
  const url = e.scan(`https://x.io/cb?next=${pct(`aws_access_key_id=${aws}`)}`, "a.md");
  assert.equal(url.find((h) => h.rule.id === "aws-access-key")?.via, "url");

  const hex = e.scan(`blob = "${Buffer.from(`aws_access_key_id=${aws}`).toString("hex")}"`, "a.py");
  assert.equal(hex.find((h) => h.rule.id === "aws-access-key")?.via, "hex");

  const twice = e.scan(`x: ${b64(b64(aws))}`, "a.yaml");
  assert.equal(twice.find((h) => h.rule.id === "aws-access-key")?.via, "base64>base64");

  assert.deepEqual(e.scan(`etag: ${b64(rand(40))}`, "a.yaml").filter((h) => h.via), [], "binary garbage is not scanned");
});

test("found in real repos: password hashes are not secrets, hex SECRET_KEY is, docs rank lower", () => {
  const e = defaultEngine();
  assert.deepEqual(e.scan('"password" : "$2a$10$8Zo/1e8KM8QzqOKqbDlYlONBOzukWXrM.IiyzqHRYDXqwB3gzDsba",', "db-reset.js"), [], "bcrypt");
  assert.deepEqual(e.scan("password_hash = $argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG", "a.conf"), [], "argon2");
  assert.deepEqual(e.scan("curl --data 'userName=a&password=Admin_123&_csrf='", "tutorial.html"), [], "form value stops at &");

  const hex = "192b9bdd22ab9ed4d12e236c78afcb9a393ec15f71bbf5dc987d54727823bcbf";
  const inCode = e.scan(`SECRET_KEY = '${hex}'`, "app/config.py");
  assert.equal(inCode.length, 1);
  assert.equal(inCode[0].confidence, "medium");
  assert.equal(e.scan(`SECRET_KEY = '${hex}'`, "docs/config.rst")[0].confidence, "low", "documentation example");
  assert.deepEqual(e.scan(`CHECKSUM_KEY=${hex}`, "a.env"), [], "a digest under a digest-like name");
  assert.deepEqual(e.scan(`SECRET_HASH=${hex}`, "a.env"), [], "SECRET_HASH is a hash");
});

test("found in django: format strings, file names and attribute chains are not secrets; tutorial passwords are low confidence", () => {
  const e = defaultEngine();
  assert.deepEqual(e.scan('template_url = "%s/custom_templates/project_template.tgz" % self.live_server_url', "tests.py"), []);
  assert.deepEqual(e.scan("b\"//# sourceMappingURL=source_map.js.99914b932bd3.map\",", "test_storage.py"), []);
  assert.deepEqual(e.scan("layer_key=AllOGRFields._meta.db_table,", "tests.py"), []);

  const weak = e.scan('"LOCATION": "redis://username:password@127.0.0.1:6379",', "app/settings.py");
  assert.equal(weak.length, 1, "still reported");
  assert.equal(weak[0].confidence, "low", "tutorial password");
  const strong = e.scan(`DATABASE_URL=postgres://app:${rand(20)}@db.internal/app`, "app/settings.py");
  assert.equal(strong[0].confidence, "high");
  assert.equal(e.scan(`DATABASE_URL=postgres://app:${rand(20)}@db.internal/app`, "docs/deploy.md")[0].confidence, "low", "same URL inside docs");
});

test("path-restricted rules only run on matching files", () => {
  const e = defaultEngine();
  const tf = 'administrator_login_password = "p4ssw0rdx7q2m9zk"';
  assert.ok(e.scan(tf, "infra/main.tf").some((h) => h.rule.id === "hashicorp-tf-password"));
  assert.ok(!e.scan(tf, "src/app.py").some((h) => h.rule.id === "hashicorp-tf-password"), "wrong file type");
  assert.ok(!e.scan(tf).some((h) => h.rule.id === "hashicorp-tf-password"), "no path at all");
  // The Kubernetes Secret rule spans lines, so it runs over whole files.
  const k8s = ["apiVersion: v1", "kind: Secret", "metadata:", "  name: db", "data:", "  password: " + Buffer.from(rand(24)).toString("base64")].join("\n");
  assert.ok(e.scan(k8s, "k8s/secret.yaml").length >= 1);
});

test("a multi-line key is the same finding whether the file uses CRLF or LF", () => {
  const e = defaultEngine();
  const lf = ["-----BEGIN RSA PRIVATE KEY-----", rand(64), rand(64), "-----END RSA PRIVATE KEY-----"].join("\n");
  const a = e.scan(lf, "k.pem");
  const b = e.scan(lf.replace(/\n/g, "\r\n"), "k.pem");
  assert.equal(a.length, 1);
  assert.equal(b.length, 1);
  assert.equal(a[0].value, b[0].value);
});
