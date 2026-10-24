// Deterministic labeled corpus. Positives are real provider token formats with synthetic values; negatives are the things
// secret scanners usually get wrong. Values are generated at run time so no provider-format token is ever committed.
import { createHash } from "node:crypto";
import { crc32, toBase62 } from "../server/detect/filters";

export interface Case {
  id: string;
  /** What the case checks, for the report. */
  name: string;
  kind: "positive" | "negative";
  /** File the content is written to, relative to the case directory. */
  path: string;
  content: string;
}

let n = 0;
const stream = (len: number, alphabet: string): string => {
  let out = "";
  while (out.length < len) out += [...createHash("sha256").update(`tw-bench-${n++}`).digest()].map((b) => alphabet[b % alphabet.length]).join("");
  return out.slice(0, len);
};
const ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const UPPER_NUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const HEX = "0123456789abcdef";
const WORD = `${ALNUM}_-`;
const B64 = `${ALNUM}+/`;

const githubToken = () => {
  const body = stream(30, ALNUM);
  return `ghp_${body}${toBase62(crc32(body), 6)}`;
};
const b64 = (s: string) => Buffer.from(s).toString("base64");
const b64url = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");

interface Spec {
  name: string;
  token: () => string;
  /** How the token appears in a file; `{}` is replaced by the token. */
  contexts: { path: string; line: string }[];
}

const ENV = (name: string) => ({ path: ".env", line: `${name}={}` });
const JS = (name: string) => ({ path: "src/config.js", line: `const ${name} = "{}";` });
const YAML = (name: string) => ({ path: "deploy/values.yaml", line: `  ${name.toLowerCase()}: "{}"` });

const SPECS: Spec[] = [
  { name: "AWS access key ID", token: () => `AKIA${stream(16, UPPER_NUM)}`, contexts: [ENV("AWS_ACCESS_KEY_ID"), JS("awsKeyId")] },
  { name: "AWS secret access key", token: () => stream(40, B64), contexts: [{ path: ".env", line: "AWS_SECRET_ACCESS_KEY={}" }, { path: "config/aws.ini", line: "aws_secret_access_key = {}" }] },
  { name: "GitHub personal access token", token: githubToken, contexts: [ENV("GITHUB_TOKEN"), JS("ghToken")] },
  { name: "GitHub fine-grained token", token: () => `github_pat_${stream(22, ALNUM)}_${stream(59, ALNUM)}`, contexts: [ENV("GH_PAT"), YAML("token")] },
  { name: "GitLab token", token: () => `glpat-${stream(20, WORD)}`, contexts: [ENV("GITLAB_TOKEN"), JS("gitlabToken")] },
  { name: "Stripe live key", token: () => `sk_live_${stream(24, ALNUM)}`, contexts: [ENV("STRIPE_SECRET_KEY"), JS("stripeKey")] },
  { name: "Stripe restricted key", token: () => `rk_live_${stream(24, ALNUM)}`, contexts: [ENV("STRIPE_RESTRICTED"), YAML("stripe")] },
  { name: "Slack bot token", token: () => `xoxb-${stream(12, "0123456789")}-${stream(12, "0123456789")}-${stream(24, ALNUM)}`, contexts: [ENV("SLACK_BOT_TOKEN"), JS("slackToken")] },
  { name: "Slack webhook", token: () => `https://hooks.slack.com/services/T${stream(10, UPPER_NUM)}/B${stream(10, UPPER_NUM)}/${stream(24, ALNUM)}`, contexts: [ENV("SLACK_WEBHOOK_URL"), JS("hook")] },
  { name: "Google API key", token: () => `AIza${stream(35, WORD)}`, contexts: [ENV("GOOGLE_API_KEY"), JS("mapsKey")] },
  { name: "OpenAI API key", token: () => `sk-${stream(20, ALNUM)}T3BlbkFJ${stream(20, ALNUM)}`, contexts: [ENV("OPENAI_API_KEY"), JS("openai")] },
  { name: "Anthropic API key", token: () => `sk-ant-api03-${stream(93, WORD)}AA`, contexts: [ENV("ANTHROPIC_API_KEY"), JS("anthropicKey")] },
  { name: "SendGrid API key", token: () => `SG.${stream(22, WORD)}.${stream(43, WORD)}`, contexts: [ENV("SENDGRID_API_KEY"), JS("sendgrid")] },
  { name: "Twilio API key", token: () => `SK${stream(32, HEX)}`, contexts: [ENV("TWILIO_API_KEY"), JS("twilioKey")] },
  { name: "npm access token", token: () => `npm_${stream(36, ALNUM)}`, contexts: [ENV("NPM_TOKEN"), { path: ".npmrc", line: "//registry.npmjs.org/:_authToken={}" }] },
  { name: "DigitalOcean token", token: () => `dop_v1_${stream(64, HEX)}`, contexts: [ENV("DIGITALOCEAN_TOKEN"), JS("doToken")] },
  { name: "Shopify access token", token: () => `shpat_${stream(32, HEX)}`, contexts: [ENV("SHOPIFY_ACCESS_TOKEN"), JS("shopify")] },
  { name: "Databricks token", token: () => `dapi${stream(32, HEX)}`, contexts: [ENV("DATABRICKS_TOKEN"), YAML("databricks")] },
  { name: "PyPI upload token", token: () => `pypi-AgEIcHlwaS5vcmc${stream(60, WORD)}`, contexts: [{ path: ".pypirc", line: "password = {}" }, ENV("PYPI_TOKEN")] },
  { name: "Docker Hub token", token: () => `dckr_pat_${stream(27, WORD)}`, contexts: [ENV("DOCKERHUB_TOKEN"), YAML("dockerhub")] },
  { name: "Postman API key", token: () => `PMAK-${stream(24, HEX)}-${stream(34, HEX)}`, contexts: [ENV("POSTMAN_API_KEY"), JS("postman")] },
  { name: "Linear API key", token: () => `lin_api_${stream(40, ALNUM)}`, contexts: [ENV("LINEAR_API_KEY"), JS("linear")] },
  { name: "Replicate API token", token: () => `r8_${stream(37, ALNUM)}`, contexts: [ENV("REPLICATE_API_TOKEN"), JS("replicate")] },
  { name: "Groq API key", token: () => `gsk_${stream(52, ALNUM)}`, contexts: [ENV("GROQ_API_KEY"), JS("groq")] },
  { name: "xAI API key", token: () => `xai-${stream(80, ALNUM)}`, contexts: [ENV("XAI_API_KEY"), JS("xai")] },
  { name: "Supabase access token", token: () => `sbp_${stream(40, HEX)}`, contexts: [ENV("SUPABASE_ACCESS_TOKEN"), YAML("supabase")] },
  { name: "Figma personal access token", token: () => `figd_${stream(40, WORD)}`, contexts: [ENV("FIGMA_TOKEN"), JS("figma")] },
  { name: "Neon API key", token: () => `napi_${stream(64, "abcdefghijklmnopqrstuvwxyz0123456789")}`, contexts: [ENV("NEON_API_KEY"), YAML("neon")] },
  { name: "Azure storage account key", token: () => `DefaultEndpointsProtocol=https;AccountName=prod;AccountKey=${stream(86, B64)}==;EndpointSuffix=core.windows.net`, contexts: [ENV("AZURE_STORAGE_CONNECTION_STRING"), JS("azureStorage")] },
  { name: "Postgres URL with password", token: () => `postgres://app:${stream(16, ALNUM)}@db.internal:5432/app`, contexts: [ENV("DATABASE_URL"), YAML("database_url")] },
  { name: "MongoDB URL with password", token: () => `mongodb+srv://svc:${stream(16, ALNUM)}@cluster0.example.mongodb.net/prod`, contexts: [ENV("MONGO_URL"), JS("mongoUrl")] },
  { name: "JWT", token: () => `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url({ sub: "1234567890", name: "svc", iat: 1516239022 })}.${stream(43, WORD)}`, contexts: [{ path: "src/client.js", line: 'const headers = { Authorization: "Bearer {}" };' }, ENV("SERVICE_JWT")] },
  { name: "Generic session secret", token: () => stream(32, ALNUM), contexts: [ENV("SESSION_SECRET"), YAML("api_secret")] },
  { name: "Generic bare password key", token: () => `${stream(20, ALNUM)}7!`, contexts: [{ path: "config/app.yml", line: "password: {}" }] },
  { name: "Generic API key assignment", token: () => stream(40, ALNUM), contexts: [{ path: "src/client.py", line: 'API_KEY = "{}"' }, { path: "src/client.js", line: 'const apiKey = "{}";' }] },
];

/** The same token in the places real repos keep them, to test boundaries and quoting rather than the pattern itself. */
const MATRIX: { path: string; line: string }[] = [
  { path: "scripts/deploy.sh", line: "export TOKEN='{}'" },
  { path: "config/settings.json", line: '{ "token": "{}" }' },
  { path: "Dockerfile", line: "ENV TOKEN {}" },
  { path: "scripts/call.sh", line: 'curl -H "Authorization: Bearer {}" https://api.example.com' },
  { path: "infra/vars.tfvars", line: 'token = "{}"' },
  { path: "src/settings.py", line: 'SETTINGS = {"token": "{}", "retries": 3}' },
  { path: "docs/usage.md", line: "    token: {}" },
  { path: "config/app.properties", line: "app.token={}" },
  { path: "src/Main.java", line: 'private static final String TOKEN = "{}";' },
  { path: "src/client.go", line: 'var token = "{}"' },
  { path: "config/windows.env", line: "TOKEN={}\r" },
];
const MATRIX_TOKENS: { name: string; token: () => string }[] = [
  { name: "GitHub token", token: githubToken },
  { name: "Stripe live key", token: () => `sk_live_${stream(24, ALNUM)}` },
  { name: "AWS access key ID", token: () => `AKIA${stream(16, UPPER_NUM)}` },
];
const matrix = (): Case[] =>
  MATRIX_TOKENS.flatMap((s, i) => MATRIX.map((c, j) => ({ id: `ctx-${i}-${String(j).padStart(2, "0")}`, name: `${s.name} in ${c.path}`, kind: "positive" as const, path: c.path, content: `${c.line.replace("{}", s.token())}
` })));

const positives = (): Case[] =>
  SPECS.flatMap((s, i) =>
    s.contexts.map((c, j) => ({ id: `pos-${String(i).padStart(2, "0")}-${j}`, name: s.name, kind: "positive" as const, path: c.path, content: `${c.line.replace("{}", s.token())}\n` })),
  );

const pem = (type = "RSA"): string => {
  const label = type ? `${type} PRIVATE KEY` : "PRIVATE KEY";
  return [`-----BEGIN ${label}-----`, ...Array.from({ length: 6 }, () => stream(64, B64)), `-----END ${label}-----`].join("\n") + "\n";
};

const hard = (): Case[] => {
  const aws = `AKIA${stream(16, UPPER_NUM)}`;
  return [
    { id: "pos-pem-rsa", name: "RSA private key block", kind: "positive", path: "deploy/id_rsa", content: pem("RSA") },
    { id: "pos-pem-openssh", name: "OpenSSH private key block", kind: "positive", path: "ci/key.pem", content: pem("OPENSSH") },
    { id: "pos-b64-k8s", name: "AWS key base64-encoded in a Kubernetes secret", kind: "positive", path: "k8s/secret.yaml", content: `apiVersion: v1\nkind: Secret\ndata:\n  access-key: ${b64(aws)}\n` },
    { id: "pos-b64-password", name: "password value base64-encoded under its key", kind: "positive", path: "k8s/db.yaml", content: `data:\n  password: ${b64(`${stream(20, ALNUM)}9q`)}\n` },
    { id: "pos-pem-json", name: "private key escaped inside a GCP service-account JSON", kind: "positive", path: "gcp/service-account.json", content: JSON.stringify({ type: "service_account", project_id: "prod", private_key_id: stream(40, HEX), private_key: pem("") }, null, 2) + "\n" },
    { id: "pos-multi", name: "two secrets on one line", kind: "positive", path: "scripts/deploy.sh", content: `curl -u ${githubToken()}:x -H "X-Key: sk_live_${stream(24, ALNUM)}" https://api.example.com\n` },
  ];
};

const neg = (id: string, name: string, path: string, content: string): Case => ({ id: `neg-${id}`, name, kind: "negative", path, content: content.endsWith("\n") ? content : `${content}\n` });

const negatives = (): Case[] => {
  const sha1 = stream(40, HEX);
  const sha256 = stream(64, HEX);
  return [
    neg("aws-doc-example", "AWS documentation example keys", "README.md", "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    neg("placeholder-key", "placeholder API key", ".env.example", "API_KEY=your_api_key_here"),
    neg("placeholder-angle", "angle-bracket placeholder", "docs/setup.md", "export GITHUB_TOKEN=<your-token>"),
    neg("placeholder-x", "x-filled placeholder", ".env.example", `STRIPE_SECRET_KEY=${["sk", "live", "x".repeat(24)].join("_")}`),
    neg("placeholder-gh", "x-filled GitHub token", "docs/ci.md", `GH_TOKEN=ghp_${"x".repeat(36)}`),
    neg("placeholder-changeme", "changeme password", "config/app.yml", "password: changeme"),
    neg("placeholder-aws", "x-filled AWS secret", ".env.example", `AWS_SECRET_ACCESS_KEY=${"x".repeat(40)}`),
    neg("env-ref-js", "reads token from process.env", "src/gh.js", "const token = process.env.GITHUB_TOKEN;"),
    neg("env-ref-py", "reads key from os.environ", "src/app.py", 'api_key = os.environ["API_KEY"]'),
    neg("env-ref-shell", "shell variable reference", "scripts/run.sh", 'export SECRET_KEY="${SECRET_KEY}"'),
    neg("env-ref-actions", "GitHub Actions secret reference", ".github/workflows/ci.yml", "        env:\n          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}"),
    neg("git-sha", "git commit SHA", "docs/release.md", `commit_key: ${sha1}`),
    neg("sha256-digest", "sha256 digest in a checksum field", "deploy/SHA256SUMS.txt", `CHECKSUM_KEY=${sha256}`),
    neg("cache-key-sha1", "cache key that is a sha1", ".github/workflows/cache.yml", `cache_key: ${sha1}`),
    neg("uuid-key", "UUID assigned to an ID_KEY", "config/ids.env", "API_KEY=550e8400-e29b-41d4-a716-446655440000"),
    neg("version-string", "version string under a secret-like name", "config/app.env", "SECRET_VERSION=12.4.1-beta.3"),
    neg("docker-digest", "docker image digest", "deploy/compose.yml", `image: registry.example.com/app@sha256:${sha256}`),
    neg("lockfile-integrity", "npm lockfile integrity hashes", "package-lock.json", `{"packages":{"node_modules/x":{"integrity":"sha512-${stream(86, B64)}=="}}}`),
    neg("yarn-lock", "yarn.lock checksum", "yarn.lock", `  checksum: ${sha256}`),
    neg("sri-hash", "subresource integrity attribute", "public/index.html", `<script src="app.js" integrity="sha384-${stream(64, B64)}" crossorigin></script>`),
    neg("pem-header-doc", "private key header mentioned in docs", "docs/keys.md", "Generate a key with `openssl genrsa`; it starts with -----BEGIN RSA PRIVATE KEY-----"),
    neg("pem-truncated", "truncated example key", "docs/keys.md", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"),
    neg("file-path", "path to a secret file", "config/app.env", "SECRET_FILE=/run/secrets/database_password"),
    neg("key-path", "path to a key file", "nginx.conf", "KEY_PATH=/etc/ssl/private/server-key.pem"),
    neg("token-url", "token endpoint URL", "config/oauth.env", "TOKEN_URL=https://auth.example.com/oauth/token"),
    neg("reset-url", "password reset URL", "config/mail.env", "PASSWORD_RESET_URL=https://example.com/reset?code=abc"),
    neg("form-field", "reads password from a form", "src/login.py", 'password = request.form["password"]'),
    neg("dom-lookup", "looks up a password input", "src/login.js", 'const passwordInput = document.getElementById("password-field-main");'),
    neg("func-call", "token from a function call", "src/auth.js", "const token = generateSecureTokenForSession(user.id, 3600);"),
    neg("jwt-sign", "signs with a variable secret", "src/auth.js", "const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });"),
    neg("long-identifier", "long identifier under KEY", "src/cache.js", 'const CACHE_KEY = "userProfileLookupByAccountIdentifier";'),
    neg("class-name", "long class name", "src/factory.java", "public class SecretKeyFactoryBuilderImplementation extends AbstractFactory {"),
    neg("css-color", "css colors", "public/app.css", "a { color: #a1b2c3; background: #0f0f0f; }"),
    neg("email-ip", "email and ip", "docs/contact.md", "Contact admin@example.com or 192.168.100.200 for access."),
    neg("data-uri", "inline base64 image", "public/index.html", `<img src="data:image/png;base64,${stream(120, B64)}==">`),
    neg("short-password", "short default password in docs", "docs/setup.md", "password: admin"),
    neg("sql-text", "SQL mentioning a password column", "db/schema.sql", "ALTER TABLE users ADD COLUMN password_hash VARCHAR(255) NOT NULL;"),
    neg("test-name", "test names", "tests/auth.test.js", 'it("rejects an expired token and a wrong password", () => {});'),
    neg("regex-literal", "regex that matches tokens", "src/lint.js", String.raw`const TOKEN_RE = /^(ghp|gho)_[A-Za-z0-9]{36}$/;`),
    neg("base64-binary", "base64 of binary data in config", "k8s/cm.yaml", `data:\n  etag: ${b64(Buffer.from(stream(48, ALNUM), "hex").toString("binary") || stream(48, ALNUM))}`),
    neg("jwt-lookalike", "string shaped like a JWT with no JSON header", "src/x.js", `const id = "eyJ${stream(14, ALNUM)}.eyJ${stream(14, ALNUM)}.${stream(24, ALNUM)}";`),
    neg("db-url-nopass", "database URL without a password", ".env", "DATABASE_URL=postgres://db.internal:5432/app"),
    neg("secret-name", "secret manager name", "config/app.env", "DB_SECRET_NAME=prod/payments/database-credentials"),
    neg("kms-alias", "KMS key alias", "infra/kms.tf", 'encryption_key_id = "alias/my-application-data-key"'),
    neg("token-ttl", "token lifetime", "config/app.env", "TOKEN_TTL_SECONDS=3600"),
    neg("password-policy", "password policy", "config/app.env", "PASSWORD_MIN_LENGTH=12"),
    neg("max-tokens", "LLM max tokens", "src/llm.py", "MAX_TOKENS = 4096"),
    neg("key-file-rel", "relative key path", "config/app.env", "PRIVATE_KEY_PATH=./keys/private-signing-key.pem"),
    neg("helm-template", "helm template value", "chart/values.yaml", "secret: {{ .Values.auth.secretName }}"),
    neg("sops-encrypted", "sops-encrypted value", "secrets.enc.yaml", `api_key: ENC[AES256_GCM,data:${stream(24, B64)},iv:${stream(44, B64)},tag:${stream(24, B64)},type:str]`),
    neg("ansible-vault", "ansible-vault marker", "group_vars/all.yml", "db_password: !vault |\n          $ANSIBLE_VAULT;1.1;AES256"),
    neg("request-id", "request id header", "tests/http.md", `x-request-id: ${stream(8, HEX)}-${stream(4, HEX)}-${stream(4, HEX)}-${stream(4, HEX)}-${stream(12, HEX)}`),
    neg("csp-nonce-note", "docs sentence about tokens", "docs/auth.md", "Rotate the API key every 90 days and store each token in the vault."),
    neg("empty-secret", "empty value", ".env", "SECRET_KEY="),
    neg("bool-secret", "boolean flag", "config/app.env", "USE_SECRET_STORE=true"),
    neg("db-url-ref", "database URL built from variables", ".env", "DATABASE_URL=postgres://${DB_USER}:${DB_PASS}@${DB_HOST}/app"),
  ];
};

export function buildCorpus(): Case[] {
  n = 0;
  return [...positives(), ...matrix(), ...hard(), ...negatives()];
}
