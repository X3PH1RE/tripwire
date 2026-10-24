import { entropy } from "../scanner";

export interface Rule {
  id: string;
  label: string;
  provider: string;
  /** Group 1, when present, is the secret value; otherwise the whole match is. */
  re: RegExp;
}

// Patterns follow the token formats published by each provider (and mirrored in gitleaks' default rules).
export const RULES: Rule[] = [
  { id: "private-key", label: "Private key", provider: "ssh", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/ },
  { id: "aws-access-key", label: "AWS access key ID", provider: "aws", re: /\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b/ },
  { id: "aws-secret-key", label: "AWS secret access key", provider: "aws", re: /aws_?secret_?(?:access_?)?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})\b/i },
  { id: "github-pat", label: "GitHub token", provider: "github", re: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b/ },
  { id: "github-fine-grained", label: "GitHub fine-grained token", provider: "github", re: /\b(github_pat_[A-Za-z0-9_]{60,255})\b/ },
  { id: "gitlab-pat", label: "GitLab token", provider: "gitlab", re: /\b(glpat-[A-Za-z0-9_-]{20,})\b/ },
  { id: "stripe-live", label: "Stripe live key", provider: "stripe", re: /\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b/ },
  { id: "stripe-test", label: "Stripe test key", provider: "stripe-test", re: /\b((?:sk|rk)_test_[A-Za-z0-9]{20,})\b/ },
  { id: "slack-token", label: "Slack token", provider: "slack", re: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/ },
  { id: "slack-webhook", label: "Slack webhook", provider: "slack", re: /(https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9_]+)/ },
  { id: "google-api-key", label: "Google API key", provider: "gcp", re: /\b(AIza[0-9A-Za-z_-]{35})\b/ },
  { id: "anthropic-key", label: "Anthropic API key", provider: "anthropic", re: /\b(sk-ant-[A-Za-z0-9_-]{32,})\b/ },
  { id: "openai-key", label: "OpenAI API key", provider: "openai", re: /\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})\b/ },
  { id: "sendgrid-key", label: "SendGrid API key", provider: "sendgrid", re: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/ },
  { id: "twilio-key", label: "Twilio API key", provider: "twilio", re: /\b(SK[0-9a-f]{32})\b/ },
  { id: "npm-token", label: "npm access token", provider: "npm", re: /\b(npm_[A-Za-z0-9]{36})\b/ },
  { id: "db-url", label: "Database URL with password", provider: "database", re: /\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?):\/\/[^\s:/@"']+:([^\s@"'/]+)@[^\s"']+)/ },
  { id: "tripwire-demo", label: "Tripwire demo secret", provider: "demo", re: /\b(tw_fake_[a-z]+_[a-z0-9]{16,})\b/ },
];

const ASSIGN = /\b([A-Za-z][A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIALS?|AUTH|URL|URI|DSN))["']?\s*[:=]\s*["']?([^\s"'`,;]+)/i;
const PLACEHOLDER = /example|sample|dummy|placeholder|changeme|change_me|your[_-]|xxxx|\*\*\*|<|>|\$\{|\{\{|process\.env|os\.environ|getenv|secrets\.|redacted|todo|replace|insert|test123|password123|^true$|^false$|^null$/i;

export interface Match {
  rule: Rule;
  value: string;
  variable?: string;
}

const GENERIC: Rule = { id: "generic-assignment", label: "High-entropy secret", provider: "unknown", re: /$^/ };

export function isPlaceholder(value: string): boolean {
  return PLACEHOLDER.test(value) || /^(.)\1+$/.test(value);
}

/** Returns every secret on one line. Known provider formats win; a generic high-entropy assignment is the fallback. */
export function matchLine(text: string): Match[] {
  if (text.length > 2000) return [];
  const variable = text.match(ASSIGN)?.[1];
  const out: Match[] = [];
  for (const rule of RULES) {
    const m = text.match(rule.re);
    if (!m) continue;
    const value = rule.id === "db-url" ? m[2] : (m[1] ?? m[0]);
    if (rule.id !== "private-key" && isPlaceholder(value)) continue;
    if (rule.id === "db-url" && value.length < 6) continue;
    out.push({ rule, value: rule.id === "db-url" ? m[1] : value, variable });
  }
  if (out.length) return out.filter((m) => !out.some((o) => o !== m && o.value.length > m.value.length && o.value.includes(m.value)));
  const a = text.match(ASSIGN);
  if (a) {
    const value = a[2];
    if (value.length >= 16 && value.length <= 200 && !value.includes("://") && !isPlaceholder(value) && !/^[a-z]+(?:[._-][a-z]+)*$/i.test(value) && entropy(value) >= 3.8)
      out.push({ rule: GENERIC, value, variable: a[1] });
  }
  return out;
}

export function mask(value: string, rule: Rule): string {
  if (rule.id === "private-key") return "-----BEGIN … PRIVATE KEY-----";
  if (rule.id === "db-url") return value.replace(/:\/\/([^:/@\s]+):[^@\s]+@/, "://$1:••••@").slice(0, 48);
  if (rule.id === "tripwire-demo") return value.length > 22 ? `${value.slice(0, 22)}…` : value;
  const keep = Math.min(6, Math.floor(value.length / 4));
  return `${value.slice(0, keep)}${"•".repeat(8)} (${value.length} chars)`;
}
