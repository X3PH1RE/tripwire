import type { Pack, RuleDef } from "../schema";

// Written from each provider's published token format. Order matters: when two rules match the same value, the earlier one wins.
const rule = (r: Omit<RuleDef, "source">): RuleDef => ({ ...r, source: "tripwire" });

export const tripwirePack: Pack = {
  source: "tripwire",
  rules: [
    // Only a complete BEGIN..END block counts; a bare header in docs or a truncated example does not.
    rule({ id: "private-key", label: "Private key", provider: "ssh", multiline: true, regex: "-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\\w+/=:,.\\s-]{40,}?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----", keywords: ["private key"] }),
    rule({ id: "aws-access-key", label: "AWS access key ID", provider: "aws", regex: "\\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\\b", keywords: ["akia", "asia", "abia", "acca"] }),
    rule({ id: "aws-secret-key", label: "AWS secret access key", provider: "aws", regex: "(?i)aws_?secret_?(?:access_?)?key[\"']?\\s*[:=]\\s*[\"']?([A-Za-z0-9/+=]{40})\\b", keywords: ["aws"] }),
    rule({ id: "github-pat", label: "GitHub token", provider: "github", regex: "\\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\\b", keywords: ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"], check: "github-checksum" }),
    rule({ id: "github-fine-grained", label: "GitHub fine-grained token", provider: "github", regex: "\\b(github_pat_[A-Za-z0-9_]{60,255})\\b", keywords: ["github_pat_"] }),
    rule({ id: "gitlab-pat", label: "GitLab token", provider: "gitlab", regex: "\\b(glpat-[A-Za-z0-9_-]{20,})\\b", keywords: ["glpat-"] }),
    rule({ id: "stripe-live", label: "Stripe live key", provider: "stripe", regex: "\\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\\b", keywords: ["sk_live_", "rk_live_"] }),
    rule({ id: "stripe-test", label: "Stripe test key", provider: "stripe-test", regex: "\\b((?:sk|rk)_test_[A-Za-z0-9]{20,})\\b", keywords: ["sk_test_", "rk_test_"] }),
    rule({ id: "slack-token", label: "Slack token", provider: "slack", regex: "\\b(xox[baprs]-[A-Za-z0-9-]{10,})\\b", keywords: ["xox"] }),
    rule({ id: "slack-webhook", label: "Slack webhook", provider: "slack", regex: "(https:\\/\\/hooks\\.slack\\.com\\/services\\/T[A-Za-z0-9_]+\\/B[A-Za-z0-9_]+\\/[A-Za-z0-9_]+)", keywords: ["hooks.slack.com"] }),
    rule({ id: "google-api-key", label: "Google API key", provider: "gcp", regex: "\\b(AIza[0-9A-Za-z_-]{35})\\b", keywords: ["aiza"] }),
    rule({ id: "anthropic-key", label: "Anthropic API key", provider: "anthropic", regex: "\\b(sk-ant-[A-Za-z0-9_-]{32,})\\b", keywords: ["sk-ant-"] }),
    rule({ id: "openai-key", label: "OpenAI API key", provider: "openai", regex: "\\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})\\b", keywords: ["t3blbkfj"] }),
    rule({ id: "sendgrid-key", label: "SendGrid API key", provider: "sendgrid", regex: "\\b(SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43})\\b", keywords: ["sg."] }),
    rule({ id: "twilio-key", label: "Twilio API key", provider: "twilio", regex: "\\b(SK[0-9a-f]{32})\\b", keywords: ["sk"] }),
    rule({ id: "npm-token", label: "npm access token", provider: "npm", regex: "\\b(npm_[A-Za-z0-9]{36})\\b", keywords: ["npm_"] }),
    // Same block as it appears inside a JSON string (GCP service-account files), with literal \n escapes instead of newlines.
    rule({ id: "private-key-escaped", label: "Private key (escaped in JSON)", provider: "ssh", regex: "-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[A-Za-z0-9+/=\\\\]{40,}?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----", keywords: ["private key"] }),
    rule({ id: "dockerhub-pat", label: "Docker Hub token", provider: "docker", regex: "\\b(dckr_pat_[A-Za-z0-9_-]{27,})\\b", keywords: ["dckr_pat_"] }),
    rule({ id: "replicate-token", label: "Replicate API token", provider: "replicate", regex: "\\b(r8_[A-Za-z0-9]{37})\\b", keywords: ["r8_"] }),
    rule({ id: "groq-key", label: "Groq API key", provider: "groq", regex: "\\b(gsk_[A-Za-z0-9]{52})\\b", keywords: ["gsk_"] }),
    rule({ id: "xai-key", label: "xAI API key", provider: "xai", regex: "\\b(xai-[A-Za-z0-9]{70,})\\b", keywords: ["xai-"] }),
    rule({ id: "supabase-token", label: "Supabase access token", provider: "supabase", regex: "\\b(sbp_[a-f0-9]{40})\\b", keywords: ["sbp_"] }),
    rule({ id: "figma-token", label: "Figma access token", provider: "figma", regex: "\\b(figd_[A-Za-z0-9_-]{40})\\b", keywords: ["figd_"] }),
    rule({ id: "neon-key", label: "Neon API key", provider: "neon", regex: "\\b(napi_[a-z0-9]{64})\\b", keywords: ["napi_"] }),
    rule({ id: "azure-storage-key", label: "Azure storage account key", provider: "azure", regex: "AccountKey=([A-Za-z0-9+/]{86}==)", keywords: ["accountkey="] }),
    // The password group is what gets checked; the whole URL is what gets reported.
    rule({ id: "db-url", label: "Database URL with password", provider: "database", regex: "\\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\\+srv)?|redis|rediss|amqps?):\\/\\/[^\\s:/@\"']+:([^\\s@\"'/]+)@[^\\s\"']+)", secretGroup: 2, reportGroup: 1, minLength: 6, keywords: ["://"] }),
    rule({ id: "tripwire-demo", label: "Tripwire demo secret", provider: "demo", regex: "\\b(tw_fake_[a-z]+_[a-z0-9]{16,})\\b", keywords: ["tw_fake_"] }),
  ],
};
