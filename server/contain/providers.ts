import type { Finding } from "../../shared/types";
import { awsSecretFor, sigV4 } from "../real/verify";

const TIMEOUT = Number(process.env.CONTAIN_TIMEOUT_MS ?? 10_000);
const signal = () => AbortSignal.timeout(TIMEOUT);

export interface RevokeContext {
  finding: Finding;
  findings: Finding[];
  /** Finding id -> secret value. In memory only. */
  values: Map<string, string>;
}

export interface Revoked {
  ok: boolean;
  note: string;
  /** Command that undoes a reversible action. */
  reactivate?: string;
}

export type Revoker = (ctx: RevokeContext) => Promise<Revoked>;

const secretOf = (ctx: RevokeContext) => ctx.values.get(ctx.finding.id) ?? "";

/** GitHub's public credential-revocation endpoint: no auth, the same path GitHub secret scanning uses. 202 = accepted. */
const github: Revoker = async (ctx) => {
  const res = await fetch("https://api.github.com/credentials/revoke", {
    method: "POST",
    headers: { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json" },
    body: JSON.stringify({ credentials: [secretOf(ctx)] }),
    signal: signal(),
  });
  return res.status === 202 ? { ok: true, note: "GitHub accepted the revocation." } : { ok: false, note: `GitHub returned ${res.status}.` };
};

const slack: Revoker = async (ctx) => {
  const res = await fetch("https://slack.com/api/auth.revoke", { method: "POST", headers: { Authorization: `Bearer ${secretOf(ctx)}` }, signal: signal() });
  const data = (await res.json().catch(() => ({}))) as { ok?: boolean; revoked?: boolean; error?: string };
  return data.ok ? { ok: true, note: "Slack revoked the token." } : { ok: false, note: `Slack: ${data.error ?? res.status}.` };
};

/** Self-revocation: a GitLab personal access token deletes itself. Assumes gitlab.com. */
const gitlab: Revoker = async (ctx) => {
  const res = await fetch("https://gitlab.com/api/v4/personal_access_tokens/self", { method: "DELETE", headers: { "PRIVATE-TOKEN": secretOf(ctx) }, signal: signal() });
  return res.status === 204 ? { ok: true, note: "GitLab revoked the token." } : { ok: false, note: `GitLab returned ${res.status}.` };
};

/** Deactivates (does not delete) the key, so it can be switched back on if the app still needed it. Needs iam:UpdateAccessKey on the key's own user. */
const aws: Revoker = async (ctx) => {
  const id = secretOf(ctx);
  const arn = ctx.finding.verify?.identity ?? "";
  const user = arn.includes(":user/") ? arn.split("/").pop() : undefined;
  if (!user) return { ok: false, note: "Only IAM user access keys can be deactivated this way (this key's identity is not an IAM user)." };
  const pair = awsSecretFor(ctx.findings, ctx.finding);
  const secret = pair ? ctx.values.get(pair.id) : undefined;
  if (!secret) return { ok: false, note: "No matching AWS secret access key was found next to this key ID." };
  const body = `Action=UpdateAccessKey&AccessKeyId=${encodeURIComponent(id)}&Status=Inactive&UserName=${encodeURIComponent(user)}&Version=2010-05-08`;
  const res = await fetch("https://iam.amazonaws.com/", { method: "POST", headers: sigV4({ id, secret, service: "iam", host: "iam.amazonaws.com", region: "us-east-1", body, now: new Date() }), body, signal: signal() });
  if (!res.ok) {
    const code = (await res.text()).match(/<Code>([^<]*)<\/Code>/)?.[1] ?? res.status;
    return { ok: false, note: `AWS refused (${code}). The key may lack iam:UpdateAccessKey.` };
  }
  return { ok: true, note: `Deactivated ${id} for IAM user ${user}.`, reactivate: `aws iam update-access-key --access-key-id ${id} --status Active --user-name ${user}` };
};

/** Providers where a leaked credential can be killed with an API call. */
export const REVOKERS: Record<string, Revoker> = { github, slack, gitlab, aws };

export interface Guide {
  url?: string;
  steps: string[];
}

const GUIDES: Record<string, Guide> = {
  stripe: { url: "https://dashboard.stripe.com/apikeys", steps: ["Roll the key (Developers > API keys > Roll key). There is no API to do it for you.", "Deploy the new key.", "Check Developers > Logs for charges or refunds you do not recognise."] },
  "stripe-test": { url: "https://dashboard.stripe.com/test/apikeys", steps: ["Roll the test key; it cannot move real money, but it exposes test customer data."] },
  openai: { url: "https://platform.openai.com/api-keys", steps: ["Delete the key and create a new one.", "Check the usage dashboard for spend you do not recognise."] },
  anthropic: { url: "https://console.anthropic.com/settings/keys", steps: ["Delete the key and create a new one.", "Check usage for spend you do not recognise."] },
  sendgrid: { url: "https://app.sendgrid.com/settings/api_keys", steps: ["Delete the key, create a new one with the least scope it needs.", "Check Activity for mail you did not send."] },
  npm: { url: "https://www.npmjs.com/settings/~/tokens", steps: ["Revoke the token (or run `npm token revoke <id>`), then create a granular replacement.", "Check your packages for versions you did not publish."] },
  gcp: { url: "https://console.cloud.google.com/apis/credentials", steps: ["Delete or regenerate the API key and restrict the new one to the APIs and referrers it needs.", "Check API usage for spikes."] },
  twilio: { url: "https://console.twilio.com/us1/account/keys-credentials/api-keys", steps: ["Delete the API key and create a new one.", "Check the usage logs for messages or calls you did not make."] },
  database: { steps: ["Change the password: ALTER USER <user> WITH PASSWORD '<new>' (or the equivalent), then update the connection string wherever it is used.", "Restrict the database to the hosts that need it, and check its logs for unknown clients."] },
  ssh: { steps: ["Remove the matching public key from every server's authorized_keys and from GitHub/GitLab deploy keys.", "Generate a new key pair and install the new public key."] },
  github: { url: "https://github.com/settings/tokens", steps: ["Delete the token in Settings > Developer settings, then create a replacement with the least scope it needs."] },
  gitlab: { url: "https://gitlab.com/-/user_settings/personal_access_tokens", steps: ["Revoke the token, then create a replacement with the least scope it needs."] },
  slack: { url: "https://api.slack.com/apps", steps: ["Reinstall or rotate the app token, then revoke the old one."] },
  aws: { url: "https://console.aws.amazon.com/iam/home#/security_credentials", steps: ["Deactivate the access key (IAM > Users > Security credentials), create a new one, update the app, then delete the old key.", "Review CloudTrail for activity by the key since it leaked."] },
};

const GENERIC: Guide = { steps: ["Revoke or rotate the credential in the service that issued it.", "Deploy the replacement wherever the old one was used."] };

const TAIL = ["Review the provider's audit log for use of the old key since it leaked.", "Remove it from the code; if it is also in git history, the revocation is what protects you."];

export function guideFor(provider: string): Guide {
  const g = GUIDES[provider] ?? GENERIC;
  return { url: g.url, steps: [...g.steps, ...TAIL] };
}
