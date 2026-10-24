# Containment

Turns "found a live key" into "the key is dead", with a human in the loop.

## Scope

Contain means revoke. It does not issue replacement credentials, update CI or vaults, or change database passwords; it prints the follow-up steps for those.

## Flow

`tripwire contain [path]` scans with key verification, builds a plan, and prints it. Nothing is written to any provider. `--apply` executes the plan:

1. Only findings the provider confirmed `live` are eligible. Unverified, revoked and honey findings are never touched.
2. Steps are ordered by blast radius (provider-reported access, falling back to the graph), highest first.
3. For each eligible step with an automatic revoker, call it. A failure is recorded and the run continues.
4. Re-verify each revoked key. It counts as contained only if the provider now rejects it. Otherwise it is `still-live` and the command exits 1.

## Providers

| Mode | Providers | Mechanism |
| --- | --- | --- |
| revoke | GitHub tokens | `POST /credentials/revoke` (unauthenticated, 202) |
| revoke | Slack | `auth.revoke` with the token |
| revoke | GitLab | `DELETE /api/v4/personal_access_tokens/self` |
| revoke | AWS access keys | IAM `UpdateAccessKey` Status=Inactive (reversible; the reactivation command is logged) |
| guided | Stripe, OpenAI, Anthropic, SendGrid, npm, Google, Twilio, databases, SSH, anything else | ordered runbook with dashboard link |

A revoker that fails (for example AWS `AccessDenied`) degrades to the guided runbook for that key.

## Safety

- Dry-run unless `--apply` (CLI) or an explicit confirm (API/UI).
- Secret values are never logged or sent to the browser. Containment needs them, so a scan exposes them in-process through `ScanOptions.onValues`; the server keeps the last scan's values in memory only.
- Every action is appended to `~/.tripwire/contain-log.jsonl`: time, provider, fingerprint, file, outcome, reactivation command. No secret.

## Surfaces

CLI `tripwire contain`, `--json`; `POST /api/real/contain {apply, ids?}`; a UI panel in scan mode with a plan and a confirm button per key.

## Testing

Provider calls use the global `fetch`, which tests replace. Covered: ordering, dry-run makes no write calls, non-live and honey keys are skipped, request shape per provider, failure fallback to guided, re-verification result, log never holds a secret.

Not testable here: real accounts. The request shapes follow each provider's documented API; a first run against a throwaway token is a manual check.
