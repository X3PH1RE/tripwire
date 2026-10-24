# Security policy

## Reporting a vulnerability

Please report security issues privately through [GitHub security advisories](https://github.com/X3PH1RE/tripwire/security/advisories/new) rather than a public issue. Include the version, what you did, and what you expected. Expect an acknowledgement within a few days.

## What Tripwire does with your credentials

Knowing this matters more for a secret scanner than for most tools:

- **Scanning** reads files and git history locally (or in a temporary clone for a remote URL). Secret values are masked in every report, comment and the web UI, and are never sent to any LLM.
- **`--verify`** sends each found key to its own provider (read-only "who am I" calls). Only use it on repositories you are entitled to test keys for.
- **`tripwire contain --apply`** calls provider revocation APIs for keys confirmed live. It is a dry run unless you pass `--apply`, and it logs every action (never the secret) to `~/.tripwire/contain-log.jsonl`.
- **Honey secrets** use the Canarytokens service; the decoy is stored in `~/.tripwire/honey.json`.

## Trust model of the CI check

- In a pull request, `.tripwireignore` and `.tripwire-baseline.json` are read from the **base** branch, never from the change under review, and a change that edits either is called out in the report. A pull request cannot switch the check off by editing its own configuration.
- An inline `tripwire:ignore` / `gitleaks:allow` comment still hides a secret by default (that is what it is for), but every hidden secret is listed in the report. Set `inline-ignore: false` (Action) or `--no-inline-ignore` (CLI) to make such comments hide nothing.
- Every tracked file is scanned wherever it sits (`build/`, `dist/`, `vendor/`, minified bundles, source maps, lockfiles, SVG, files up to 20 MB, lines of any length). Symlinks are not followed, so a repository cannot make the scanner read files outside itself.
- The web app's API has no login. It listens on 127.0.0.1 only and rejects any request whose Host or Origin is not local, so another machine or another website cannot make it scan your disk or revoke keys. `HOST` and `ALLOWED_HOSTS` opt in to anything else.

## Known limits

- A pattern scanner cannot see a secret that is assembled at run time (`"AKIA" + suffix`), split across lines or files, or encoded more than two layers deep.
- Baseline entries are an unsalted SHA-256 of the rule, file and value. They never contain the secret, but a low-entropy secret (a short password) could be guessed from its hash if the baseline file is public.
- `tripwire contain --apply` has been tested against stubbed provider responses, not live accounts.

## Supply chain

The Action and CLI run a single committed bundle (`action/`) built from this repository by `npm run build:cli`. Pin the Action to a full commit SHA if you need to review what you run. The npm package (`tripwire-scan`) contains only that bundle, the license and the notices.
