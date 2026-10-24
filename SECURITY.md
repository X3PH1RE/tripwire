# Security policy

## Reporting a vulnerability

Please report security issues privately through [GitHub security advisories](https://github.com/X3PH1RE/tripwire/security/advisories/new) rather than a public issue. Include the version, what you did, and what you expected. Expect an acknowledgement within a few days.

## What Tripwire does with your credentials

Knowing this matters more for a secret scanner than for most tools:

- **Scanning** reads files and git history locally (or in a temporary clone for a remote URL). Secret values are masked in every report, comment and the web UI, and are never sent to any LLM.
- **`--verify`** sends each found key to its own provider (read-only "who am I" calls). Only use it on repositories you are entitled to test keys for.
- **`tripwire contain --apply`** calls provider revocation APIs for keys confirmed live. It is a dry run unless you pass `--apply`, and it logs every action (never the secret) to `~/.tripwire/contain-log.jsonl`.
- **Honey secrets** use the Canarytokens service; the decoy is stored in `~/.tripwire/honey.json`.

## Supply chain

The Action and CLI run a single committed bundle (`action/`) built from this repository by `npm run build:cli`. Pin the Action to a full commit SHA if you need to review what you run. The npm package (`tripwire-scan`) contains only that bundle, the license and the notices.
