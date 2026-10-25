<p align="center">
  <img src="assets/banner.svg" alt="Tripwire: find the leaked key, see what it unlocks, kill it" width="100%" />
</p>

## Why this exists

Attackers keep going after secrets: API keys, tokens, database passwords. The last few days made it concrete (as of October 25, 2026; some of these are still developing, so follow the links rather than this summary):

- **Railway, October 21.** The cloud platform said an attacker "may have accessed encrypted environment variables and, for some of them, obtained the decrypted contents." Railway urged all users to revoke and rotate their keys, said the impact is limited to a subset of users, and had not disclosed the cause or how many were affected. ([TechCrunch](https://techcrunch.com/2026/10/22/developer-platform-railway-urges-all-users-to-revoke-secret-keys-after-cyberattack/), [GitGuardian](https://blog.gitguardian.com/railway-october-2026-incident-environment-variables/))
- **PHP, October 20 to 21.** Two critical flaws, CVE-2026-109618 and CVE-2026-109619 (CVSS v4.0 9.2, unauthenticated remote code execution), leaked before the patch and were fixed a day early in PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35. Wiz showed a separate memory-disclosure path that, per [Huntress](https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities), "could expose passwords, tokens, API keys, and certificates". Huntress had not seen exploitation on its own systems when it wrote that. ([PHP advisory](https://www.php.net/))
- **LiteLLM, October 21.** A malicious version 1.107.0 was published to PyPI and Docker. It is an infostealer aimed at cloud credentials, LLM provider API keys, SSH and GPG keys. The same package had an earlier compromise in March. ([The Register](https://www.theregister.com/security/2026/10/21/litellm-supply-chain-attack-hoovers-up-passwords-and-secrets/5304548))
- **Vercel, April.** An attacker who compromised a third-party AI tool (Context.ai) reached a Vercel employee's account and decrypted the non-sensitive environment variables of a limited subset of customers; Vercel said such values "should be treated as potentially exposed and rotated as a priority". ([Vercel's bulletin](https://examples.vercel.com/kb/bulletin/vercel-april-2026-security-incident))
- **The background rate.** GitGuardian counted 29 million new hardcoded secrets in public GitHub commits in 2025, a 34% rise, and found 64% of secrets confirmed valid in 2022 still exploitable four years later. ([The Hacker News](https://thehackernews.com/2026/03/the-state-of-secrets-sprawl-2026-9.html))

What these have in common is the day after. Whether the cause is a platform breach, a language runtime bug or a poisoned package, the questions are the same: **which secrets did we have, which of them still work, what does each one unlock, and how fast can we kill them?** Most teams answer from memory, and rotate in whatever order they remember.

Tripwire is built for that day, and for the commit before it:

- **Find** every secret in the code and in git history, including ones deleted long ago but never rotated.
- **Check** which are live, by asking each provider, instead of assuming.
- **Show** what each one reaches, so rotation goes highest blast radius first.
- **Revoke** what can be revoked by API (GitHub, Slack, GitLab, AWS) and give ordered runbooks for the rest, as a dry run until you confirm.
- **Stop** the next one earlier, with a pre-commit hook and a pull-request check that a pull request cannot switch off.

What it does not do, so you are not misled: Tripwire scans repositories. It cannot see secrets that live only inside a platform's dashboard (Railway, Vercel), it does not prevent a platform breach, and it does not detect an outdated PHP runtime. In an incident like Railway's it helps you find and rotate the credentials that also exist in your code and history, and it gives you the method to work through the rest. Its revocation calls are tested against stubbed responses, not live accounts, and on provider breadth it is level with Gitleaks and well short of TruffleHog (see [Benchmark](#benchmark)).

A repo security agent with a visual attack graph. It scans a repo for secrets, maps their blast radius, plants honey secrets as tripwires, contains a breach by rotating keys highest-danger first, and responds to new CVEs by opening a real patch PR.

All credentials in the demo world are fake (`tw_fake_<provider>_<random>`).

## See it working

Recorded end to end on a real public repository, [OWASP/NodeGoat](https://github.com/OWASP/NodeGoat) (an intentionally vulnerable demo app), by driving the actual app with Playwright. Re-record everything with `npm run dev` in one terminal and `npm run demo:record` in another; it writes to [docs/demo/](docs/demo).

![Tripwire tour](docs/demo/tripwire-demo.gif)

[Download the full-length video (WebM, 25 MB)](https://github.com/X3PH1RE/tripwire/releases/download/v1.0.1/tripwire-tour.webm)

### Scan a real repository

Paste a GitHub URL, tick **Check if keys are live**, and scan. Everything on this page except the "Live demo" section below is real output from NodeGoat.

| | |
| --- | --- |
| ![Scan form](docs/demo/screenshots/08-scan-a-repo.png)<br>**1. Point it at a repo.** URL or `owner/name`, optionally checking each found key with its provider. | ![Progress](docs/demo/screenshots/09-scan-progress.png)<br>**2. Clone, scan files and history, look up dependencies.** Private repos use `GITHUB_TOKEN` or your `gh` login. |
| ![Results](docs/demo/screenshots/10-scan-results.png)<br>**3. Results.** 2 secrets and 131 vulnerable dependencies (OSV.dev), with the attack graph of what each secret unlocks. | ![Blast radius](docs/demo/screenshots/11-finding-blast-radius.png)<br>**4. Click a secret** to trace its blast radius. |

| | |
| --- | --- |
| ![Secrets found](docs/demo/screenshots/12-secrets-found.png)<br>**Secrets found.** Masked previews, file and line, rule, and a confidence badge. | ![Vulnerable dependencies](docs/demo/screenshots/15-vulnerable-dependencies.png)<br>**Vulnerable dependencies**, with the fixed version and a one-click fix PR for GitHub repos. |
| ![Containment plan](docs/demo/screenshots/13-containment-plan.png)<br>**Containment plan**, ordered by what each key can reach. Nothing is revoked until you confirm. | ![Runbook](docs/demo/screenshots/14-containment-runbook.png)<br>**Runbook** for keys Tripwire cannot revoke by API: dashboard link and ordered steps. |

NodeGoat's keys are not live, so there is nothing to revoke here and the plan shows the manual route. Automatic revocation (GitHub, Slack, GitLab, AWS) is covered by tests against stubbed provider responses, not shown on a live key.

### Live demo: a simulated incident

The **Live demo** tab plays a breach against a fake company (`acme-shop`, all credentials fake). It is a simulation by design; the zero-day step replays instead of opening a pull request unless `GITHUB_TOKEN` is set.

| | |
| --- | --- |
| ![Attack graph](docs/demo/screenshots/01-demo-attack-graph.png)<br>**Attack graph** of services, secrets and what they unlock. | ![Blast radius](docs/demo/screenshots/02-blast-radius.png)<br>**Blast radius** of one leaked database URL, hop by hop, to production. |
| ![Breach](docs/demo/screenshots/03-provider-breach.png)<br>**Provider breach.** Every secret hosted there turns red and the exposure spreads. | ![Honey secrets](docs/demo/screenshots/04-honey-secrets-planted.png)<br>**Honey secrets** planted as tripwires next to the real ones. |
| ![Tripwire alert](docs/demo/screenshots/05-tripwire-alert.png)<br>**A decoy is used.** The alert names the file, and the real secrets beside it jump in risk. | ![Contained](docs/demo/screenshots/06-contained.png)<br>**Contain.** Rotated highest risk first, with before and after values and a timer. |
| ![CVE patch](docs/demo/screenshots/07-cve-patch.png)<br>**New CVE.** The affected service is found and a patch is prepared. | |

### Command line

Rendered from the real output of the commands shown, on the same repository.

| | |
| --- | --- |
| ![scan](docs/demo/screenshots/cli-2-scan.png)<br>**`tripwire scan`**: secrets, what they unlock, vulnerable dependencies, and a pass/fail exit code for CI. | ![contain](docs/demo/screenshots/cli-3-contain-dry-run.png)<br>**`tripwire contain`**: a dry-run plan; add `--apply` to revoke what can be revoked. |
| ![pre-commit](docs/demo/screenshots/cli-5-pre-commit.png)<br>**Pre-commit hook.** A real `git commit` is refused while it adds a key, and passes once the key is gone. | ![baseline](docs/demo/screenshots/cli-4-baseline.png)<br>**`tripwire baseline`** accepts existing findings (as hashes) so only new secrets fail. |
| ![benchmark](docs/demo/screenshots/cli-6-benchmark.png)<br>**`npm run bench`**: precision and recall on the labeled corpus, next to Gitleaks. | ![help](docs/demo/screenshots/cli-1-help.png)<br>**`tripwire --help`**. |

## Run

```bash
npm install
cp .env.example .env.local   # optional: add GITHUB_TOKEN for the real PR beat
npm run dev                  # server :3001, web http://localhost:5173
```

## Demo beats

| Button | What happens |
| --- | --- |
| Simulate breach (provider) | Secrets hosted on that provider go red; the compromise spreads along graph edges. |
| Click any secret | Blast radius animates hop by hop with a plain-English explanation. |
| Plant tripwires | Four decoy secrets are written into the runtime env and CI files. |
| Simulate attacker | A decoy is used; alert with file, time, source IP; real secrets in the same file jump in danger. |
| Contain | Exposed secrets are rotated highest danger first, with before/after values and a timer. |
| Simulate new CVE | Finds the PHP service in the affected range and opens a real version-bump PR on the demo repo, left open for review. |
| Run full demo | Plays all beats in order. |
| Reset | Restores runtime files, graph, scores and timeline, and closes PRs from earlier runs. |

`demo-world/` is a read-only template; the app only mutates the gitignored `runtime/` copy.

## Scan a real repo

Switch to **Scan a repo**, paste a GitHub URL or `owner/name`, and press **Scan repository**. Tripwire:

1. Shallow-clones the repo (last 300 commits; `SCAN_HISTORY_COMMITS` to change). Private GitHub repos are cloned with `GITHUB_TOKEN`, or with your `gh auth login` session if that is unset. Big repositories can take minutes on a slow connection; the limit is 10 minutes (`CLONE_TIMEOUT_MS`).
2. Scans every text file for secrets with 230+ provider rules (see Detection engine below), database URLs with passwords, and high-entropy `*_KEY/TOKEN/SECRET` assignments. Placeholders and `${VAR}` references are ignored.
3. Scans git history, so secrets that were deleted but are still in old commits show up marked `history`.
4. Builds the attack graph from the repo: folders with a manifest become services, findings become secrets, key names and token types decide what each secret unlocks, and `${{ secrets.X }}` in workflows are linked through repo write access.
5. Checks dependencies (`package-lock.json`, `package.json`, `requirements*.txt`, `go.mod`, `composer.lock`, `Gemfile.lock`) against [OSV.dev](https://osv.dev).
6. **Open fix PR** bumps direct npm and pinned Python dependencies (and same-major npm transitive deps via `overrides`) on a `tripwire/deps-*` branch and opens a PR for review. This needs `GITHUB_TOKEN` with Contents + Pull requests write on that repo.

Secret values are never sent to the browser; the UI only shows masked previews. Nothing is sent to any LLM. Breach, honey-secret and rotation beats are simulations and only exist in **Live demo** mode.

## Use it in a project

### CLI

```bash
npx github:X3PH1RE/tripwire scan .                 # current repo
npx github:X3PH1RE/tripwire scan owner/repo        # any GitHub repo
npx github:X3PH1RE/tripwire scan . --diff origin/main --fail-on-vulns high
```

Exits `1` when something blocks, `0` when clean, `2` on usage errors. `tripwire baseline [path]` accepts the current findings (see below). By default every secret still in the code blocks; with `--diff <base>` only secrets added since `<base>` block, so existing debt doesn't fail every PR. Secrets found only in history are reported but never block (rotate them). Other flags: `--min-confidence <low|medium|high>`, `--no-baseline`, `--history <n>`, `--skip-vulns`, `--no-fail-secrets`, `--json <file|->`, `--markdown <file>`. Inside this repo: `npm run scan -- <target>`.

False positives: add `tripwire:ignore` (or `gitleaks:allow`) on the line, or globs to `.tripwireignore` (`fixtures/`, `*.test.ts`, `docs/**/*.md`).

### Pre-commit hook

Catch a secret before it is ever committed:

```bash
npx github:X3PH1RE/tripwire install-hook     # writes .git/hooks/pre-commit (respects core.hooksPath)
```

The hook runs `tripwire scan --staged`: only lines you have `git add`ed, no history and no dependency lookup, so it takes a fraction of a second. A commit that adds a secret is refused; `.tripwireignore`, `tripwire:ignore` comments and the baseline all apply. Bypass once with `git commit --no-verify` or `TRIPWIRE_SKIP=1 git commit`. `install-hook` never overwrites a hook it did not write (`--force` to replace, `--remove` to uninstall). If `tripwire` is not on your PATH, the hook fetches it with `npx`.

Using the [pre-commit](https://pre-commit.com) framework instead? Add this to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/X3PH1RE/tripwire
    rev: v1.0.2
    hooks:
      - id: tripwire
```

### Live keys and real reach (`--verify`)

With `--verify` (CLI), `verify: true` (Action) or **Check if keys are live** (UI), Tripwire makes one read-only "who am I" call per key to its own provider: AWS STS + IAM, GitHub, Stripe, Slack, OpenAI, Anthropic, SendGrid and npm. Each secret is marked `live`, `revoked` or `unverified`. For live keys the graph shows what the provider says the key reaches (AWS account and IAM policies, GitHub repos it can write to, Stripe account, Slack workspace and scopes) instead of a guess from the variable name. Revoked keys and Tripwire's own decoys stop failing the check. Off by default because it uses the found key.

### Detection engine

Rules live in data, not code. `server/detect/` loads two packs: Tripwire's own rules (`rules/tripwire.ts`, written from each provider's token format) and the Gitleaks default pack (`rules/gitleaks.json`, 219 rules, MIT), regenerated with `npm run import:gitleaks`. Tripwire's rules win when both match the same value, and the generic `generic-api-key` rule is replaced by Tripwire's own.

- **Fast.** One Aho-Corasick pass per file finds every rule keyword at once; regexes only run on lines that contain one.
- **Fewer false positives.** Per-rule entropy, allowlists (regexes, stopwords, paths), placeholders, UUIDs, digests, password hashes (bcrypt, argon2), version strings, file names, `%s` templates and attribute chains are all rejected. GitHub tokens are checked against their built-in checksum and JWTs must have a real header.
- **Confidence.** Every finding is `high` (fixed provider format), `medium` or `low` (name-based). Name-based matches in docs and test files, and database URLs whose password is a tutorial default (`password`, `root`, `changeme`), report at `low`; provider-format tokens in test files and docs rank `medium` instead of `high`. A key the provider confirms live always counts as `high`. `--min-confidence high` fails the check only on `high`; the rest are still listed.
- **Hidden secrets.** Values inside base64, URL-encoding and hex (up to two layers) are decoded and rescanned, including Kubernetes `password: <base64>`. Those findings say how they were found. Private keys count only as a full BEGIN..END block, including keys escaped inside a JSON string.
- **Baseline.** `tripwire baseline` writes `.tripwire-baseline.json`: hashes of the current findings, never the secrets. Those findings stay in the report but stop failing the check; a new secret still fails. `--no-baseline` ignores the file.

#### Benchmark

```bash
npm run bench:fetch   # downloads Gitleaks 8.30.1 into bench/.cache (once)
npm run bench         # scores Tripwire and Gitleaks, writes bench/RESULTS.md
npm run bench -- --gate   # exit 1 if Tripwire drops below 95% precision or recall
```

[bench/RESULTS.md](bench/RESULTS.md) has the latest numbers. The corpus (`bench/corpus.mts`) is written by this project, so it favours Tripwire's own rules: treat it as a regression gate and a parity check, not an independent ranking. Add a case whenever a real repo produces a miss or a false positive; several of the filters above came from scanning Flask, Django and NodeGoat.

Because that corpus is ours, there is a second benchmark on data we did not write: `npm run bench:coverage` fetches TruffleHog's detector tests (743 providers with example credentials) and counts how many providers each tool recognises at all. Tripwire is level with Gitleaks there (347 and 351 of 743, see [bench/COVERAGE.md](bench/COVERAGE.md)) and recognises well under half of TruffleHog's providers, so on breadth it does not beat either; the case for Tripwire is the engine's false-positive filtering, the CI trust model, and what happens after a key is found (verify, blast radius, containment), not the number of providers.

### Containment (`tripwire contain`)

```bash
npx github:X3PH1RE/tripwire contain .            # dry run: verifies keys, prints the plan, changes nothing
npx github:X3PH1RE/tripwire contain . --apply    # revokes every live key it can, then re-checks each with its provider
```

Contain means revoke; it does not issue replacements or update your CI or vault. Keys are ordered by what they reach, highest first. Only keys the provider confirmed live are ever revoked automatically; unverified keys, already-revoked keys and Tripwire's own decoys are never touched.

| Revoked by Tripwire | How |
| --- | --- |
| GitHub tokens | GitHub's credential-revocation endpoint |
| Slack tokens | `auth.revoke` |
| GitLab personal access tokens | self-revocation (gitlab.com) |
| AWS access keys | deactivated, not deleted (`UpdateAccessKey`), so it can be switched back on; the undo command is printed and logged. Needs `iam:UpdateAccessKey` on the key's own user. |

Everything else (Stripe, OpenAI, Anthropic, SendGrid, npm, Google, Twilio, databases, SSH keys) gets an ordered runbook with the dashboard link, because those providers have no safe self-service revoke API. If an automatic revoke fails, that key falls back to its runbook and the rest of the plan continues. A key counts as revoked only if the provider rejects it afterwards; one that still works is reported `still-live`. With `--apply` the exit code is `1` while any live key is left standing, including ones that need manual action.

Each action is appended to `~/.tripwire/contain-log.jsonl` (time, provider, fingerprint, outcome, undo command) and never contains a secret. In the UI, scan with **Check if keys are live**, then use the **Containment** panel: each revoke needs a second click to confirm. `POST /api/real/contain {apply, ids?}` does nothing destructive unless `apply` is exactly `true`.

The revoke request shapes follow each provider's documented API and are covered by tests against stubbed responses. They have not been run against live accounts: try a throwaway token first.

### Honey secrets

```bash
npx github:X3PH1RE/tripwire honey create --email you@example.com --plant owner/repo   # opens a PR that plants the decoy
npx github:X3PH1RE/tripwire honey check                                               # exits 1 if any decoy was used
```

A honey secret is a real AWS key from [Canarytokens](https://canarytokens.org) with no permissions. Any use of it (a scraper, a leaked clone, an insider) is reported with the source IP, location, client and the AWS call tried: by email, in `honey check`, and live in the UI's **Honey secrets** panel (the server polls every minute). `--plant` opens a PR adding the decoy, but GitHub push protection blocks AWS-format keys on most repos (public repos by default); then place the printed decoy yourself where GitHub doesn't scan (CI/CD variables, a server `.env`, an S3 backup, an internal wiki). Decoys are stored locally in `~/.tripwire/honey.json`; scans recognise them and never call AWS with them.

### GitHub Action

Copy [examples/tripwire.yml](examples/tripwire.yml) to `.github/workflows/tripwire.yml` (it uses `X3PH1RE/tripwire@v1`; pin a full commit SHA if you want to review exactly what runs). On pull requests it fails only when the PR adds a secret, annotates the offending lines, and keeps one summary comment up to date with the secrets, what each unlocks, and vulnerable dependencies. On pushes it fails while any secret is in the code. Inputs: `path`, `fail-on-secrets`, `fail-on-vulns`, `comment`, `history`, `verify`, `min-confidence`, `baseline`, `token`. Outputs: `secrets`, `new-secrets`, `vulns`, `failed`.

The action runs `action/action.mjs`, a self-contained bundle (no install step). Rebuild it with `npm run build:cli` after changing `server/real` or `server/cli`.

## API

`GET /api/state`, `GET /api/events` (SSE), `POST /api/reset`, `GET /api/scan?target=`, `GET /api/blast/:id`, `POST /api/honey/plant`, `POST /api/honey/attack`, `POST /api/breach {provider}`, `POST /api/contain`, `POST /api/cve`, `POST /api/real/scan {target}`, `POST /api/real/fix {keys?}`, `POST /api/real/contain {apply, ids?}`, `POST /api/real/clear`.

See [docs/PLAN.md](docs/PLAN.md) for the build plan.
