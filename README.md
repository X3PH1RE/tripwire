<p align="center">
  <img src="assets/banner.svg" alt="Tripwire: find the leaked key, see what it unlocks, kill it" width="100%" />
</p>

A repo security agent with a visual attack graph. It scans a repo for secrets, maps their blast radius, plants honey secrets as tripwires, contains a breach by rotating keys highest-danger first, and responds to new CVEs by opening a real patch PR.

All credentials in the demo world are fake (`tw_fake_<provider>_<random>`).

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
    rev: v1.0.0
    hooks:
      - id: tripwire
```

### Live keys and real reach (`--verify`)

With `--verify` (CLI), `verify: true` (Action) or **Check if keys are live** (UI), Tripwire makes one read-only "who am I" call per key to its own provider: AWS STS + IAM, GitHub, Stripe, Slack, OpenAI, Anthropic, SendGrid and npm. Each secret is marked `live`, `revoked` or `unverified`. For live keys the graph shows what the provider says the key reaches (AWS account and IAM policies, GitHub repos it can write to, Stripe account, Slack workspace and scopes) instead of a guess from the variable name. Revoked keys and Tripwire's own decoys stop failing the check. Off by default because it uses the found key.

### Detection engine

Rules live in data, not code. `server/detect/` loads two packs: Tripwire's own rules (`rules/tripwire.ts`, written from each provider's token format) and the Gitleaks default pack (`rules/gitleaks.json`, 219 rules, MIT), regenerated with `npm run import:gitleaks`. Tripwire's rules win when both match the same value, and the generic `generic-api-key` rule is replaced by Tripwire's own.

- **Fast.** One Aho-Corasick pass per file finds every rule keyword at once; regexes only run on lines that contain one.
- **Fewer false positives.** Per-rule entropy, allowlists (regexes, stopwords, paths), placeholders, UUIDs, digests, password hashes (bcrypt, argon2), version strings, file names, `%s` templates and attribute chains are all rejected. GitHub tokens are checked against their built-in checksum and JWTs must have a real header.
- **Confidence.** Every finding is `high` (fixed provider format), `medium` or `low` (name-based). Examples in docs and tests, and database URLs whose password is a tutorial default (`password`, `root`, `changeme`), report at `low`. `--min-confidence high` fails the check only on `high`; the rest are still listed.
- **Hidden secrets.** Values inside base64, URL-encoding and hex (up to two layers) are decoded and rescanned, including Kubernetes `password: <base64>`. Those findings say how they were found. Private keys count only as a full BEGIN..END block, including keys escaped inside a JSON string.
- **Baseline.** `tripwire baseline` writes `.tripwire-baseline.json`: hashes of the current findings, never the secrets. Those findings stay in the report but stop failing the check; a new secret still fails. `--no-baseline` ignores the file.

#### Benchmark

```bash
npm run bench:fetch   # downloads Gitleaks 8.30.1 into bench/.cache (once)
npm run bench         # scores Tripwire and Gitleaks, writes bench/RESULTS.md
npm run bench -- --gate   # exit 1 if Tripwire drops below 95% precision or recall
```

[bench/RESULTS.md](bench/RESULTS.md) has the latest numbers. The corpus (`bench/corpus.mts`) is written by this project, so it favours Tripwire's own rules: treat it as a regression gate and a parity check, not an independent ranking. Add a case whenever a real repo produces a miss or a false positive; several of the filters above came from scanning Flask, Django and NodeGoat.

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
