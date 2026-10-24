# Tripwire

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

1. Shallow-clones the repo (last 300 commits; `SCAN_HISTORY_COMMITS` to change).
2. Scans every text file for secrets: AWS, GitHub, GitLab, Stripe, Slack, Google, OpenAI, Anthropic, SendGrid, Twilio, npm, private keys, database URLs with passwords, plus high-entropy `*_KEY/TOKEN/SECRET` assignments. Placeholders and `${VAR}` references are ignored.
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

Exits `1` when something blocks, `0` when clean, `2` on usage errors. By default every secret still in the code blocks; with `--diff <base>` only secrets added since `<base>` block, so existing debt doesn't fail every PR. Secrets found only in history are reported but never block (rotate them). Other flags: `--history <n>`, `--skip-vulns`, `--no-fail-secrets`, `--json <file|->`, `--markdown <file>`. Inside this repo: `npm run scan -- <target>`.

False positives: add `tripwire:ignore` (or `gitleaks:allow`) on the line, or globs to `.tripwireignore` (`fixtures/`, `*.test.ts`, `docs/**/*.md`).

### GitHub Action

Copy [examples/tripwire.yml](examples/tripwire.yml) to `.github/workflows/tripwire.yml`. On pull requests it fails only when the PR adds a secret, annotates the offending lines, and keeps one summary comment up to date with the secrets, what each unlocks, and vulnerable dependencies. On pushes it fails while any secret is in the code. Inputs: `path`, `fail-on-secrets`, `fail-on-vulns`, `comment`, `history`, `token`. Outputs: `secrets`, `new-secrets`, `vulns`, `failed`.

The action runs `action/action.mjs`, a self-contained bundle (no install step). Rebuild it with `npm run build:cli` after changing `server/real` or `server/cli`.

## API

`GET /api/state`, `GET /api/events` (SSE), `POST /api/reset`, `GET /api/scan?target=`, `GET /api/blast/:id`, `POST /api/honey/plant`, `POST /api/honey/attack`, `POST /api/breach {provider}`, `POST /api/contain`, `POST /api/cve`, `POST /api/real/scan {target}`, `POST /api/real/fix {keys?}`, `POST /api/real/clear`.

See [docs/PLAN.md](docs/PLAN.md) for the build plan.
