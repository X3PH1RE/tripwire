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

## API

`GET /api/state`, `GET /api/events` (SSE), `POST /api/reset`, `GET /api/scan?target=`, `GET /api/blast/:id`, `POST /api/honey/plant`, `POST /api/honey/attack`, `POST /api/breach {provider}`, `POST /api/contain`, `POST /api/cve`.

See [docs/PLAN.md](docs/PLAN.md) for the build plan.
