# Tripwire: Build Plan for AI Coding Agents

A repo security agent with a visual attack graph. Built for a 12 hour hackathon and a 3 minute live demo.

## 1. What we are building

Tripwire is a web app that, for a dummy company, does four things on one screen:

1. Scans a repo for secrets and maps what each secret can reach (Breach Day Radar).
2. Plants fake secrets as tripwires and alerts when one is used (Honey Secrets).
3. Traces how far a leaked key can go and draws the attack path (Secret Blast Radius).
4. Responds to a new CVE by finding affected services and opening a patch PR (Zero-Day Responder).

Most of it is scripted so the demo works every single time. The one real action is the zero-day beat, where the agent opens an actual pull request on a real throwaway GitHub repo. No real credentials from any real account or provider, and no real rotation.

## 1b. Track fit (Devin Hacks Kochi)

Primary track: **2. Make the invisible visible.** Hidden secret exposure and blast radius are exactly what people miss, and the track says the interesting part is what happens after detection. That is our containment and patch PR beats.

Backup framing: **1. Kill the busywork.** Rotating leaked secrets and chasing CVE patches by hand is real busywork, and the agent finishes the job instead of just reporting it.

Not a fit: track 3 (works anyway) and track 4 (make room for play). Do not force them.

Pitch line: "After a breach, nobody knows what was exposed or how far it spreads. Tripwire makes it visible in seconds, then fixes it."

Because tracks 1 and 2 reward finishing the job, at least one action must be real, not mocked. That is the real pull request in Step 8. Check the official judging criteria and adjust the pitch if they weigh something we have not covered.

## 2. Ground rules for the agents

- Never use real credentials anywhere in the demo world. All keys are obviously fake (for example `FAKE_sk_live_...`).
- One exception: a GitHub fine-grained token scoped to the single throwaway demo repo (contents and pull requests write only). It lives in a server environment variable, is never committed, and is never shown on screen.
- Every incident is deterministic and triggered by a button. No live typing during the demo.
- Prefer fewer features that look great over more features that look rough.
- Build in the order of the steps below. Commit after each step so there is always a working version.
- After each step, run the app and confirm the "Done when" check before moving on.
- Keep the code simple and readable. No premature abstraction.
- One command to start everything (`npm run dev`), one click to reset the demo.

## 3. The demo we are building toward (3 minutes, 5 beats)

Every feature exists to serve one of these beats.

| Beat | Time | What happens on screen |
|------|------|------------------------|
| 1. Setup | 20s | Graph of the dummy company is already visible. One line of narration: "When a provider gets breached, every developer asks what we exposed and how bad it is." |
| 2. Breach | 40s | Click "Simulate: Railway breach". Exposed secrets turn red and the red spreads outward. Click the leaked database key and the attack path animates across the graph to production. |
| 3. Tripwire | 40s | Click "Simulate attacker" (or hand a judge a fake key). The decoy fires, an alert slides in with file, time and source. Danger scores rise on the real secrets stored in the same file. |
| 4. Contain | 40s | Click "Contain". Secrets rotate in order of danger. Nodes flip red to green with a progress counter. Ends on an all-green graph and a time-to-contain number. |
| 5. Zero-day | 30s | Click "Simulate new CVE". Vulnerable service highlights, the agent opens a real pull request on GitHub (switch to the browser tab to show it), and the timeline ticks from disclosed to found to patched. |

Closing line: "Breach to contained in under a minute, versus days by hand."

## 4. Tech stack

- Front end: React, TypeScript, Vite, Tailwind for styling.
- Graph: React Flow (preferred) or Cytoscape.js. Pick one in step 3 and stay with it.
- Animation: Framer Motion for UI, CSS transitions for node color changes.
- Back end: Node with Express (or Fastify) and TypeScript.
- Live updates: Server-Sent Events from backend to front end.
- Storage: one JSON file for the demo world plus in-memory state. No database needed.
- LLM: one API call wrapper used for plain-language explanations and PR text. Must have a canned fallback response for each call so the demo never depends on the network.

Suggested layout:

```
tripwire/
  demo-world/          # the fake company repo that gets scanned
    acme-shop/
      web/.env
      api/.env
      worker/.env
      .github/workflows/deploy.yml
    world.json         # nodes, secrets, and what unlocks what
  server/
    scanner.ts
    scoring.ts
    incidents.ts       # breach, honey, cve simulations
    rotation.ts
    llm.ts             # with canned fallbacks
    index.ts           # express + SSE
  web/
    src/
      components/Graph.tsx
      components/AlertFeed.tsx
      components/Timeline.tsx
      components/ControlBar.tsx
      state/store.ts
  README.md
```

## 5. Core data model

Define these types first and share them between server and web.

```ts
type NodeType = "repo" | "service" | "resource" | "secret" | "decoy";

interface GraphNode {
  id: string;
  type: NodeType;
  label: string;
  provider?: string;          // e.g. "railway", "aws", "stripe"
  sensitivity?: "low" | "medium" | "high" | "production";
  file?: string;              // for secrets: where it lives
  line?: number;
  version?: string;           // for services: runtime version, used by the CVE step
  status: "ok" | "exposed" | "attacked" | "rotating" | "rotated" | "patched";
  danger?: number;            // 0 to 100, computed
}

interface GraphEdge {
  id: string;
  from: string;
  to: string;
  kind: "stored_in" | "unlocks";
}

interface Incident {
  id: string;
  kind: "breach" | "honey" | "cve";
  at: number;                 // timestamp
  summary: string;
  affectedNodeIds: string[];
}
```

## 6. The demo world (dummy company "acme-shop")

Nodes to include:

- Services: web app, API, background worker, CI pipeline (GitHub Actions).
- Resources: Postgres database, storage bucket, payment provider account, production deploy target.
- Secrets (all fake): `DATABASE_URL` (provider railway), `STRIPE_KEY`, `CLOUD_ACCESS_KEY`, `DEPLOY_TOKEN`, `STORAGE_KEY`.

Chains that must exist so the blast radius view is impressive:

- `DATABASE_URL` unlocks the Postgres database.
- The database contains a table that stores `CLOUD_ACCESS_KEY` (stored_in edge from the database to that secret).
- `CLOUD_ACCESS_KEY` unlocks the storage bucket, which stores `DEPLOY_TOKEN`.
- `DEPLOY_TOKEN` unlocks the production deploy target.

So one leaked database URL chains to production in four hops. This is the hero path of the demo.

Write the fake `.env` and workflow files so a real pattern scanner would find the secrets. `world.json` holds the authoritative mapping so results are deterministic.

## 7. Build steps

Each step lists the task, what to build, and a "Done when" check. Hand them to the agents one at a time.

### Step 1: Demo world (about 1 hour)

Create the `demo-world/acme-shop` files and `world.json` as described in section 6.

Done when: `world.json` describes every node, every secret, and every unlock or stored_in link, and the fake files contain the secrets at known file and line positions.

### Step 2: Scanner (about 1.5 hours)

Build `scanner.ts`. It walks the demo repo, finds secret-looking strings using regex patterns (known key prefixes, `KEY=`/`TOKEN=` assignments) plus a Shannon entropy check for long random values. For each hit, look up the matching secret in `world.json` to attach what it unlocks.

Expose `GET /api/scan` returning secrets with file, line, provider and the resources each reaches.

Make the scanner accept either a local path or a cloned repo, so it can also run against the real demo repo used in Step 8.

Done when: the endpoint returns all five secrets with correct file, line, and reach, and the same scanner works on a freshly cloned copy of the demo repo.

### Step 3: Graph and danger scoring (about 2.5 hours)

Build the main screen. Dark theme, graph fills most of the viewport, control bar on top, alert feed on the right.

Danger score per secret, computed in `scoring.ts`:

- Base score from the highest sensitivity among reachable resources (production = 40, high = 30, medium = 15, low = 5).
- Plus 10 per additional reachable resource, up to 30.
- Plus 20 if the chain can reach production through stored secrets.
- Plus 15 if the secret's status is `exposed`.
- Cap at 100.

Color nodes by danger (green, amber, red) and show a small numeric badge on each secret.

Done when: the graph renders cleanly with no overlapping labels and every secret shows a score. Layout should be fixed or deterministic so it looks the same on every load.

### Step 4: Blast radius view (about 1.5 hours)

Clicking a secret computes all reachable nodes by walking `unlocks` and `stored_in` edges transitively, in order. Animate the path: highlight edges one hop at a time, about 400ms per hop, with a glowing pulse.

A side panel shows a plain-language explanation of the chain and the worst case. Generate it with the LLM, with a canned fallback for the hero path.

Done when: clicking `DEPLOY_TOKEN` or `DATABASE_URL` animates the multi-hop path ending at the production node, and the panel shows the explanation.

### Step 5: Honey secrets (about 1.5 hours)

"Plant tripwires" button inserts 3 to 4 fake decoy secrets into the demo env and CI files (actually write them to the files) and adds them to the graph as decoy nodes with a distinct style, for example dashed outline and a small trap icon.

"Simulate attacker" button picks a decoy and fires an event via SSE. The alert shows: decoy name, file it was planted in, timestamp, and a fake source (for example an IP and city). Then it raises the danger score of every real secret stored in the same file, with a visible score animation.

Done when: using a decoy triggers a slide-in alert and the neighboring real secrets visibly escalate.

### Step 6: Breach simulation (about 1 hour)

"Simulate provider breach" button with a provider dropdown (default railway). It marks every secret tied to that provider as `exposed`, turns them red, and spreads the red state outward along edges with a short delay per hop. Recompute danger scores.

Done when: one click produces the red spread animation and updated scores.

### Step 7: Containment (about 1.5 hours)

"Contain" button. The agent sorts exposed secrets by danger, highest first, and rotates each one:

1. Status goes to `rotating` (pulsing amber).
2. Generate a new fake value.
3. Update the value in the demo file.
4. Status goes to `rotated`, node flips green.
5. Progress counter ticks (for example 3 of 5).

For two secrets, show a before and after value in a small panel to make the rotation feel real. Show a large time-to-contain timer that stops when everything is green.

Done when: every red node ends green, the counter reaches complete, and the timer shows a final number.

### Step 8: Zero-day responder with a real pull request (about 1.5 hours)

This is the one real action in the demo, so build it carefully.

Setup: create a throwaway public GitHub repo (for example `acme-shop-demo`) containing the same files as the demo world, including a pinned runtime version in a Dockerfile or package file for each service.

Add a "Simulate new CVE" button using a PHP-style remote code execution vulnerability with a fake CVE ID and an affected version range. Then:

1. The agent checks each service's `version` against the affected range and highlights vulnerable ones on the graph.
2. It creates a branch on the demo repo through the GitHub API and commits a real version bump to the right file.
3. It opens a real pull request with an LLM-written title and description (canned fallback if the LLM call fails).
4. The UI shows the PR link and a timeline: Disclosed, Found, PR opened, Patched, each with a timestamp. The PR number and link are real and clickable.
5. On "Patched", the service node turns green with a badge. Either merge the PR automatically through the API, or leave it open and say a human reviews it. Pick one and stay consistent.

Fallbacks: if the GitHub API call fails, show a pre-opened PR from a dry run and mark the timeline as replayed. Write a small reset routine that closes the old PR and deletes the branch so the demo can run repeatedly.

Done when: one click opens a real PR on GitHub within 30 seconds, the link works, the timeline completes, and the vulnerable service turns green. Running reset and doing it again works.

### Step 9: Polish and rehearsal (remaining time, about 1.5 hours)

- Smooth animations for path drawing and color flips.
- Large readable counters and fonts, since this will be on a projector.
- One-click reset that returns files, graph, scores and timeline to the starting state.
- A "Run full demo" mode that is optional, but each button must also work on its own.
- Run the full five-beat demo three times in a row without reloading.
- Record a backup video of a clean run.

Done when: three clean consecutive runs, and the backup video exists.

## 8. Time budget (12 hours)

| Block | Hours |
|-------|-------|
| Demo world | 1.0 |
| Scanner | 1.5 |
| Graph and scoring | 2.5 |
| Blast radius view | 1.5 |
| Honey secrets | 1.5 |
| Breach simulation | 1.0 |
| Containment | 1.5 |
| Zero-day responder (real PR) | 1.5 |
| Polish and rehearsal | remainder |

If time runs short, cut in this order: the second realistic rotation first, then the LLM explanations (use canned text), then the honey secret alert polish. Do not cut the real pull request. It is what makes the demo fit the track.

## 9. Failure-proofing checklist

- [ ] Every LLM call has a canned fallback so the demo works offline.
- [ ] No step depends on a live external service.
- [ ] Reset button tested after each beat.
- [ ] Graph layout is deterministic.
- [ ] Fonts and contrast tested at projector scale.
- [ ] Backup video recorded.
- [ ] GitHub token works from the demo machine and is scoped to the demo repo only.
- [ ] Pre-opened fallback PR exists in case the API call fails on stage.
- [ ] PR reset routine tested so repeat runs start clean.
- [ ] Wi-Fi checked at the venue, with a phone hotspot as backup.
- [ ] Demo runs from a fresh clone with one command.

## 10. Demo day notes

- Present on a laptop, with a phone or second device ready if you hand a judge the fake key.
- Keep the narration short. Let the animations carry it.
- Lead with the problem (real recent breaches like Railway and the PHP flaws), then show the product.
- Be honest about what is real and what is scripted. Real: the scanner, scoring, graph logic, and the pull request opened on GitHub. Scripted: the breach, the honey key use, and the secret rotation.
- Have one answer ready for "what would make this production ready": real provider integrations for rotation, real scanning of connected repos via the GitHub API, and real honey token services that call home when used.

## 11. Prompt to start the agents

Paste this as the first message to your coding agent, then feed it one step at a time:

> You are building Tripwire, a demo web app described in this document. Read the whole document first. Then implement Step 1 only, following the ground rules in section 2 and the data model in section 5. When Step 1 meets its "Done when" check, commit with a clear message and stop. Wait for me to say "next" before starting the next step.