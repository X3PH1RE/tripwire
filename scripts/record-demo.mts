// Records the whole product on a real repository: screenshots, a video and a GIF of the web app, plus terminal
// screenshots of the CLI rendered from its real output.
//
//   npm run dev                  # in another terminal: app on :5173, API on :3001
//   npm run demo:record          # writes docs/demo/
//
// Uses the Edge or Chrome already installed (no browser download). DEMO_REPO overrides the scanned repository.
import { execFileSync, spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import gifenc from "gifenc";
import { chromium, type Browser, type Page } from "playwright-core";
import pngjs from "pngjs";

const { GIFEncoder, applyPalette, quantize } = gifenc;
const { PNG } = pngjs;

const root = fileURLToPath(new URL("..", import.meta.url));
const OUT = join(root, "docs", "demo");
const SHOTS = join(OUT, "screenshots");
const APP = process.env.APP_URL ?? "http://localhost:5173";
const API = process.env.API_URL ?? "http://localhost:3001/api";
const TARGET = process.env.DEMO_REPO ?? "https://github.com/OWASP/NodeGoat";
const BUNDLE = join(root, "action", "tripwire.mjs").split("\\").join("/");
const VIEW = { width: 1440, height: 900 };
const GIF_WIDTH = 960;
const MAX_GIF_FRAMES = 40;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const api = async (path: string, body?: unknown) => (await fetch(`${API}${path}`, { method: body === undefined ? "GET" : "POST", headers: { "Content-Type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) })).json() as Promise<any>;

// ---------------------------------------------------------------- web app

const frames: Buffer[] = [];
const grab = async (page: Page) => void frames.push(await page.screenshot({ type: "png" }));

/** Waits while capturing frames, so animations (blast radius, rotation) show up in the GIF. */
async function hold(page: Page, ms: number, every = 800) {
  for (let t = 0; t < ms; t += every) {
    await grab(page);
    await sleep(Math.min(every, ms - t));
  }
}

async function until(page: Page, what: string, test: () => Promise<boolean>, timeoutMs: number) {
  const end = Date.now() + timeoutMs;
  let n = 0;
  while (Date.now() < end) {
    if (await test()) return;
    if (n++ % 3 === 0) await grab(page);
    await sleep(1000);
  }
  throw new Error(`timed out waiting for ${what}`);
}

const snap = async (page: Page, name: string) => {
  await page.screenshot({ path: join(SHOTS, `${name}.png`), type: "png" });
  await grab(page);
  console.log(`  ${name}.png`);
};
const panel = async (page: Page, text: string, name: string) => {
  const el = page.locator(`section:has-text("${text}")`).last();
  await el.scrollIntoViewIfNeeded();
  await sleep(400);
  await el.screenshot({ path: join(SHOTS, `${name}.png`), type: "png" });
  console.log(`  ${name}.png`);
};

async function demoTour(page: Page) {
  console.log("Live demo (fake acme-shop world)");
  await api("/reset", {});
  await page.goto(APP);
  await page.getByRole("button", { name: "Live demo" }).click();
  await page.waitForSelector(".react-flow__node");
  await hold(page, 2000);
  await snap(page, "01-demo-attack-graph");

  await page.locator(".react-flow__node", { hasText: "DATABASE_URL" }).first().click();
  await hold(page, 3600);
  await snap(page, "02-blast-radius");

  await page.getByRole("button", { name: "Simulate provider breach" }).click();
  await hold(page, 3200);
  await snap(page, "03-provider-breach");

  await page.getByRole("button", { name: "Plant tripwires" }).click();
  await hold(page, 2400);
  await snap(page, "04-honey-secrets-planted");

  await page.getByRole("button", { name: "Simulate attacker" }).click();
  await hold(page, 2800);
  await snap(page, "05-tripwire-alert");

  await page.getByRole("button", { name: /Contain/ }).click();
  await until(page, "containment", async () => (await api("/state")).containment.status === "done", 60_000);
  await hold(page, 1600);
  await snap(page, "06-contained");

  await page.getByRole("button", { name: "Simulate new CVE" }).click();
  await until(page, "CVE response", async () => ["done", "failed"].includes((await api("/state")).cve.status), 90_000);
  await hold(page, 1800);
  await snap(page, "07-cve-patch");
  await api("/reset", {});
}

async function scanTour(page: Page) {
  console.log(`Scan a repo (${TARGET})`);
  await api("/real/clear", {});
  await page.getByRole("button", { name: "Scan a repo" }).click();
  await page.getByPlaceholder(/github\.com/).fill(TARGET);
  const verify = page.getByLabel("Check if keys are live");
  if (!(await verify.isChecked())) await verify.check();
  await hold(page, 1400);
  await snap(page, "08-scan-a-repo");

  await page.getByRole("button", { name: "Scan repository" }).click();
  await hold(page, 2400);
  await snap(page, "09-scan-progress");
  await until(page, "scan to finish", async () => ["done", "failed"].includes((await api("/state")).scan.status), 300_000);
  const state = (await api("/state")).scan;
  if (state.status === "failed") throw new Error(`scan failed: ${state.error}`);
  await hold(page, 2200);
  await snap(page, "10-scan-results");

  await page.locator('aside button:has-text("in code")').first().click();
  await hold(page, 3600);
  await snap(page, "11-finding-blast-radius");

  await panel(page, "Secrets found", "12-secrets-found");
  await panel(page, "Containment", "13-containment-plan");
  await page.locator('section:has-text("Containment") summary').first().click();
  await panel(page, "Containment", "14-containment-runbook");
  await panel(page, "Vulnerable dependencies", "15-vulnerable-dependencies");
  await hold(page, 1200);
  await api("/real/clear", {});
}

// ---------------------------------------------------------------- terminal screenshots

const COLORS: Record<string, string> = { "31": "#fb7185", "32": "#4ade80", "33": "#fbbf24", "36": "#22d3ee" };
const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

/** ANSI colours to HTML; only the codes Tripwire emits. */
function ansi(text: string): string {
  let out = "";
  let open = 0;
  for (const part of text.split(/(\x1b\[[0-9;]*m)/)) {
    const m = part.match(/^\x1b\[([0-9;]*)m$/);
    if (!m) {
      out += esc(part);
      continue;
    }
    for (const code of m[1].split(";")) {
      if (code === "0" || code === "") out += "</span>".repeat(open), (open = 0);
      else if (code === "1") out += '<span style="font-weight:700;color:#fafafa">', open++;
      else if (code === "2") out += '<span style="opacity:.55">', open++;
      else if (COLORS[code]) out += `<span style="color:${COLORS[code]}">`, open++;
    }
  }
  return out + "</span>".repeat(open);
}

function terminalHtml(blocks: { cmd: string; out: string }[], title: string): string {
  const body = blocks.map((b) => `<span style="color:#4ade80">$</span> <span style="color:#fafafa">${esc(b.cmd)}</span>\n${ansi(b.out.trimEnd())}\n`).join("\n");
  return `<!doctype html><body style="margin:0;background:#0a0a0c;padding:28px">
<div id="term" style="width:1100px;background:#111114;border:1px solid #2a2a30;border-radius:12px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,.5)">
<div style="display:flex;align-items:center;gap:8px;padding:12px 16px;background:#16161a;border-bottom:1px solid #2a2a30"><i style="width:12px;height:12px;border-radius:50%;background:#ff5f57"></i><i style="width:12px;height:12px;border-radius:50%;background:#febc2e"></i><i style="width:12px;height:12px;border-radius:50%;background:#28c840"></i><span style="margin-left:12px;font:12px system-ui;color:#71717a">${esc(title)}</span></div>
<pre style="margin:0;padding:18px 22px;font:14px/1.55 'Cascadia Mono',Consolas,'SF Mono',monospace;color:#d4d4d8;white-space:pre-wrap;word-break:break-word">${body}</pre></div></body>`;
}

const run = (cmd: string, args: string[], cwd: string, env: NodeJS.ProcessEnv = {}) => {
  const r = spawnSync(cmd, args, { cwd, encoding: "utf8", env: { ...process.env, FORCE_COLOR: "1", ...env }, maxBuffer: 64 * 1024 * 1024 });
  return `${r.stdout ?? ""}${r.stderr ?? ""}`;
};
const tw = (args: string[], cwd: string) => run(process.execPath, [BUNDLE, ...args], cwd);

async function terminalShots(browser: Browser) {
  console.log("Command line (rendered from real output)");
  const work = mkdtempSync(join(tmpdir(), "tw-demo-"));
  const repo = join(work, TARGET.split("/").pop()!);
  const page = await (await browser.newContext({ viewport: { width: 1180, height: 900 }, deviceScaleFactor: 2 })).newPage();
  const scenes: Record<string, Scene> = {};
  const shot = async (name: string, title: string, blocks: { cmd: string; out: string }[]) => {
    scenes[name] = { title, blocks };
    await page.setContent(terminalHtml(blocks, title));
    await page.locator("#term").screenshot({ path: join(SHOTS, `${name}.png`), type: "png" });
    console.log(`  ${name}.png`);
  };
  try {
    const name = TARGET.split("/").slice(-2).join("/");
    execFileSync("git", ["clone", "--quiet", "--depth", "300", TARGET, repo], { stdio: "ignore" });

    await shot("cli-1-help", "tripwire", [{ cmd: "tripwire --help", out: tw(["--help"], root) }]);
    await shot("cli-2-scan", name, [{ cmd: `tripwire scan ${name} --history 300`, out: tw(["scan", repo, "--history", "300", "-q"], root) }]);
    await shot("cli-3-contain-dry-run", name, [{ cmd: `tripwire contain ${name}`, out: tw(["contain", repo, "-q"], root) }]);

    const before = tw(["baseline", repo], root);
    await shot("cli-4-baseline", name, [
      { cmd: "tripwire baseline", out: before },
      { cmd: "tripwire scan --skip-vulns", out: tw(["scan", repo, "--skip-vulns", "--history", "0", "-q"], root) },
    ]);

    // Pre-commit: a real hook, a real `git commit`.
    const hookRepo = join(work, "app");
    mkdirSync(hookRepo);
    const git = (...a: string[]) => run("git", ["-c", "user.name=demo", "-c", "user.email=demo@example.com", "-c", "core.autocrlf=false", ...a], hookRepo, { FORCE_COLOR: "1" });
    git("init", "-q", "-b", "main");
    writeFileSync(join(hookRepo, "README.md"), "# app\n");
    git("add", "-A");
    git("commit", "-qm", "init");
    writeFileSync(join(hookRepo, ".git", "hooks", "pre-commit"), `#!/bin/sh\nexec "${process.execPath.split("\\").join("/")}" "${BUNDLE}" scan --staged\n`, { mode: 0o755 });
    const fake = ["sk", "live", "x7Kq2mZ9vL4wT8nB3cR6yH1d"].join("_");
    writeFileSync(join(hookRepo, "billing.js"), `const stripe = require("stripe")("${fake}");\n`);
    git("add", "billing.js");
    const blocked = git("commit", "-m", "add billing");
    writeFileSync(join(hookRepo, "billing.js"), `const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);\n`);
    git("add", "billing.js");
    const passed = git("commit", "-m", "add billing");
    await shot("cli-5-pre-commit", "app", [
      { cmd: 'git commit -m "add billing"', out: blocked },
      { cmd: "# move the key to an environment variable, then commit again", out: "" },
      { cmd: 'git commit -m "add billing"', out: passed },
    ]);

    const bench = run(process.execPath, [join(root, "node_modules", "tsx", "dist", "cli.mjs"), join(root, "bench", "run.mts")], root, { FORCE_COLOR: "0" });
    await shot("cli-6-benchmark", "tripwire", [{ cmd: "npm run bench", out: bench.split("\n").slice(0, 9).join("\n") }]);

    // The same real output, animated: scan, plan containment, then a commit the hook refuses.
    await cliGif(browser, [scenes["cli-2-scan"], scenes["cli-3-contain-dry-run"], scenes["cli-5-pre-commit"]], join(OUT, "tripwire-cli.gif"));
  } finally {
    await page.context().close();
    rmSync(work, { recursive: true, force: true });
    try {
      execFileSync("git", ["checkout", "bench/RESULTS.md"], { cwd: root, stdio: "ignore" });
    } catch {
      // not tracked or already clean
    }
  }
}

// ---------------------------------------------------------------- GIF

function shrink(png: InstanceType<typeof PNG>, width: number) {
  const scale = png.width / width;
  const height = Math.round(png.height / scale);
  const data = new Uint8Array(width * height * 4);
  for (let y = 0; y < height; y++)
    for (let x = 0; x < width; x++) {
      const x0 = Math.floor(x * scale);
      const x1 = Math.max(x0 + 1, Math.floor((x + 1) * scale));
      const y0 = Math.floor(y * scale);
      const y1 = Math.max(y0 + 1, Math.floor((y + 1) * scale));
      let r = 0, g = 0, b = 0, n = 0;
      for (let yy = y0; yy < y1 && yy < png.height; yy++)
        for (let xx = x0; xx < x1 && xx < png.width; xx++) {
          const i = (yy * png.width + xx) * 4;
          r += png.data[i]; g += png.data[i + 1]; b += png.data[i + 2]; n++;
        }
      const o = (y * width + x) * 4;
      data[o] = r / n; data[o + 1] = g / n; data[o + 2] = b / n; data[o + 3] = 255;
    }
  return { data, width, height };
}

interface Shot {
  png: Buffer;
  /** Milliseconds this frame stays on screen. */
  delay: number;
}

function encodeGif(shots: Shot[], path: string, width: number) {
  const gif = GIFEncoder();
  for (const s of shots) {
    const img = shrink(PNG.sync.read(s.png), width);
    const palette = quantize(img.data, 256);
    gif.writeFrame(applyPalette(img.data, palette), img.width, img.height, { palette, delay: s.delay });
  }
  gif.finish();
  writeFileSync(path, gif.bytes());
  console.log(`  ${path.split(/[\\/]/).pop()} (${shots.length} frames, ${(gif.bytes().length / 1e6).toFixed(1)} MB)`);
}

function writeGif(path: string) {
  const step = Math.max(1, Math.ceil(frames.length / MAX_GIF_FRAMES));
  encodeGif(
    frames.filter((_, i) => i % step === 0).map((png) => ({ png, delay: 850 })),
    path,
    GIF_WIDTH,
  );
}

// ---------------------------------------------------------------- animated terminal GIF

interface Scene {
  title: string;
  blocks: { cmd: string; out: string }[];
}

/** Types each command, then reveals its real output in chunks, one scene after another, at a fixed frame size. */
async function cliGif(browser: Browser, scenes: Scene[], path: string) {
  const page = await (await browser.newContext({ viewport: { width: 1180, height: 1400 }, deviceScaleFactor: 1 })).newPage();
  try {
    // One fixed height for every frame (a GIF cannot change size): the tallest finished scene.
    let height = 0;
    for (const s of scenes) {
      await page.setContent(terminalHtml(s.blocks, s.title));
      height = Math.max(height, Math.ceil((await page.locator("#term").boundingBox())!.height));
    }
    const shots: Shot[] = [];
    const frame = async (title: string, blocks: Scene["blocks"], delay: number) => {
      await page.setContent(terminalHtml(blocks, title).replace('id="term" style="', `id="term" style="min-height:${height}px;`));
      shots.push({ png: await page.locator("#term").screenshot({ type: "png" }), delay });
    };
    for (const s of scenes) {
      for (let i = 0; i < s.blocks.length; i++) {
        const done = s.blocks.slice(0, i);
        const { cmd, out } = s.blocks[i];
        for (const frac of [0.3, 0.65, 1]) await frame(s.title, [...done, { cmd: `${cmd.slice(0, Math.ceil(cmd.length * frac))}█`, out: "" }], frac === 1 ? 450 : 140);
        const lines = out.trimEnd().split("\n");
        const chunks = Math.min(7, lines.length);
        for (let c = 1; c <= chunks; c++) {
          const last = c === chunks;
          await frame(s.title, [...done, { cmd, out: lines.slice(0, Math.ceil((lines.length * c) / chunks)).join("\n") }], last ? (i === s.blocks.length - 1 ? 2600 : 900) : 160);
        }
      }
    }
    encodeGif(shots, path, 900);
  } finally {
    await page.context().close();
  }
}

// ---------------------------------------------------------------- main

async function main() {
  for (const url of [APP, `${API}/state`]) {
    try {
      await fetch(url);
    } catch {
      throw new Error(`${url} is not reachable. Start the app first: npm run dev`);
    }
  }
  if ((await api("/state")).scan === undefined) throw new Error("unexpected API response");
  execFileSync(process.execPath, [join(root, "scripts", "build-cli.mjs")], { cwd: root, stdio: "ignore" });
  mkdirSync(SHOTS, { recursive: true });

  const launch = async () => {
    for (const channel of ["msedge", "chrome"] as const) {
      try {
        return await chromium.launch({ channel });
      } catch {
        // try the next one
      }
    }
    throw new Error("Needs Microsoft Edge or Google Chrome installed.");
  };
  const browser = await launch();
  // ONLY=terminal re-renders just the command-line screenshots (quick); the default records everything.
  if (process.env.ONLY === "terminal") {
    await terminalShots(browser);
    await browser.close();
    return;
  }
  const videoDir = mkdtempSync(join(tmpdir(), "tw-video-"));
  const context = await browser.newContext({ viewport: VIEW, colorScheme: "dark", recordVideo: { dir: videoDir, size: VIEW } });
  const page = await context.newPage();
  try {
    await demoTour(page);
    await scanTour(page);
  } finally {
    const video = page.video();
    await context.close();
    if (video) copyFileSync(await video.path(), join(OUT, "tripwire-tour.webm"));
    rmSync(videoDir, { recursive: true, force: true });
  }
  console.log("Video + GIF");
  console.log("  tripwire-tour.webm");
  writeGif(join(OUT, "tripwire-demo.gif"));

  await terminalShots(browser);
  await browser.close();
  console.log(`\nDone: ${OUT}`);
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
