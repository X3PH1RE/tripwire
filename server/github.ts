const API = "https://api.github.com";

export const demoRepo = () => process.env.DEMO_REPO ?? "X3PH1RE/acme-shop-demo";
export const hasToken = () => !!process.env.GITHUB_TOKEN;

export async function gh<T = any>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    method: init.method ?? "GET",
    headers: {
      Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "Content-Type": "application/json",
    },
    body: init.body ? JSON.stringify(init.body) : undefined,
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`GitHub ${init.method ?? "GET"} ${path}: ${res.status}`);
  return (res.status === 204 ? undefined : await res.json()) as T;
}

export const PATCH_BRANCH_PREFIX = "tripwire/cve-patch-";

export async function openPatchPr(opts: { file: string; from: string; to: string; title: string; body: string }): Promise<{ url: string; number: number }> {
  if (!hasToken()) throw new Error("GITHUB_TOKEN not set");
  const repo = demoRepo();
  const main = await gh(`/repos/${repo}/git/ref/heads/main`);
  const branch = `${PATCH_BRANCH_PREFIX}${Date.now()}`;
  await gh(`/repos/${repo}/git/refs`, { method: "POST", body: { ref: `refs/heads/${branch}`, sha: main.object.sha } });
  const file = await gh(`/repos/${repo}/contents/${opts.file}?ref=${branch}`);
  const content = Buffer.from(file.content, "base64").toString("utf8");
  if (!content.includes(opts.from)) throw new Error(`${opts.file} does not contain ${opts.from}`);
  await gh(`/repos/${repo}/contents/${opts.file}`, {
    method: "PUT",
    body: {
      message: `fix(api): bump ${opts.from} to ${opts.to}`,
      content: Buffer.from(content.replace(opts.from, opts.to)).toString("base64"),
      sha: file.sha,
      branch,
    },
  });
  const pr = await gh(`/repos/${repo}/pulls`, { method: "POST", body: { title: opts.title, body: opts.body, head: branch, base: "main" } });
  return { url: pr.html_url, number: pr.number };
}

/** Closes PRs opened by earlier runs and deletes their branches so the demo can repeat. */
export async function cleanupPatchPrs(): Promise<number> {
  if (!hasToken()) return 0;
  const repo = demoRepo();
  const prs = await gh<{ number: number; head: { ref: string } }[]>(`/repos/${repo}/pulls?state=open&per_page=100`);
  const ours = prs.filter((p) => p.head.ref.startsWith(PATCH_BRANCH_PREFIX));
  for (const p of ours) {
    await gh(`/repos/${repo}/pulls/${p.number}`, { method: "PATCH", body: { state: "closed" } });
    await gh(`/repos/${repo}/git/refs/heads/${p.head.ref}`, { method: "DELETE" }).catch(() => undefined);
  }
  return ours.length;
}

export async function repoInfo(repo: string): Promise<{ default_branch: string; permissions?: { push?: boolean } }> {
  return gh(`/repos/${repo}`);
}

export async function getFile(repo: string, path: string, ref: string): Promise<string> {
  const file = await gh(`/repos/${repo}/contents/${path}?ref=${encodeURIComponent(ref)}`);
  return Buffer.from(file.content, "base64").toString("utf8");
}

/** Commits several files on a new branch in one commit and opens a PR against `base`. */
export async function openMultiFilePr(repo: string, opts: { base: string; branch: string; files: { path: string; content: string }[]; message: string; title: string; body: string }): Promise<{ url: string; number: number }> {
  const head = await gh(`/repos/${repo}/git/ref/heads/${opts.base}`);
  const parent = await gh(`/repos/${repo}/git/commits/${head.object.sha}`);
  const tree = await gh(`/repos/${repo}/git/trees`, { method: "POST", body: { base_tree: parent.tree.sha, tree: opts.files.map((f) => ({ path: f.path, mode: "100644", type: "blob", content: f.content })) } });
  const commit = await gh(`/repos/${repo}/git/commits`, { method: "POST", body: { message: opts.message, tree: tree.sha, parents: [parent.sha] } });
  await gh(`/repos/${repo}/git/refs`, { method: "POST", body: { ref: `refs/heads/${opts.branch}`, sha: commit.sha } });
  const pr = await gh(`/repos/${repo}/pulls`, { method: "POST", body: { title: opts.title, body: opts.body, head: opts.branch, base: opts.base } });
  return { url: pr.html_url, number: pr.number };
}
