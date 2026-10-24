import { motion } from "framer-motion";
import { useState } from "react";
import type { ContainResult, ContainStep, DemoState, Finding, RealScan, Severity, VulnPackage } from "../../../shared/types";
import { post } from "../api";
import { Panel } from "./ui";
import { fmt } from "./useNow";

const SEV: Record<Severity, string> = {
  CRITICAL: "bg-rose-500/15 text-rose-300 ring-rose-500/30",
  HIGH: "bg-orange-500/15 text-orange-300 ring-orange-500/30",
  MODERATE: "bg-amber-500/10 text-amber-200 ring-amber-500/25",
  LOW: "bg-zinc-500/10 text-zinc-300 ring-zinc-500/25",
  UNKNOWN: "bg-zinc-500/10 text-zinc-400 ring-zinc-500/20",
};

const VERIFY: Record<string, string> = {
  live: "bg-rose-500/20 text-rose-200 ring-rose-500/40",
  revoked: "bg-emerald-500/10 text-emerald-300 ring-emerald-500/25",
  honey: "bg-violet-500/10 text-violet-300 ring-violet-500/25",
  unverified: "bg-zinc-500/10 text-zinc-400 ring-zinc-500/20",
};

const pill = "rounded-md px-1.5 py-0.5 font-mono text-[10px] font-medium ring-1 ring-inset";

const STEPS: { key: RealScan["status"]; label: string }[] = [
  { key: "cloning", label: "Clone repository" },
  { key: "secrets", label: "Scan files for secrets" },
  { key: "history", label: "Scan git history" },
  { key: "verify", label: "Check keys with providers" },
  { key: "vulns", label: "Check dependencies (OSV.dev)" },
];
const ORDER = ["cloning", "secrets", "history", "verify", "vulns", "done"];

export function ScanPanel({ scan }: { scan: RealScan }) {
  const at = ORDER.indexOf(scan.status);
  const failedAt = scan.filesScanned ? 1 : 0;
  const detail = (k: RealScan["status"]) =>
    k === "secrets" && scan.filesScanned ? `${scan.filesScanned} files` : k === "history" && scan.commitsScanned ? `${scan.commitsScanned} commits` : k === "vulns" && scan.status === "done" ? `${scan.vulns.length} vulnerable` : k === "verify" && at > 3 ? `${scan.findings.filter((f) => f.verify?.status === "live").length} live` : "";
  return (
    <Panel
      eyebrow="Repository scan"
      accent={scan.status === "failed" ? "bg-rose-500" : scan.status === "done" ? "bg-emerald-400" : "bg-sky-400 animate-pulse"}
      title={<span className="font-mono text-[15px]">{scan.repo ?? scan.target}</span>}
      right={scan.finishedAt && scan.startedAt ? <span className="font-mono text-[11px] text-zinc-500">{fmt(scan.finishedAt - scan.startedAt)}</span> : undefined}
    >
      <ol className="mt-3 space-y-2">
        {STEPS.filter((s) => s.key !== "verify" || scan.verify).map((s) => {
          const i = ORDER.indexOf(s.key);
          const done = scan.status === "done" || (at > i && scan.status !== "failed") || (scan.status === "failed" && i < failedAt);
          const active = scan.status === s.key;
          return (
            <li key={s.key} className="flex items-center gap-2.5 text-[13px]">
              <span className={`flex h-4 w-4 items-center justify-center rounded-full ${done ? "bg-emerald-500/15 text-emerald-300" : active ? "bg-sky-500/15" : "bg-white/5"}`}>
                {done ? (
                  <svg viewBox="0 0 24 24" className="h-2.5 w-2.5" fill="none" stroke="currentColor" strokeWidth={3}><path d="M5 12l5 5L20 7" /></svg>
                ) : (
                  <span className={`h-1.5 w-1.5 rounded-full ${active ? "animate-pulse bg-sky-400" : "bg-zinc-600"}`} />
                )}
              </span>
              <span className={done || active ? "text-zinc-200" : "text-zinc-500"}>{s.label}</span>
              <span className="ml-auto font-mono text-[11px] text-zinc-500">{detail(s.key)}</span>
            </li>
          );
        })}
      </ol>
      {scan.error && <div className="mt-3 rounded-lg border border-rose-500/20 bg-rose-500/5 px-3 py-2 text-[12px] text-rose-200/90">{scan.error}</div>}
    </Panel>
  );
}

function FindingRow({ f, onSelect }: { f: Finding; onSelect: (id: string) => void }) {
  return (
    <button
      onClick={() => f.nodeId && onSelect(f.nodeId)}
      className="w-full rounded-lg border border-line bg-ink-850 p-3 text-left transition hover:border-line-strong disabled:cursor-default"
      disabled={!f.nodeId}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="truncate font-mono text-[13px] font-medium text-zinc-100">{f.variable ?? f.ruleLabel}</span>
        <span className="flex shrink-0 gap-1">
          {f.verify && <span className={`${pill} ${VERIFY[f.verify.status]}`}>{f.verify.status}</span>}
          {f.baselined && <span className={`${pill} bg-zinc-500/10 text-zinc-300 ring-zinc-500/25`} title="Accepted in .tripwire-baseline.json">baselined</span>}
          {f.confidence && f.confidence !== "high" && <span className={`${pill} bg-sky-500/10 text-sky-300 ring-sky-500/25`} title="Name-based or example-context match: more likely a false positive than a provider-format token">{f.confidence} confidence</span>}
          {f.via && <span className={`${pill} bg-violet-500/10 text-violet-300 ring-violet-500/25`} title="The value was hidden inside an encoded string">{f.via}</span>}
          <span className={`${pill} ${f.inHead ? "bg-rose-500/10 text-rose-300 ring-rose-500/25" : "bg-amber-500/10 text-amber-300 ring-amber-500/25"}`}>{f.inHead ? "in code" : "history"}</span>
        </span>
      </div>
      <div className="mt-1 flex items-center justify-between gap-2 text-[11px] text-zinc-500">
        <span className="truncate font-mono">
          {f.file}:{f.line}
        </span>
        <span className="shrink-0">{f.ruleLabel}</span>
      </div>
      <div className="mt-1.5 truncate font-mono text-[11px] text-zinc-400">{f.preview}</div>
      {f.verify?.status === "live" && (
        <div className="mt-2 rounded-md border border-rose-500/20 bg-rose-500/5 px-2 py-1.5 text-[11px] leading-relaxed text-rose-100/90">
          <div>
            Works right now as <span className="font-mono">{f.verify.identity}</span>
          </div>
          {f.verify.access?.map((a) => (
            <div key={a.label} className="text-rose-200/70">
              → {a.label}
              {a.detail ? <span className="text-zinc-500"> · {a.detail}</span> : null}
            </div>
          ))}
        </div>
      )}
      {f.verify && f.verify.status !== "live" && f.verify.note && <div className="mt-1.5 text-[11px] text-zinc-500">{f.verify.note}</div>}
      {!f.inHead && <div className="mt-1.5 text-[11px] leading-relaxed text-amber-200/80">Deleted from the code but still in commit {f.commit}. Anyone who clones the repo has it. Rotate it.</div>}
    </button>
  );
}

export function FindingsPanel({ scan, onSelect }: { scan: RealScan; onSelect: (id: string) => void }) {
  const history = scan.findings.filter((f) => !f.inHead).length;
  return (
    <Panel
      eyebrow="Secrets found"
      accent={scan.findings.length ? "bg-rose-500" : "bg-emerald-400"}
      title={scan.findings.length ? `${scan.findings.length} exposed secret${scan.findings.length === 1 ? "" : "s"}` : "No secrets found"}
      right={history ? <span className={`${pill} bg-amber-500/10 text-amber-300 ring-amber-500/25`}>{history} only in history</span> : undefined}
    >
      {scan.findings.length > 0 && (
        <div className="mt-3 flex flex-col gap-2">
          {scan.findings.slice(0, 30).map((f) => (
            <FindingRow key={f.id} f={f} onSelect={onSelect} />
          ))}
          {scan.findings.length > 30 && <div className="text-center text-[12px] text-zinc-500">+{scan.findings.length - 30} more</div>}
        </div>
      )}
      {!scan.findings.length && <p className="mt-2 text-[13px] text-zinc-400">No known token formats or high-entropy assignments in the files or the last {scan.commitsScanned} commits.</p>}
    </Panel>
  );
}

function VulnRow({ v }: { v: VulnPackage }) {
  return (
    <div className="rounded-lg border border-line bg-ink-850 p-3">
      <div className="flex items-center justify-between gap-2">
        <span className="truncate font-mono text-[13px] text-zinc-100">
          {v.name}
          <span className="text-zinc-500">@{v.version}</span>
        </span>
        <span className={`${pill} shrink-0 ${SEV[v.severity]}`}>{v.severity.toLowerCase()}</span>
      </div>
      <div className="mt-1 flex items-center justify-between gap-2 text-[11px] text-zinc-500">
        <span className="truncate">
          {v.ecosystem} · {v.direct ? "direct" : "transitive"} · {v.advisories.length} advisor{v.advisories.length === 1 ? "y" : "ies"}
        </span>
        {v.fixed && <span className={`shrink-0 font-mono ${v.fixable ? "text-emerald-300" : "text-zinc-400"}`}>→ {v.fixed}</span>}
      </div>
      <div className="mt-1.5 truncate text-[12px] text-zinc-400">
        <span className="font-mono text-zinc-500">{v.advisories[0].id}</span> {v.advisories[0].summary}
      </div>
    </div>
  );
}

export function VulnPanel({ scan }: { scan: RealScan }) {
  const fixable = scan.vulns.filter((v) => v.fixable);
  const counts = (["CRITICAL", "HIGH", "MODERATE", "LOW"] as Severity[]).map((s) => [s, scan.vulns.filter((v) => v.severity === s).length] as const).filter(([, n]) => n);
  const fix = scan.fix;
  return (
    <Panel eyebrow="Vulnerable dependencies" accent={scan.vulns.length ? "bg-sky-400" : "bg-emerald-400"} title={scan.vulns.length ? `${scan.vulns.length} vulnerable package${scan.vulns.length === 1 ? "" : "s"}` : "No known vulnerabilities"}>
      {counts.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {counts.map(([s, n]) => (
            <span key={s} className={`${pill} ${SEV[s]}`}>
              {n} {s.toLowerCase()}
            </span>
          ))}
        </div>
      )}
      {scan.vulns.length > 0 && (
        <div className="mt-3">
          {fix.status === "done" && fix.prUrl ? (
            <motion.a initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} href={fix.prUrl} target="_blank" rel="noreferrer" className="flex items-center gap-3 rounded-lg border border-emerald-500/25 bg-emerald-500/5 px-3 py-2.5 hover:border-emerald-500/40">
              <svg viewBox="0 0 24 24" className="h-4 w-4 text-emerald-300" fill="none" stroke="currentColor" strokeWidth={2}><circle cx="6" cy="6" r="2" /><circle cx="6" cy="18" r="2" /><circle cx="18" cy="18" r="2" /><path d="M6 8v8M18 16V9a3 3 0 0 0-3-3h-4" /></svg>
              <span className="text-[13px] text-zinc-100">Fix PR #{fix.prNumber}</span>
              <span className="text-[12px] text-zinc-500">{fix.packages?.length} packages</span>
              <span className="ml-auto text-[12px] text-emerald-300">Open on GitHub ↗</span>
            </motion.a>
          ) : (
            <button
              disabled={!fixable.length || !scan.repo || fix.status === "running"}
              onClick={() => post("/real/fix")}
              className="flex h-9 w-full items-center justify-center gap-2 rounded-lg bg-zinc-100 text-[13px] font-medium text-zinc-900 transition hover:bg-white disabled:cursor-not-allowed disabled:opacity-40"
            >
              {fix.status === "running" ? "Opening PR…" : fixable.length ? `Open fix PR · ${new Set(fixable.map((v) => v.name)).size} packages` : "No automatic fixes available"}
            </button>
          )}
          {fix.status === "failed" && <div className="mt-2 rounded-lg border border-rose-500/20 bg-rose-500/5 px-3 py-2 text-[12px] text-rose-200/90">{fix.note}</div>}
          {!scan.repo && <div className="mt-2 text-[11px] text-zinc-500">Fix PRs are available for GitHub repositories.</div>}
        </div>
      )}
      {scan.vulns.length > 0 && (
        <div className="mt-3 flex flex-col gap-2">
          {scan.vulns.slice(0, 8).map((v) => (
            <VulnRow key={v.key} v={v} />
          ))}
          {scan.vulns.length > 8 && <div className="text-center text-[12px] text-zinc-500">+{scan.vulns.length - 8} more</div>}
        </div>
      )}
    </Panel>
  );
}

export function HoneyPanel({ demo }: { demo: DemoState }) {
  const [email, setEmail] = useState(() => localStorage.getItem("tw-honey-email") ?? "");
  const [error, setError] = useState("");
  const repo = demo.scan.repo;
  const tokens = demo.honeyTokens;
  const used = tokens.reduce((n, t) => n + t.hits.length, 0);
  const send = async (path: string, body?: unknown) => {
    setError("");
    const res = await fetch(`/api${path}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body ?? {}) });
    if (!res.ok) setError(((await res.json().catch(() => ({}))) as { error?: string }).error ?? `HTTP ${res.status}`);
  };
  return (
    <Panel
      eyebrow="Honey secrets"
      accent={used ? "bg-rose-500 animate-pulse" : tokens.length ? "bg-violet-400" : "bg-zinc-600"}
      title={used ? `Decoy used ${used} time${used === 1 ? "" : "s"}` : tokens.length ? `${tokens.length} decoy${tokens.length === 1 ? "" : "s"} armed` : "Plant a real decoy key"}
    >
      <p className="mt-1 text-[12px] leading-relaxed text-zinc-400">A real AWS key from Canarytokens with no permissions. Anyone who tries it is reported here and by email.</p>
      <div className="mt-3 flex gap-2">
        <input
          value={email}
          onChange={(e) => {
            setEmail(e.target.value);
            localStorage.setItem("tw-honey-email", e.target.value);
          }}
          placeholder="alert email"
          className="h-9 min-w-0 flex-1 rounded-lg border border-line bg-ink-850 px-3 font-mono text-[12px] text-zinc-200 outline-none placeholder:text-zinc-600 focus:border-line-strong"
        />
        <button
          disabled={!!demo.honeyBusy}
          onClick={() => send("/real/honey", { email: email || undefined, repo, plant: !!repo })}
          className="h-9 shrink-0 rounded-lg bg-zinc-100 px-3 text-[12px] font-medium text-zinc-900 transition hover:bg-white disabled:opacity-40"
        >
          {demo.honeyBusy ?? (repo ? `Plant in ${repo.split("/")[1]}` : "Create decoy")}
        </button>
      </div>
      {error && <div className="mt-2 rounded-lg border border-rose-500/20 bg-rose-500/5 px-3 py-2 text-[12px] text-rose-200/90">{error}</div>}
      {tokens.length > 0 && (
        <div className="mt-3 flex flex-col gap-2">
          {tokens.map((t) => (
            <div key={t.id} className={`rounded-lg border p-3 ${t.hits.length ? "border-rose-500/30 bg-rose-500/5" : "border-line bg-ink-850"}`}>
              <div className="flex items-center justify-between gap-2">
                <span className="truncate font-mono text-[12px] text-zinc-100">{t.accessKeyPreview}</span>
                <span className={`${pill} shrink-0 ${t.hits.length ? VERIFY.live : VERIFY.honey}`}>{t.hits.length ? `used ${t.hits.length}x` : "quiet"}</span>
              </div>
              <div className="mt-1 flex items-center justify-between gap-2 text-[11px] text-zinc-500">
                <span className="truncate">{t.repo ? `${t.repo}${t.file ? `:${t.file}` : ""}` : "not planted"}</span>
                {t.prUrl && (
                  <a href={t.prUrl} target="_blank" rel="noreferrer" className="shrink-0 text-violet-300 hover:text-violet-200">
                    planting PR ↗
                  </a>
                )}
              </div>
              {t.snippet && !t.hits.length && (
                <details className="mt-1.5 text-[11px] text-zinc-500">
                  <summary className="cursor-pointer hover:text-zinc-300">Show decoy to place by hand</summary>
                  <pre className="mt-1 overflow-x-auto rounded bg-ink-950 p-2 font-mono text-[10px] text-zinc-300">{t.snippet}</pre>
                </details>
              )}
              {t.hits.slice(0, 3).map((h) => (
                <div key={h.at} className="mt-1.5 font-mono text-[11px] text-rose-200/80">
                  {new Date(h.at).toLocaleString()} · {h.ip ?? "?"} {h.location ? `· ${h.location}` : ""} {h.action ? `· ${h.action}` : ""}
                </div>
              ))}
            </div>
          ))}
          <button onClick={() => send("/real/honey/check")} disabled={!!demo.honeyBusy} className="text-[11px] text-zinc-500 hover:text-zinc-300 disabled:opacity-40">
            Checked {tokens[0].lastCheck ? new Date(tokens[0].lastCheck).toLocaleTimeString() : "never"} · check now
          </button>
        </div>
      )}
    </Panel>
  );
}

const RESULT_STYLE: Record<ContainResult["status"], string> = {
  planned: "bg-amber-500/10 text-amber-300 ring-amber-500/25",
  guided: "bg-sky-500/10 text-sky-300 ring-sky-500/25",
  revoked: "bg-emerald-500/10 text-emerald-300 ring-emerald-500/25",
  failed: "bg-rose-500/20 text-rose-200 ring-rose-500/40",
  "still-live": "bg-rose-500/20 text-rose-200 ring-rose-500/40",
};

function ContainRow({ step, result, busy, onRevoke }: { step: ContainStep; result?: ContainResult; busy: boolean; onRevoke: (id: string) => void }) {
  // Revoking is destructive, so the first click only arms the button.
  const [armed, setArmed] = useState(false);
  const done = result?.status === "revoked";
  const open = !done && (step.mode === "guided" || result?.status === "failed" || result?.status === "still-live");
  return (
    <div className="rounded-lg border border-line bg-ink-850 p-3">
      <div className="flex items-center justify-between gap-2">
        <span className="truncate font-mono text-[13px] font-medium text-zinc-100">{step.label}</span>
        <span className="flex shrink-0 gap-1">
          <span className={`${pill} bg-zinc-500/10 text-zinc-300 ring-zinc-500/25`}>{step.provider}</span>
          {result && result.status !== "planned" ? <span className={`${pill} ${RESULT_STYLE[result.status]}`}>{result.status}</span> : <span className={`${pill} ${step.mode === "revoke" ? RESULT_STYLE.planned : RESULT_STYLE.guided}`}>{step.mode === "revoke" ? "can revoke" : "manual"}</span>}
        </span>
      </div>
      <div className="mt-1 truncate font-mono text-[11px] text-zinc-500">
        {step.file}:{step.line}
      </div>
      {step.reach.length > 0 && <div className="mt-1 text-[11px] text-zinc-400">Reaches {step.reach.slice(0, 3).join(", ")}{step.reach.length > 3 ? ` +${step.reach.length - 3}` : ""}</div>}
      {result && result.status !== "planned" && <div className="mt-1.5 text-[11px] leading-relaxed text-zinc-400">{result.note}</div>}
      {result?.reactivate && <div className="mt-1.5 break-all rounded-md bg-ink-950 px-2 py-1 font-mono text-[10px] text-zinc-400">undo: {result.reactivate}</div>}
      {step.mode === "revoke" && !done && (
        <button
          disabled={busy}
          onClick={() => (armed ? (setArmed(false), onRevoke(step.findingId)) : setArmed(true))}
          onBlur={() => setArmed(false)}
          className={`mt-2 h-8 w-full rounded-md text-[12px] font-medium transition disabled:cursor-not-allowed disabled:opacity-40 ${armed ? "bg-rose-500 text-white hover:bg-rose-400" : "bg-zinc-800 text-zinc-100 hover:bg-zinc-700"}`}
        >
          {armed ? `Confirm: revoke this ${step.provider} key now` : "Revoke…"}
        </button>
      )}
      {open && (
        <details className="mt-2 text-[11px] text-zinc-400">
          <summary className="cursor-pointer text-zinc-300">How to do it yourself</summary>
          {step.reason && <p className="mt-1.5 text-zinc-500">{step.reason}</p>}
          {step.guide.url && (
            <a href={step.guide.url} target="_blank" rel="noreferrer" className="mt-1.5 block truncate text-sky-300 hover:underline">
              {step.guide.url} ↗
            </a>
          )}
          <ol className="mt-1.5 list-decimal space-y-1 pl-4">
            {step.guide.steps.map((s) => (
              <li key={s}>{s}</li>
            ))}
          </ol>
        </details>
      )}
    </div>
  );
}

export function ContainRealPanel({ scan }: { scan: RealScan }) {
  const { contain } = scan;
  const [armedAll, setArmedAll] = useState(false);
  if (!contain.plan.length) return null;
  const auto = contain.plan.filter((s) => s.mode === "revoke" && contain.results.find((r) => r.findingId === s.findingId)?.status !== "revoked");
  const busy = contain.status === "running";
  const revoke = (ids?: string[]) => post("/real/contain", { apply: true, ids });
  const revoked = contain.results.filter((r) => r.status === "revoked").length;
  return (
    <Panel eyebrow="Containment" accent={auto.length ? "bg-amber-400" : "bg-emerald-400"} title={auto.length ? `${auto.length} live key${auto.length === 1 ? "" : "s"} Tripwire can revoke` : revoked ? `${revoked} key${revoked === 1 ? "" : "s"} revoked` : `${contain.plan.length} key${contain.plan.length === 1 ? "" : "s"} to handle`}>
      <p className="mt-2 text-[12px] leading-relaxed text-zinc-400">
        Ordered by what each key can reach. Nothing is revoked until you confirm, and each revocation is checked with the provider afterwards.
        {!scan.verify && " Run the scan with “Check if keys are live” to find which keys can be revoked automatically."}
      </p>
      <div className="mt-3 flex flex-col gap-2">
        {contain.plan.map((s) => (
          <ContainRow key={s.findingId} step={s} result={contain.results.find((r) => r.findingId === s.findingId)} busy={busy} onRevoke={(id) => revoke([id])} />
        ))}
      </div>
      {auto.length > 1 && (
        <button
          disabled={busy}
          onClick={() => (armedAll ? (setArmedAll(false), revoke()) : setArmedAll(true))}
          onBlur={() => setArmedAll(false)}
          className={`mt-3 h-9 w-full rounded-lg text-[13px] font-medium transition disabled:cursor-not-allowed disabled:opacity-40 ${armedAll ? "bg-rose-500 text-white hover:bg-rose-400" : "bg-zinc-100 text-zinc-900 hover:bg-white"}`}
        >
          {busy ? "Revoking…" : armedAll ? `Confirm: revoke all ${auto.length} keys now` : `Revoke all ${auto.length} live keys…`}
        </button>
      )}
      {contain.status === "failed" && <div className="mt-2 rounded-lg border border-rose-500/20 bg-rose-500/5 px-3 py-2 text-[12px] text-rose-200/90">{contain.note}</div>}
    </Panel>
  );
}
