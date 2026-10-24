import { AnimatePresence, motion } from "framer-motion";
import type { Incident } from "../../../shared/types";

const TONE: Record<Incident["kind"], { dot: string; label: string }> = {
  breach: { dot: "bg-rose-500", label: "Breach" },
  honey: { dot: "bg-violet-400", label: "Tripwire" },
  cve: { dot: "bg-sky-400", label: "Vulnerability" },
  contain: { dot: "bg-emerald-400", label: "Response" },
  info: { dot: "bg-zinc-500", label: "Info" },
};

export function AlertFeed({ incidents }: { incidents: Incident[] }) {
  return (
    <section>
      <div className="mb-2 flex items-center justify-between px-1">
        <h3 className="text-[11px] font-medium uppercase tracking-[0.14em] text-zinc-500">Activity</h3>
        <span className="font-mono text-[11px] text-zinc-600">{incidents.length}</span>
      </div>
      {!incidents.length && <div className="rounded-xl border border-dashed border-line px-4 py-8 text-center text-[13px] text-zinc-500">No incidents. Everything is quiet.</div>}
      <div className="flex flex-col gap-2">
        <AnimatePresence initial={false}>
          {incidents.map((i) => (
            <motion.article
              key={i.id}
              layout
              initial={{ opacity: 0, x: 40 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0 }}
              transition={{ type: "spring", stiffness: 260, damping: 28 }}
              className="rounded-xl border border-line bg-ink-900 p-3.5"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="flex items-center gap-2 text-[10px] font-medium uppercase tracking-[0.14em] text-zinc-500">
                  <span className={`h-1.5 w-1.5 rounded-full ${TONE[i.kind].dot}`} />
                  {TONE[i.kind].label}
                </span>
                <span className="font-mono text-[11px] text-zinc-600">{new Date(i.at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</span>
              </div>
              <h4 className="mt-1.5 text-[14px] font-semibold tracking-tight text-zinc-100">{i.title}</h4>
              <p className="mt-1 text-[13px] leading-relaxed text-zinc-400">{i.summary}</p>
              {i.details && (
                <dl className="mt-2.5 grid grid-cols-[88px_1fr] gap-y-1 rounded-lg bg-ink-950/60 px-3 py-2 text-[12px]">
                  {i.details.map((d) => (
                    <div key={d.label} className="contents">
                      <dt className="text-zinc-500">{d.label}</dt>
                      <dd className="truncate font-mono text-zinc-300">{d.value}</dd>
                    </div>
                  ))}
                </dl>
              )}
            </motion.article>
          ))}
        </AnimatePresence>
      </div>
    </section>
  );
}
