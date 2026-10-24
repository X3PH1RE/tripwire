import { AnimatePresence, motion } from "framer-motion";
import type { Incident } from "../../../shared/types";

const TONE: Record<Incident["kind"], string> = {
  breach: "border-red-500 bg-red-950/70",
  honey: "border-fuchsia-400 bg-fuchsia-950/70",
  cve: "border-sky-400 bg-sky-950/70",
  contain: "border-emerald-400 bg-emerald-950/70",
  info: "border-slate-600 bg-slate-900",
};

export function AlertFeed({ incidents }: { incidents: Incident[] }) {
  return (
    <section className="flex flex-col gap-2">
      <h3 className="text-xs uppercase tracking-widest text-slate-400">Alerts</h3>
      {!incidents.length && <p className="text-slate-500">All quiet. No incidents yet.</p>}
      <AnimatePresence initial={false}>
        {incidents.map((i) => (
          <motion.article
            key={i.id}
            layout
            initial={{ opacity: 0, x: 120 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0 }}
            transition={{ type: "spring", stiffness: 220, damping: 24 }}
            className={`rounded-xl border-l-4 p-3 ${TONE[i.kind]}`}
          >
            <div className="flex items-baseline justify-between gap-2">
              <h4 className="text-lg font-bold text-slate-50">{i.title}</h4>
              <span className="font-mono text-xs text-slate-400">{new Date(i.at).toLocaleTimeString()}</span>
            </div>
            <p className="mt-1 text-[15px] leading-snug text-slate-200">{i.summary}</p>
            {i.details && (
              <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-sm">
                {i.details.map((d) => (
                  <div key={d.label} className="contents">
                    <dt className="text-slate-400">{d.label}</dt>
                    <dd className="font-mono text-slate-100">{d.value}</dd>
                  </div>
                ))}
              </dl>
            )}
          </motion.article>
        ))}
      </AnimatePresence>
    </section>
  );
}
