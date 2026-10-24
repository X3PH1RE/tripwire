import type { ReactNode } from "react";

export function Panel({ eyebrow, title, accent = "bg-zinc-500", right, children }: { eyebrow: string; title?: ReactNode; accent?: string; right?: ReactNode; children: ReactNode }) {
  return (
    <section className="rounded-xl border border-line bg-ink-900 p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-[0.14em] text-zinc-500">
            <span className={`h-1.5 w-1.5 rounded-full ${accent}`} />
            {eyebrow}
          </div>
          {title && <h3 className="mt-1.5 truncate text-[17px] font-semibold tracking-tight text-zinc-50">{title}</h3>}
        </div>
        {right}
      </div>
      {children}
    </section>
  );
}
