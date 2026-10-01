const PIPELINE = [
  'EVENT',
  'CONTEXT',
  'CORRELATION',
  'RISK',
  'DECISION',
  'AUTHORIZATION',
  'CONTAINMENT',
  'MEMORY',
]

export function IntelligencePipeline() {
  return (
    <div className="relative overflow-hidden rounded-[28px] border border-border/80 bg-[linear-gradient(180deg,rgba(14,20,28,0.96),rgba(10,15,22,0.82))] p-4 shadow-[0_24px_80px_-40px_rgba(56,217,255,0.32)] sm:p-6">
      <div className="absolute inset-x-8 top-1/2 hidden h-px -translate-y-1/2 bg-[linear-gradient(90deg,rgba(56,217,255,0),rgba(56,217,255,0.6),rgba(56,217,255,0))] md:block" />
      <div className="relative grid gap-4 md:grid-cols-8">
        {PIPELINE.map((step, index) => (
          <div key={step} className="relative z-10 flex flex-col items-center text-center">
            <div className="flex items-center gap-2">
              <span className="flex size-10 items-center justify-center rounded-full border border-primary/40 bg-primary/10 text-[10px] font-medium tracking-[0.18em] text-primary shadow-[0_0_20px_rgba(56,217,255,0.22)]">
                {index + 1}
              </span>
            </div>
            <div className="mt-3 text-[10px] font-medium tracking-[0.2em] text-muted-foreground/90 uppercase sm:text-[11px]">
              {step}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
