import { useEffect, useState } from 'react'
import { ChevronLeft, ChevronRight, Lightbulb } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { usePrefersReducedMotion } from './reducedMotion'

const INSIGHTS = [
  'High severity does not always mean high risk. NETRA evaluates context.',
  'Asset criticality changes the meaning of a detection.',
  'Every containment action should be explainable and authorized.',
  'Cyber Memory allows previous security decisions to inform future response.',
  'A MITRE ATT&CK mapping explains how an attack progresses, not just that it happened.',
]

const INTERVAL_MS = 8000

/** Auto-rotates unless the viewer interacts, hovers, focuses it, or prefers reduced motion. */
export function SecurityInsight() {
  const reduced = usePrefersReducedMotion()
  const [index, setIndex] = useState(0)
  const [paused, setPaused] = useState(false)
  const [userDriven, setUserDriven] = useState(false)

  const auto = !reduced && !paused && !userDriven

  useEffect(() => {
    if (!auto) return
    const id = window.setInterval(() => setIndex((i) => (i + 1) % INSIGHTS.length), INTERVAL_MS)
    return () => window.clearInterval(id)
  }, [auto])

  function go(next: number) {
    setUserDriven(true)
    setIndex((next + INSIGHTS.length) % INSIGHTS.length)
  }

  return (
    <section
      aria-labelledby="security-insight-title"
      aria-roledescription="carousel"
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
      onFocus={() => setPaused(true)}
      onBlur={() => setPaused(false)}
      className="surface-panel relative overflow-hidden rounded-2xl p-5 sm:p-6"
    >
      <span aria-hidden className="absolute inset-y-6 left-0 w-px bg-linear-to-b from-transparent via-cyan/60 to-transparent" />

      <div className="flex items-center justify-between gap-3">
        <h2 id="security-insight-title" className="flex items-center gap-2 font-mono text-[10px] font-medium tracking-[0.18em] text-cyan uppercase">
          <Lightbulb className="size-3.5" /> Security insight
        </h2>
        <span className="font-mono text-[10px] text-muted-foreground tabular-nums">
          {String(index + 1).padStart(2, '0')} / {String(INSIGHTS.length).padStart(2, '0')}
        </span>
      </div>

      <p
        key={index}
        aria-live={userDriven ? 'polite' : 'off'}
        className="mt-4 min-h-[3.5rem] text-[15px] leading-relaxed text-foreground/90 motion-safe:animate-in motion-safe:fade-in-0 motion-safe:slide-in-from-bottom-1 motion-safe:duration-500 sm:text-base"
      >
        {INSIGHTS[index]}
      </p>

      <div className="mt-4 flex items-center justify-between gap-3">
        <div className="flex items-center gap-1.5">
          {INSIGHTS.map((_, i) => (
            <button
              key={i}
              type="button"
              onClick={() => go(i)}
              aria-label={`Show insight ${i + 1}`}
              aria-current={i === index}
              className="grid h-6 place-items-center px-0.5"
            >
              <span className={cn('block h-1 rounded-full transition-all', i === index ? 'w-5 bg-cyan' : 'w-2 bg-white/15 hover:bg-white/30')} />
            </button>
          ))}
        </div>
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="icon-sm" onClick={() => go(index - 1)} aria-label="Previous insight">
            <ChevronLeft />
          </Button>
          <Button variant="ghost" size="icon-sm" onClick={() => go(index + 1)} aria-label="Next insight">
            <ChevronRight />
          </Button>
        </div>
      </div>
    </section>
  )
}
