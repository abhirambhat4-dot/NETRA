import { cn } from '@/lib/utils'
import { toneStyles, type Tone } from '@/lib/tones'

interface MeterBarProps {
  value: number // 0–max
  max?: number
  tone?: Tone
  className?: string
}

/** Thin horizontal meter for risk / volume in list rows. */
export function MeterBar({ value, max = 100, tone = 'accent', className }: MeterBarProps) {
  const pct = Math.max(0, Math.min(100, (value / max) * 100))
  return (
    <div className={cn('h-1 w-full overflow-hidden rounded-full bg-foreground/6', className)}>
      <div
        className={cn('h-full rounded-full transition-[width] duration-700 ease-out', toneStyles[tone].solid)}
        style={{ width: `${pct}%` }}
      />
    </div>
  )
}
