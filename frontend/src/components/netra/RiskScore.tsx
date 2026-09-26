import { cn } from '@/lib/utils'
import { riskToSeverity, severityTone, toneStyles } from '@/lib/tones'

const SIZES = {
  sm: { box: 72, stroke: 6, value: 'text-xl', label: 'text-[9px]' },
  md: { box: 120, stroke: 8, value: 'text-4xl', label: 'text-[10px]' },
  lg: { box: 168, stroke: 10, value: 'text-5xl', label: 'text-[11px]' },
} as const

interface RiskScoreProps {
  score: number // 0–100
  size?: keyof typeof SIZES
  /** Show severity label under the number. */
  showLabel?: boolean
  className?: string
}

/** 270° risk gauge. Colour follows the severity band of the score. */
export function RiskScore({ score, size = 'md', showLabel = true, className }: RiskScoreProps) {
  const s = SIZES[size]
  const clamped = Math.max(0, Math.min(100, score))
  const severity = riskToSeverity(clamped)
  const tone = toneStyles[severityTone[severity]]

  const r = (s.box - s.stroke) / 2
  const circumference = 2 * Math.PI * r
  const arc = circumference * 0.75
  const filled = (arc * clamped) / 100

  return (
    <div
      className={cn('relative inline-grid place-items-center', className)}
      style={{ width: s.box, height: s.box }}
      role="meter"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={clamped}
      aria-label={`Risk score ${clamped} of 100, ${severity}`}
    >
      <svg width={s.box} height={s.box} className="absolute inset-0 rotate-135">
        <circle
          cx={s.box / 2}
          cy={s.box / 2}
          r={r}
          fill="none"
          strokeWidth={s.stroke}
          strokeLinecap="round"
          strokeDasharray={`${arc} ${circumference}`}
          className="stroke-foreground/7"
        />
        <circle
          cx={s.box / 2}
          cy={s.box / 2}
          r={r}
          fill="none"
          strokeWidth={s.stroke}
          strokeLinecap="round"
          strokeDasharray={`${filled} ${circumference}`}
          className={cn(tone.stroke, tone.text, 'transition-[stroke-dasharray] duration-700 ease-out')}
          style={{ filter: 'drop-shadow(0 0 4px color-mix(in oklch, currentColor 55%, transparent))' }}
        />
      </svg>
      <div className="relative flex flex-col items-center">
        <span className={cn('metric', s.value)}>{Math.round(clamped)}</span>
        {showLabel && (
          <span className={cn('mt-1 font-semibold tracking-[0.14em] uppercase', s.label, tone.text)}>
            {severity}
          </span>
        )}
      </div>
    </div>
  )
}
