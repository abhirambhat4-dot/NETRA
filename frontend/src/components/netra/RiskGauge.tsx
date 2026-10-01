import { useEffect, useState } from 'react'
import { useCountUp } from '@/hooks/useCountUp'
import { cn } from '@/lib/utils'
import { riskToSeverity, severityTone, toneStyles } from '@/lib/tones'

const START = 135 // degrees, bottom-left
const SWEEP = 270

const BANDS = [
  { from: 0, to: 15, color: 'var(--sev-info)' },
  { from: 15, to: 40, color: 'var(--sev-low)' },
  { from: 40, to: 65, color: 'var(--sev-medium)' },
  { from: 65, to: 85, color: 'var(--sev-high)' },
  { from: 85, to: 100, color: 'var(--sev-critical)' },
]

function polar(cx: number, cy: number, r: number, deg: number) {
  const rad = (deg * Math.PI) / 180
  return [cx + r * Math.cos(rad), cy + r * Math.sin(rad)] as const
}

function arcPath(cx: number, cy: number, r: number, fromPct: number, toPct: number) {
  const a0 = START + (SWEEP * fromPct) / 100
  const a1 = START + (SWEEP * toPct) / 100
  const [x0, y0] = polar(cx, cy, r, a0)
  const [x1, y1] = polar(cx, cy, r, a1)
  return `M${x0},${y0} A${r},${r} 0 ${a1 - a0 > 180 ? 1 : 0} 1 ${x1},${y1}`
}

interface RiskGaugeProps {
  score: number
  label?: string
  size?: number
  className?: string
}

/**
 * Hero risk gauge: severity band ring, animated progress arc, tick marks,
 * count-up number. Colour of the value follows its severity band.
 */
export function RiskGauge({ score, label = 'Overall risk', size = 220, className }: RiskGaugeProps) {
  const prefersReducedMotion = typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches
  const [mounted, setMounted] = useState(() => typeof window !== 'undefined' && window.matchMedia('(prefers-reduced-motion: reduce)').matches)

  useEffect(() => {
    if (prefersReducedMotion) {
      return
    }

    const id = requestAnimationFrame(() => setMounted(true))
    return () => cancelAnimationFrame(id)
  }, [prefersReducedMotion])

  const value = Math.max(0, Math.min(100, score))
  const shown = useCountUp(value, prefersReducedMotion ? 0 : 1100)
  const severity = riskToSeverity(value)
  const tone = toneStyles[severityTone[severity]]
  const color = BANDS.find((b) => value >= b.from && value <= b.to)?.color ?? 'var(--primary)'

  const c = size / 2
  const rBand = c - 4
  const rMain = c - 18
  const [ex, ey] = polar(c, c, rMain, START + (SWEEP * (mounted ? value : 0)) / 100)

  return (
    <div
      className={cn('relative', className)}
      style={{ width: size, height: size }}
      role="meter"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={value}
      aria-label={`${label} ${value} of 100, ${severity}`}
    >
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="overflow-visible">
        {/* severity bands */}
        {BANDS.map((b) => (
          <path key={b.from} d={arcPath(c, c, rBand, b.from + 0.6, b.to - 0.6)} stroke={b.color} strokeOpacity={0.4} strokeWidth={2} fill="none" strokeLinecap="round" />
        ))}

        {/* ticks */}
        {Array.from({ length: 21 }, (_, i) => {
          const deg = START + (SWEEP * i * 5) / 100
          const major = i % 2 === 0
          const [x0, y0] = polar(c, c, rMain - 11, deg)
          const [x1, y1] = polar(c, c, rMain - (major ? 16 : 14), deg)
          return <line key={i} x1={x0} y1={y0} x2={x1} y2={y1} stroke="currentColor" strokeOpacity={major ? 0.22 : 0.12} strokeWidth={1} className="text-foreground" />
        })}

        {/* track */}
        <path d={arcPath(c, c, rMain, 0, 100)} stroke="currentColor" strokeOpacity={0.06} strokeWidth={10} fill="none" strokeLinecap="round" className="text-foreground" />

        {/* progress */}
        <path
          d={arcPath(c, c, rMain, 0, 100)}
          pathLength={100}
          stroke={color}
          strokeWidth={10}
          fill="none"
          strokeLinecap="round"
          strokeDasharray={`${mounted ? value : 0} 100`}
          style={{ transition: 'stroke-dasharray 1.1s cubic-bezier(0.22, 1, 0.36, 1)', filter: `drop-shadow(0 0 6px color-mix(in srgb, ${color} 45%, transparent))` }}
        />

        {/* end marker */}
        <circle
          cx={ex}
          cy={ey}
          r={4}
          fill="var(--background)"
          stroke={color}
          strokeWidth={2.5}
          style={{ transition: 'cx 1.1s cubic-bezier(0.22, 1, 0.36, 1), cy 1.1s cubic-bezier(0.22, 1, 0.36, 1)' }}
        />
      </svg>

      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="eyebrow text-[10px] transition-opacity duration-500" style={{ opacity: mounted ? 1 : 0 }}>{label}</span>
        <span className="metric mt-1.5 text-6xl transition-all duration-500" style={{ opacity: mounted ? 1 : 0, transform: mounted ? 'translateY(0)' : 'translateY(8px)' }}>{Math.round(shown)}</span>
        <span className={cn('mt-2 inline-flex items-center gap-1.5 text-xs font-semibold tracking-[0.14em] transition-all duration-500', tone.text)} style={{ opacity: mounted ? 1 : 0, filter: mounted ? `drop-shadow(0 0 12px color-mix(in srgb, ${color} 55%, transparent))` : 'none' }}>
          <span className={cn('size-1.5 rounded-full', tone.solid, mounted && 'animate-status-pulse')} />
          {severity}
        </span>
      </div>
    </div>
  )
}
