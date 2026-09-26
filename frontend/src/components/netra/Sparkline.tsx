import { useId } from 'react'
import { cn } from '@/lib/utils'

interface SparklineProps {
  data: number[]
  /** CSS colour, e.g. "var(--sev-high)". */
  color?: string
  className?: string
  height?: number
}

/** Tiny trend line for stat tiles — decorative, no axes. */
export function Sparkline({ data, color = 'var(--primary)', className, height = 32 }: SparklineProps) {
  const id = useId()
  if (data.length < 2) return null

  const w = 100
  const min = Math.min(...data)
  const max = Math.max(...data)
  const span = max - min || 1
  const pts = data.map((v, i) => [(i / (data.length - 1)) * w, height - 2 - ((v - min) / span) * (height - 4)] as const)
  const line = pts.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(2)},${y.toFixed(2)}`).join(' ')
  const area = `${line} L${w},${height} L0,${height} Z`

  return (
    <svg viewBox={`0 0 ${w} ${height}`} preserveAspectRatio="none" className={cn('w-full overflow-visible', className)} style={{ height }} aria-hidden>
      <defs>
        <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor={color} stopOpacity="0.22" />
          <stop offset="1" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={area} fill={`url(#${id})`} />
      <path d={line} fill="none" stroke={color} strokeWidth="1.5" vectorEffect="non-scaling-stroke" strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  )
}
