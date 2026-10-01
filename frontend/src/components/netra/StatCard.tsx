import type * as React from 'react'
import type { LucideIcon } from 'lucide-react'
import { ArrowDownRight, ArrowUpRight } from 'lucide-react'
import { useCountUp } from '@/hooks/useCountUp'
import { cn } from '@/lib/utils'
import { toneStyles, type Tone } from '@/lib/tones'
import { Sparkline } from './Sparkline'
import { SurfaceCard } from './SurfaceCard'

const TONE_COLOR: Record<Tone, string> = {
  critical: 'var(--sev-critical)',
  high: 'var(--sev-high)',
  medium: 'var(--sev-medium)',
  low: 'var(--sev-low)',
  info: 'var(--sev-info)',
  accent: 'var(--primary)',
  neutral: 'var(--muted-foreground)',
}

interface StatCardProps {
  label: string
  value: number | null
  /** Suffix shown small after the number, e.g. "/100" or "/ 10". */
  unit?: string
  icon?: LucideIcon
  tone?: Tone
  /** Colour the number itself with the tone (use for severity metrics). */
  toneValue?: boolean
  /** e.g. "+8.4%". `good` decides colour, independent of direction. */
  trend?: { value: string; direction: 'up' | 'down'; good: boolean }
  context?: React.ReactNode
  spark?: number[]
  onClick?: () => void
  className?: string
}

/** Headline metric tile: label → animated number → context, optional sparkline. */
export function StatCard({
  label,
  value,
  unit,
  icon: Icon,
  tone = 'neutral',
  toneValue,
  trend,
  context,
  spark,
  onClick,
  className,
}: StatCardProps) {
  const style = toneStyles[tone]
  const shown = useCountUp(value ?? 0)
  const TrendIcon = trend?.direction === 'up' ? ArrowUpRight : ArrowDownRight

  return (
    <SurfaceCard
      interactive={!!onClick}
      onClick={onClick}
      className={cn('group flex flex-col overflow-hidden p-0', className)}
    >
      <div className="flex items-center justify-between gap-3 px-5 pt-4.5">
        <span className="text-[13px] font-medium text-muted-foreground">{label}</span>
        {Icon && (
          <span className={cn('grid size-7 place-items-center rounded-md', style.soft, style.text)}>
            <Icon className="size-3.5" />
          </span>
        )}
      </div>

      <div className="flex items-end justify-between gap-4 px-5 pt-2.5">
        <div className="flex items-baseline gap-1">
          <span className={cn('metric text-[2.125rem]', toneValue && value !== null && style.text)}>
            {value === null ? '—' : Math.round(shown)}
          </span>
          {unit && <span className="text-sm font-medium text-muted-foreground">{unit}</span>}
        </div>
        {spark && (
          <Sparkline data={spark} color={TONE_COLOR[tone]} className="mb-0.5 w-28 shrink-0 opacity-80 transition-opacity group-hover:opacity-100" height={30} />
        )}
      </div>
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 px-5 pt-2.5 pb-4.5 text-xs text-muted-foreground">
        {trend && (
          <span className={cn('inline-flex items-center gap-0.5 font-medium', trend.good ? 'text-low' : 'text-critical')}>
            <TrendIcon className="size-3.5" />
            {trend.value}
          </span>
        )}
        {context}
      </div>

      {/* tone hairline */}
      {tone !== 'neutral' && (
        <span aria-hidden className={cn('absolute inset-x-0 bottom-0 h-px opacity-50', style.solid)} style={{ maskImage: 'linear-gradient(90deg, transparent, black 50%, transparent)' }} />
      )}
    </SurfaceCard>
  )
}
