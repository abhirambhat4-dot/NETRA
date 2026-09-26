import type * as React from 'react'
import type { Severity } from '@/api/types'
import { cn } from '@/lib/utils'
import {
  riskToSeverity,
  severityTone,
  statusMeta,
  toneStyles,
  type AnyStatus,
  type Tone,
} from '@/lib/tones'
import { StatusDot } from './StatusDot'

interface ToneBadgeProps extends React.ComponentProps<'span'> {
  tone: Tone
  size?: 'sm' | 'md'
}

/** Low-level tinted pill. Prefer SeverityBadge / StatusBadge / RiskBadge. */
export function ToneBadge({ tone, size = 'md', className, ...props }: ToneBadgeProps) {
  const style = toneStyles[tone]
  return (
    <span
      className={cn(
        'inline-flex shrink-0 items-center gap-1.5 rounded-md border font-medium whitespace-nowrap',
        size === 'sm' ? 'h-5 px-1.5 text-[10px]' : 'h-6 px-2 text-[11px]',
        style.text,
        style.soft,
        style.border,
        className,
      )}
      {...props}
    />
  )
}

// ---------------------------------------------------------------------------

interface SeverityBadgeProps {
  severity: Severity
  size?: 'sm' | 'md'
  className?: string
}

/** CRITICAL / HIGH / MEDIUM / LOW / INFO */
export function SeverityBadge({ severity, size, className }: SeverityBadgeProps) {
  const tone = severityTone[severity]
  return (
    <ToneBadge tone={tone} size={size} className={cn('tracking-[0.08em] uppercase', className)}>
      <span className={cn('size-1.5 rounded-full', toneStyles[tone].solid)} aria-hidden />
      {severity}
    </ToneBadge>
  )
}

// ---------------------------------------------------------------------------

interface StatusBadgeProps {
  status: AnyStatus
  size?: 'sm' | 'md'
  className?: string
}

/** Any workflow status: incident, event, authorization, containment, asset, health. */
export function StatusBadge({ status, size, className }: StatusBadgeProps) {
  const meta = statusMeta[status]
  return (
    <ToneBadge tone={meta.tone} size={size} className={cn('bg-transparent', className)}>
      <StatusDot tone={meta.tone} pulse={meta.pulse} size="sm" />
      {meta.label}
    </ToneBadge>
  )
}

// ---------------------------------------------------------------------------

interface RiskBadgeProps {
  score: number // 0–100
  size?: 'sm' | 'md'
  className?: string
}

/** Compact numeric risk, coloured by its severity band. */
export function RiskBadge({ score, size, className }: RiskBadgeProps) {
  const tone = severityTone[riskToSeverity(score)]
  return (
    <ToneBadge
      tone={tone}
      size={size}
      className={cn('font-mono tabular-nums', className)}
      title={`Risk score ${score}/100`}
    >
      {Math.round(score)}
      <span className="opacity-60">/100</span>
    </ToneBadge>
  )
}
