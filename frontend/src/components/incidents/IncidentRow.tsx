import { Link } from 'react-router-dom'
import { ChevronRight } from 'lucide-react'
import type { Asset, Incident } from '@/api/types'
import { SeverityBadge, StatusBadge } from '@/components/netra'
import { timeAgo } from '@/lib/format'
import { ROUTES } from '@/lib/navigation'
import { detectionSourceMeta } from '@/lib/sources'
import { severityTone, toneStyles } from '@/lib/tones'
import { cn } from '@/lib/utils'

interface IncidentRowProps {
  incident: Incident
  asset?: Asset
  /** `full` adds technique, event count and risk meter columns (Incidents page). */
  variant?: 'compact' | 'full'
}

/** Risk-ranked incident row — shared by the Command Center and Incidents page. */
export function IncidentRow({ incident: i, asset, variant = 'compact' }: IncidentRowProps) {
  const tone = toneStyles[severityTone[i.severity]]
  const source = detectionSourceMeta[i.detectionSource]
  const full = variant === 'full'

  return (
    <li className="border-b border-border/70 last:border-b-0">
      <Link
        to={ROUTES.incident(i.id)}
        className="group relative flex items-center gap-4 px-5 py-3 transition-colors hover:bg-foreground/2.5 focus-visible:bg-foreground/3 focus-visible:outline-none"
      >
        <span aria-hidden className={cn('absolute inset-y-2.5 left-0 w-0.5 rounded-full opacity-70 transition-opacity group-hover:opacity-100', tone.solid)} />

        <RiskTile score={i.riskScore} severity={i.severity} />

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate text-sm font-medium">{i.threatName}</span>
            <SeverityBadge severity={i.severity} size="sm" className="hidden sm:inline-flex" />
          </div>
          <div className="mt-1 flex items-center gap-1.5 truncate text-xs text-muted-foreground">
            <span className="font-mono text-foreground/70">{i.id}</span>
            <Sep />
            <span className="truncate">{asset?.name ?? i.assetId}</span>
            <Sep className="hidden md:inline" />
            <span className="hidden items-center gap-1 md:inline-flex">
              <source.icon className="size-3" />
              {source.short}
            </span>
            <Sep className="hidden lg:inline" />
            <span className="hidden lg:inline">{timeAgo(i.lastSeen)}</span>
          </div>
        </div>

        {full && (
          <>
            <div className="hidden w-20 shrink-0 xl:block">
              <div className="font-mono text-[11px] text-primary">{i.mitreTechniqueId}</div>
              <div className="mt-0.5 text-[11px] text-muted-foreground">technique</div>
            </div>
            <div className="hidden w-20 shrink-0 text-right lg:block">
              <div className="font-mono text-[13px] tabular-nums">{i.eventCount}</div>
              <div className="mt-0.5 text-[11px] text-muted-foreground">events</div>
            </div>
            <div className="hidden w-24 shrink-0 text-right xl:block">
              <div className="font-mono text-[11px] text-foreground/85">{i.sourceIp}</div>
              <div className="mt-0.5 text-[11px] text-muted-foreground">source</div>
            </div>
          </>
        )}

        <div className={cn('hidden shrink-0 sm:flex', full && 'w-44 justify-end')}>
          <StatusBadge status={i.status} size="sm" />
        </div>
        <ChevronRight className="size-4 shrink-0 text-muted-foreground/40 transition-all group-hover:translate-x-0.5 group-hover:text-foreground" />
      </Link>
    </li>
  )
}

export function RiskTile({ score, severity, size = 'md' }: { score: number; severity: Incident['severity']; size?: 'md' | 'lg' }) {
  const tone = toneStyles[severityTone[severity]]
  return (
    <div className={cn('grid shrink-0 place-items-center rounded-lg border', tone.soft, tone.border, size === 'lg' ? 'size-14' : 'size-11')}>
      <div className="text-center leading-none">
        <div className={cn('metric', tone.text, size === 'lg' ? 'text-2xl' : 'text-[17px]')}>{score}</div>
        <div className="mt-0.5 text-[8px] font-semibold tracking-[0.12em] text-muted-foreground uppercase">risk</div>
      </div>
    </div>
  )
}

const Sep = ({ className }: { className?: string }) => <span className={cn('text-muted-foreground/40', className)}>·</span>
