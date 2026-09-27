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
  /**
   * `compact`: Command Center list.
   * `full`: Incidents queue — adds affected asset and recommended-action columns;
   * technique, source and timing move to a quiet metadata line.
   */
  variant?: 'compact' | 'full'
  /** Recommended action, e.g. "Block IP 192.168.1.25" (full variant). */
  action?: string
}

/** Risk-ranked incident row — shared by the Command Center and Incidents page. */
export function IncidentRow({ incident: i, asset, variant = 'compact', action }: IncidentRowProps) {
  const tone = toneStyles[severityTone[i.severity]]
  const source = detectionSourceMeta[i.detectionSource]
  const full = variant === 'full'
  const urgent = i.severity === 'CRITICAL'

  return (
    <li className="border-b border-border/70 last:border-b-0">
      <Link
        to={ROUTES.incident(i.id)}
        className={cn(
          'group relative flex items-center gap-4 px-5 py-3 transition-colors hover:bg-foreground/2.5 focus-visible:bg-foreground/3 focus-visible:outline-none',
          full && urgent && 'bg-critical/3',
        )}
      >
        <span
          aria-hidden
          className={cn(
            'absolute inset-y-2.5 left-0 rounded-full transition-opacity group-hover:opacity-100',
            tone.solid,
            urgent ? 'w-0.75 opacity-90' : 'w-0.5 opacity-60',
          )}
        />

        <RiskTile score={i.riskScore} severity={i.severity} />

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate text-sm font-medium">{i.threatName}</span>
            <SeverityBadge severity={i.severity} size="sm" className="hidden sm:inline-flex" />
          </div>
          <div className="mt-1 flex items-center gap-1.5 truncate text-xs text-muted-foreground">
            <span className="font-mono text-foreground/70">{i.id}</span>
            {full ? (
              <>
                <Sep className="lg:hidden" />
                <span className="truncate lg:hidden">{asset?.name ?? i.assetId}</span>
                {i.mitreTechniqueId && (
                  <>
                    <Sep className="hidden md:inline" />
                    <span className="hidden font-mono text-[11px] text-primary/80 md:inline">{i.mitreTechniqueId}</span>
                  </>
                )}
              </>
            ) : (
              <>
                <Sep />
                <span className="truncate">{asset?.name ?? i.assetId}</span>
              </>
            )}
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
            <div className="hidden w-36 shrink-0 lg:block">
              <div className="truncate text-[13px] text-foreground/90">{asset?.name ?? i.assetId}</div>
              <div className="mt-0.5 text-[11px] text-muted-foreground capitalize">
                {asset ? `${asset.criticality.toLowerCase()} · ${asset.exposure.toLowerCase()}` : 'asset'}
              </div>
            </div>
            <div className="hidden w-52 shrink-0 xl:block">
              {action ? (
                <>
                  <div className="truncate text-[13px] font-medium text-foreground/90">{action}</div>
                  <div className="mt-0.5 text-[11px] text-muted-foreground">recommended action</div>
                </>
              ) : (
                <span className="text-xs text-muted-foreground">—</span>
              )}
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
