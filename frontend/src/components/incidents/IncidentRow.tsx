import { Link } from 'react-router-dom'
import { ChevronRight } from 'lucide-react'
import type { Asset, BackendEventAssetReference, Incident, IncidentQueueItem } from '@/api/types'
import { SeverityBadge, StatusBadge } from '@/components/netra'
import { timeAgo } from '@/lib/format'
import { ROUTES } from '@/lib/navigation'
import { detectionSourceMeta, eventSourceMeta } from '@/lib/sources'
import { severityTone, toneStyles } from '@/lib/tones'
import { cn } from '@/lib/utils'

interface IncidentRowProps {
  incident: Incident | IncidentQueueItem
  asset?: Asset | BackendEventAssetReference
  /**
   * `compact`: Command Center list.
   * `full`: Incidents queue — adds affected asset and recommended-action columns;
   * technique, source and timing move to a quiet metadata line.
   */
  variant?: 'compact' | 'full'
  /** Recommended action, e.g. "Block IP 192.168.1.25" (full variant). */
  action?: string
  entryIndex?: number
  priorityRank?: number
}

/** Risk-ranked incident row — shared by the Command Center and Incidents page. */
export function IncidentRow({ incident: i, asset, variant = 'compact', action, entryIndex = 0, priorityRank }: IncidentRowProps) {
  const live = 'lifecycle' in i
  const linkedAsset = asset ?? (live ? i.asset ?? undefined : undefined)
  const title = live ? i.title : i.threatName
  const displayId = live ? i.key : i.id
  const assetId = live ? i.asset?.id : i.assetId
  const status = live ? i.lifecycle : i.status
  const source = live ? eventSourceMeta(i.detectionSource) : detectionSourceMeta[i.detectionSource]
  const techniqueId = live ? null : i.mitreTechniqueId
  const activityTime = live ? i.updatedAt : i.lastSeen
  const tone = toneStyles[severityTone[i.severity]]
  const full = variant === 'full'
  const urgent = i.severity === 'CRITICAL'

  return (
    <li
      className="border-b border-border/70 last:border-b-0 motion-safe:animate-in motion-safe:fade-in-0 motion-safe:slide-in-from-bottom-1"
      style={{ animationDelay: `${Math.min(entryIndex, 8) * 40}ms` }}
    >
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

        {priorityRank !== undefined && (
          <span
            aria-label={`Priority ${priorityRank}`}
            title={`Priority ${priorityRank} by NETRA risk score`}
            className="inline-flex shrink-0 font-mono text-[10px] font-semibold text-primary/90 motion-safe:animate-in motion-safe:fade-in-0"
            style={{ animationDelay: `${Math.min(entryIndex, 8) * 55}ms` }}
          >
            P{priorityRank}
          </span>
        )}

        <RiskTile score={i.riskScore} severity={i.severity} />

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate text-sm font-medium">{title}</span>
            <SeverityBadge severity={i.severity} size="sm" className="hidden sm:inline-flex" />
          </div>
          <div className="mt-1 flex items-center gap-1.5 truncate text-xs text-muted-foreground">
            <span className="font-mono text-foreground/70">{displayId}</span>
            {live && <><Sep /><span>{i.eventCount} events</span></>}
            {full ? (
              <>
                <Sep className="lg:hidden" />
                <span className="truncate lg:hidden">{linkedAsset?.name ?? (live ? 'No linked asset' : assetId)}</span>
                {techniqueId && (
                  <>
                    <Sep className="hidden md:inline" />
                    <span className="hidden font-mono text-[11px] text-primary/80 md:inline">{techniqueId}</span>
                  </>
                )}
              </>
            ) : (
              <>
                <Sep />
                <span className="truncate">{linkedAsset?.name ?? (live ? 'No linked asset' : assetId)}</span>
              </>
            )}
            <Sep className="hidden md:inline" />
            <span className="hidden items-center gap-1 md:inline-flex">
              <source.icon className="size-3" />
              {source.short}
            </span>
            <Sep className="hidden lg:inline" />
            <span className="hidden lg:inline">{live ? 'updated ' : ''}{timeAgo(activityTime)}</span>
          </div>
        </div>

        {full && (
          <>
            <div className="hidden w-36 shrink-0 lg:block">
              <div className="truncate text-[13px] text-foreground/90">{linkedAsset?.name ?? (live ? 'No linked asset' : assetId)}</div>
              <div className="mt-0.5 text-[11px] text-muted-foreground capitalize">
                {linkedAsset
                  ? 'exposure' in linkedAsset
                    ? `${linkedAsset.criticality.toLowerCase()} · ${linkedAsset.exposure.toLowerCase()}`
                    : `${linkedAsset.criticality.toLowerCase()} · ${linkedAsset.status.toLowerCase()}`
                  : 'No linked asset'}
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
          <StatusBadge status={status} size="sm" />
        </div>
        <ChevronRight className="size-4 shrink-0 text-muted-foreground/40 transition-all group-hover:translate-x-0.5 group-hover:text-foreground" />
      </Link>
    </li>
  )
}

export function RiskTile({ score, severity, size = 'md' }: { score: number | null; severity: Incident['severity']; size?: 'md' | 'lg' }) {
  const tone = toneStyles[severityTone[severity]]
  return (
    <div className={cn('relative grid shrink-0 place-items-center rounded-lg border', tone.soft, tone.border, size === 'lg' ? 'size-14' : 'size-11')}>
      <div className="text-center leading-none">
        <div className={cn('metric', score === null ? 'text-muted-foreground' : tone.text, size === 'lg' ? 'text-2xl' : 'text-[17px]')}>
          {score ?? 'N/A'}
        </div>
        <div className="mt-0.5 text-[8px] font-semibold tracking-[0.12em] text-muted-foreground uppercase">risk</div>
      </div>
      {score !== null && (
        <span aria-hidden className="absolute inset-x-1.5 bottom-1 h-0.5 overflow-hidden rounded-full bg-background/60">
          <span className={cn('block h-full rounded-full transition-[width] duration-500', tone.solid)} style={{ width: `${Math.max(0, Math.min(score, 100))}%` }} />
        </span>
      )}
    </div>
  )
}

const Sep = ({ className }: { className?: string }) => <span className={cn('text-muted-foreground/40', className)}>·</span>
