import { Link } from 'react-router-dom'
import { ArrowRight, Globe, Lock } from 'lucide-react'
import type { AssetInventoryItem } from '@/api/types'
import { EmptyState, LoadingState, MeterBar, Panel, StatusBadge, ToneBadge } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { ASSET_ICON, CRITICALITY_TONE } from '@/lib/assets'
import { ROUTES } from '@/lib/navigation'
import { riskToSeverity, severityTone, toneStyles } from '@/lib/tones'
import { cn } from '@/lib/utils'

const COLS = 'md:grid-cols-[minmax(0,1.7fr)_88px_84px_minmax(96px,1fr)_96px]'

export function AssetRiskPanel({ assets }: { assets?: AssetInventoryItem[] }) {
  return (
    <Panel
      title="Asset risk overview"
      description="Highest-risk assets and their current exposure"
      flush
      className="h-full"
      actions={
        <Button variant="ghost" size="sm" asChild className="text-muted-foreground">
          <Link to={ROUTES.assets}>
            All assets <ArrowRight />
          </Link>
        </Button>
      }
    >
      {!assets ? (
        <LoadingState className="px-5 py-2" count={6} />
      ) : assets.length === 0 ? (
        <EmptyState title="No assets available" description="The current inventory has no registered assets to assess." />
      ) : (
        <div>
          <div className={cn('hidden gap-4 border-y border-border px-5 py-2 text-[11px] font-medium text-muted-foreground md:grid', COLS)}>
            <span>Asset</span>
            <span>Criticality</span>
            <span>Exposure</span>
            <span>Risk</span>
            <span className="text-right">Status</span>
          </div>
          <ul>
            {assets.slice(0, 6).map((a) => {
              const Icon = a.type ? ASSET_ICON[a.type] : null
              const riskTone = a.riskScore === null ? 'neutral' : severityTone[riskToSeverity(a.riskScore)]
              return (
                <li
                  key={a.id}
                  className={cn(
                    'grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 gap-y-2 border-b border-border/70 px-5 py-2.5 transition-colors last:border-b-0 hover:bg-foreground/2',
                    COLS,
                  )}
                >
                  <div className="flex min-w-0 items-center gap-3">
                    <span className="surface-inset grid size-8 shrink-0 place-items-center rounded-md text-muted-foreground">
                      {Icon && <Icon className="size-4" />}
                    </span>
                    <div className="min-w-0">
                      <div className="truncate text-[13px] font-medium">{a.name}</div>
                      <div className="truncate font-mono text-[11px] text-muted-foreground">
                        {a.hostname ?? 'Hostname unavailable'} · {a.ipAddress ?? 'IP unavailable'}
                      </div>
                    </div>
                  </div>

                  <div className="max-md:hidden">
                    <ToneBadge tone={CRITICALITY_TONE[a.criticality]} size="sm" className="bg-transparent capitalize">
                      {a.criticality.toLowerCase()}
                    </ToneBadge>
                  </div>

                  <div className="inline-flex items-center gap-1.5 text-xs text-muted-foreground max-md:hidden">
                    {a.exposure === 'EXTERNAL' || a.exposure === 'INTERNET_FACING' ? (
                      <Globe className="size-3.5 text-high" />
                    ) : (
                      <Lock className="size-3.5" />
                    )}
                    {a.exposure === 'EXTERNAL' || a.exposure === 'INTERNET_FACING'
                      ? 'Internet-facing'
                      : a.exposure === 'DMZ'
                        ? 'DMZ'
                        : 'Internal'}
                  </div>

                  <div className="flex items-center gap-2.5 max-md:col-span-2 max-md:row-start-2">
                    <span className={cn('w-6 font-mono text-[13px] font-semibold tabular-nums', toneStyles[riskTone].text)}>
                      {a.riskScore ?? 'N/A'}
                    </span>
                    {a.riskScore !== null && <MeterBar value={a.riskScore} tone={riskTone} className="flex-1" />}
                  </div>

                  <div className="flex justify-end max-md:col-start-2 max-md:row-start-1">
                    {a.posture ? (
                      <StatusBadge status={a.posture} size="sm" />
                    ) : (
                      <ToneBadge tone="neutral" size="sm">Posture unavailable</ToneBadge>
                    )}
                  </div>
                </li>
              )
            })}
          </ul>
        </div>
      )}
    </Panel>
  )
}
