import { useMemo } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Gauge, ServerCrash, ShieldAlert, Siren } from 'lucide-react'
import { useGuideTone } from '@/components/guide'
import { ErrorState, PageContainer, PageHeader, StatCard, SurfaceCard } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { useNow } from '@/hooks/useNow'
import { useQuery } from '@/hooks/useQuery'
import { ROUTES } from '@/lib/navigation'
import { riskToSeverity, severityTone } from '@/lib/tones'
import { assetService, dashboardService, eventService, incidentService, threatIntelService } from '@/services'
import { AssetRiskPanel } from './dashboard/AssetRiskPanel'
import { PrioritizedIncidentsPanel } from './dashboard/PrioritizedIncidentsPanel'
import { RiskPosturePanel } from './dashboard/RiskPosturePanel'
import { RiskTrendPanel } from './dashboard/RiskTrendPanel'
import { SeverityDistributionPanel } from './dashboard/SeverityDistributionPanel'
import { DetectionIntelPanel } from './dashboard/DetectionIntelPanel'

const ACTIVE = new Set(['NEW', 'INVESTIGATING', 'AWAITING_AUTHORIZATION', 'CONTAINING'])

export function CommandCenterPage() {
  const navigate = useNavigate()
  const now = useNow(1000)

  const stats = useQuery('dash-stats', dashboardService.getStats)
  const trend = useQuery('dash-trend-24h', () => dashboardService.getRiskTrend('24h'))
  const incidents = useQuery('dash-incidents', () => incidentService.list({ pageSize: 50 }))
  const assets = useQuery('dash-assets', assetService.list)
  const techniques = useQuery('dash-techniques', threatIntelService.getObservedTechniques)
  const events = useQuery('dash-events', () => eventService.list({ pageSize: 8 }))

  const activeIncidents = useMemo(
    () => incidents.data?.items.filter((i) => ACTIVE.has(i.status)),
    [incidents.data],
  )
  const assetsById = useMemo(() => new Map((assets.data ?? []).map((a) => [a.id, a])), [assets.data])

  const s = stats.data
  const riskSpark = trend.data?.map((p) => p.riskScore)
  const activeSpark = trend.data?.map((p) => p.activeIncidents)
  const bySev = s?.incidentsBySeverity
  useGuideTone(!s ? 'normal' : s.overallRisk >= 85 ? 'critical' : s.overallRisk >= 65 ? 'warning' : 'normal')

  if (stats.error) {
    return (
      <SurfaceCard>
        <ErrorState onRetry={stats.reload} />
      </SurfaceCard>
    )
  }

  return (
    <PageContainer>
      <PageHeader
        title="Command Center"
        description={
          s
            ? `Live security posture across ${s.totalAssets} monitored assets · ${s.eventsLast24h.toLocaleString('en-US')} detections in the last 24 hours`
            : 'Live security posture'
        }
        actions={
          <>
            <div className="surface-inset flex h-8 items-center gap-2 rounded-lg px-3 text-xs">
              <span className="relative flex size-2">
                <span className="absolute inset-0 animate-status-pulse rounded-full bg-cyan" />
                <span className="relative size-2 rounded-full bg-cyan" />
              </span>
              <span className="font-medium">Live</span>
              <span className="font-mono text-muted-foreground tabular-nums">{now.toISOString().slice(11, 19)}</span>
            </div>
            <Button asChild>
              <Link to={ROUTES.incidents}>
                <ShieldAlert /> Triage incidents
              </Link>
            </Button>
          </>
        }
      />

      {/* 1 · Executive summary */}
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Overall risk"
          value={s?.overallRisk ?? 0}
          unit="/100"
          icon={Gauge}
          tone={s ? severityTone[riskToSeverity(s.overallRisk)] : 'neutral'}
          toneValue
          trend={s && { value: `${s.overallRiskChange > 0 ? '+' : ''}${s.overallRiskChange.toFixed(0)}%`, direction: s.overallRiskChange > 0 ? 'up' : 'down', good: s.overallRiskChange <= 0 }}
          context={s && <span>vs 24h ago · {s.overallRiskLevel.toLowerCase()}</span>}
          spark={riskSpark}
        />
        <StatCard
          label="Active incidents"
          value={s?.activeIncidents ?? 0}
          icon={ShieldAlert}
          tone="accent"
          context={bySev && <span>{bySev.CRITICAL} critical · {bySev.HIGH} high · {bySev.MEDIUM} medium</span>}
          spark={activeSpark}
          onClick={() => navigate(ROUTES.incidents)}
        />
        <StatCard
          label="Critical threats"
          value={s?.criticalThreats ?? 0}
          icon={Siren}
          tone="critical"
          toneValue
          context={s && <span>{s.containedThreats} contained this week</span>}
          onClick={() => navigate(ROUTES.incidents)}
        />
        <StatCard
          label="Assets at risk"
          value={s?.assetsAtRisk ?? 0}
          unit={s ? `/ ${s.totalAssets}` : undefined}
          icon={ServerCrash}
          tone="high"
          toneValue
          context={s && <span>{s.criticalAssets} critical assets monitored</span>}
          onClick={() => navigate(ROUTES.assets)}
        />
      </div>

      {/* 2 · Security posture + risk trend */}
      <div className="grid gap-4 xl:grid-cols-12">
        <div className="min-w-0 rounded-xl xl:col-span-4" data-guide-target="security-posture">
          <RiskPosturePanel stats={s} />
        </div>
        <div className="min-w-0 xl:col-span-8">
          <RiskTrendPanel />
        </div>
      </div>

      {/* 3 · Priority incidents + distribution */}
      <div className="grid gap-4 xl:grid-cols-12">
        <div className="min-w-0 xl:col-span-8">
          <PrioritizedIncidentsPanel incidents={activeIncidents} assetsById={assetsById} />
        </div>
        <div className="min-w-0 xl:col-span-4">
          <SeverityDistributionPanel incidents={activeIncidents} />
        </div>
      </div>

      {/* 4 · Asset risk + secondary detection analytics (tabbed) */}
      <div className="grid gap-4 xl:grid-cols-12">
        <div className="min-w-0 xl:col-span-7">
          <AssetRiskPanel assets={assets.data} />
        </div>
        <div className="min-w-0 xl:col-span-5">
          <DetectionIntelPanel techniques={techniques.data} events={events.data?.items} health={s?.systemHealth} />
        </div>
      </div>
    </PageContainer>
  )
}
