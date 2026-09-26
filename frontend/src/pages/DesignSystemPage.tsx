import { Activity, ShieldAlert, ShieldCheck, Siren } from 'lucide-react'
import {
  EmptyState,
  ErrorState,
  LoadingState,
  PageContainer,
  PageHeader,
  RiskBadge,
  RiskScore,
  SectionHeader,
  SeverityBadge,
  StatCard,
  StatusBadge,
  SurfaceCard,
} from '@/components/netra'
import { Button } from '@/components/ui/button'
import { SEVERITY_ORDER, type AnyStatus } from '@/lib/tones'

const SAMPLE_STATUSES: AnyStatus[] = [
  'NEW',
  'INVESTIGATING',
  'AWAITING_AUTHORIZATION',
  'CONTAINING',
  'CONTAINED',
  'OTP_SENT',
  'VERIFIED',
  'FAILED',
  'HEALTHY',
  'DEGRADED',
]

/** Internal reference for the NETRA design system (not in navigation). Sample values only. */
export function DesignSystemPage() {
  return (
    <PageContainer>
      <PageHeader
        eyebrow="Internal"
        title="Design System"
        description="Reference for NETRA components. Values on this page are illustrative."
        actions={
          <>
            <Button variant="outline">Secondary</Button>
            <Button>Primary action</Button>
          </>
        }
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Critical incidents" value={3} icon={Siren} tone="critical" trend={{ value: '+1 vs 24h', direction: 'up', good: false }} />
        <StatCard label="High incidents" value={7} icon={ShieldAlert} tone="high" context="Last 24h" />
        <StatCard label="Events ingested" value={12480} icon={Activity} tone="accent" trend={{ value: '-8% vs 24h', direction: 'down', good: true }} />
        <StatCard label="Contained threats" value={18} icon={ShieldCheck} tone="low" context="This week" />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <SurfaceCard className="space-y-5">
          <SectionHeader title="Risk score" description="Gauge colour follows severity band" />
          <div className="flex flex-wrap items-end justify-around gap-4">
            <RiskScore score={91} size="lg" />
            <RiskScore score={68} />
            <RiskScore score={34} size="sm" />
          </div>
        </SurfaceCard>

        <SurfaceCard className="space-y-5">
          <SectionHeader title="Severity & risk badges" />
          <div className="flex flex-wrap gap-2">
            {SEVERITY_ORDER.map((s) => (
              <SeverityBadge key={s} severity={s} />
            ))}
          </div>
          <div className="flex flex-wrap gap-2">
            {[91, 72, 55, 22, 8].map((s) => (
              <RiskBadge key={s} score={s} />
            ))}
          </div>
        </SurfaceCard>

        <SurfaceCard className="space-y-5">
          <SectionHeader title="Status badges" />
          <div className="flex flex-wrap gap-2">
            {SAMPLE_STATUSES.map((s) => (
              <StatusBadge key={s} status={s} />
            ))}
          </div>
        </SurfaceCard>
      </div>

      <div className="grid gap-4 lg:grid-cols-2 xl:grid-cols-4">
        <SurfaceCard className="space-y-4">
          <SectionHeader title="Loading · rows" />
          <LoadingState count={4} />
        </SurfaceCard>
        <SurfaceCard>
          <SectionHeader title="Loading · inline" />
          <LoadingState variant="inline" label="Fetching incidents…" />
        </SurfaceCard>
        <SurfaceCard>
          <SectionHeader title="Empty" />
          <EmptyState title="No incidents" description="Nothing matches the current filters." />
        </SurfaceCard>
        <SurfaceCard>
          <SectionHeader title="Error" />
          <ErrorState onRetry={() => undefined} />
        </SurfaceCard>
      </div>

      <LoadingState variant="cards" count={4} />
    </PageContainer>
  )
}
