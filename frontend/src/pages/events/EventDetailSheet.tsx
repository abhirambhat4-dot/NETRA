import { Link } from 'react-router-dom'
import { ArrowRight } from 'lucide-react'
import type { Asset, SecurityEvent } from '@/api/types'
import { RiskTile } from '@/components/incidents/IncidentRow'
import { DetailSection, DetailSheet, KeyValueList, LoadingState, MeterBar, SeverityBadge, StatusBadge } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { useQuery } from '@/hooks/useQuery'
import { formatDateTime } from '@/lib/format'
import { ROUTES } from '@/lib/navigation'
import { detectionSourceMeta } from '@/lib/sources'
import { incidentService } from '@/services'

interface Props {
  event?: SecurityEvent
  asset?: Asset
  onClose: () => void
}

export function EventDetailSheet({ event, asset, onClose }: Props) {
  return (
    <DetailSheet
      open={!!event}
      onOpenChange={(o) => !o && onClose()}
      eyebrow={event && `${event.id} · ${formatDateTime(event.timestamp)} UTC`}
      title={event?.eventType ?? ''}
      description={event?.signature ?? undefined}
    >
      {event && <Body event={event} asset={asset} />}
    </DetailSheet>
  )
}

function Body({ event: e, asset }: { event: SecurityEvent; asset?: Asset }) {
  const src = detectionSourceMeta[e.detectionSource]
  const incident = useQuery(`event-incident-${e.incidentId}`, () =>
    e.incidentId ? incidentService.get(e.incidentId) : Promise.resolve(null),
  )

  return (
    <>
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={e.severity} />
        <StatusBadge status={e.status} />
        <span className="inline-flex items-center gap-1.5 rounded-md border border-border px-2 py-0.5 text-[11px] text-foreground/85">
          <src.icon className="size-3.5" />
          {src.label}
        </span>
      </div>

      <DetailSection title="Network">
        <KeyValueList
          columns={2}
          items={[
            { label: 'Source', value: `${e.sourceIp}${e.sourcePort ? `:${e.sourcePort}` : ''}`, mono: true },
            { label: 'Destination', value: `${e.destinationIp}${e.destinationPort ? `:${e.destinationPort}` : ''}`, mono: true },
            { label: 'Protocol', value: e.protocol },
            { label: 'MITRE technique', value: e.mitreTechniqueId ?? '—', mono: true },
          ]}
        />
      </DetailSection>

      <DetailSection title="Detection">
        <div className="surface-inset space-y-2 rounded-lg p-3.5">
          <div className="flex items-center justify-between text-xs">
            <span className="text-muted-foreground">ML anomaly score</span>
            <span className="font-mono">{Math.round(e.anomalyScore * 100)}%</span>
          </div>
          <MeterBar value={e.anomalyScore * 100} tone={e.anomalyScore >= 0.75 ? 'critical' : e.anomalyScore >= 0.5 ? 'high' : 'accent'} />
          {e.signature && (
            <p className="pt-1 font-mono text-[11px] leading-relaxed text-muted-foreground">{e.signature}</p>
          )}
        </div>
      </DetailSection>

      <DetailSection title="Affected asset">
        {asset ? (
          <Link to={`${ROUTES.assets}?asset=${asset.id}`} className="surface-inset flex items-center justify-between rounded-lg p-3.5 transition-colors hover:border-primary/25">
            <div>
              <div className="text-[13px] font-medium">{asset.name}</div>
              <div className="font-mono text-[11px] text-muted-foreground">
                {asset.hostname} · {asset.ipAddress}
              </div>
            </div>
            <StatusBadge status={asset.posture} size="sm" />
          </Link>
        ) : (
          <p className="text-xs text-muted-foreground">No managed asset matched this event.</p>
        )}
      </DetailSection>

      <DetailSection title="Correlated incident">
        {!e.incidentId ? (
          <p className="text-xs text-muted-foreground">
            Not correlated. NETRA keeps uncorrelated events for context; they do not affect risk scoring on their own.
          </p>
        ) : !incident.data ? (
          <LoadingState count={2} />
        ) : (
          <div className="surface-inset space-y-3 rounded-lg p-3.5">
            <div className="flex items-center gap-3">
              <RiskTile score={incident.data.incident.riskScore} severity={incident.data.incident.severity} />
              <div className="min-w-0">
                <div className="truncate text-[13px] font-medium">{incident.data.incident.threatName}</div>
                <div className="mt-0.5 font-mono text-[11px] text-muted-foreground">
                  {incident.data.incident.id} · {incident.data.incident.eventCount} events
                </div>
              </div>
              <StatusBadge status={incident.data.incident.status} size="sm" className="ml-auto" />
            </div>
            <Button asChild size="sm" className="w-full">
              <Link to={ROUTES.incident(e.incidentId)}>
                Open incident <ArrowRight />
              </Link>
            </Button>
          </div>
        )}
      </DetailSection>
    </>
  )
}
