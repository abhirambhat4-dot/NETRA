import { Link } from 'react-router-dom'
import { ArrowRight, Copy } from 'lucide-react'
import { toast } from 'sonner'
import type { Asset, SecurityEvent } from '@/api/types'
import { RiskTile } from '@/components/incidents/IncidentRow'
import { DetailSection, DetailSheet, KeyValueList, LoadingState, MeterBar, SeverityBadge, StatusBadge } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
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

/**
 * Event drawer — the Summary tab answers "what is this and does it matter";
 * network, detection, anomaly and raw data are one tab away.
 */
export function EventDetailSheet({ event, asset, onClose }: Props) {
  return (
    <DetailSheet
      open={!!event}
      onOpenChange={(o) => !o && onClose()}
      eyebrow={event && `${event.id} · ${formatDateTime(event.timestamp)} UTC`}
      title={event?.eventType ?? ''}
      description={event?.signature ?? undefined}
    >
      {event && <Body key={event.id} event={event} asset={asset} />}
    </DetailSheet>
  )
}

const TABS = [
  { value: 'summary', label: 'Summary' },
  { value: 'network', label: 'Network' },
  { value: 'detection', label: 'Detection' },
  { value: 'anomaly', label: 'Anomaly' },
  { value: 'raw', label: 'Raw' },
] as const

function anomalyReading(score: number) {
  if (score >= 0.75) return 'Highly abnormal compared with the learned behavioural baseline.'
  if (score >= 0.5) return 'Moderately unusual — worth correlating with other signals.'
  return 'Within normal variation for this source.'
}

function Body({ event: e, asset }: { event: SecurityEvent; asset?: Asset }) {
  const src = detectionSourceMeta[e.detectionSource]
  const incident = useQuery(`event-incident-${e.incidentId}`, () =>
    e.incidentId ? incidentService.get(e.incidentId) : Promise.resolve(null),
  )
  const anomalyTone = e.anomalyScore >= 0.75 ? 'critical' : e.anomalyScore >= 0.5 ? 'high' : 'accent'

  const copyRaw = () => {
    navigator.clipboard
      ?.writeText(JSON.stringify(e, null, 2))
      .then(() => toast.success('Raw event copied'))
      .catch(() => toast.error('Clipboard unavailable'))
  }

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

      <Tabs defaultValue="summary" className="gap-5">
        <TabsList variant="line" className="w-full justify-start gap-0 border-b border-border pb-px">
          {TABS.map((t) => (
            <TabsTrigger key={t.value} value={t.value} className="flex-none px-2.5 text-xs">
              {t.label}
            </TabsTrigger>
          ))}
        </TabsList>

        {/* SUMMARY */}
        <TabsContent value="summary" className="space-y-6 motion-safe:animate-in motion-safe:fade-in-0">
          <DetailSection title="Correlated incident">
            {!e.incidentId ? (
              <p className="text-xs leading-relaxed text-muted-foreground">
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

          <KeyValueList
            columns={2}
            items={[
              { label: 'Flow', value: `${e.sourceIp} → ${e.destinationIp}`, mono: true },
              { label: 'Anomaly score', value: `${Math.round(e.anomalyScore * 100)}%`, mono: true },
            ]}
          />
        </TabsContent>

        {/* NETWORK */}
        <TabsContent value="network" className="motion-safe:animate-in motion-safe:fade-in-0">
          <KeyValueList
            columns={2}
            items={[
              { label: 'Source IP', value: e.sourceIp, mono: true },
              { label: 'Source port', value: e.sourcePort ?? '—', mono: true },
              { label: 'Destination IP', value: e.destinationIp, mono: true },
              { label: 'Destination port', value: e.destinationPort ?? '—', mono: true },
              { label: 'Protocol', value: e.protocol },
              { label: 'Destination asset', value: asset?.name ?? 'Unmanaged' },
            ]}
          />
        </TabsContent>

        {/* DETECTION */}
        <TabsContent value="detection" className="space-y-5 motion-safe:animate-in motion-safe:fade-in-0">
          <KeyValueList
            columns={2}
            items={[
              { label: 'Detection source', value: src.label },
              { label: 'Detected at', value: `${formatDateTime(e.timestamp)} UTC` },
              { label: 'MITRE technique', value: e.mitreTechniqueId ?? '—', mono: true },
              { label: 'Event status', value: <StatusBadge status={e.status} size="sm" /> },
            ]}
          />
          <DetailSection title="Signature">
            {e.signature ? (
              <p className="surface-inset rounded-lg p-3.5 font-mono text-[11px] leading-relaxed text-foreground/85">{e.signature}</p>
            ) : (
              <p className="text-xs text-muted-foreground">No rule signature — raised by behavioural detection.</p>
            )}
          </DetailSection>
        </TabsContent>

        {/* ANOMALY */}
        <TabsContent value="anomaly" className="motion-safe:animate-in motion-safe:fade-in-0">
          <div className="surface-inset space-y-3 rounded-lg p-4">
            <div className="flex items-baseline justify-between">
              <span className="text-xs text-muted-foreground">ML anomaly score</span>
              <span className="metric text-2xl">{Math.round(e.anomalyScore * 100)}%</span>
            </div>
            <MeterBar value={e.anomalyScore * 100} tone={anomalyTone} />
            <p className="text-xs leading-relaxed text-foreground/80">{anomalyReading(e.anomalyScore)}</p>
          </div>
        </TabsContent>

        {/* RAW */}
        <TabsContent value="raw" className="space-y-2 motion-safe:animate-in motion-safe:fade-in-0">
          <div className="flex items-center justify-between">
            <span className="text-[11px] text-muted-foreground">Event record as received from the API</span>
            <Button variant="ghost" size="xs" onClick={copyRaw} className="text-muted-foreground">
              <Copy /> Copy
            </Button>
          </div>
          <pre className="surface-inset max-h-[55vh] overflow-auto rounded-lg p-3.5 font-mono text-[11px] leading-relaxed text-foreground/85">
            {JSON.stringify(e, null, 2)}
          </pre>
        </TabsContent>
      </Tabs>
    </>
  )
}
