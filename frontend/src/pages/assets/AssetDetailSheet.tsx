import type { AssetInventoryItem, BackendVulnerabilityResponse } from '@/api/types'
import { Link } from 'react-router-dom'
import { RiskTile } from '@/components/incidents/IncidentRow'
import { DetailSection, DetailSheet, EmptyState, ErrorState, KeyValueList, LoadingState, RiskScore, SeverityBadge, StatusBadge, ToneBadge } from '@/components/netra'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useQuery } from '@/hooks/useQuery'
import { ASSET_TYPE_LABEL, CRITICALITY_TONE } from '@/lib/assets'
import { timeAgo } from '@/lib/format'
import { ROUTES } from '@/lib/navigation'
import type { Tone } from '@/lib/tones'
import { cn } from '@/lib/utils'
import { assetVulnerabilityService, incidentService } from '@/services'
import { HttpError, USE_MOCKS } from '@/services/http'

export function AssetDetailSheet({ asset, assetId, loading, error, onRetry, onClose }: {
  asset?: AssetInventoryItem
  assetId: string | null
  loading: boolean
  error: Error | undefined
  onRetry: () => void
  onClose: () => void
}) {
  return (
    <DetailSheet
      open={!!assetId || !!asset}
      onOpenChange={(o) => !o && onClose()}
      eyebrow={asset ? `${asset.id} · ${asset.hostname ?? 'Hostname unavailable'}` : assetId ?? undefined}
      title={asset?.name ?? (loading ? 'Loading asset' : 'Asset details')}
      description={asset && [asset.operatingSystem, asset.owner ? `owned by ${asset.owner}` : null].filter(Boolean).join(' · ')}
    >
      {loading && !asset && <LoadingState variant="inline" label="Loading asset details…" />}
      {error && (
        <ErrorState
          title={error instanceof HttpError && error.status === 401 ? 'Authentication required' : 'Asset details unavailable'}
          message={error instanceof HttpError && error.status === 401 ? undefined : error.message}
          onRetry={error instanceof HttpError && error.status === 401 ? undefined : onRetry}
        />
      )}
      {error instanceof HttpError && error.status === 401 && (
        <div className="-mt-8 pb-8 text-center"><Button asChild><Link to={ROUTES.login}>Sign in</Link></Button></div>
      )}
      {asset && !error && <Body key={asset.id} asset={asset} />}
    </DetailSheet>
  )
}

/** Risk and prioritisation context first; technical inventory behind tabs. */
function Body({ asset: a }: { asset: AssetInventoryItem }) {
  const incidents = useQuery('asset-sheet-incidents', () =>
    USE_MOCKS ? incidentService.list({ pageSize: 500 }) : Promise.resolve(undefined),
  )
  const related = (incidents.data?.items ?? []).filter((i) => i.assetId === a.id)
  const vulnerabilityCount = a.vulnerabilities?.length ?? a.vulnerabilityCount

  return (
    <>
      <div className="flex items-center gap-5">
        {a.riskScore !== null ? (
          <RiskScore score={a.riskScore} size="sm" />
        ) : (
          <div className="grid size-[72px] shrink-0 place-items-center rounded-full border border-border text-center text-[10px] text-muted-foreground">
            Risk<br />unavailable
          </div>
        )}
        <div className="space-y-2">
          <div className="flex flex-wrap gap-2">
            {a.posture && <StatusBadge status={a.posture} />}
            {USE_MOCKS ? (
              <StatusBadge status={a.status as 'ONLINE' | 'ISOLATED' | 'OFFLINE'} />
            ) : (
              <ToneBadge tone="neutral" size="sm">{a.status.replaceAll('_', ' ').toLowerCase()}</ToneBadge>
            )}
          </div>
          <p className="text-xs text-muted-foreground">
            {a.activeIncidentIds === null
              ? 'Incident links are not provided by this endpoint.'
              : a.activeIncidentIds.length
              ? `Risk driven by ${a.activeIncidentIds.length} active incident${a.activeIncidentIds.length > 1 ? 's' : ''} on this asset.`
              : 'Residual risk from exposure and patch level — no active incident.'}
          </p>
        </div>
      </div>

      <DetailSection title="Context used for prioritisation">
        <KeyValueList
          columns={2}
          items={[
            { label: 'Asset type', value: a.type ? ASSET_TYPE_LABEL[a.type] : a.assetType?.replaceAll('_', ' ') ?? 'Not provided' },
            { label: 'Environment', value: a.environment ?? 'Not provided' },
            {
              label: 'Criticality',
              value: (
                <ToneBadge tone={CRITICALITY_TONE[a.criticality]} size="sm" className="capitalize">
                  {a.criticality.toLowerCase()}
                </ToneBadge>
              ),
            },
            {
              label: 'Exposure',
              value:
                a.exposure === 'EXTERNAL' || a.exposure === 'INTERNET_FACING'
                  ? a.exposure === 'EXTERNAL' ? 'Internet-exposed' : 'Internet-facing'
                  : a.exposure === 'DMZ'
                    ? 'DMZ'
                    : 'Internal',
            },
            { label: 'IP address', value: a.ipAddress ?? 'Not provided', mono: true },
            {
              label: a.lastSeen ? 'Last seen' : 'Updated',
              value: a.lastSeen ? timeAgo(a.lastSeen) : a.updatedAt ? timeAgo(a.updatedAt) : 'Not provided',
            },
          ]}
        />
      </DetailSection>

      <Tabs defaultValue="vulns" className="gap-4">
        <TabsList variant="line" className="w-full justify-start gap-0 border-b border-border pb-px">
          <TabsTrigger value="vulns" className="flex-none px-2.5 text-xs">
            Vulnerabilities · {vulnerabilityCount ?? '—'}
          </TabsTrigger>
          {a.services !== null && (
            <TabsTrigger value="services" className="flex-none px-2.5 text-xs">
              Services · {a.services.length}
            </TabsTrigger>
          )}
          {a.activeIncidentIds !== null && (
            <TabsTrigger value="incidents" className="flex-none px-2.5 text-xs">
              Incidents{incidents.data ? ` · ${related.length}` : ''}
            </TabsTrigger>
          )}
        </TabsList>

        <TabsContent value="vulns" className="motion-safe:animate-in motion-safe:fade-in-0">
          {!USE_MOCKS ? (
            <LiveVulnerabilities assetId={a.id} />
          ) : a.vulnerabilities === null ? (
            <p className="text-xs text-muted-foreground">
              {vulnerabilityCount === 0 ? 'No vulnerability records are linked.' : 'The endpoint provides a count only; vulnerability details are unavailable.'}
            </p>
          ) : a.vulnerabilities.length === 0 ? (
            <p className="text-xs text-muted-foreground">No open vulnerabilities.</p>
          ) : (
            <ul className="surface-inset divide-y divide-border/70 rounded-lg">
              {a.vulnerabilities.map((v) => (
                <li key={v.cveId} className="flex items-center gap-3 px-3.5 py-2.5">
                  <div className="min-w-0 flex-1">
                    <div className="font-mono text-xs">{v.cveId}</div>
                    <div className="truncate text-[11px] text-muted-foreground">{v.title}</div>
                  </div>
                  <span className={cn('font-mono text-sm font-semibold', v.cvss >= 9 ? 'text-critical' : v.cvss >= 7 ? 'text-high' : 'text-medium')}>
                    {v.cvss.toFixed(1)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </TabsContent>

        {a.services !== null && (
          <TabsContent value="services" className="motion-safe:animate-in motion-safe:fade-in-0">
            <div className="flex flex-wrap gap-1.5">
              {a.services.map((s) => (
                <span key={s} className="rounded-md border border-border bg-foreground/3 px-2 py-0.5 font-mono text-[11px] text-foreground/85">
                  {s}
                </span>
              ))}
            </div>
          </TabsContent>
        )}

        {a.activeIncidentIds !== null && (
          <TabsContent value="incidents" className="motion-safe:animate-in motion-safe:fade-in-0">
            {incidents.error ? (
              <ErrorState onRetry={incidents.reload} />
            ) : !incidents.data ? (
              <LoadingState count={2} />
            ) : related.length === 0 ? (
              <EmptyState title="No incidents for this asset" description="No incident records are linked to this asset in the current data set." className="py-8" />
            ) : (
              <ul className="surface-inset divide-y divide-border/70 overflow-hidden rounded-lg">
                {related.map((i) => (
                  <li key={i.id}>
                    <Link to={ROUTES.incident(i.id)} className="flex items-center gap-3 px-3.5 py-2.5 transition-colors hover:bg-foreground/3">
                      <RiskTile score={i.riskScore} severity={i.severity} />
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-[13px] font-medium">{i.threatName}</div>
                        <div className="mt-0.5 font-mono text-[11px] text-muted-foreground">
                          {i.id} · {timeAgo(i.lastSeen)}
                        </div>
                      </div>
                      <StatusBadge status={i.status} size="sm" />
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </TabsContent>
        )}
      </Tabs>
    </>
  )
}


const VULNERABILITY_STATUS_TONE: Record<BackendVulnerabilityResponse['status'], Tone> = {
  OPEN: 'high',
  ACCEPTED: 'medium',
  MITIGATED: 'low',
  FALSE_POSITIVE: 'neutral',
}

/** Live vulnerability records from GET /api/assets/{id}/vulnerabilities, highest CVSS first. */
function LiveVulnerabilities({ assetId }: { assetId: string }) {
  const vulnerabilities = useQuery(`asset-vulnerabilities-${assetId}`, () => assetVulnerabilityService.list(assetId))
  const error = vulnerabilities.error
  const unauthorized = error instanceof HttpError && error.status === 401
  const items = vulnerabilities.data

  if (error) {
    return (
      <div>
        <ErrorState
          title={unauthorized ? 'Authentication required' : 'Vulnerabilities unavailable'}
          message={unauthorized ? undefined : error.message}
          onRetry={unauthorized ? undefined : vulnerabilities.reload}
          className="py-8"
        />
        {unauthorized && (
          <div className="-mt-4 pb-6 text-center"><Button asChild><Link to={ROUTES.login}>Sign in</Link></Button></div>
        )}
      </div>
    )
  }
  if (!items) return <LoadingState count={3} label="Loading vulnerabilities…" />
  if (items.length === 0) return <p className="text-xs text-muted-foreground">No vulnerability records are linked.</p>

  return (
    <ul className="surface-inset divide-y divide-border/70 rounded-lg">
      {items.map((v) => (
        <li key={v.id} className="flex items-center gap-3 px-3.5 py-2.5">
          <div className="min-w-0 flex-1">
            <div className="font-mono text-xs">{v.cveId ?? 'No CVE identifier'}</div>
            <div className="truncate text-[11px] text-muted-foreground" title={v.description ?? v.title}>{v.title}</div>
          </div>
          <ToneBadge tone={VULNERABILITY_STATUS_TONE[v.status]} size="sm" className="capitalize">
            {v.status.replaceAll('_', ' ').toLowerCase()}
          </ToneBadge>
          {v.cvssScore === null ? (
            <SeverityBadge severity={v.severity} size="sm" />
          ) : (
            <span
              className={cn('font-mono text-sm font-semibold', v.cvssScore >= 9 ? 'text-critical' : v.cvssScore >= 7 ? 'text-high' : 'text-medium')}
              title={`CVSS ${v.cvssScore.toFixed(1)} · ${v.severity}`}
            >
              {v.cvssScore.toFixed(1)}
            </span>
          )}
        </li>
      ))}
    </ul>
  )
}
