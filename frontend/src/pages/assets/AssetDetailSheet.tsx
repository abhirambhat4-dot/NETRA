import type { Asset } from '@/api/types'
import { Link } from 'react-router-dom'
import { RiskTile } from '@/components/incidents/IncidentRow'
import { DetailSection, DetailSheet, KeyValueList, LoadingState, RiskScore, StatusBadge, ToneBadge } from '@/components/netra'
import { useQuery } from '@/hooks/useQuery'
import { CRITICALITY_TONE } from '@/lib/assets'
import { timeAgo } from '@/lib/format'
import { ROUTES } from '@/lib/navigation'
import { cn } from '@/lib/utils'
import { incidentService } from '@/services'

export function AssetDetailSheet({ asset, onClose }: { asset?: Asset; onClose: () => void }) {
  return (
    <DetailSheet
      open={!!asset}
      onOpenChange={(o) => !o && onClose()}
      eyebrow={asset && `${asset.id} · ${asset.hostname}`}
      title={asset?.name ?? ''}
      description={asset && `${asset.operatingSystem} · owned by ${asset.owner}`}
    >
      {asset && <Body asset={asset} />}
    </DetailSheet>
  )
}

function Body({ asset: a }: { asset: Asset }) {
  const incidents = useQuery('asset-sheet-incidents', () => incidentService.list({ pageSize: 500 }))
  const related = (incidents.data?.items ?? []).filter((i) => i.assetId === a.id)

  return (
    <>
      <div className="flex items-center gap-5">
        <RiskScore score={a.riskScore} size="sm" />
        <div className="space-y-2">
          <div className="flex flex-wrap gap-2">
            <StatusBadge status={a.posture} />
            <StatusBadge status={a.status} />
          </div>
          <p className="text-xs text-muted-foreground">
            {a.activeIncidentIds.length
              ? `Risk driven by ${a.activeIncidentIds.length} active incident${a.activeIncidentIds.length > 1 ? 's' : ''} on this asset.`
              : 'Residual risk from exposure and patch level — no active incident.'}
          </p>
        </div>
      </div>

      <DetailSection title="Context used for prioritisation">
        <KeyValueList
          columns={2}
          items={[
            {
              label: 'Criticality',
              value: (
                <ToneBadge tone={CRITICALITY_TONE[a.criticality]} size="sm" className="capitalize">
                  {a.criticality.toLowerCase()}
                </ToneBadge>
              ),
            },
            { label: 'Exposure', value: a.exposure === 'EXTERNAL' ? 'Internet-exposed' : 'Internal only' },
            { label: 'IP address', value: a.ipAddress, mono: true },
            { label: 'Last seen', value: timeAgo(a.lastSeen) },
          ]}
        />
      </DetailSection>

      <DetailSection title="Services">
        <div className="flex flex-wrap gap-1.5">
          {a.services.map((s) => (
            <span key={s} className="rounded-md border border-border bg-foreground/3 px-2 py-0.5 font-mono text-[11px] text-foreground/85">
              {s}
            </span>
          ))}
        </div>
      </DetailSection>

      <DetailSection title={`Vulnerabilities (${a.vulnerabilities.length})`}>
        {a.vulnerabilities.length === 0 ? (
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
      </DetailSection>

      <DetailSection title="Incidents on this asset">
        {!incidents.data ? (
          <LoadingState count={2} />
        ) : related.length === 0 ? (
          <p className="text-xs text-muted-foreground">No incidents recorded.</p>
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
      </DetailSection>
    </>
  )
}
