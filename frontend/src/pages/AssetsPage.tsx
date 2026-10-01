import { useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Boxes, Globe, Lock } from 'lucide-react'
import type { AssetCriticality, AssetExposure, AssetInventoryItem, BackendAssetExposure } from '@/api/types'
import {
  EmptyState,
  ErrorState,
  FilterChips,
  LoadingState,
  MeterBar,
  MetricStrip,
  PageContainer,
  PageHeader,
  SearchInput,
  SelectFilter,
  StatusBadge,
  SurfaceCard,
  ToneBadge,
} from '@/components/netra'
import { Button } from '@/components/ui/button'
import { useQuery } from '@/hooks/useQuery'
import { useCountUp } from '@/hooks/useCountUp'
import { ASSET_ICON, ASSET_TYPE_LABEL, CRITICALITY_TONE } from '@/lib/assets'
import { ROUTES } from '@/lib/navigation'
import { riskToSeverity, severityRowAccent, severityTone, toneStyles } from '@/lib/tones'
import { cn } from '@/lib/utils'
import { assetInventoryService } from '@/services'
import { HttpError, USE_MOCKS } from '@/services/http'
import { AssetDetailSheet } from './assets/AssetDetailSheet'

type RiskBand = 'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
const BAND: Record<Exclude<RiskBand, 'ALL'>, [number, number]> = {
  CRITICAL: [85, 101],
  HIGH: [65, 85],
  MEDIUM: [40, 65],
  LOW: [0, 40],
}

// Asset · Risk · Criticality · Exposure · Status — vulnerabilities, services and incidents live in the drawer.
const COLS = 'lg:grid-cols-[minmax(0,1.8fr)_minmax(140px,1fr)_100px_100px_104px]'

export function AssetsPage() {
  const [params, setParams] = useSearchParams()
  const [search, setSearch] = useState('')
  const [criticality, setCriticality] = useState<AssetCriticality | 'ALL'>('ALL')
  const [exposure, setExposure] = useState<AssetExposure | BackendAssetExposure | 'ALL'>('ALL')
  const [band, setBand] = useState<RiskBand>('ALL')

  const queryKey = JSON.stringify([search, criticality, exposure])
  const assets = useQuery(`assets-${USE_MOCKS ? 'mock' : queryKey}`, () =>
    assetInventoryService.list(
      USE_MOCKS
        ? undefined
        : {
            search: search.trim() || undefined,
            criticality: criticality === 'ALL' ? undefined : criticality,
            exposure:
              exposure === 'ALL'
                ? undefined
                : exposure === 'EXTERNAL'
                  ? 'INTERNET_FACING'
                  : exposure,
          },
    ),
  )
  // Live filters run server-side, so inventory metrics come from an unfiltered read.
  const inventory = useQuery(`assets-inventory-${USE_MOCKS ? 'mock' : 'live'}`, () =>
    USE_MOCKS ? Promise.resolve(undefined) : assetInventoryService.list(),
  )
  const all = useMemo(() => assets.data ?? [], [assets.data])
  const metricSource = USE_MOCKS ? assets.data : inventory.data
  const selectedId = params.get('asset')
  const listedSelection = all.find((a) => a.id === selectedId)
  const selectedDetail = useQuery(`asset-detail-${USE_MOCKS ? 'mock' : selectedId ?? 'none'}`, () =>
    !USE_MOCKS && selectedId ? assetInventoryService.get(selectedId) : Promise.resolve(undefined),
  )
  const selected = USE_MOCKS
    ? listedSelection
    : selectedDetail.data?.id === selectedId
      ? selectedDetail.data
      : listedSelection

  const inBand = (a: AssetInventoryItem, b: Exclude<RiskBand, 'ALL'>) =>
    a.riskScore !== null && a.riskScore >= BAND[b][0] && a.riskScore < BAND[b][1]
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return all.filter(
      (a) =>
        (criticality === 'ALL' || a.criticality === criticality) &&
        (exposure === 'ALL' || a.exposure === exposure) &&
        (USE_MOCKS && band !== 'ALL' ? inBand(a, band) : true) &&
        (USE_MOCKS && q
          ? [a.name, a.hostname, a.ipAddress, a.owner, ...(a.vulnerabilities ?? []).map((v) => v.cveId)]
              .some((f) => f?.toLowerCase().includes(q))
          : true),
    )
  }, [all, search, criticality, exposure, band])

  const openAsset = (id: string | null) => {
    const next = new URLSearchParams(params)
    if (id) next.set('asset', id)
    else next.delete('asset')
    setParams(next, { replace: true })
  }

  const metricAssets = metricSource ?? []
  const criticalCount = metricAssets.filter((asset) => asset.criticality === 'CRITICAL').length
  const exposedCount = metricAssets.filter((asset) => asset.exposure !== 'INTERNAL').length
  const attentionCount = metricAssets.filter((asset) => asset.posture === 'AT_RISK').length
  const totalAnimated = useCountUp(metricAssets.length, 650)
  const criticalAnimated = useCountUp(criticalCount, 650)
  const exposedAnimated = useCountUp(exposedCount, 650)
  const attentionAnimated = useCountUp(attentionCount, 650)

  return (
    <PageContainer>
      <PageHeader
        title="Assets"
        description={USE_MOCKS
          ? 'Protected infrastructure and the business context NETRA uses to prioritise risk — criticality, exposure and open vulnerabilities. Open an asset for services, CVEs and incidents.'
          : 'Registered infrastructure with backend-reported owner, type, criticality, exposure, lifecycle status and vulnerability counts.'}
      />

      <MetricStrip
        metrics={[
          { label: 'Total assets', value: metricSource ? Math.round(totalAnimated) : '—', hint: `${USE_MOCKS ? 'interconnected mock inventory' : 'registered inventory'}` },
          { label: 'Critical assets', value: metricSource ? Math.round(criticalAnimated) : '—', valueClassName: 'text-critical', hint: 'rated critical by the inventory' },
          { label: 'Exposed assets', value: metricSource ? Math.round(exposedAnimated) : '—', valueClassName: 'text-high', hint: 'external or DMZ perimeter' },
          { label: 'Require attention', value: metricSource ? USE_MOCKS ? Math.round(attentionAnimated) : '—' : '—', valueClassName: 'text-medium', hint: USE_MOCKS ? 'NETRA at-risk posture' : 'posture not returned by this endpoint' },
        ]}
      />

      <SurfaceCard flush className="overflow-hidden" data-guide-target="asset-inventory">
        <div className="flex flex-col gap-3 border-b border-border px-5 py-4">
          <div className="flex flex-wrap items-center gap-2">
            <SearchInput value={search} onChange={setSearch} placeholder={USE_MOCKS ? 'Search asset, host, IP, CVE…' : 'Search name, host, IP, owner…'} className="w-full sm:w-80" />
            <SelectFilter
              label="Criticality"
              value={criticality}
              onChange={setCriticality}
              options={[
                { value: 'ALL', label: 'All' },
                { value: 'CRITICAL', label: 'Critical' },
                { value: 'HIGH', label: 'High' },
                { value: 'MEDIUM', label: 'Medium' },
                { value: 'LOW', label: 'Low' },
              ]}
            />
            <SelectFilter
              label="Exposure"
              value={exposure}
              onChange={setExposure}
              options={[
                { value: 'ALL', label: 'All' },
                ...(USE_MOCKS
                  ? [
                      { value: 'EXTERNAL' as const, label: 'External' },
                      { value: 'INTERNAL' as const, label: 'Internal' },
                    ]
                  : [
                      { value: 'INTERNET_FACING' as const, label: 'Internet-facing' },
                      { value: 'DMZ' as const, label: 'DMZ' },
                      { value: 'INTERNAL' as const, label: 'Internal' },
                    ]),
              ]}
            />
          </div>
          {USE_MOCKS && (
            <FilterChips
              aria-label="Risk band"
              value={band}
              onChange={setBand}
              options={[
                { value: 'ALL', label: 'Any risk', count: all.length },
                { value: 'CRITICAL', label: 'Critical ≥85', count: all.filter((a) => inBand(a, 'CRITICAL')).length, dot: 'bg-critical' },
                { value: 'HIGH', label: 'High 65–84', count: all.filter((a) => inBand(a, 'HIGH')).length, dot: 'bg-high' },
                { value: 'MEDIUM', label: 'Medium 40–64', count: all.filter((a) => inBand(a, 'MEDIUM')).length, dot: 'bg-medium' },
                { value: 'LOW', label: 'Low <40', count: all.filter((a) => inBand(a, 'LOW')).length, dot: 'bg-low' },
              ]}
            />
          )}
        </div>

        {assets.error ? (
          <div>
            <ErrorState
              title={assets.error instanceof HttpError && assets.error.status === 401 ? 'Authentication required' : 'Assets unavailable'}
              message={assets.error instanceof HttpError && assets.error.status === 401 ? undefined : assets.error.message}
              onRetry={assets.error instanceof HttpError && assets.error.status === 401 ? undefined : assets.reload}
            />
            {assets.error instanceof HttpError && assets.error.status === 401 && (
              <div className="-mt-8 pb-8 text-center"><Button asChild><Link to={ROUTES.login}>Sign in</Link></Button></div>
            )}
          </div>
        ) : !assets.data ? (
          <LoadingState className="p-5" count={8} />
        ) : filtered.length === 0 ? (
          <EmptyState
            title={(metricSource ?? all).length ? 'No assets match' : 'No assets available'}
            description={(metricSource ?? all).length
              ? USE_MOCKS ? 'Adjust the criticality, exposure or risk filters.' : 'Adjust the criticality, exposure or search filters.'
              : 'No registered assets are available from the current inventory.'}
          />
        ) : (
          <>
            <div className={cn('hidden gap-4 border-b border-border px-5 py-2.5 text-[11px] font-medium text-muted-foreground lg:grid', COLS)}>
              <span>Asset</span>
              <span>Risk score</span>
              <span>Criticality</span>
              <span>Exposure</span>
              <span className="text-right">Status</span>
            </div>
            <ul>
              {filtered.map((a, index) => (
                <AssetRow key={a.id} asset={a} onOpen={() => openAsset(a.id)} active={selected?.id === a.id} entryIndex={index} />
              ))}
            </ul>
          </>
        )}
      </SurfaceCard>

      <AssetDetailSheet
        asset={selected}
        assetId={selectedId}
        loading={selectedDetail.loading}
        error={selectedDetail.error}
        onRetry={selectedDetail.reload}
        onClose={() => openAsset(null)}
      />
    </PageContainer>
  )
}

function AssetRow({ asset: a, onOpen, active, entryIndex }: { asset: AssetInventoryItem; onOpen: () => void; active: boolean; entryIndex: number }) {
  const Icon = a.type ? ASSET_ICON[a.type] : Boxes
  const riskTone = a.riskScore === null ? null : severityTone[riskToSeverity(a.riskScore)]
  const critical = a.criticality === 'CRITICAL'
  const vulnerabilityCount = a.vulnerabilities?.length ?? a.vulnerabilityCount ?? 0
  const typeLabel = a.type ? ASSET_TYPE_LABEL[a.type] : a.assetType?.replaceAll('_', ' ').toLowerCase() ?? 'Asset'

  return (
    <li
      className="border-b border-border/70 last:border-b-0 motion-safe:animate-in motion-safe:fade-in-0 motion-safe:slide-in-from-bottom-1"
      style={{ animationDelay: `${Math.min(entryIndex, 8) * 35}ms` }}
    >
      <button
        type="button"
        onClick={onOpen}
        aria-label={`${a.name}, ${a.criticality.toLowerCase()} criticality${a.riskScore === null ? '' : `, risk ${a.riskScore}`} — open details`}
        className={cn(
          'group grid w-full grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 gap-y-2 px-5 py-3 text-left transition-colors outline-none hover:bg-foreground/2.5 focus-visible:bg-primary/6',
          COLS,
          critical && severityRowAccent.CRITICAL,
          active && 'bg-primary/6',
        )}
      >
        <div className="flex min-w-0 items-center gap-3">
          <span
            className={cn(
              'grid size-9 shrink-0 place-items-center rounded-md',
              critical ? 'border border-critical/25 bg-critical/8 text-critical' : 'surface-inset text-muted-foreground',
            )}
          >
            <Icon className="size-4" />
          </span>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="truncate text-[13px] font-medium">{a.name}</span>
              {a.status === 'ISOLATED' && <StatusBadge status="ISOLATED" size="sm" />}
            </div>
            <div className="truncate text-[11px] text-muted-foreground">
              <span className="font-mono">{a.hostname ?? 'Hostname unavailable'}</span> · {typeLabel}{a.environment ? ` · ${a.environment}` : ''}
              {vulnerabilityCount > 0 && (
                <span className="hidden xl:inline">
                  {' '}· {vulnerabilityCount} {USE_MOCKS ? `CVE${vulnerabilityCount > 1 ? 's' : ''}` : 'vulnerabilities'}
                </span>
              )}
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-x-1.5 text-[10px] text-muted-foreground lg:hidden">
              <span>{a.criticality.toLowerCase()} criticality</span>
              <span aria-hidden>·</span>
              <span>{a.exposure === 'EXTERNAL' || a.exposure === 'INTERNET_FACING' ? 'internet-exposed' : a.exposure === 'DMZ' ? 'DMZ' : 'internal'}</span>
              {a.ipAddress && <><span aria-hidden>·</span><span className="font-mono">{a.ipAddress}</span></>}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2.5 max-lg:col-span-2 max-lg:row-start-2">
          {a.riskScore === null ? (
            <span className="text-xs text-muted-foreground">Risk unavailable</span>
          ) : (
            <>
              <span className={cn('w-6 font-mono text-[13px] font-semibold tabular-nums', toneStyles[riskTone!].text)}>{a.riskScore}</span>
              <MeterBar value={a.riskScore} tone={riskTone!} className="max-w-40 flex-1" />
            </>
          )}
        </div>
        <span className="max-lg:hidden">
          <ToneBadge tone={CRITICALITY_TONE[a.criticality]} size="sm" className="bg-transparent capitalize">
            {a.criticality.toLowerCase()}
          </ToneBadge>
        </span>
        <span className={cn('inline-flex items-center gap-1.5 text-xs max-lg:hidden', a.exposure === 'EXTERNAL' || a.exposure === 'INTERNET_FACING' ? 'text-high' : 'text-muted-foreground')}>
          {a.exposure === 'EXTERNAL' || a.exposure === 'INTERNET_FACING' || a.exposure === 'DMZ' ? <Globe className="size-3.5" /> : <Lock className="size-3.5" />}
          {a.exposure === 'EXTERNAL' ? 'External' : a.exposure === 'INTERNET_FACING' ? 'Internet-facing' : a.exposure === 'DMZ' ? 'DMZ' : 'Internal'}
        </span>
        <div className="flex justify-end max-lg:col-start-2 max-lg:row-start-1">
          {a.posture ? (
            <StatusBadge status={a.posture} size="sm" />
          ) : a.status === 'ACTIVE' ? (
            <span className="rounded-md border border-border px-1.5 py-0.5 text-[10px] text-muted-foreground">Active</span>
          ) : a.status === 'INACTIVE' || a.status === 'DECOMMISSIONED' ? (
            <span className="rounded-md border border-border px-1.5 py-0.5 text-[10px] text-muted-foreground">{a.status === 'INACTIVE' ? 'Inactive' : 'Decommissioned'}</span>
          ) : (
            <StatusBadge status={a.status} size="sm" />
          )}
        </div>
      </button>
    </li>
  )
}
