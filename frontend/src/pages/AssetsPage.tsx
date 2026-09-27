import { useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Globe, Lock } from 'lucide-react'
import type { Asset, AssetCriticality, AssetExposure } from '@/api/types'
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
import { useQuery } from '@/hooks/useQuery'
import { ASSET_ICON, ASSET_TYPE_LABEL, CRITICALITY_TONE } from '@/lib/assets'
import { riskToSeverity, severityRowAccent, severityTone, toneStyles } from '@/lib/tones'
import { cn } from '@/lib/utils'
import { assetService } from '@/services'
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
  const [exposure, setExposure] = useState<AssetExposure | 'ALL'>('ALL')
  const [band, setBand] = useState<RiskBand>('ALL')

  const assets = useQuery('assets-all', assetService.list)
  const all = useMemo(() => assets.data ?? [], [assets.data])

  const inBand = (a: Asset, b: Exclude<RiskBand, 'ALL'>) => a.riskScore >= BAND[b][0] && a.riskScore < BAND[b][1]
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return all.filter(
      (a) =>
        (criticality === 'ALL' || a.criticality === criticality) &&
        (exposure === 'ALL' || a.exposure === exposure) &&
        (band === 'ALL' || inBand(a, band)) &&
        (!q || [a.name, a.hostname, a.ipAddress, a.owner, ...a.vulnerabilities.map((v) => v.cveId)].some((f) => f.toLowerCase().includes(q))),
    )
  }, [all, search, criticality, exposure, band])

  const selected = all.find((a) => a.id === params.get('asset'))
  const openAsset = (id: string | null) => {
    const next = new URLSearchParams(params)
    if (id) next.set('asset', id)
    else next.delete('asset')
    setParams(next, { replace: true })
  }

  const vulns = all.flatMap((a) => a.vulnerabilities)

  return (
    <PageContainer>
      <PageHeader
        title="Assets"
        description="Protected infrastructure and the business context NETRA uses to prioritise risk — criticality, exposure and open vulnerabilities. Open an asset for services, CVEs and incidents."
      />

      <MetricStrip
        metrics={[
          { label: 'Monitored assets', value: all.length || '—', hint: `${all.filter((a) => a.criticality === 'CRITICAL').length} rated critical` },
          { label: 'At risk', value: all.filter((a) => a.posture === 'AT_RISK').length, valueClassName: 'text-critical', hint: 'active incident, risk ≥ 75' },
          { label: 'Internet-exposed', value: all.filter((a) => a.exposure === 'EXTERNAL').length, valueClassName: 'text-high', hint: 'external attack surface' },
          {
            label: 'Open vulnerabilities',
            value: vulns.length,
            hint: `${vulns.filter((v) => v.cvss >= 9).length} with CVSS ≥ 9.0 · ${all.filter((a) => a.status === 'ISOLATED').length} isolated`,
          },
        ]}
      />

      <SurfaceCard flush className="overflow-hidden" data-guide-target="asset-inventory">
        <div className="flex flex-col gap-3 border-b border-border px-5 py-4">
          <div className="flex flex-wrap items-center gap-2">
            <SearchInput value={search} onChange={setSearch} placeholder="Search asset, host, IP, CVE…" className="w-full sm:w-80" />
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
                { value: 'EXTERNAL', label: 'External' },
                { value: 'INTERNAL', label: 'Internal' },
              ]}
            />
          </div>
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
        </div>

        {assets.error ? (
          <ErrorState onRetry={assets.reload} />
        ) : !assets.data ? (
          <LoadingState className="p-5" count={8} />
        ) : filtered.length === 0 ? (
          <EmptyState title="No assets match" description="Adjust the criticality, exposure or risk filters." />
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
              {filtered.map((a) => (
                <AssetRow key={a.id} asset={a} onOpen={() => openAsset(a.id)} active={selected?.id === a.id} />
              ))}
            </ul>
          </>
        )}
      </SurfaceCard>

      <AssetDetailSheet asset={selected} onClose={() => openAsset(null)} />
    </PageContainer>
  )
}

function AssetRow({ asset: a, onOpen, active }: { asset: Asset; onOpen: () => void; active: boolean }) {
  const Icon = ASSET_ICON[a.type]
  const riskTone = severityTone[riskToSeverity(a.riskScore)]
  const critical = a.criticality === 'CRITICAL'

  return (
    <li className="border-b border-border/70 last:border-b-0">
      <button
        type="button"
        onClick={onOpen}
        aria-label={`${a.name}, ${a.criticality.toLowerCase()} criticality, risk ${a.riskScore} — open details`}
        className={cn(
          'grid w-full grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 gap-y-2 px-5 py-3 text-left transition-colors outline-none hover:bg-foreground/2.5 focus-visible:bg-primary/6',
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
              <span className="font-mono">{a.hostname}</span> · {ASSET_TYPE_LABEL[a.type]}
              {a.vulnerabilities.length > 0 && (
                <span className="hidden xl:inline">
                  {' '}
                  · {a.vulnerabilities.length} CVE{a.vulnerabilities.length > 1 ? 's' : ''}
                </span>
              )}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2.5 max-lg:col-span-2 max-lg:row-start-2">
          <span className={cn('w-6 font-mono text-[13px] font-semibold tabular-nums', toneStyles[riskTone].text)}>{a.riskScore}</span>
          <MeterBar value={a.riskScore} tone={riskTone} className="max-w-40 flex-1" />
        </div>
        <span className="max-lg:hidden">
          <ToneBadge tone={CRITICALITY_TONE[a.criticality]} size="sm" className="bg-transparent capitalize">
            {a.criticality.toLowerCase()}
          </ToneBadge>
        </span>
        <span className={cn('inline-flex items-center gap-1.5 text-xs max-lg:hidden', a.exposure === 'EXTERNAL' ? 'text-high' : 'text-muted-foreground')}>
          {a.exposure === 'EXTERNAL' ? <Globe className="size-3.5" /> : <Lock className="size-3.5" />}
          {a.exposure === 'EXTERNAL' ? 'External' : 'Internal'}
        </span>
        <div className="flex justify-end max-lg:col-start-2 max-lg:row-start-1">
          <StatusBadge status={a.posture} size="sm" />
        </div>
      </button>
    </li>
  )
}
