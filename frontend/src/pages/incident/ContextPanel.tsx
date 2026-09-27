import { Link } from 'react-router-dom'
import { Globe, Lock } from 'lucide-react'
import type { IncidentDetail, ThreatIndicator } from '@/api/types'
import { SeverityBadge, StatusBadge, ToneBadge } from '@/components/netra'
import { ASSET_ICON, CRITICALITY_TONE } from '@/lib/assets'
import { defang, shortHash } from '@/lib/defang'
import { ROUTES } from '@/lib/navigation'
import { cn } from '@/lib/utils'

/** Asset, exposure and open vulnerabilities (Attack & behaviour → Asset tab). */
export function AssetContext({ detail: d }: { detail: IncidentDetail }) {
  const a = d.asset
  const Icon = ASSET_ICON[a.type]

  return (
    <Link to={`${ROUTES.assets}?asset=${a.id}`} className="surface-inset group block rounded-lg p-4 transition-colors hover:border-primary/25">
      <div className="flex items-start gap-3">
        <span className="grid size-9 shrink-0 place-items-center rounded-md bg-foreground/5 text-muted-foreground">
          <Icon className="size-4.5" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center justify-between gap-2">
            <span className="truncate text-sm font-medium group-hover:text-primary">{a.name}</span>
            <StatusBadge status={a.posture} size="sm" />
          </div>
          <div className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">
            {a.hostname} · {a.ipAddress}
          </div>
        </div>
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-2 text-[11px]">
        <ToneBadge tone={CRITICALITY_TONE[a.criticality]} size="sm" className="capitalize">
          {a.criticality.toLowerCase()} criticality
        </ToneBadge>
        <span className={cn('inline-flex items-center gap-1', a.exposure === 'EXTERNAL' ? 'text-high' : 'text-muted-foreground')}>
          {a.exposure === 'EXTERNAL' ? <Globe className="size-3.5" /> : <Lock className="size-3.5" />}
          {a.exposure === 'EXTERNAL' ? 'Internet-exposed' : 'Internal only'}
        </span>
        <span className="text-muted-foreground">· {a.owner}</span>
      </div>
      <div className="mt-3 space-y-1.5 border-t border-border pt-3">
        {a.vulnerabilities.length === 0 ? (
          <div className="text-[11px] text-muted-foreground">No open vulnerabilities</div>
        ) : (
          a.vulnerabilities.map((v) => (
            <div key={v.cveId} className="flex items-center gap-2 text-[11px]">
              <span className="font-mono text-foreground/85">{v.cveId}</span>
              <span className="min-w-0 flex-1 truncate text-muted-foreground">{v.title}</span>
              <span className={cn('font-mono font-semibold', v.cvss >= 9 ? 'text-critical' : v.cvss >= 7 ? 'text-high' : 'text-medium')}>
                {v.cvss.toFixed(1)}
              </span>
            </div>
          ))
        )}
      </div>
    </Link>
  )
}

/** MITRE ATT&CK mapping (Attack & behaviour → ATT&CK tab). */
export function TechniqueContext({ detail: d }: { detail: IncidentDetail }) {
  const t = d.mitreTechnique
  return (
    <div className="surface-inset rounded-lg p-4">
      <div className="text-[11px] text-muted-foreground">MITRE ATT&CK technique</div>
      {t ? (
        <>
          <div className="mt-1.5 flex flex-wrap items-center gap-2">
            <span className="rounded-md border border-primary/20 bg-primary/8 px-1.5 py-0.5 font-mono text-xs font-medium text-primary">{t.id}</span>
            <span className="text-sm font-medium">{t.name}</span>
            <span className="text-[11px] text-violet">· {t.tactic}</span>
          </div>
          <p className="mt-2 max-w-2xl text-xs leading-relaxed text-muted-foreground">{t.description}</p>
          <a href={t.url} target="_blank" rel="noreferrer" className="mt-2 inline-block text-[11px] text-muted-foreground transition-colors hover:text-primary">
            attack.mitre.org ↗
          </a>
        </>
      ) : (
        <div className="mt-1 text-xs text-muted-foreground">Not mapped</div>
      )}
    </div>
  )
}

/** Threat-intelligence indicators matched to this incident (Attack & behaviour → Threat intel tab). */
export function IntelMatches({ indicators }: { indicators: ThreatIndicator[] }) {
  return (
    <div>
      <div className="mb-2 flex items-center justify-between text-xs">
        <span className="font-medium text-foreground/85">Threat-intelligence matches</span>
        <Link to={ROUTES.threatIntelligence} className="text-muted-foreground transition-colors hover:text-primary">
          Threat Intelligence →
        </Link>
      </div>
      {indicators.length === 0 ? (
        <div className="surface-inset rounded-lg px-3.5 py-3 text-xs text-muted-foreground">
          No indicator matched — risk relies on behaviour and asset context.
        </div>
      ) : (
        <ul className="surface-inset divide-y divide-border/70 rounded-lg">
          {indicators.map((ind) => (
            <li key={ind.id} className="flex items-center gap-3 px-3.5 py-2.5">
              <span className="w-14 shrink-0 text-[10px] font-semibold tracking-wider text-muted-foreground">{ind.type}</span>
              <span className="min-w-0 flex-1 truncate font-mono text-xs" title={ind.description}>
                {ind.type === 'HASH' ? shortHash(ind.value) : defang(ind.value, ind.type)}
              </span>
              <span className="hidden text-[11px] text-muted-foreground sm:inline">{ind.source}</span>
              <span className="font-mono text-[11px] text-foreground/85">{Math.round(ind.confidence * 100)}%</span>
              <SeverityBadge severity={ind.severity} size="sm" />
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
