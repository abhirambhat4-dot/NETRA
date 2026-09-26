import { useState } from 'react'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import type { RiskTrendPoint, TrendRange } from '@/api/types'
import { ErrorState, LoadingState, Panel, SegmentedControl } from '@/components/netra'
import { useQuery } from '@/hooks/useQuery'
import { formatNumber } from '@/lib/format'
import { EVENT_SOURCES, detectionSourceMeta } from '@/lib/sources'
import { riskToSeverity, severityTone, toneStyles } from '@/lib/tones'
import { cn } from '@/lib/utils'
import { dashboardService } from '@/services'

interface Row {
  ts: string
  risk: number
  active: number
  SURICATA: number
  THREAT_INTEL: number
  ML_ANOMALY: number
}

const AXIS = { fill: 'var(--muted-foreground)', fontSize: 11 }
const GRID = 'rgb(148 163 184 / 0.08)'

function tickLabel(ts: string, range: TrendRange) {
  const d = new Date(ts)
  if (range === '24h') return `${d.toISOString().slice(11, 13)}:00`
  return `${d.getUTCDate()} ${d.toLocaleString('en-GB', { month: 'short', timeZone: 'UTC' })}`
}

function toRows(points: RiskTrendPoint[]): Row[] {
  return points.map((p) => ({ ts: p.timestamp, risk: p.riskScore, active: p.activeIncidents, ...p.events }))
}

export function RiskTrendPanel() {
  const [range, setRange] = useState<TrendRange>('24h')
  const { data, error, reload } = useQuery(`risk-trend-${range}`, () => dashboardService.getRiskTrend(range))
  const rows = data ? toRows(data) : []
  const totalEvents = rows.reduce((s, r) => s + r.SURICATA + r.THREAT_INTEL + r.ML_ANOMALY, 0)
  const peak = rows.reduce((m, r) => Math.max(m, r.risk), 0)

  return (
    <Panel
      title="System risk trend"
      description={range === '24h' ? 'Hourly, last 24 hours · UTC' : '6-hour buckets, last 7 days · UTC'}
      className="h-full"
      actions={
        <SegmentedControl
          aria-label="Time range"
          value={range}
          onChange={setRange}
          options={[
            { value: '24h', label: '24h' },
            { value: '7d', label: '7d' },
          ]}
        />
      }
    >
      {error ? (
        <ErrorState onRetry={reload} />
      ) : !data ? (
        <LoadingState variant="inline" label="Loading trend…" className="h-[360px]" />
      ) : (
        <div className="flex flex-col gap-4">
          <div className="flex flex-wrap gap-x-8 gap-y-2 text-xs">
            <Kpi label="Current" value={rows.at(-1)!.risk} tone />
            <Kpi label="Peak" value={peak} tone />
            <Kpi label="Detections" value={formatNumber(totalEvents)} />
          </div>

          {/* Risk line */}
          <div className="h-[220px] -ml-2">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={rows} syncId="netra-trend" margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
                <defs>
                  <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--primary)" stopOpacity={0.28} />
                    <stop offset="100%" stopColor="var(--primary)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid vertical={false} stroke={GRID} />
                <XAxis dataKey="ts" hide />
                <YAxis domain={[0, 100]} ticks={[0, 25, 50, 75, 100]} tick={AXIS} axisLine={false} tickLine={false} width={32} />
                <ReferenceLine y={85} stroke="var(--sev-critical)" strokeOpacity={0.55} strokeDasharray="4 4" label={{ value: 'Critical 85', position: 'insideTopRight', fill: 'var(--sev-critical)', fontSize: 10 }} />
                <ReferenceLine y={65} stroke="var(--sev-high)" strokeOpacity={0.45} strokeDasharray="4 4" label={{ value: 'High 65', position: 'insideTopRight', fill: 'var(--sev-high)', fontSize: 10 }} />
                <Tooltip
                  cursor={{ stroke: 'rgb(148 163 184 / 0.35)', strokeWidth: 1 }}
                  content={({ active, payload }) => <TrendTooltip active={active} row={payload?.[0]?.payload as Row | undefined} range={range} />}
                />
                <Area
                  type="monotone"
                  dataKey="risk"
                  stroke="var(--primary)"
                  strokeWidth={2}
                  fill="url(#riskFill)"
                  activeDot={{ r: 4.5, stroke: 'var(--surface)', strokeWidth: 2, fill: 'var(--primary)' }}
                  animationDuration={900}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Detection volume — separate chart, same x (no dual axis) */}
          <div>
            <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2">
              <span className="text-xs font-medium text-foreground/85">Detection volume</span>
              <div className="flex flex-wrap items-center gap-3">
                {EVENT_SOURCES.map((s) => (
                  <span key={s} className="inline-flex items-center gap-1.5 text-[11px] text-muted-foreground">
                    <span className={cn('size-2 rounded-xs', detectionSourceMeta[s].dot)} />
                    {detectionSourceMeta[s].short}
                  </span>
                ))}
              </div>
            </div>
            <div className="h-[96px] -ml-2">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={rows} syncId="netra-trend" margin={{ top: 4, right: 8, bottom: 0, left: 0 }} barCategoryGap="22%">
                  <CartesianGrid vertical={false} stroke={GRID} />
                  <XAxis dataKey="ts" tick={AXIS} axisLine={false} tickLine={false} tickFormatter={(ts: string) => tickLabel(ts, range)} interval={range === '24h' ? 3 : 3} minTickGap={16} />
                  <YAxis tick={AXIS} axisLine={false} tickLine={false} width={32} tickCount={3} tickFormatter={(v: number) => formatNumber(v)} />
                  <Tooltip cursor={{ fill: 'rgb(148 163 184 / 0.06)' }} content={({ active, payload }) => <TrendTooltip active={active} row={payload?.[0]?.payload as Row | undefined} range={range} />} />
                  {EVENT_SOURCES.map((s, i) => (
                    <Bar
                      key={s}
                      dataKey={s}
                      stackId="events"
                      fill={detectionSourceMeta[s].color}
                      stroke="var(--surface)"
                      strokeWidth={1}
                      radius={i === EVENT_SOURCES.length - 1 ? [2, 2, 0, 0] : 0}
                      animationDuration={700}
                    />
                  ))}
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}
    </Panel>
  )
}

function Kpi({ label, value, tone }: { label: string; value: number | string; tone?: boolean }) {
  const cls = tone && typeof value === 'number' ? toneStyles[severityTone[riskToSeverity(value)]].text : 'text-foreground'
  return (
    <div className="flex items-baseline gap-2">
      <span className="text-muted-foreground">{label}</span>
      <span className={cn('font-mono text-sm font-semibold tabular-nums', cls)}>{value}</span>
    </div>
  )
}

function TrendTooltip({ active, row, range }: { active?: boolean; row?: Row; range: TrendRange }) {
  if (!active || !row) return null
  const d = new Date(row.ts)
  const when =
    range === '24h'
      ? `${d.toISOString().slice(11, 16)} UTC`
      : `${tickLabel(row.ts, range)}, ${d.toISOString().slice(11, 16)} UTC`
  const sev = riskToSeverity(row.risk)
  return (
    <div className="min-w-44 rounded-lg border border-border bg-popover/95 px-3 py-2.5 text-xs shadow-xl backdrop-blur-md">
      <div className="mb-2 font-mono text-[11px] text-muted-foreground">{when}</div>
      <div className="flex items-center justify-between gap-6">
        <span className="text-muted-foreground">System risk</span>
        <span className={cn('font-mono font-semibold', toneStyles[severityTone[sev]].text)}>
          {row.risk} <span className="text-[10px] font-medium">{sev}</span>
        </span>
      </div>
      <div className="mt-1 flex items-center justify-between gap-6">
        <span className="text-muted-foreground">Active incidents</span>
        <span className="font-mono font-medium">{row.active}</span>
      </div>
      <div className="my-2 h-px bg-border" />
      {EVENT_SOURCES.map((s) => (
        <div key={s} className="mt-1 flex items-center justify-between gap-6">
          <span className="inline-flex items-center gap-1.5 text-muted-foreground">
            <span className={cn('size-2 rounded-xs', detectionSourceMeta[s].dot)} />
            {detectionSourceMeta[s].short}
          </span>
          <span className="font-mono">{formatNumber(row[s])}</span>
        </div>
      ))}
    </div>
  )
}
