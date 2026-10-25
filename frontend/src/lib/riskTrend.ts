// Dependency-free so it runs under `node --test` (tests/riskTrend.test.ts).

/** One bucket as GET /api/dashboard/risk-trend returns it (events keyed by every backend detection source). */
export interface BackendRiskTrendPoint {
  timestamp: string
  riskScore: number | null
  activeIncidents: number
  scoredIncidents: number
  events: Record<string, number>
}

/** The sources the trend chart plots; other backend sources (manual, scans, dataset imports) are not charted. */
export const CHARTED_TREND_SOURCES = ['SURICATA', 'THREAT_INTEL', 'ML_ANOMALY'] as const

export interface AdaptedRiskTrendPoint {
  timestamp: string
  /** Average risk of incidents active at the bucket end; null when none was scored (never shown as 0). */
  riskScore: number | null
  activeIncidents: number
  events: Record<(typeof CHARTED_TREND_SOURCES)[number], number>
}

const count = (value: unknown): number => (typeof value === 'number' && Number.isFinite(value) ? value : 0)

export function adaptRiskTrend(points: BackendRiskTrendPoint[]): AdaptedRiskTrendPoint[] {
  return points.map((point) => ({
    timestamp: point.timestamp,
    riskScore: typeof point.riskScore === 'number' && Number.isFinite(point.riskScore) ? point.riskScore : null,
    activeIncidents: count(point.activeIncidents),
    events: {
      SURICATA: count(point.events?.SURICATA),
      THREAT_INTEL: count(point.events?.THREAT_INTEL),
      ML_ANOMALY: count(point.events?.ML_ANOMALY),
    },
  }))
}
