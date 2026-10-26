import type {
  BackendDatabaseHealthResponse,
  DashboardStats,
  HealthStatus,
  RiskFactor,
  RiskTrendPoint,
  Severity,
  SystemComponentHealth,
  TrendRange,
} from '@/api/types'
import { adaptRiskTrend, type BackendRiskTrendPoint } from '@/lib/riskTrend'
import type { HealthOutcome } from '@/lib/workspaceStatus'
import { HttpError, http } from './http'

/** A health request's outcome, without judging it: the body whenever the API answered. */
async function healthOutcome(path: string): Promise<HealthOutcome> {
  try {
    return { responded: true, ok: true, status: 200, body: await http.get<unknown>(path) }
  } catch (error) {
    if (error instanceof HttpError) return { responded: true, ok: false, status: error.status, body: error.body }
    return { responded: false }
  }
}

interface BackendDashboardStats {
  totalSecurityEvents: number
  criticalEvents: number
  highEvents: number
  activeIncidents: number
  criticalIncidents: number
  averageRiskScore: number | null
  currentRiskScore: number | null
  assetCount: number
  criticalAssetCount: number
  threatIndicatorCount: number
  recentEvents24h: number
  recentIncidents24h: number
}

const EMPTY_RISK_DRIVERS: RiskFactor[] = []

function adaptDashboardStats(response: BackendDashboardStats): DashboardStats {
  const incidentsBySeverity: Record<Severity, number | null> = {
    CRITICAL: response.criticalIncidents,
    HIGH: null,
    MEDIUM: null,
    LOW: null,
    INFO: null,
  }

  return {
    overallRisk: response.currentRiskScore,
    averageRiskScore: response.averageRiskScore,
    overallRiskLevel: null,
    overallRiskChange: null,
    incidentsBySeverity,
    activeIncidents: response.activeIncidents,
    criticalThreats: null,
    containedThreats: null,
    assetsAtRisk: null,
    totalAssets: response.assetCount,
    criticalAssets: response.criticalAssetCount,
    eventsLast24h: response.recentEvents24h,
    criticalEvents: response.criticalEvents,
    highEvents: response.highEvents,
    riskDrivers: EMPTY_RISK_DRIVERS,
    systemHealth: [],
  }
}

export const liveDashboardService = {
  getStats: async (): Promise<DashboardStats> =>
    adaptDashboardStats(await http.get<BackendDashboardStats>('/dashboard/stats')),
  getDatabaseHealth: (): Promise<BackendDatabaseHealthResponse> =>
    http.get<BackendDatabaseHealthResponse>('/health/db'),
  /** API + database status from the backend health endpoints; rejects when the API is unreachable. */
  getSystemHealth: async (): Promise<Array<Pick<SystemComponentHealth, 'name' | 'status'>>> => {
    const [, database] = await Promise.all([
      http.get('/health'),
      http.get<BackendDatabaseHealthResponse>('/health/db').then(
        (response): HealthStatus => (response.status === 'healthy' ? 'HEALTHY' : 'DOWN'),
        // /health/db answers 503 when the database is unreachable.
        (): HealthStatus => 'DOWN',
      ),
    ])
    return [
      { name: 'API', status: 'HEALTHY' },
      { name: 'Database', status: database },
    ]
  },
  /** Raw /health and /health/db outcomes, each kept separate; see lib/workspaceStatus.ts for how they are read. */
  getHealthChecks: async (): Promise<{ api: HealthOutcome; database: HealthOutcome }> => {
    const [api, database] = await Promise.all([healthOutcome('/health'), healthOutcome('/health/db')])
    return { api, database }
  },
  /** Reconstructed from stored incident history and risk evaluations (GET /dashboard/risk-trend); read-only. */
  getRiskTrend: async (range: TrendRange): Promise<RiskTrendPoint[]> =>
    adaptRiskTrend(await http.get<BackendRiskTrendPoint[]>('/dashboard/risk-trend', { range })),
}