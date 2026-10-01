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
import { http } from './http'

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
  getRiskTrend: async (_range: TrendRange): Promise<RiskTrendPoint[]> => [],
}