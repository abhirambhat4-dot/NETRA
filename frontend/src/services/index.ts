import type {
  Asset,
  Authorization,
  ContainmentAction,
  CyberMemoryEntry,
  DashboardStats,
  Incident,
  IncidentDetail,
  IncidentFilters,
  PaginatedResponse,
  RiskTrendPoint,
  SecurityEvent,
  SecurityEventFilters,
  SystemComponentHealth,
  TechniqueObservation,
  ThreatIndicator,
  TrendRange,
} from '@/api/types'
import { mockApi } from '@/mocks/api'
import { DEMO_OTP } from '@/mocks/db'
import { USE_MOCKS, http } from './http'

/**
 * NETRA service layer — the ONLY place pages get data from.
 * Each function maps 1:1 to an endpoint in docs/ARCHITECTURE.md.
 * Flip VITE_USE_MOCKS=false to hit FastAPI; the UI does not change.
 */

export const DATA_CHANGED_EVENT = 'netra:data-changed'

/** Demo OTP shown in the UI while running on mock data (null against the real API). */
export const DEMO_OTP_HINT: string | null = USE_MOCKS ? DEMO_OTP : null

/** After a mutation, tell every mounted query to refetch. */
async function mutate<T>(request: Promise<T>): Promise<T> {
  const result = await request
  window.dispatchEvent(new Event(DATA_CHANGED_EVENT))
  return result
}

export const dashboardService = {
  getStats: (): Promise<DashboardStats> =>
    USE_MOCKS ? mockApi.getDashboardStats() : http.get('/dashboard/stats'),
  getRiskTrend: (range: TrendRange): Promise<RiskTrendPoint[]> =>
    USE_MOCKS ? mockApi.getRiskTrend(range) : http.get('/dashboard/risk-trend', { range }),
  getSystemHealth: (): Promise<SystemComponentHealth[]> =>
    USE_MOCKS ? mockApi.getSystemHealth() : http.get('/system/health'),
}

export const incidentService = {
  list: (filters?: IncidentFilters): Promise<PaginatedResponse<Incident>> =>
    USE_MOCKS ? mockApi.listIncidents(filters) : http.get('/incidents', filters),
  get: (id: string): Promise<IncidentDetail> =>
    USE_MOCKS ? mockApi.getIncident(id) : http.get(`/incidents/${id}`),
}

export const eventService = {
  list: (filters?: SecurityEventFilters): Promise<PaginatedResponse<SecurityEvent>> =>
    USE_MOCKS ? mockApi.listEvents(filters) : http.get('/events', filters),
}

export const assetService = {
  list: (): Promise<Asset[]> => (USE_MOCKS ? mockApi.listAssets() : http.get('/assets')),
  get: (id: string): Promise<Asset> => (USE_MOCKS ? mockApi.getAsset(id) : http.get(`/assets/${id}`)),
}

export const threatIntelService = {
  getObservedTechniques: (): Promise<TechniqueObservation[]> =>
    USE_MOCKS ? mockApi.getObservedTechniques() : http.get('/threat-intel/observed'),
  listIndicators: (): Promise<ThreatIndicator[]> =>
    USE_MOCKS ? mockApi.listIndicators() : http.get('/threat-intel/indicators'),
}

export const memoryService = {
  list: (): Promise<CyberMemoryEntry[]> => (USE_MOCKS ? mockApi.listMemory() : http.get('/memory')),
}

export const authorizationService = {
  request: (incidentId: string): Promise<Authorization> =>
    mutate(USE_MOCKS ? mockApi.requestAuthorization(incidentId) : http.post(`/incidents/${incidentId}/authorization`)),
  verifyOtp: (authorizationId: string, otp: string): Promise<Authorization> =>
    mutate(
      USE_MOCKS
        ? mockApi.verifyOtp(authorizationId, otp)
        : http.post(`/authorizations/${authorizationId}/otp/verify`, { authorizationId, otp }),
    ),
  reject: (authorizationId: string, reason: string): Promise<Authorization> =>
    mutate(
      USE_MOCKS
        ? mockApi.rejectAuthorization(authorizationId, reason)
        : http.post(`/authorizations/${authorizationId}/reject`, { reason }),
    ),
}

export const containmentService = {
  execute: (containmentId: string): Promise<ContainmentAction> =>
    mutate(USE_MOCKS ? mockApi.executeContainment(containmentId) : http.post(`/containment/${containmentId}/execute`)),
  verify: (containmentId: string): Promise<ContainmentAction> =>
    mutate(USE_MOCKS ? mockApi.verifyContainment(containmentId) : http.post(`/containment/${containmentId}/verify`)),
}
