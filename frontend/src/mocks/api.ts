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
import { db } from './db'

/**
 * Mock implementation of the NETRA REST API (see docs/ARCHITECTURE.md §4).
 * Same signatures as the HTTP client, so services can switch transparently.
 */

function respond<T>(produce: () => T): Promise<T> {
  // Errors thrown by `produce` become rejected promises (like HTTP 4xx).
  // structuredClone so callers can never mutate the mock database.
  return Promise.resolve().then(() => structuredClone(produce()))
}

function paginate<T>(items: T[], page = 1, pageSize = 25): PaginatedResponse<T> {
  const start = (page - 1) * pageSize
  return { items: items.slice(start, start + pageSize), total: items.length, page, pageSize }
}

const matches = (search: string | undefined, ...fields: (string | null)[]) =>
  !search || fields.some((f) => f?.toLowerCase().includes(search.toLowerCase()))

function orThrow<T>(value: T | null | undefined, what: string): T {
  if (value == null) throw new Error(`${what} not found`)
  return value
}

export const mockApi = {
  getDashboardStats: (): Promise<DashboardStats> => respond(db.getDashboardStats),

  getRiskTrend: (range: TrendRange): Promise<RiskTrendPoint[]> => respond(() => db.getTrend(range)),

  getSystemHealth: (): Promise<SystemComponentHealth[]> => respond(db.getSystemHealth),

  listIncidents: (f: IncidentFilters = {}): Promise<PaginatedResponse<Incident>> =>
    respond(() =>
      paginate(
        db.incidents.filter(
          (i) =>
            (!f.severity || i.severity === f.severity) &&
            (!f.status || i.status === f.status) &&
            matches(f.search, i.id, i.threatName, i.sourceIp, i.destinationIp),
        ),
        f.page,
        f.pageSize,
      ),
    ),

  getIncident: (id: string): Promise<IncidentDetail> => respond(() => orThrow(db.buildIncidentDetail(id), `Incident ${id}`)),

  listEvents: (f: SecurityEventFilters = {}): Promise<PaginatedResponse<SecurityEvent>> =>
    respond(() =>
      paginate(
        db.events.filter(
          (e) =>
            (!f.severity || e.severity === f.severity) &&
            (!f.detectionSource || e.detectionSource === f.detectionSource) &&
            (!f.status || e.status === f.status) &&
            matches(f.search, e.id, e.eventType, e.sourceIp, e.destinationIp, e.signature, e.incidentId),
        ),
        f.page,
        f.pageSize,
      ),
    ),

  listAssets: (): Promise<Asset[]> => respond(db.getAssets),

  getAsset: (id: string): Promise<Asset> => respond(() => orThrow(db.getAssets().find((a) => a.id === id), `Asset ${id}`)),

  getObservedTechniques: (): Promise<TechniqueObservation[]> => respond(db.getTechniqueObservations),

  listIndicators: (): Promise<ThreatIndicator[]> => respond(db.getIndicators),

  listMemory: (): Promise<CyberMemoryEntry[]> =>
    respond(() => [...db.memoryEntries].sort((a, b) => Date.parse(b.recordedAt) - Date.parse(a.recordedAt))),

  // --- workflow actions (UI simulation) ------------------------------------

  requestAuthorization: (incidentId: string): Promise<Authorization> =>
    respond(() => db.actions.requestAuthorization(incidentId)),

  verifyOtp: (authorizationId: string, otp: string): Promise<Authorization> =>
    respond(() => db.actions.verifyOtp(authorizationId, otp)),

  rejectAuthorization: (authorizationId: string, reason: string): Promise<Authorization> =>
    respond(() => db.actions.rejectAuthorization(authorizationId, reason)),

  executeContainment: (containmentId: string): Promise<ContainmentAction> =>
    respond(() => db.actions.executeContainment(containmentId)),

  verifyContainment: (containmentId: string): Promise<ContainmentAction> =>
    respond(() => db.actions.verifyContainment(containmentId)),
}
