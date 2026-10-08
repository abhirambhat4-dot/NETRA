import type {
  Asset,
  AssetInventoryFilters,
  AssetInventoryItem,
  Authorization,
  BackendDatabaseHealthResponse,
  BackendAssetPage,
  BackendAssetResponse,
  CollectorEventSubmission,
  CollectorStatus,
  CollectorSubmitResponse,
  IncidentCreateRequest,
  BackendEventAssetReference,
  BackendEventResponse,
  BackendEventsPage,
  BackendEventSource,
  BackendIncidentDetailResponse,
  BackendIncidentAuthorizationResponse,
  BackendIncidentContainmentResponse,
  BackendIncidentDecisionResponse,
  BackendIncidentPage,
  BackendIncidentResponse,
  ContainmentAction,
  CyberMemoryEntry,
  DashboardStats,
  DetectionSource,
  EventStatus,
  EventsPageItem,
  Incident,
  IncidentDetail,
  IncidentFilters,
  IncidentLifecycleState,
  IncidentStatus,
  IncidentQueueFilters,
  IncidentQueueItem,
  LiveIncidentDetailsViewModel,
  PaginatedResponse,
  RiskTrendPoint,
  SecurityEvent,
  SecurityEventFilters,
  SystemComponentHealth,
  TechniqueObservation,
  ThreatIndicator,
  ThreatIndicatorInventoryFilters,
  ThreatIndicatorInventoryItem,
  BackendThreatIndicatorPage,
  BackendThreatIndicatorResponse,
  TrendRange,
} from '@/api/types'
import { mockApi } from '@/mocks/api'
import { DEMO_OTP } from '@/mocks/db'
import { USE_MOCKS, http } from './http'
import { liveCollectorService } from './liveCollector'
import { liveCyberMemoryService } from './liveCyberMemory'
import { liveDashboardService } from './liveDashboard'

export { liveCyberMemoryService, liveDashboardService }

/**
 * NETRA service layer — the ONLY place pages get data from.
 * Each function maps 1:1 to an endpoint in docs/ARCHITECTURE.md.
 * Flip VITE_USE_MOCKS=false to hit FastAPI; the UI does not change.
 */

export const DATA_CHANGED_EVENT = 'netra:data-changed'

/** Demo OTP shown in the UI while running on mock data (null against the real API). */
export const DEMO_OTP_HINT: string | null = USE_MOCKS ? DEMO_OTP : null

const EVENT_API_PAGE_SIZE = 100
const INCIDENT_API_PAGE_SIZE = 100
const INCIDENT_LIFECYCLE_STATES: readonly IncidentLifecycleState[] = [
  'DETECTED',
  'UNDERSTOOD',
  'PRIORITISED',
  'VERIFIED',
  'AUTHORIZED',
  'CONTAINED',
  'LEARNED',
]

type EventsPageFilters = Pick<SecurityEventFilters, 'search' | 'severity' | 'status'> & {
  status?: EventStatus
  detectionSource?: BackendEventSource | DetectionSource
}

const MOCK_EVENT_SOURCES: readonly DetectionSource[] = ['SURICATA', 'ML_ANOMALY', 'THREAT_INTEL', 'HYBRID']
const MOCK_ACTIVE_INCIDENT_STATES: readonly IncidentStatus[] = [
  'NEW',
  'INVESTIGATING',
  'AWAITING_AUTHORIZATION',
  'CONTAINING',
]

function isDetectionSource(source: BackendEventSource | DetectionSource): source is DetectionSource {
  return MOCK_EVENT_SOURCES.includes(source as DetectionSource)
}

function toMockAssetReference(asset: Asset): BackendEventAssetReference {
  return {
    id: asset.id,
    name: asset.name,
    hostname: asset.hostname,
    ipAddress: asset.ipAddress,
    criticality: asset.criticality,
    status: asset.status,
  }
}

function adaptBackendEvent(event: BackendEventResponse): EventsPageItem {
  return {
    id: event.id,
    eventUid: event.eventUid,
    timestamp: event.occurredAt,
    sourceIp: event.sourceIp,
    sourcePort: event.sourcePort,
    destinationIp: event.destinationIp,
    destinationPort: event.destinationPort,
    protocol: event.protocol,
    eventType: event.eventType,
    signature: event.signature,
    severity: event.severity,
    detectionSource: event.detectionSource,
    status: event.status,
    anomalyScore: event.anomalyScore,
    incidentIds: event.incidentIds,
    assetId: event.assetId,
    asset: event.asset,
    mitreTechniqueId: null,
  }
}

function adaptMockEvent(event: SecurityEvent, assetsById: Map<string, Asset>): EventsPageItem {
  const asset = event.assetId ? assetsById.get(event.assetId) : undefined
  return {
    id: event.id,
    timestamp: event.timestamp,
    sourceIp: event.sourceIp,
    sourcePort: event.sourcePort,
    destinationIp: event.destinationIp,
    destinationPort: event.destinationPort,
    protocol: event.protocol,
    eventType: event.eventType,
    signature: event.signature,
    severity: event.severity,
    detectionSource: event.detectionSource,
    status: event.status,
    anomalyScore: event.anomalyScore,
    incidentIds: event.incidentId ? [event.incidentId] : [],
    assetId: event.assetId,
    asset: asset ? toMockAssetReference(asset) : null,
    mitreTechniqueId: event.mitreTechniqueId,
  }
}

function adaptBackendIncident(incident: BackendIncidentResponse): IncidentQueueItem {
  if (!INCIDENT_LIFECYCLE_STATES.includes(incident.state)) {
    throw new Error(`Unsupported incident lifecycle state: ${incident.state}`)
  }

  return {
    id: incident.id,
    key: incident.incidentKey,
    title: incident.title,
    description: incident.description,
    severity: incident.severity,
    riskScore: incident.riskScore,
    lifecycle: incident.state,
    detectionSource: incident.detectionSource,
    recommendedAction: incident.recommendedAction,
    asset: incident.asset,
    eventCount: incident.eventCount,
    createdAt: incident.createdAt,
    updatedAt: incident.updatedAt,
    latestDecision: incident.latestDecision,
  }
}

async function listEventsForPage(filters: EventsPageFilters = {}): Promise<PaginatedResponse<EventsPageItem>> {
  if (USE_MOCKS) {
    const { detectionSource, ...mockFilters } = filters
    const [page, assets] = await Promise.all([
      mockApi.listEvents({
        ...mockFilters,
        detectionSource: detectionSource && isDetectionSource(detectionSource) ? detectionSource : undefined,
        page: 1,
        pageSize: 1000,
      }),
      mockApi.listAssets(),
    ])
    const assetsById = new Map(assets.map((asset) => [asset.id, asset]))
    const items = page.items
      .map((event) => adaptMockEvent(event, assetsById))
      .filter((event) => !detectionSource || event.detectionSource === detectionSource)
    return { items, total: items.length, page: 1, pageSize: 1000 }
  }

  if (filters.detectionSource === 'HYBRID' || filters.status === 'DISMISSED') {
    return { items: [], total: 0, page: 1, pageSize: EVENT_API_PAGE_SIZE }
  }

  const { detectionSource, ...backendFilters } = filters
  const query = {
    ...backendFilters,
    source: detectionSource,
    pageSize: EVENT_API_PAGE_SIZE,
  }
  const firstPage = await http.get<BackendEventsPage>('/events', { ...query, page: 1 })
  const additionalPageCount = Math.ceil(firstPage.total / EVENT_API_PAGE_SIZE) - 1
  const additionalPages = await Promise.all(
    Array.from({ length: additionalPageCount }, (_, index) =>
      http.get<BackendEventsPage>('/events', { ...query, page: index + 2 }),
    ),
  )

  return {
    items: [firstPage, ...additionalPages].flatMap((page) => page.items.map(adaptBackendEvent)),
    total: firstPage.total,
    page: 1,
    pageSize: EVENT_API_PAGE_SIZE,
  }
}

async function listLiveIncidents(filters: IncidentQueueFilters = {}): Promise<IncidentQueueItem[]> {
  const query = {
    search: filters.search?.trim() || undefined,
    severity: filters.severity,
    state:
      filters.state === 'CONTAINED' ? 'CONTAINED' : filters.state === 'LEARNED' ? 'LEARNED' : undefined,
    active: filters.state === 'ACTIVE' ? true : undefined,
    sortBy: filters.sort === 'risk' ? 'riskScore' : 'updatedAt',
    sortOrder: 'desc',
    pageSize: INCIDENT_API_PAGE_SIZE,
  }
  const firstPage = await http.get<BackendIncidentPage>('/incidents', { ...query, page: 1 })
  const additionalPageCount = Math.ceil(firstPage.total / INCIDENT_API_PAGE_SIZE) - 1
  const additionalPages = await Promise.all(
    Array.from({ length: additionalPageCount }, (_, index) =>
      http.get<BackendIncidentPage>('/incidents', { ...query, page: index + 2 }),
    ),
  )

  return [firstPage, ...additionalPages].flatMap((page) => page.items.map(adaptBackendIncident))
}

async function listMockIncidents(filters: IncidentQueueFilters = {}): Promise<IncidentQueueItem[]> {
  const [page, assets] = await Promise.all([
    mockApi.listIncidents({
      severity: filters.severity,
      page: 1,
      pageSize: 1000,
    }),
    mockApi.listAssets(),
  ])
  const assetsById = new Map(assets.map((asset) => [asset.id, asset]))
  const items: IncidentQueueItem[] = page.items.map((incident) => {
    const asset = assetsById.get(incident.assetId)
    return {
      id: incident.id,
      key: incident.id,
      title: incident.threatName,
      description: incident.description,
      severity: incident.severity,
      riskScore: incident.riskScore,
      lifecycle: incident.status,
      detectionSource: incident.detectionSource,
      recommendedAction: null,
      asset: asset ? toMockAssetReference(asset) : null,
      eventCount: incident.eventCount,
      createdAt: incident.firstSeen,
      updatedAt: incident.lastSeen,
      latestDecision: null,
    }
  })
  const search = filters.search?.trim().toLowerCase()
  const matchingItems = search
    ? items.filter((incident) =>
        [
          incident.id,
          incident.title,
          incident.description,
          incident.asset?.name,
          incident.asset?.hostname,
          incident.asset?.ipAddress,
        ].some((value) => value?.toLowerCase().includes(search)),
      )
    : items
  const byState = filters.state === 'ACTIVE'
    ? matchingItems.filter((incident) => MOCK_ACTIVE_INCIDENT_STATES.includes(incident.lifecycle as IncidentStatus))
    : filters.state === 'CONTAINED'
      ? matchingItems.filter((incident) => incident.lifecycle === 'CONTAINED')
      : filters.state === 'LEARNED'
        ? []
        : matchingItems

  return byState.sort((left, right) =>
    filters.sort === 'recent'
      ? Date.parse(right.updatedAt) - Date.parse(left.updatedAt)
      : (right.riskScore ?? -1) - (left.riskScore ?? -1),
  )
}

/** After a mutation, tell every mounted query to refetch. */
async function mutate<T>(request: Promise<T>): Promise<T> {
  const result = await request
  window.dispatchEvent(new Event(DATA_CHANGED_EVENT))
  return result
}

function mockWorkflowOnly<T>(): Promise<T> {
  return Promise.reject(new Error('This simulated workflow is available only when VITE_USE_MOCKS=true.'))
}

export const dashboardService = {
  getStats: (): Promise<DashboardStats> =>
    USE_MOCKS ? mockApi.getDashboardStats() : liveDashboardService.getStats(),
  getRiskTrend: (range: TrendRange): Promise<RiskTrendPoint[]> =>
    USE_MOCKS ? mockApi.getRiskTrend(range) : liveDashboardService.getRiskTrend(range),
  getSystemHealth: (): Promise<Array<Pick<SystemComponentHealth, 'name' | 'status'>>> =>
    USE_MOCKS ? mockApi.getSystemHealth() : liveDashboardService.getSystemHealth(),
  getDatabaseHealth: (): Promise<BackendDatabaseHealthResponse | null> =>
    USE_MOCKS ? Promise.resolve(null) : liveDashboardService.getDatabaseHealth(),
}

export const incidentService = {
  list: (filters?: IncidentFilters): Promise<PaginatedResponse<Incident>> =>
    USE_MOCKS ? mockApi.listIncidents(filters) : http.get('/incidents', filters),
  get: (id: string): Promise<IncidentDetail> =>
    USE_MOCKS ? mockApi.getIncident(id) : http.get(`/incidents/${id}`),
}

function adaptLiveIncidentDetails(response: BackendIncidentDetailResponse): LiveIncidentDetailsViewModel {
  return {
    incident: response.incident,
    asset: response.asset,
    events: response.events,
    timeline: response.timeline,
    decisions: response.decisions,
    authorizations: response.authorizations,
    containmentActions: response.containmentActions,
    cyberMemories: response.cyberMemories,
  }
}

interface LiveIncidentContextResponse {
  incident: {
    id: string
    incidentKey: string
    title: string
    description: string | null
    severity: string
    state: string
    detectionSource: string
    assetId: string | null
  }
  asset: {
    id: string
    assetKey: string
    name: string
    hostname: string | null
    ipAddress: string | null
    criticality: string
    exposure: string
    status: string
    assetType: string
    environment: string
  } | null
  vulnerabilities: Array<{
    id: string
    cveId: string | null
    title: string
    description: string | null
    cvssScore: number | null
    severity: string
    status: string
  }>
  threatIntelligenceMatches: Array<{
    id: string
    value: string
    indicatorType: string
    confidence: number | null
    severity: string
    source: string
    isActive: boolean
    matchedEventIds: string[]
  }>
  events: Array<{
    id: string
    eventUid: string
    occurredAt: string
    eventType: string
    signature: string | null
    severity: string
    anomalyScore: number | null
    detectionSource: string
    sourceIp: string | null
    destinationIp: string | null
    sourcePort: number | null
    destinationPort: number | null
    protocol: string | null
  }>
  findings: Array<{ category: string; reason: string; count: number | null }>
}

interface LiveCorrelationResponse {
  incidentId: string
  state: string
  stateTransition: { fromState: string; toState: string; action: string } | null
  correlatedEvents: Array<{
    id: string
    eventUid: string
    occurredAt: string
    eventType: string
    signature: string | null
    severity: string
    detectionSource: string
    sourceIp: string | null
    destinationIp: string | null
    assetId: string | null
  }>
  findings: Array<Record<string, unknown>>
}

interface LiveRiskResponse {
  incidentId: string
  riskScore: number
  severity: string
  factors: Record<string, {
    normalizedValue: number
    weight: number
    contribution: number
    evidence: string[]
    reason: string
  }>
  reasons: string[]
  missingEvidence: string[]
  stateTransition: { fromState: string; toState: string; action: string }
}

interface LiveCyberMemoryResponse {
  id: string
  incidentId: string | null
  decisionId: string | null
  lesson: string
  outcome: string | null
  actionTaken: string | null
  effectiveness: string
  createdAt: string
  incident: {
    id: string
    incidentKey: string
    title: string
    state: string
    severity: string
    riskScore: number | null
  } | null
  decision: BackendIncidentDecisionResponse | null
  authorizations: BackendIncidentAuthorizationResponse[]
  containmentActions: BackendIncidentContainmentResponse[]
}

/** Read and mutation contracts for the live Incident Details workflow. */
export const liveIncidentDetailsService = {
  get: async (id: string): Promise<LiveIncidentDetailsViewModel> =>
    adaptLiveIncidentDetails(await http.get<BackendIncidentDetailResponse>(`/incidents/${id}`)),
}

export const liveIncidentWorkflowService = {
  enrich: (incidentId: string): Promise<LiveIncidentContextResponse> =>
    mutate(http.post(`/incidents/${incidentId}/enrich`)),
  correlate: (incidentId: string): Promise<LiveCorrelationResponse> =>
    mutate(http.post(`/incidents/${incidentId}/correlate`)),
  calculateRisk: (incidentId: string): Promise<LiveRiskResponse> =>
    mutate(http.post(`/incidents/${incidentId}/risk-score`)),
  recommendDecision: (incidentId: string): Promise<BackendIncidentDecisionResponse> =>
    mutate(http.post(`/incidents/${incidentId}/decision`)),
  requestAuthorization: (decisionId: string): Promise<BackendIncidentAuthorizationResponse> =>
    mutate(http.post(`/decisions/${decisionId}/authorize`)),
  approveAuthorization: (authorizationId: string): Promise<BackendIncidentAuthorizationResponse> =>
    mutate(http.post(`/authorizations/${authorizationId}/approve`)),
  rejectAuthorization: (authorizationId: string, reason: string): Promise<BackendIncidentAuthorizationResponse> => {
    const operatorReason = reason.trim()
    if (!operatorReason) return Promise.reject(new Error('A rejection reason is required.'))
    return mutate(http.post(`/authorizations/${authorizationId}/reject`, { reason: operatorReason }))
  },
  simulateContainment: (authorizationId: string): Promise<BackendIncidentContainmentResponse> =>
    mutate(http.post(`/authorizations/${authorizationId}/contain`, { simulateFailure: false })),
  verifyContainment: (containmentId: string): Promise<BackendIncidentContainmentResponse> =>
    mutate(http.post(`/containments/${containmentId}/verify`)),
  createCyberMemory: (incidentId: string): Promise<LiveCyberMemoryResponse> =>
    mutate(http.post(`/incidents/${incidentId}/cyber-memory`)),
}

export const incidentQueueService = {
  list: (filters?: IncidentQueueFilters): Promise<IncidentQueueItem[]> =>
    USE_MOCKS ? listMockIncidents(filters) : listLiveIncidents(filters),
}

export const eventService = {
  list: (filters?: SecurityEventFilters): Promise<PaginatedResponse<SecurityEvent>> =>
    USE_MOCKS ? mockApi.listEvents(filters) : http.get('/events', filters),
  listForEventsPage: (filters?: EventsPageFilters): Promise<PaginatedResponse<EventsPageItem>> =>
    listEventsForPage(filters),
  getForEventsPage: async (id: string): Promise<EventsPageItem> => {
    if (USE_MOCKS) {
      const page = await listEventsForPage()
      const event = page.items.find((item) => item.id === id)
      if (!event) throw new Error('Security event not found')
      return event
    }
    return adaptBackendEvent(await http.get<BackendEventResponse>(`/events/${id}`))
  },
}

export const assetService = {
  list: (): Promise<Asset[]> => (USE_MOCKS ? mockApi.listAssets() : http.get('/assets')),
  get: (id: string): Promise<Asset> => (USE_MOCKS ? mockApi.getAsset(id) : http.get(`/assets/${id}`)),
}

const INVENTORY_API_PAGE_SIZE = 100

function adaptMockAsset(asset: Asset): AssetInventoryItem {
  return {
    ...asset,
    vulnerabilityCount: asset.vulnerabilities.length,
  }
}

function adaptBackendAsset(asset: BackendAssetResponse): AssetInventoryItem {
  const knownTypes = ['DATABASE', 'SERVER', 'WORKSTATION', 'NETWORK_DEVICE', 'WEB_APPLICATION']
  return {
    id: asset.id,
    name: asset.name,
    hostname: asset.hostname,
    ipAddress: asset.ipAddress,
    type: knownTypes.includes(asset.assetType) ? (asset.assetType as Asset['type']) : null,
    criticality: asset.criticality,
    owner: asset.owner,
    operatingSystem: null,
    services: null,
    vulnerabilities: null,
    vulnerabilityCount: asset.vulnerabilityCount,
    status: asset.status,
    exposure: asset.exposure,
    riskScore: null,
    posture: null,
    activeIncidentIds: null,
    lastSeen: null,
    assetKey: asset.assetKey,
    assetType: asset.assetType,
    environment: asset.environment,
    createdAt: asset.createdAt,
    updatedAt: asset.updatedAt,
  }
}

async function listLiveAssets(filters: AssetInventoryFilters = {}): Promise<AssetInventoryItem[]> {
  const query = {
    search: filters.search?.trim() || undefined,
    criticality: filters.criticality,
    exposure: filters.exposure,
    status: filters.status,
    sortBy: filters.sortBy ?? 'name',
    sortOrder: filters.sortOrder ?? 'asc',
    pageSize: INVENTORY_API_PAGE_SIZE,
  }
  const firstPage = await http.get<BackendAssetPage>('/assets', { ...query, page: 1 })
  const additionalPageCount = Math.ceil(firstPage.total / INVENTORY_API_PAGE_SIZE) - 1
  const additionalPages = await Promise.all(
    Array.from({ length: additionalPageCount }, (_, index) =>
      http.get<BackendAssetPage>('/assets', { ...query, page: index + 2 }),
    ),
  )

  return [firstPage, ...additionalPages].flatMap((page) => page.items.map(adaptBackendAsset))
}

/** Read-only inventory adapter for the Assets page; mock records remain unchanged. */
export const assetInventoryService = {
  list: (filters?: AssetInventoryFilters): Promise<AssetInventoryItem[]> =>
    USE_MOCKS
      ? mockApi.listAssets().then((assets) => assets.map(adaptMockAsset))
      : listLiveAssets(filters),
  get: async (id: string): Promise<AssetInventoryItem> =>
    USE_MOCKS
      ? adaptMockAsset(await mockApi.getAsset(id))
      : adaptBackendAsset(await http.get<BackendAssetResponse>(`/assets/${id}`)),
}

function adaptBackendThreatIndicator(indicator: BackendThreatIndicatorResponse): ThreatIndicatorInventoryItem {
  return {
    id: indicator.id,
    type: indicator.indicatorType,
    value: indicator.value,
    source: indicator.source,
    confidence: indicator.confidence,
    severity: indicator.severity,
    description: null,
    tags: null,
    firstSeen: indicator.firstSeen,
    lastSeen: indicator.lastSeen,
    matchCount: null,
    incidentIds: null,
    mitreTechniqueIds: null,
    isActive: indicator.isActive,
  }
}

async function listLiveThreatIndicators(
  filters: ThreatIndicatorInventoryFilters = {},
): Promise<ThreatIndicatorInventoryItem[]> {
  const query = {
    indicatorType: filters.indicatorType,
    severity: filters.severity,
    minConfidence: filters.minConfidence,
    maxConfidence: filters.maxConfidence,
    source: filters.source?.trim() || undefined,
    search: filters.search?.trim() || undefined,
    sortBy: filters.sortBy ?? 'lastSeen',
    sortOrder: filters.sortOrder ?? 'desc',
    pageSize: INVENTORY_API_PAGE_SIZE,
  }
  const firstPage = await http.get<BackendThreatIndicatorPage>('/threat-intelligence', { ...query, page: 1 })
  const additionalPageCount = Math.ceil(firstPage.total / INVENTORY_API_PAGE_SIZE) - 1
  const additionalPages = await Promise.all(
    Array.from({ length: additionalPageCount }, (_, index) =>
      http.get<BackendThreatIndicatorPage>('/threat-intelligence', { ...query, page: index + 2 }),
    ),
  )

  return [firstPage, ...additionalPages].flatMap((page) => page.items.map(adaptBackendThreatIndicator))
}

/** Read-only indicator adapter for the Threat Intelligence page. */
export const threatIntelInventoryService = {
  list: (filters?: ThreatIndicatorInventoryFilters): Promise<ThreatIndicatorInventoryItem[]> =>
    USE_MOCKS
      ? mockApi.listIndicators()
      : listLiveThreatIndicators(filters),
  get: async (id: string): Promise<ThreatIndicatorInventoryItem> =>
    adaptBackendThreatIndicator(await http.get<BackendThreatIndicatorResponse>(`/threat-intelligence/${id}`)),
}

export const threatIntelService = {
  getObservedTechniques: (): Promise<TechniqueObservation[]> => mockApi.getObservedTechniques(),
  listIndicators: (): Promise<ThreatIndicator[]> => mockApi.listIndicators(),
}

/** Live Event Collector status; the collector has no mock adapter, so pages gate on USE_MOCKS. */
export const collectorService = {
  getStatus: async (): Promise<CollectorStatus> => {
    if (USE_MOCKS) throw new Error('The Live Event Collector requires the NETRA API.')
    const status = await liveCollectorService.getStatus()
    return { ...status, recentEvents: status.recentEvents.map(adaptBackendEvent) }
  },
  /** Mutations refresh every mounted query, so collector status updates immediately. */
  submit: (events: CollectorEventSubmission[]): Promise<CollectorSubmitResponse> =>
    USE_MOCKS ? mockWorkflowOnlyCollector() : mutate(liveCollectorService.submit(events)),
  /** Uses the existing POST /api/incidents; the incident starts in its normal initial state. */
  createIncident: (request: IncidentCreateRequest): Promise<BackendIncidentResponse> =>
    USE_MOCKS ? mockWorkflowOnlyCollector() : mutate(liveCollectorService.createIncident(request)),
}

function mockWorkflowOnlyCollector<T>(): Promise<T> {
  return Promise.reject(new Error('The Live Event Collector requires the NETRA API.'))
}

export const memoryService = {
  list: (): Promise<CyberMemoryEntry[]> =>
    USE_MOCKS ? mockApi.listMemory() : liveCyberMemoryService.listAll(),
}

export const authorizationService = {
  request: (incidentId: string): Promise<Authorization> =>
    USE_MOCKS ? mutate(mockApi.requestAuthorization(incidentId)) : mockWorkflowOnly(),
  verifyOtp: (authorizationId: string, otp: string): Promise<Authorization> =>
    USE_MOCKS ? mutate(mockApi.verifyOtp(authorizationId, otp)) : mockWorkflowOnly(),
  reject: (authorizationId: string, reason: string): Promise<Authorization> =>
    USE_MOCKS ? mutate(mockApi.rejectAuthorization(authorizationId, reason)) : mockWorkflowOnly(),
}

export const containmentService = {
  execute: (containmentId: string): Promise<ContainmentAction> =>
    USE_MOCKS ? mutate(mockApi.executeContainment(containmentId)) : mockWorkflowOnly(),
  verify: (containmentId: string): Promise<ContainmentAction> =>
    USE_MOCKS ? mutate(mockApi.verifyContainment(containmentId)) : mockWorkflowOnly(),
}
