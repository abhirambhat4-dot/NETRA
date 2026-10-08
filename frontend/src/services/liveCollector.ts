import type {
  BackendCollectorStatusResponse,
  BackendIncidentResponse,
  CollectorEventSubmission,
  CollectorSubmitResponse,
  IncidentCreateRequest,
} from '@/api/types'
import { http } from './http'

/** NETRA Web Collector API plus the existing incident-creation endpoint it hands off to. */
export const liveCollectorService = {
  getStatus: (): Promise<BackendCollectorStatusResponse> =>
    http.get<BackendCollectorStatusResponse>('/collector/status'),
  submit: (events: CollectorEventSubmission[]): Promise<CollectorSubmitResponse> =>
    http.post<CollectorSubmitResponse>('/collector/events', { events }),
  createIncident: (request: IncidentCreateRequest): Promise<BackendIncidentResponse> =>
    http.post<BackendIncidentResponse>('/incidents', request),
}
