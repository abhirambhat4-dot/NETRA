import type {
  AssessmentCreateRequest,
  AssessmentFilters,
  BackendAssessmentDetail,
  BackendAssessmentPage,
  BackendVulnerabilityResponse,
} from '@/api/types'
import { http } from './http'

/** Security Assessment API plus the asset vulnerability details it reports on. */
export const liveAssessmentService = {
  list: (filters: AssessmentFilters = {}): Promise<BackendAssessmentPage> =>
    http.get<BackendAssessmentPage>('/assessments', filters),
  get: (id: string): Promise<BackendAssessmentDetail> =>
    http.get<BackendAssessmentDetail>(`/assessments/${encodeURIComponent(id)}`),
  run: (request: AssessmentCreateRequest): Promise<BackendAssessmentDetail> =>
    http.post<BackendAssessmentDetail>('/assessments', request),
  listAssetVulnerabilities: (assetId: string): Promise<BackendVulnerabilityResponse[]> =>
    http.get<BackendVulnerabilityResponse[]>(`/assets/${encodeURIComponent(assetId)}/vulnerabilities`),
}
