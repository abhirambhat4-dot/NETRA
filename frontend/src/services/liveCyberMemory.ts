import type {
  BackendCyberMemoryPage,
  BackendCyberMemoryResponse,
  CyberMemoryEntry,
  CyberMemoryFilters,
} from '@/api/types'
import { http } from './http'

const DEFAULT_PAGE_SIZE = 100

function adaptCyberMemory(record: BackendCyberMemoryResponse): CyberMemoryEntry {
  return {
    id: record.id,
    incidentId: record.incidentId,
    threatName: record.incident?.title ?? null,
    mitreTechniqueId: null,
    sourceIp: null,
    assetId: null,
    riskScore: record.incident?.riskScore ?? null,
    actionTaken: record.actionTaken,
    outcome: record.outcome,
    lessonsLearned: record.lesson,
    tags: null,
    similarIncidentIds: null,
    recordedAt: record.createdAt,
    effectiveness: record.effectiveness,
  }
}

/** The backend returns newest records first and does not expose sort parameters. */
export const liveCyberMemoryService = {
  listPage: async (filters: CyberMemoryFilters = {}) => {
    const page = filters.page ?? 1
    const pageSize = filters.pageSize ?? DEFAULT_PAGE_SIZE
    const response = await http.get<BackendCyberMemoryPage>('/cyber-memory', {
      page,
      pageSize,
      incidentId: filters.incidentId,
      effectiveness: filters.effectiveness,
      actionTaken: filters.actionTaken,
      search: filters.search?.trim() || undefined,
    })

    return {
      items: response.items.map(adaptCyberMemory),
      total: response.total,
      page: response.page,
      pageSize: response.pageSize,
    }
  },

  listAll: async (filters: Omit<CyberMemoryFilters, 'page' | 'pageSize'> = {}): Promise<CyberMemoryEntry[]> => {
    const firstPage = await liveCyberMemoryService.listPage({ ...filters, page: 1, pageSize: DEFAULT_PAGE_SIZE })
    const pageCount = Math.ceil(firstPage.total / DEFAULT_PAGE_SIZE)
    const remaining = await Promise.all(
      Array.from({ length: Math.max(0, pageCount - 1) }, (_, index) =>
        liveCyberMemoryService.listPage({ ...filters, page: index + 2, pageSize: DEFAULT_PAGE_SIZE }),
      ),
    )
    return [firstPage, ...remaining].flatMap((result) => result.items)
  },
}