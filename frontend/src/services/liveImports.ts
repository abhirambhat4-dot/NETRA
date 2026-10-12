import type { BackendImportBatchDetail, BackendImportBatchPage, ImportBatchFilters } from '@/api/types'
import { buildImportFormData } from '@/lib/datasetImport'
import { http } from './http'

/** Dataset import API: validation-only CSV uploads and the caller's own batch history. */
export const liveImportService = {
  list: (filters: ImportBatchFilters = {}): Promise<BackendImportBatchPage> =>
    http.get<BackendImportBatchPage>('/imports', filters),
  get: (id: string): Promise<BackendImportBatchDetail> =>
    http.get<BackendImportBatchDetail>(`/imports/${encodeURIComponent(id)}`),
  upload: (file: File, profile: string): Promise<BackendImportBatchDetail> =>
    http.postForm<BackendImportBatchDetail>('/imports', buildImportFormData(file, file.name, profile)),
}
