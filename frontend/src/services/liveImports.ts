import type {
  BackendImportBatchDetail,
  BackendImportBatchPage,
  BackendImportPreview,
  FieldMappingRequest,
  ImportBatchFilters,
  ImportPreviewOverrides,
} from '@/api/types'
import { buildImportFormData, buildPreviewFormData } from '@/lib/datasetImport'
import { http } from './http'

/** Dataset import API: read-only previews, profile-validated CSV uploads and the caller's own batch history. */
export const liveImportService = {
  list: (filters: ImportBatchFilters = {}): Promise<BackendImportBatchPage> =>
    http.get<BackendImportBatchPage>('/imports', filters),
  get: (id: string): Promise<BackendImportBatchDetail> =>
    http.get<BackendImportBatchDetail>(`/imports/${encodeURIComponent(id)}`),
  preview: (file: File, overrides: ImportPreviewOverrides = {}): Promise<BackendImportPreview> =>
    http.postForm<BackendImportPreview>('/imports/preview', buildPreviewFormData(file, file.name, overrides)),
  upload: (file: File, profile: string, mapping?: FieldMappingRequest): Promise<BackendImportBatchDetail> =>
    http.postForm<BackendImportBatchDetail>('/imports', buildImportFormData(file, file.name, profile, mapping)),
}
