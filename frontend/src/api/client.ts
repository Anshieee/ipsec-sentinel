import type { AnalysisResult, UploadStage } from '@/types/analysis'
import type { LogLine, ModelEntry } from '@/types/misc'
import type { LiveSocket } from './live'
import { mockApi } from './mock'
import { httpApi } from './http'

export interface UploadProgressEvent {
  stage: UploadStage
  progress: number
}

export interface SentinelApi {
  uploadAndAnalyze(
    file: File,
    onProgress: (p: UploadProgressEvent) => void,
    signal?: AbortSignal,
  ): Promise<AnalysisResult>
  getModelRegistry(): Promise<ModelEntry[]>
  getModelLogs(sinceId?: string): Promise<LogLine[]>
  openLiveCapture(sourceId: 'A' | 'B' | 'C', speed: 1 | 4): LiveSocket
}

export type DataSource = 'mock' | 'live'

const STORAGE_KEY = 'sentinel.settings.v1'

/** Build-time default: live only with explicit opt-out. */
export const defaultDataSource = (): DataSource =>
  import.meta.env.VITE_USE_MOCK === 'false' ? 'live' : 'mock'

/** Runtime data source: persisted Settings override, else env default.
 * Reads localStorage directly (no store import: the store imports this). */
export const getDataSource = (): DataSource => {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY)
    if (raw) {
      const parsed: unknown = JSON.parse(raw)
      if (
        typeof parsed === 'object' &&
        parsed !== null &&
        'state' in parsed &&
        typeof (parsed as { state?: unknown }).state === 'object'
      ) {
        const settings = (parsed as { state: { settings?: { dataSource?: unknown } } }).state.settings
        if (settings?.dataSource === 'live' || settings?.dataSource === 'mock') {
          return settings.dataSource
        }
      }
    }
  } catch {
    /* corrupted storage falls through to the env default */
  }
  return defaultDataSource()
}

export const isMockMode = (): boolean => getDataSource() === 'mock'

/** The API honoring the runtime toggle (upload/live slices must use this). */
export const getActiveApi = (): SentinelApi => (isMockMode() ? mockApi : httpApi)

/** Kept for compatibility; resolves the default once at import. */
export const api: SentinelApi = defaultDataSource() === 'mock' ? mockApi : httpApi
