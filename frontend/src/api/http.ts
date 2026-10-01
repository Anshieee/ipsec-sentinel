import type { AnalysisResult, UploadStage } from '@/types/analysis'
import type { LogLine, ModelEntry } from '@/types/misc'
import type { LiveSocket } from './live'
import { MockLiveSocket } from './live'
import type { SentinelApi, UploadProgressEvent } from './client'
import { MODEL_REGISTRY } from './models'
import { mapAnalyzeResponse, type BackendAnalyzeResponse } from './backend'

/**
 * Real-backend API base. `VITE_API_URL` wins, `VITE_API_BASE_URL` is kept
 * as a fallback; default matches `ipsec-analyze serve` (:8000).
 */
export const apiBase = (): string =>
  (
    import.meta.env.VITE_API_URL ??
    import.meta.env.VITE_API_BASE_URL ??
    'http://127.0.0.1:8000'
  ).replace(/\/$/, '')

function stageForProgress(progress: number): UploadStage {
  if (progress < 40) return 'uploading'
  if (progress < 75) return 'parsing'
  return 'inferring'
}

async function getJson<T>(path: string): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${apiBase()}${path}`, { headers: { Accept: 'application/json' } })
  } catch {
    throw new Error(`API unreachable at ${apiBase()}. Start it with \`ipsec-analyze serve\`.`)
  }
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status} ${response.statusText}`)
  }
  return (await response.json()) as T
}

/** Server-provided error detail, or a friendly fallback (never a traceback). */
function serverMessage(status: number, statusText: string, body: string): string {
  try {
    const parsed: unknown = JSON.parse(body)
    if (typeof parsed === 'object' && parsed !== null && 'detail' in parsed) {
      const detail = (parsed as { detail: unknown }).detail
      if (typeof detail === 'string' && detail.length > 0) return detail
    }
  } catch {
    /* fall through to the status-based message */
  }
  if (status === 400) return 'Unsupported file type. Upload a .pcap trace.'
  if (status === 413) return 'File exceeds the 50 MB server limit.'
  if (status === 422) return 'The server could not analyze this capture.'
  return `Analysis failed: ${status} ${statusText}`
}

function uploadAndAnalyze(
  file: File,
  onProgress: (p: UploadProgressEvent) => void,
  signal?: AbortSignal,
): Promise<AnalysisResult> {
  return new Promise<AnalysisResult>((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('POST', `${apiBase()}/analyze`)
    xhr.responseType = 'text'

    xhr.upload.onprogress = (event: ProgressEvent) => {
      if (!event.lengthComputable) return
      const progress = Math.round((event.loaded / event.total) * 100)
      onProgress({ stage: stageForProgress(progress), progress })
    }
    xhr.upload.onload = () => onProgress({ stage: 'parsing', progress: 40 })

    xhr.onreadystatechange = () => {
      if (xhr.readyState !== XMLHttpRequest.DONE) return
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          const parsed = JSON.parse(xhr.responseText) as BackendAnalyzeResponse
          onProgress({ stage: 'inferring', progress: 100 })
          resolve(mapAnalyzeResponse(file, parsed))
        } catch {
          reject(new Error('Failed to parse the analysis response.'))
        }
      } else if (xhr.status === 0) {
        reject(new Error(`API unreachable at ${apiBase()}. Start it with \`ipsec-analyze serve\`.`))
      } else {
        reject(new Error(serverMessage(xhr.status, xhr.statusText, xhr.responseText)))
      }
    }
    xhr.onerror = () => reject(new Error(`API unreachable at ${apiBase()}. Start it with \`ipsec-analyze serve\`.`))
    xhr.onabort = () => {
      const error = new Error('The operation was aborted.')
      error.name = 'AbortError'
      reject(error)
    }

    if (signal) {
      if (signal.aborted) {
        xhr.abort()
        return
      }
      signal.addEventListener('abort', () => xhr.abort(), { once: true })
    }

    const form = new FormData()
    form.append('file', file, file.name)
    xhr.send(form)
  })
}

export const httpApi: SentinelApi = {
  uploadAndAnalyze,
  getModelRegistry: async (): Promise<ModelEntry[]> => {
    // Ping the real endpoint (proves liveness/version); the rows below are
    // the static demonstration registry — the UI badges them SIMULATED in
    // live mode because no truthful GBM/CNN mapping exists (integration doc).
    await getJson<unknown>('/models')
    return MODEL_REGISTRY
  },
  getModelLogs: (): Promise<LogLine[]> => Promise.resolve([]),
  openLiveCapture: (sourceId, speed): LiveSocket => new MockLiveSocket(sourceId, speed),
}
