import type { AnalysisResult, UploadStage } from '@/types/analysis'
import type { LogLine, ModelEntry } from '@/types/misc'
import { validateUpload } from '@/lib/validate'
import { cloneFixture, getFixtureForFileName } from './fixtures'
import { fixtureIdForFileName } from './fixtures/spec'
import { hashString } from '@/lib/prng'
import { MODEL_REGISTRY } from './models'
import { nextLogs } from './logs'
import { MockLiveSocket } from './live'
import type { LiveSocket } from './live'
import type { SentinelApi } from './client'

export interface UploadProgress {
  stage: UploadStage
  progress: number
}

const STAGES: { stage: UploadStage; from: number; to: number; durationMs: number }[] = [
  { stage: 'uploading', from: 0, to: 40, durationMs: 1200 },
  { stage: 'parsing', from: 40, to: 75, durationMs: 1500 },
  { stage: 'inferring', from: 75, to: 100, durationMs: 1300 },
]

export const PARSE_ERROR = 'Failed to parse capture: unexpected end of file at packet 18,204.'

const TICK_MS = 50
const TOTAL_MS = STAGES.reduce((sum, s) => sum + s.durationMs, 0)

let simulateErrors = false
let idCounter = 0

/** The settings slice pushes the "Simulate parse errors" flag into the mock layer. */
export function configureMock(options: { simulateErrors: boolean }): void {
  simulateErrors = options.simulateErrors
}

function abortError(): Error {
  if (typeof DOMException !== 'undefined') return new DOMException('The operation was aborted.', 'AbortError')
  const error = new Error('The operation was aborted.')
  error.name = 'AbortError'
  return error
}

function freshId(prefix: string): string {
  idCounter += 1
  return `${prefix}-${Date.now().toString(36)}-${idCounter.toString(36)}`
}

function progressFor(elapsedMs: number): { stage: UploadStage; progress: number } {
  let cursor = 0
  for (const stage of STAGES) {
    if (elapsedMs <= cursor + stage.durationMs) {
      const local = (elapsedMs - cursor) / stage.durationMs
      const progress = Math.min(stage.to, Math.max(stage.from, stage.from + local * (stage.to - stage.from)))
      return { stage: stage.stage, progress: Math.round(progress) }
    }
    cursor += stage.durationMs
  }
  return { stage: 'inferring', progress: 100 }
}

/** Selects the fixture for an uploaded file name (spec 8.3). */
export function selectFixture(fileName: string) {
  return fixtureIdForFileName(fileName, hashString)
}

export async function runMockPipeline(
  file: File,
  onProgress: (p: UploadProgress) => void,
  signal?: AbortSignal,
): Promise<AnalysisResult> {
  // Validation runs before any progress starts.
  await validateUpload(file)

  const shouldFail = file.name.toLowerCase().includes('corrupt') || simulateErrors

  return new Promise<AnalysisResult>((resolve, reject) => {
    const startedAt = Date.now()
    let settled = false
    let timer: ReturnType<typeof setInterval> | null = null

    const cleanup = () => {
      if (timer !== null) clearInterval(timer)
      signal?.removeEventListener('abort', onAbort)
    }

    const onAbort = () => {
      if (settled) return
      settled = true
      cleanup()
      reject(abortError())
    }

    if (signal?.aborted) {
      onAbort()
      return
    }
    signal?.addEventListener('abort', onAbort, { once: true })

    timer = setInterval(() => {
      if (settled) return
      if (signal?.aborted) {
        onAbort()
        return
      }
      const elapsed = Date.now() - startedAt
      const { stage, progress } = progressFor(elapsed)
      onProgress({ stage, progress })

      const parseFailureAt = STAGES[0].durationMs + Math.floor(STAGES[1].durationMs * 0.55)
      if (shouldFail && elapsed >= parseFailureAt) {
        settled = true
        cleanup()
        reject(new Error(PARSE_ERROR))
        return
      }

      if (elapsed >= TOTAL_MS) {
        settled = true
        cleanup()
        onProgress({ stage: 'inferring', progress: 100 })
        const fixtureId = selectFixture(file.name)
        const analysis = cloneFixture(fixtureId)
        resolve({
          ...analysis,
          id: freshId('upload'),
          fileName: file.name,
          analyzedAt: new Date().toISOString(),
          source: 'upload',
        })
      }
    }, TICK_MS)
  })
}

export const mockApi: SentinelApi = {
  uploadAndAnalyze: (file, onProgress, signal) => runMockPipeline(file, onProgress, signal),
  getModelRegistry: (): Promise<ModelEntry[]> => Promise.resolve(MODEL_REGISTRY),
  getModelLogs: (sinceId?: string): Promise<LogLine[]> => Promise.resolve(nextLogs(sinceId)),
  openLiveCapture: (sourceId, speed): LiveSocket => new MockLiveSocket(sourceId, speed),
}

/** Re-exported for the empty-state fixture menu. */
export { getFixtureForFileName, cloneFixture }
