import type { AnalysisResult } from '@/types/analysis'
import { getActiveApi } from '@/api/client'
import { validateUpload } from '@/lib/validate'
import type { SliceCreator } from '../types'

export type UploadStatus = 'idle' | 'uploading' | 'parsing' | 'inferring' | 'complete' | 'error'

export interface UploadState {
  status: UploadStatus
  progress: number
  fileName?: string
  fileSize?: number
  error?: string
  summary?: AnalysisResult['summary']
}

export const IDLE_UPLOAD: UploadState = { status: 'idle', progress: 0 }

export interface UploadSlice {
  upload: UploadState
  startUpload: (file: File) => Promise<void>
  cancelUpload: () => void
  resetUpload: () => void
}

let activeController: AbortController | null = null

const isActive = (status: UploadStatus): boolean =>
  status === 'uploading' || status === 'parsing' || status === 'inferring'

export const createUploadSlice: SliceCreator<UploadSlice> = (set, get) => ({
  upload: IDLE_UPLOAD,
  startUpload: async (file) => {
    if (isActive(get().upload.status)) return

    try {
      await validateUpload(file)
    } catch (error) {
      set({
        upload: {
          status: 'error',
          progress: 0,
          fileName: file.name,
          fileSize: file.size,
          error: error instanceof Error ? error.message : 'Upload failed.',
        },
      })
      return
    }

    const controller = new AbortController()
    activeController = controller
    set({ upload: { status: 'uploading', progress: 0, fileName: file.name, fileSize: file.size } })

    try {
      const analysis = await getActiveApi().uploadAndAnalyze(
        file,
        (progress) => {
          set((state) => ({
            upload: {
              ...state.upload,
              status: progress.stage,
              progress: progress.progress,
              fileName: file.name,
              fileSize: file.size,
            },
          }))
        },
        controller.signal,
      )
      get().setAnalysis(analysis)
      set({
        upload: {
          status: 'complete',
          progress: 100,
          fileName: file.name,
          fileSize: file.size,
          summary: analysis.summary,
        },
      })
      get().notify({ severity: 'success', message: 'Analysis complete.' })
    } catch (error) {
      const err = error instanceof Error ? error : new Error('Upload failed.')
      if (err.name === 'AbortError') {
        set({ upload: IDLE_UPLOAD })
        return
      }
      set({
        upload: {
          status: 'error',
          progress: 0,
          fileName: file.name,
          fileSize: file.size,
          error: err.message,
        },
      })
    } finally {
      activeController = null
    }
  },
  cancelUpload: () => {
    activeController?.abort()
    activeController = null
    set({ upload: IDLE_UPLOAD })
  },
  resetUpload: () => {
    activeController?.abort()
    activeController = null
    set({ upload: IDLE_UPLOAD })
  },
})
