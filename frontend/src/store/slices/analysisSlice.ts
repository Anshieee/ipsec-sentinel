import type { AnalysisResult } from '@/types/analysis'
import type { SliceCreator } from '../types'

export type AnalysisStatus = 'idle' | 'loading' | 'ready' | 'error'

export interface AnalysisSlice {
  current: AnalysisResult | null
  previousRiskScore?: number
  status: AnalysisStatus
  error?: string
  setAnalysis: (analysis: AnalysisResult) => void
  setLoading: () => void
  setError: (message: string) => void
  clear: () => void
}

export const createAnalysisSlice: SliceCreator<AnalysisSlice> = (set, get) => ({
  current: null,
  previousRiskScore: undefined,
  status: 'idle',
  error: undefined,
  setAnalysis: (analysis) => {
    const previous = get().current
    set({
      current: analysis,
      status: 'ready',
      error: undefined,
      previousRiskScore: previous && previous.id !== analysis.id ? previous.riskScore : get().previousRiskScore,
    })
  },
  setLoading: () => set({ status: 'loading', error: undefined }),
  setError: (message) => set({ status: 'error', error: message }),
  clear: () => set({ current: null, status: 'idle', error: undefined, previousRiskScore: undefined }),
})
