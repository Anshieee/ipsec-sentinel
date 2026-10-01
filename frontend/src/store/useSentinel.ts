import { useMemo } from 'react'
import { create } from 'zustand'
import { createJSONStorage, persist } from 'zustand/middleware'
import type { AnalysisResult, Finding, Severity, ThreatCategory, TrafficLabel } from '@/types/analysis'
import type { StrideTag } from '@/lib/threat'
import { categoryScores, severityCounts, strideCounts, threatMatrix } from '@/lib/threat'
import { evaluate } from '@/lib/rules'
import { computeRiskScore, riskBand } from '@/lib/risk'
import type { RiskBand } from '@/lib/severity'
import { topClass } from '@/lib/rules'
import { configureMock } from '@/api/mock'
import { createAnalysisSlice } from './slices/analysisSlice'
import { createUploadSlice } from './slices/uploadSlice'
import { createLiveSlice } from './slices/liveSlice'
import { createUiSlice } from './slices/uiSlice'
import { createSettingsSlice } from './slices/settingsSlice'
import type { SentinelState } from './types'

const STORAGE_KEY = 'sentinel.settings.v1'

/** localStorage access is wrapped so a privacy-mode failure cannot break the app. */
const safeStorage = () => ({
  getItem: (name: string): string | null => {
    try {
      return window.localStorage.getItem(name)
    } catch {
      return null
    }
  },
  setItem: (name: string, value: string): void => {
    try {
      window.localStorage.setItem(name, value)
    } catch {
      /* storage unavailable: settings stay in memory */
    }
  },
  removeItem: (name: string): void => {
    try {
      window.localStorage.removeItem(name)
    } catch {
      /* storage unavailable */
    }
  },
})

export const useSentinel = create<SentinelState>()(
  persist(
    (set, get, api) => ({
      ...createAnalysisSlice(set, get, api),
      ...createUploadSlice(set, get, api),
      ...createLiveSlice(set, get, api),
      ...createUiSlice(set, get, api),
      ...createSettingsSlice(set, get, api),
    }),
    {
      name: STORAGE_KEY,
      storage: createJSONStorage(safeStorage),
      partialize: (state) => ({ settings: state.settings }),
      merge: (persisted, current) => {
        const incoming = (persisted ?? {}) as Partial<SentinelState>
        return {
          ...current,
          ...incoming,
          settings: { ...current.settings, ...(incoming.settings ?? {}) },
        }
      },
      onRehydrateStorage: () => (state) => {
        if (state) configureMock({ simulateErrors: state.settings.simulateErrors })
      },
    },
  ),
)

/** The analysis currently on screen: the live working state while capturing, otherwise the stored one. */
export const useAnalysis = (): AnalysisResult | null =>
  useSentinel((state) =>
    state.live.status === 'capturing' && state.live.working ? state.live.working : state.current,
  )

export interface DerivedValues {
  analysis: AnalysisResult | null
  findings: Finding[]
  bySeverity: Record<Severity, Finding[]>
  matrix: ReturnType<typeof threatMatrix>
  categoryScores: Record<ThreatCategory, number>
  severityCounts: Record<Severity, number>
  strideCounts: Record<StrideTag, number>
  riskScore: number
  band: RiskBand
  topClass: { label: TrafficLabel; probability: number }
  uncertain: boolean
}

/** Memoised derived values, always recomputed through the rule engine. */
export function useDerived(): DerivedValues {
  const analysis = useAnalysis()
  const minRuleConfidence = useSentinel((state) => state.settings.minRuleConfidence)
  const uncertainThreshold = useSentinel((state) => state.settings.uncertainThreshold)

  return useMemo(
    () => deriveValues(analysis, minRuleConfidence, uncertainThreshold),
    [analysis, minRuleConfidence, uncertainThreshold],
  )
}

/**
 * The derivation `useDerived` wraps, as a plain function: the same rule engine
 * and thresholds, callable outside a render (tests, exports, one-off reads).
 */
export function deriveValues(
  analysis: AnalysisResult | null,
  minRuleConfidence: number,
  uncertainThreshold: number,
): DerivedValues {
  if (!analysis) {
    const emptyMatrix = threatMatrix([])
    const emptyScores = categoryScores([])
    return {
      analysis: null,
      findings: [],
      bySeverity: { critical: [], high: [], medium: [], low: [] },
      matrix: emptyMatrix,
      categoryScores: emptyScores,
      severityCounts: { critical: 0, high: 0, medium: 0, low: 0 },
      strideCounts: {
        Spoofing: 0,
        Tampering: 0,
        Repudiation: 0,
        'Information Disclosure': 0,
        'Denial of Service': 0,
        'Elevation of Privilege': 0,
      },
      riskScore: 0,
      band: 'low',
      topClass: { label: 'Other', probability: 0 },
      uncertain: false,
    }
  }
  const evaluation = evaluate(analysis.protocol, analysis.trafficClasses, undefined, minRuleConfidence)
  const findings = evaluation.findings
  const top = topClass(analysis.trafficClasses)
  return {
    analysis,
    findings,
    bySeverity: {
      critical: findings.filter((f) => f.severity === 'critical'),
      high: findings.filter((f) => f.severity === 'high'),
      medium: findings.filter((f) => f.severity === 'medium'),
      low: findings.filter((f) => f.severity === 'low'),
    },
    matrix: threatMatrix(findings),
    categoryScores: categoryScores(findings),
    severityCounts: severityCounts(findings),
    strideCounts: strideCounts(findings),
    riskScore: computeRiskScore(findings),
    band: riskBand(computeRiskScore(findings)),
    topClass: top,
    uncertain: top.probability < uncertainThreshold,
  }
}
