import type { Finding, Severity } from '@/types/analysis'
import type { RiskBand } from './severity'

export const WEIGHT: Record<Severity, number> = { critical: 25, high: 12, medium: 5, low: 2 }

export const computeRiskScore = (findings: Pick<Finding, 'severity'>[]): number =>
  Math.min(100, findings.reduce((s, f) => s + WEIGHT[f.severity], 0))

export const riskBand = (s: number): RiskBand => (s >= 70 ? 'high' : s >= 40 ? 'moderate' : 'low')

/** Human sentence used in reports and aria-valuetext. */
export function riskBandSentence(score: number): string {
  const band = riskBand(score)
  const label = band === 'high' ? 'high risk' : band === 'moderate' ? 'moderate risk' : 'low risk'
  return `${score} out of 100, ${label}`
}

export function scoreDelta(current: number, previous: number | undefined): number | null {
  if (previous === undefined) return null
  return current - previous
}
