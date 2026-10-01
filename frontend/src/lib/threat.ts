import type { Finding, Severity, ThreatCategory } from '@/types/analysis'
import { SEVERITIES } from './severity'
import { WEIGHT } from './risk'

export const THREAT_CATEGORIES: ThreatCategory[] = [
  'Weak Cipher',
  'Key Exchange',
  'PFS',
  'Replay',
  'Lifetime',
  'Metadata',
  'Protocol',
]

export type ThreatMatrix = Record<Severity, Record<ThreatCategory, number>>

/** 4 x 7 count matrix: severity (rows) by threat category (columns). */
export function threatMatrix(findings: Pick<Finding, 'severity' | 'category'>[]): ThreatMatrix {
  const matrix = {} as ThreatMatrix
  for (const severity of SEVERITIES) {
    const row = {} as Record<ThreatCategory, number>
    for (const category of THREAT_CATEGORIES) row[category] = 0
    matrix[severity] = row
  }
  for (const finding of findings) {
    matrix[finding.severity][finding.category] += 1
  }
  return matrix
}

export function matrixRowTotal(matrix: ThreatMatrix, severity: Severity): number {
  return THREAT_CATEGORIES.reduce((sum, category) => sum + matrix[severity][category], 0)
}

export function matrixColumnTotal(matrix: ThreatMatrix, category: ThreatCategory): number {
  return SEVERITIES.reduce((sum, severity) => sum + matrix[severity][category], 0)
}

export function matrixGrandTotal(matrix: ThreatMatrix): number {
  return SEVERITIES.reduce((sum, severity) => sum + matrixRowTotal(matrix, severity), 0)
}

/** Per-category safety score for the radar chart: 100 minus the summed weight, capped at 0. */
export function categoryScores(findings: Pick<Finding, 'severity' | 'category'>[]): Record<ThreatCategory, number> {
  const totals = {} as Record<ThreatCategory, number>
  for (const category of THREAT_CATEGORIES) totals[category] = 0
  for (const finding of findings) {
    totals[finding.category] += WEIGHT[finding.severity]
  }
  const scores = {} as Record<ThreatCategory, number>
  for (const category of THREAT_CATEGORIES) {
    scores[category] = 100 - Math.min(100, totals[category])
  }
  return scores
}

/** Counts per severity, used by the audit header. */
export function severityCounts(findings: Pick<Finding, 'severity'>[]): Record<Severity, number> {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 } as Record<Severity, number>
  for (const finding of findings) counts[finding.severity] += 1
  return counts
}

export type StrideTag = Finding['stride']

export const STRIDE_TAGS: StrideTag[] = [
  'Spoofing',
  'Tampering',
  'Repudiation',
  'Information Disclosure',
  'Denial of Service',
  'Elevation of Privilege',
]

export function strideCounts(findings: Pick<Finding, 'stride'>[]): Record<StrideTag, number> {
  const counts = {} as Record<StrideTag, number>
  for (const tag of STRIDE_TAGS) counts[tag] = 0
  for (const finding of findings) counts[finding.stride] += 1
  return counts
}
