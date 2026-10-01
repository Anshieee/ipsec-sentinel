import type { TrafficLabel } from '@/types/analysis'
import type { ConfusionMatrix } from '@/types/misc'
import { mulberry32 } from '@/lib/prng'

/** Class order used by the classifier, the charts and the confusion matrix. */
export const TRAFFIC_LABELS: TrafficLabel[] = [
  'VoIP',
  'Video Streaming',
  'Web Browsing',
  'ICMP',
  'WhatsApp',
  'E-mail',
  'Other',
]

/** Calibration quality reported with the reliability diagram (spec 10.4). */
export const EXPECTED_CALIBRATION_ERROR = 0.031

/** Diagonal accuracy per class, ranging from 0.82 to 0.97. */
const DIAG = [0.97, 0.95, 0.94, 0.92, 0.9, 0.86, 0.82]

/**
 * 7 x 7 confusion matrix (rows = actual, columns = predicted).
 * Diagonal from 0.82 to 0.97, small off-diagonals, every row sums to 1.
 */
export function confusionMatrix(): ConfusionMatrix {
  const seed = 0xc1a55
  const rows: number[][] = TRAFFIC_LABELS.map((_, rowIndex) => {
    const rng = mulberry32((seed + Math.imul(rowIndex, 7919)) >>> 0)
    const diag = DIAG[rowIndex] ?? 0.9
    const remainder = 1 - diag
    const weights: number[] = []
    let weightSum = 0
    for (let col = 0; col < TRAFFIC_LABELS.length; col++) {
      if (col === rowIndex) {
        weights.push(0)
        continue
      }
      const weight = 0.4 + rng() * 2
      weights.push(weight)
      weightSum += weight
    }
    const values = weights.map((weight) => Number(((remainder * weight) / (weightSum || 1)).toFixed(4)))
    const assigned = values.reduce((sum, v) => sum + v, 0)
    // Push the rounding remainder onto the largest off-diagonal cell so the row sums to 1.
    let largestIndex = 0
    values.forEach((value, index) => {
      if (value > (values[largestIndex] ?? 0)) largestIndex = index
    })
    const existing = values[largestIndex] ?? 0
    values[largestIndex] = Number((existing + (remainder - assigned)).toFixed(4))
    const row = values.map((value, index) => (index === rowIndex ? diag : value))
    // Final reconciliation guards against floating-point drift.
    const rowSum = row.reduce((sum, v) => sum + v, 0)
    const delta = Number((1 - rowSum).toFixed(6))
    if (delta !== 0) {
      const safeIndex = rowIndex === 0 ? 1 : 0
      row[safeIndex] = Number(((row[safeIndex] ?? 0) + delta).toFixed(6))
    }
    return row
  })
  return { labels: TRAFFIC_LABELS, rows }
}

export interface ReliabilityPoint {
  /** Predicted probability bin centre (0.1 .. 1.0). */
  predicted: number
  /** Observed frequency in the bin. */
  observed: number
}

/**
 * Reliability diagram: predicted probability bins against observed frequency.
 * The curve sits slightly below the diagonal at high confidence.
 */
export function reliabilityDiagram(): ReliabilityPoint[] {
  const points: ReliabilityPoint[] = []
  const seed = 0xca11b
  for (let i = 1; i <= 10; i++) {
    const rng = mulberry32((seed + Math.imul(i, 104729)) >>> 0)
    const predicted = Number((i / 10).toFixed(1))
    const highConfidencePenalty = predicted >= 0.7 ? 0.05 : 0.01
    const jitter = (rng() - 0.5) * 0.02
    const observed = Math.min(1, Math.max(0, Number((predicted - highConfidencePenalty + jitter).toFixed(3))))
    points.push({ predicted, observed })
  }
  return points
}
