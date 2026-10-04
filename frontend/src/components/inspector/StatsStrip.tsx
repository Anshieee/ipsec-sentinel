import { Card } from '@/components/ui/Card'
import { fmtDuration, fmtInt } from '@/lib/format'
import type { AnalysisResult } from '@/types/analysis'

interface Stat {
  label: string
  value: string
}

function statsFor(analysis: AnalysisResult | null, counters: { packets: number; ike: number; esp: number; ah: number; other: number }, elapsedSec: number): Stat[] {
  if (analysis) {
    // Backend-mapped results: IKE/ESP/AH come from detection.evidence
    // packet counts; Other = total minus those (never total itself).
    const det = analysis.detection
    const total = det?.nPackets ?? analysis.summary.packets
    const ike = det?.nIke ?? analysis.summary.ikeHandshakes
    const esp = det?.nEsp ?? analysis.summary.espStreams
    const ah = det?.nAh ?? analysis.summary.ahPackets
    return [
      { label: 'Total', value: fmtInt(total) },
      { label: 'IKE', value: fmtInt(ike) },
      { label: 'ESP', value: fmtInt(esp) },
      { label: 'AH', value: fmtInt(ah) },
      { label: 'Other', value: fmtInt(Math.max(0, total - ike - esp - ah)) },
      { label: 'Duration', value: fmtDuration(analysis.summary.durationSec) },
    ]
  }
  return [
    { label: 'Total', value: fmtInt(counters.packets) },
    { label: 'IKE', value: fmtInt(counters.ike) },
    { label: 'ESP', value: fmtInt(counters.esp) },
    { label: 'AH', value: fmtInt(counters.ah) },
    { label: 'Other', value: fmtInt(counters.other) },
    { label: 'Duration', value: fmtDuration(elapsedSec) },
  ]
}

export interface StatsStripProps {
  analysis: AnalysisResult | null
  counters: { packets: number; ike: number; esp: number; ah: number; other: number }
  elapsedSec: number
}

/** Top stats strip for the inspector (spec 10.2 item 1). */
export function StatsStrip({ analysis, counters, elapsedSec }: StatsStripProps) {
  const stats = statsFor(analysis, counters, elapsedSec)
  return (
    <Card data-testid="stats-strip">
      <dl className="grid grid-cols-3 gap-4 sm:grid-cols-6">
        {stats.map((stat) => (
          <div key={stat.label}>
            <dt className="text-[11px] text-text-secondary">{stat.label}</dt>
            <dd className="tnum text-lg font-semibold leading-6 text-text-primary">{stat.value}</dd>
          </div>
        ))}
      </dl>
    </Card>
  )
}
