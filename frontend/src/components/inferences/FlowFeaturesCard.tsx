import { Card, CardHeader } from '@/components/ui/Card'
import { fmtNum } from '@/lib/format'
import type { AnalysisResult } from '@/types/analysis'

const DEFINITIONS: { key: keyof AnalysisResult['flowStats']; label: string; definition: string; unit: string }[] = [
  { key: 'meanLen', label: 'Mean packet length', definition: 'Arithmetic mean of observed packet lengths in bytes.', unit: 'B' },
  { key: 'stdLen', label: 'Length standard deviation', definition: 'Population standard deviation of packet lengths.', unit: 'B' },
  { key: 'meanIatMs', label: 'Mean inter-arrival time', definition: 'Mean time between consecutive packets in the flow.', unit: 'ms' },
  { key: 'burstiness', label: 'Burstiness', definition: 'Ratio of standard deviation to mean inter-arrival time; values above 1 indicate bursty traffic.', unit: '' },
  { key: 'upDownRatio', label: 'Up/down ratio', definition: 'Outbound bytes divided by inbound bytes.', unit: '' },
]

/** Flow feature card with formal one-line definitions (spec 10.3 item 3). */
export function FlowFeaturesCard({ analysis }: { analysis: AnalysisResult }) {
  const stats = analysis.flowStats

  return (
    <Card data-testid="flow-features">
      <CardHeader title="Flow features" description="Statistics computed over the sampled flow" />
      <dl className="divide-y divide-line/60">
        {DEFINITIONS.map((entry) => (
          <div key={entry.key} className="py-2 first:pt-0 last:pb-0">
            <div className="flex items-baseline justify-between gap-3">
              <dt className="text-[13px] text-ink">{entry.label}</dt>
              <dd className="tnum text-[13px] font-semibold text-ink">
                {fmtNum(stats[entry.key], 2)}
                {entry.unit ? <span className="ml-0.5 text-[11px] font-normal text-muted">{entry.unit}</span> : null}
              </dd>
            </div>
            <p className="mt-0.5 text-[11px] leading-4 text-muted">{entry.definition}</p>
          </div>
        ))}
      </dl>
    </Card>
  )
}
