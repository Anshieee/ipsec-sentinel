import { Card, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { ConfidenceBar } from '@/components/ui/ConfidenceBar'
import { useSentinel, useDerived } from '@/store/useSentinel'
import { fmtPct } from '@/lib/format'
import type { TrafficLabel } from '@/types/analysis'

export interface ClassificationDetailProps {
  classes: { label: TrafficLabel; probability: number }[]
}

/** Class probability table plus the uncertainty threshold slider (spec 10.3 item 2). */
export function ClassificationDetail({ classes }: ClassificationDetailProps) {
  const threshold = useSentinel((s) => s.settings.uncertainThreshold)
  const setSetting = useSentinel((s) => s.setSetting)
  const derived = useDerived()

  const sorted = [...classes].sort((a, b) => b.probability - a.probability)
  const top = sorted[0]

  return (
    <Card data-testid="classification-detail">
      <CardHeader
        title="Traffic classification detail"
        description="Probability per class with the uncertainty threshold applied to the top-1 prediction"
      />

      <label className="mb-3 flex flex-col gap-1.5 text-[13px] text-ink" htmlFor="uncertain-threshold">
        <span className="flex items-center justify-between gap-2">
          <span>Uncertainty threshold</span>
          <span className="tnum text-muted">{fmtPct(threshold, 0)}</span>
        </span>
        <input
          id="uncertain-threshold"
          type="range"
          min={0.3}
          max={0.9}
          step={0.05}
          value={threshold}
          data-testid="threshold-slider"
          aria-valuetext={`${fmtPct(threshold, 0)} threshold`}
          onChange={(event) => setSetting('uncertainThreshold', Number(event.target.value))}
          className="h-2 w-full cursor-pointer appearance-none rounded-full bg-track accent-accent-solid"
        />
        <span className="text-[11px] text-muted">
          The classification is marked uncertain when the top-1 probability falls below this value.
        </span>
      </label>

      <div
        role="status"
        data-testid="threshold-state"
        className={derived.uncertain ? 'mb-3 text-warn' : 'mb-3 text-safe'}
      >
        {derived.uncertain
          ? 'Uncertain classification — treat the traffic type as unknown.'
          : `Classification is confident at the current threshold.`}
      </div>

      <table className="w-full border-collapse text-xs">
        <caption className="sr-only">Class probabilities</caption>
        <thead>
          <tr className="bg-raised text-left text-muted">
            <th scope="col" className="px-3 py-2 font-medium">Class</th>
            <th scope="col" className="px-3 py-2 font-medium">Probability</th>
            <th scope="col" className="px-3 py-2 font-medium">Distribution</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((entry, index) => (
            <tr key={entry.label} className="border-t border-line/60">
              <td className="px-3 py-2 text-ink">
                {entry.label}
                {index === 0 ? (
                  <Badge tone={derived.uncertain ? 'warn' : 'info'} className="ml-1.5">
                    Top-1
                  </Badge>
                ) : null}
              </td>
              <td className="tnum px-3 py-2 text-ink">{fmtPct(entry.probability)}</td>
              <td className="px-3 py-2">
                <ConfidenceBar value={entry.probability} ariaLabel={`${entry.label} probability`} showValue={false} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {top ? (
        <p className="mt-2 text-[12px] text-muted">
          Top-1: <span className="text-ink">{top.label}</span> at{' '}
          <span className="tnum text-ink">{fmtPct(top.probability)}</span>, threshold{' '}
          <span className="tnum text-ink">{fmtPct(threshold)}</span>.
        </p>
      ) : null}
    </Card>
  )
}
