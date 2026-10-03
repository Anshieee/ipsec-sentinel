import { useMemo } from 'react'
import { Bar, BarChart, Cell, LabelList, ResponsiveContainer, Tooltip as ChartTooltip, XAxis, YAxis } from 'recharts'
import { Card, CardHeader } from '@/components/ui/Card'
import { fmtInt } from '@/lib/format'
import { SEVERITY_TONE, TONE_HEX } from '@/lib/severity'
import type { Tone } from '@/lib/severity'
import { CHART_AXIS, CHART_GRID, CHART_TOOLTIP } from '@/lib/chartColors'
import type { Finding } from '@/types/analysis'

const WEIGHT: Record<Finding['severity'], number> = { critical: 25, high: 12, medium: 5, low: 2 }

interface WaterfallBar {
  name: string
  weight: number
  tone: Tone
  total?: boolean
}

/** Score contribution waterfall: one bar per failing finding plus a total (spec 10.4 item 3). */
export function ScoreWaterfall({
  findings,
  total,
  backend,
  ruleVersion,
}: {
  findings: Finding[]
  /** Backend risk when PUBLISHED, null when WITHHELD (no total bar then). */
  total: number | null
  /** Backend-mapped result: totals come from the backend, never client weights. */
  backend?: boolean
  ruleVersion?: string | null
}) {
  const bars = useMemo<WaterfallBar[]>(() => {
    const sorted = [...findings].sort((a, b) => WEIGHT[b.severity] - WEIGHT[a.severity])
    const entries = sorted.map((finding, index) => ({
      name: `${finding.ruleId} ${index + 1}`,
      weight: WEIGHT[finding.severity],
      tone: SEVERITY_TONE[finding.severity],
    }))
    return total === null
      ? entries
      : [...entries, { name: 'Total', weight: total, tone: 'neutral' as Tone, total: true }]
  }, [findings, total])

  return (
    <Card data-testid="score-waterfall">
      <CardHeader title="Score contribution" description="Weight per failing finding, ordered descending" />
      <figure className="m-0">
        <div className="h-64 w-full" aria-hidden="true">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={bars} margin={{ top: 8, right: 12, bottom: 4, left: 0 }}>
              <XAxis
                dataKey="name"
                tick={{ fontSize: 11, fill: CHART_AXIS }}
                axisLine={{ stroke: CHART_GRID }}
                tickLine={{ stroke: CHART_GRID }}
                interval={0}
                angle={-30}
                textAnchor="end"
                height={54}
              />
              <YAxis tick={{ fontSize: 11, fill: CHART_AXIS }} axisLine={{ stroke: CHART_GRID }} tickLine={{ stroke: CHART_GRID }} />
              <ChartTooltip contentStyle={CHART_TOOLTIP} />
              <Bar dataKey="weight" isAnimationActive={false} radius={[3, 3, 0, 0]}>
                {bars.map((bar) => (
                  <Cell
                    key={bar.name}
                    fill={bar.total ? TONE_HEX.neutral : TONE_HEX[bar.tone]}
                    fillOpacity={bar.total ? 0.7 : 1}
                  />
                ))}
                <LabelList dataKey="weight" position="top" style={{ fontSize: 11, fill: CHART_AXIS }} />
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
        <figcaption className="mt-1 text-[11px] text-muted">
          {total === null ? (
            <>Score withheld: insufficient evidence — bars show finding severities only, no total.</>
          ) : backend ? (
            <>
              Total risk {fmtInt(total)} (backend rule {ruleVersion ?? 'n/a'}). Per-finding bars show severity
              weights for illustration only — the headline is the backend posture.
            </>
          ) : (
            <>Total contribution {fmtInt(total)} points before the 100-point cap.</>
          )}
        </figcaption>
        <table className="sr-only">
          <caption>Score contribution per finding</caption>
          <thead>
            <tr>
              <th scope="col">Finding</th>
              <th scope="col">Weight</th>
            </tr>
          </thead>
          <tbody>
            {bars.map((bar) => (
              <tr key={bar.name}>
                <td>{bar.name}</td>
                <td>{bar.weight}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </figure>
    </Card>
  )
}
