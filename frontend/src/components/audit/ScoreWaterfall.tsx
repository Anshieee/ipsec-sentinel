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

export interface BackendControlLike {
  id: string
  weight: number
  points: number
  source: string
  confidence: number
}

/** Per-control points lost, scaled so the bars sum exactly to the
 * displayed total risk: lost_c = (w_c−p_c)·f_c, bar_c = lost_c·risk/Σlost.
 * Evidence factor f: 1.0 observed/label, confidence when inferred. */
export function waterfallBars(controls: BackendControlLike[], riskScore: number | null): WaterfallBar[] {
  const factor = (c: BackendControlLike): number =>
    c.source === 'inferred' ? Math.min(Math.max(c.confidence, 0), 1) : c.source === 'observed' || c.source === 'label' ? 1 : 0
  const lost = controls
    .map((c) => ({ id: c.id, lost: (c.weight - c.points) * factor(c) }))
    .filter((e) => e.lost > 0)
  const sumLost = lost.reduce((s, e) => s + e.lost, 0)
  const entries = lost.map((e) => ({
    name: e.id,
    weight: sumLost > 0 && riskScore !== null ? (e.lost * riskScore) / sumLost : 0,
    tone: 'neutral' as Tone,
  }))
  return riskScore === null
    ? entries
    : [...entries, { name: 'Total', weight: riskScore, tone: 'neutral' as Tone, total: true }]
}

/** Score contribution waterfall: per-control points lost plus a total. */
export function ScoreWaterfall({
  findings,
  total,
  backend,
  ruleVersion,
  controls,
}: {
  findings: Finding[]
  /** Backend risk when PUBLISHED, null when WITHHELD (no total bar then). */
  total: number | null
  /** Backend-mapped result: totals come from the backend, never client weights. */
  backend?: boolean
  ruleVersion?: string | null
  /** Backend controls: per-control lost-points bars summing to the total. */
  controls?: BackendControlLike[]
}) {
  const bars = useMemo<WaterfallBar[]>(() => {
    if (backend && controls) return waterfallBars(controls, total ?? 0)
    const sorted = [...findings].sort((a, b) => WEIGHT[b.severity] - WEIGHT[a.severity])
    const entries = sorted.map((finding, index) => ({
      name: `${finding.ruleId} ${index + 1}`,
      weight: WEIGHT[finding.severity],
      tone: SEVERITY_TONE[finding.severity],
    }))
    return total === null
      ? entries
      : [...entries, { name: 'Total', weight: total, tone: 'neutral' as Tone, total: true }]
  }, [findings, total, backend, controls])

  return (
    <Card data-testid="score-waterfall">
      <CardHeader title="Score contribution" description="Weight per failing finding, ordered descending" />
      <figure className="m-0">
        <div className="h-64 w-full" aria-hidden="true">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={bars} margin={{ top: 20, right: 12, bottom: 4, left: 0 }}>
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
              <YAxis
                tick={{ fontSize: 11, fill: CHART_AXIS }}
                axisLine={{ stroke: CHART_GRID }}
                tickLine={{ stroke: CHART_GRID }}
                domain={[0, (dataMax: number) => Math.ceil(dataMax * 1.25)]}
              />
              <ChartTooltip contentStyle={CHART_TOOLTIP} />
              <Bar dataKey="weight" isAnimationActive={false} radius={[3, 3, 0, 0]}>
                {bars.map((bar) => (
                  <Cell
                    key={bar.name}
                    fill={bar.total ? TONE_HEX.neutral : TONE_HEX[bar.tone]}
                    fillOpacity={bar.total ? 0.7 : 1}
                  />
                ))}
                <LabelList
                  dataKey="weight"
                  position="top"
                  formatter={(value: number | string) => Number(value).toFixed(1)}
                  style={{ fontSize: 11, fill: CHART_AXIS }}
                />
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
        <figcaption className="mt-1 text-[11px] text-text-secondary">
          {total === null ? (
            <>Score withheld: insufficient evidence — bars show per-control points lost, no total.</>
          ) : backend ? (
            <>
              Total risk {fmtInt(total)} (backend rule {ruleVersion ?? 'n/a'}): per-control points lost from
              backend weights, points and evidence factors — bars sum to the total.
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
