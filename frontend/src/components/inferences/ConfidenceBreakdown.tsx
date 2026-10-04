import { useMemo } from 'react'
import { Bar, BarChart, Cell, LabelList, ResponsiveContainer, Tooltip as ChartTooltip, XAxis, YAxis } from 'recharts'
import { Card, CardHeader } from '@/components/ui/Card'
import { fmtPct } from '@/lib/format'
import { confidenceTone, TONE_HEX } from '@/lib/severity'
import type { Tone } from '@/lib/severity'
import { CHART_AXIS, CHART_GRID, CHART_TOOLTIP } from '@/lib/chartColors'
import type { AnalysisResult } from '@/types/analysis'

interface Point {
  name: string
  confidence: number
  tone: Tone
}

const UNOBSERVED_STATUSES = ['UNKNOWN', 'NOT_OBSERVED', 'NOT_APPLICABLE']

/** Confidence breakdown: only fields with real confidence (spec 10.3 item 5).
 * Unknown / not-observed fields are omitted (listed below the chart). */
export function ConfidenceBreakdown({ analysis }: { analysis: AnalysisResult }) {
  const p = analysis.protocol

  const candidates = useMemo<{ name: string; param: { confidence: number; status?: string } }[]>(() => {
    const ip: { confidence: number; status?: string } = p.ipVersion
    const nat: { confidence: number; status?: string } = p.natTraversal
    return [
      { name: 'Mode', param: p.mode },
      { name: 'IP version', param: ip },
      { name: 'NAT traversal', param: nat },
      { name: 'IKE cipher', param: p.ike.encryption },
      { name: 'IKE integrity', param: p.ike.integrity },
      { name: 'PRF', param: p.ike.prf },
      { name: 'DH group', param: p.ike.dhGroup },
      { name: 'CHILD cipher', param: p.child.encryption },
      { name: 'CHILD integrity', param: p.child.integrity },
      { name: 'PFS', param: p.child.pfs },
    ]
  }, [p])

  const { points, omitted } = useMemo(() => {
    const pts: Point[] = []
    const omit: string[] = []
    for (const entry of candidates) {
      const st = entry.param.status
      if (st !== undefined && UNOBSERVED_STATUSES.includes(st)) {
        omit.push(entry.name)
        continue
      }
      const c = entry.param.confidence
      if (!Number.isFinite(c)) {
        omit.push(entry.name)
        continue
      }
      pts.push({ name: entry.name, confidence: c, tone: confidenceTone(c) })
    }
    return { points: pts, omitted: omit }
  }, [candidates])
  // Keep every category tick legible: grow the chart with the row count.
  const height = Math.max(160, points.length * 36 + 64)

  return (
    <Card data-testid="confidence-breakdown">
      <CardHeader title="Confidence breakdown" description="Backend confidence per observed field" />
      <figure className="m-0">
        <div className="w-full" style={{ height }} aria-hidden="true">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={points} layout="vertical" margin={{ top: 4, right: 12, bottom: 4, left: 4 }}>
              <XAxis
                type="number"
                domain={[0, 1]}
                tickFormatter={(value: number) => `${Math.round(value * 100)}%`}
                tick={{ fontSize: 11, fill: CHART_AXIS }}
                axisLine={{ stroke: CHART_GRID }}
                tickLine={{ stroke: CHART_GRID }}
              />
              <YAxis
                type="category"
                dataKey="name"
                width={110}
                tick={{ fontSize: 11, fill: CHART_AXIS }}
                axisLine={{ stroke: CHART_GRID }}
                tickLine={{ stroke: CHART_GRID }}
                interval={0}
              />
              <ChartTooltip
                formatter={(value: number | string) => [`${Number(value) * 100}%`, 'Confidence']}
                contentStyle={CHART_TOOLTIP}
              />
              <Bar dataKey="confidence" radius={[0, 4, 4, 0]} isAnimationActive={false}>
                {points.map((point) => (
                  <Cell key={point.name} fill={TONE_HEX[point.tone]} />
                ))}
                <LabelList
                  dataKey="confidence"
                  position="right"
                  formatter={(value: number | string) => `${Math.round(Number(value) * 100)}%`}
                  style={{ fontSize: 11, fill: CHART_AXIS }}
                />
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
        <figcaption className="mt-1 text-[11px] text-muted">
          Bands: at least 85 % strong, 70–85 % moderate, below 70 % weak.
          {omitted.length > 0 ? ` Not observed (omitted): ${omitted.join(', ')}.` : ''}
        </figcaption>
        <table className="sr-only">
          <caption>Confidence per inferred parameter</caption>
          <thead>
            <tr>
              <th scope="col">Parameter</th>
              <th scope="col">Confidence</th>
            </tr>
          </thead>
          <tbody>
            {points.map((point) => (
              <tr key={point.name}>
                <td>{point.name}</td>
                <td>{fmtPct(point.confidence)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </figure>
    </Card>
  )
}
