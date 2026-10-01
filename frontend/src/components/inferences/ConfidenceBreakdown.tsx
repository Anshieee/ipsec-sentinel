import { useMemo } from 'react'
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip as ChartTooltip, XAxis, YAxis } from 'recharts'
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

/** Confidence breakdown for inferred parameters (spec 10.3 item 5). */
export function ConfidenceBreakdown({ analysis }: { analysis: AnalysisResult }) {
  const p = analysis.protocol

  const points = useMemo<Point[]>(() => {
    const entries: Point[] = [
      { name: 'Mode', confidence: p.mode.confidence, tone: confidenceTone(p.mode.confidence) },
      { name: 'IKE cipher', confidence: p.ike.encryption.confidence, tone: confidenceTone(p.ike.encryption.confidence) },
      { name: 'IKE integrity', confidence: p.ike.integrity.confidence, tone: confidenceTone(p.ike.integrity.confidence) },
      { name: 'DH group', confidence: p.ike.dhGroup.confidence, tone: confidenceTone(p.ike.dhGroup.confidence) },
      { name: 'CHILD cipher', confidence: p.child.encryption.confidence, tone: confidenceTone(p.child.encryption.confidence) },
      { name: 'CHILD integrity', confidence: p.child.integrity.confidence, tone: confidenceTone(p.child.integrity.confidence) },
      { name: 'PFS', confidence: p.child.pfs.confidence, tone: confidenceTone(p.child.pfs.confidence) },
      { name: 'Lifetime', confidence: p.child.lifetimeSec.confidence, tone: confidenceTone(p.child.lifetimeSec.confidence) },
      { name: 'Replay', confidence: p.child.replayProtection.confidence, tone: confidenceTone(p.child.replayProtection.confidence) },
      { name: 'ESN', confidence: p.child.esn.confidence, tone: confidenceTone(p.child.esn.confidence) },
    ]
    return entries.filter((entry) => Number.isFinite(entry.confidence))
  }, [p])

  return (
    <Card data-testid="confidence-breakdown">
      <CardHeader title="Confidence breakdown" description="Calibrated probability per inferred parameter" />
      <figure className="m-0">
        <div className="h-64 w-full" aria-hidden="true">
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
                width={96}
                tick={{ fontSize: 11, fill: CHART_AXIS }}
                axisLine={{ stroke: CHART_GRID }}
                tickLine={{ stroke: CHART_GRID }}
              />
              <ChartTooltip
                formatter={(value: number | string) => [`${Number(value) * 100}%`, 'Confidence']}
                contentStyle={CHART_TOOLTIP}
              />
              <Bar dataKey="confidence" radius={[0, 4, 4, 0]} isAnimationActive={false}>
                {points.map((point) => (
                  <Cell key={point.name} fill={TONE_HEX[point.tone]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
        <figcaption className="mt-1 text-[11px] text-muted">
          Bands: at least 85 % strong, 70–85 % moderate, below 70 % weak.
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
