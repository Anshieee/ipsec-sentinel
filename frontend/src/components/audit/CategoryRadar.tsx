import { useMemo } from 'react'
import {
  PolarAngleAxis,
  PolarGrid,
  PolarRadiusAxis,
  Radar,
  RadarChart,
  ResponsiveContainer,
  Tooltip as ChartTooltip,
} from 'recharts'
import { Card, CardHeader } from '@/components/ui/Card'
import { CHART_AXIS, CHART_GRID, CHART_PALETTE, CHART_TOOLTIP } from '@/lib/chartColors'
import { THREAT_CATEGORIES } from '@/lib/threat'
import type { ThreatCategory } from '@/types/analysis'

/** Category safety radar: 100 is safe, 0 is fully weighted (spec 10.4 item 4). */
export function CategoryRadar({ scores }: { scores: Record<ThreatCategory, number> }) {
  const data = useMemo(
    () => THREAT_CATEGORIES.map((category) => ({ category, score: scores[category] })),
    [scores],
  )

  return (
    <Card data-testid="category-radar">
      <CardHeader title="Category safety" description="Higher is safer" />
      <figure className="m-0">
        <div className="h-64 w-full" aria-hidden="true">
          <ResponsiveContainer width="100%" height="100%">
            <RadarChart data={data} outerRadius="70%">
              <PolarGrid stroke={CHART_GRID} />
              <PolarAngleAxis dataKey="category" tick={{ fontSize: 11, fill: CHART_AXIS }} />
              <PolarRadiusAxis domain={[0, 100]} tick={{ fontSize: 11, fill: CHART_AXIS }} />
              <ChartTooltip contentStyle={CHART_TOOLTIP} />
              <Radar
                dataKey="score"
                stroke={CHART_PALETTE[0]}
                fill={CHART_PALETTE[0]}
                fillOpacity={0.35}
                isAnimationActive={false}
              />
            </RadarChart>
          </ResponsiveContainer>
        </div>
        <figcaption className="mt-1 text-[11px] text-text-secondary">Higher is safer.</figcaption>
        <table className="sr-only">
          <caption>Safety score per threat category</caption>
          <thead>
            <tr>
              <th scope="col">Category</th>
              <th scope="col">Safety score</th>
            </tr>
          </thead>
          <tbody>
            {data.map((entry) => (
              <tr key={entry.category}>
                <td>{entry.category}</td>
                <td>{entry.score}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </figure>
    </Card>
  )
}
