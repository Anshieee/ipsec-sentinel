import { useState } from 'react'
import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip as ChartTooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { TriangleAlert } from 'lucide-react'
import { Card, CardHeader } from '@/components/ui/Card'
import { SegmentedControl } from '@/components/ui/SegmentedControl'
import { useSentinel, useDerived } from '@/store/useSentinel'
import { fmtPct } from '@/lib/format'
import { CHART_AXIS, CHART_GRID, CHART_PALETTE, CHART_TOOLTIP } from '@/lib/chartColors'
import type { TrafficLabel } from '@/types/analysis'

type View = 'bar' | 'donut'

const BAR_FILL = CHART_PALETTE[0]
const BAR_MUTED = CHART_PALETTE[6]
const PALETTE = CHART_PALETTE

/** Encrypted traffic classifier chart (spec 10.1 C.1). */
export function ClassChart({ classes }: { classes: { label: TrafficLabel; probability: number }[] }) {
  const [view, setView] = useState<View>('bar')
  const threshold = useSentinel((s) => s.settings.uncertainThreshold)
  const derived = useDerived()

  const sorted = [...classes].sort((a, b) => b.probability - a.probability)
  const top = sorted[0]
  const uncertain = derived.uncertain && Boolean(top && top.probability < threshold)
  const data = sorted.map((entry) => ({
    label: entry.label,
    percent: Math.round(entry.probability * 1000) / 10,
    probability: entry.probability,
  }))

  if (!top) return null

  return (
    <Card data-testid="class-chart">
      <CardHeader
        title="Encrypted traffic classifier"
        description="Probability per traffic class (0–100 %)"
        actions={
          <SegmentedControl
            ariaLabel="Chart type"
            value={view}
            onChange={(value) => setView(value as View)}
            compact
            options={[
              { value: 'bar', label: 'Bar' },
              { value: 'donut', label: 'Donut' },
            ]}
          />
        }
      />

      <figure className="m-0">
        <div className="h-56 w-full" aria-hidden="true">
          <ResponsiveContainer width="100%" height="100%">
            {view === 'bar' ? (
              <BarChart data={data} layout="vertical" margin={{ top: 4, right: 12, bottom: 4, left: 4 }}>
                <XAxis
                  type="number"
                  domain={[0, 100]}
                  tickFormatter={(v: number) => `${v}%`}
                  tick={{ fontSize: 11, fill: CHART_AXIS }}
                  axisLine={{ stroke: CHART_GRID }}
                  tickLine={{ stroke: CHART_GRID }}
                />
                <YAxis
                  type="category"
                  dataKey="label"
                  width={110}
                  tick={{ fontSize: 11, fill: CHART_AXIS }}
                  axisLine={{ stroke: CHART_GRID }}
                  tickLine={{ stroke: CHART_GRID }}
                />
                <ChartTooltip
                  formatter={(value: number | string) => [`${value}%`, 'Probability']}
                  contentStyle={CHART_TOOLTIP}
                />
                <Bar dataKey="percent" radius={[0, 4, 4, 0]} isAnimationActive={false}>
                  {data.map((entry, index) => (
                    <Cell key={entry.label} fill={index === 0 ? BAR_FILL : BAR_MUTED} />
                  ))}
                </Bar>
              </BarChart>
            ) : (
              <PieChart>
                <Pie
                  data={data}
                  dataKey="percent"
                  nameKey="label"
                  innerRadius={50}
                  outerRadius={80}
                  isAnimationActive={false}
                >
                  {data.map((entry, index) => (
                    <Cell key={entry.label} fill={PALETTE[index % PALETTE.length]} />
                  ))}
                </Pie>
                <ChartTooltip
                  formatter={(value: number | string) => [`${value}%`, 'Probability']}
                  contentStyle={CHART_TOOLTIP}
                />
              </PieChart>
            )}
          </ResponsiveContainer>
        </div>

        <figcaption className="mt-1 text-[13px] text-muted">
          Top-1: <span className="font-medium text-ink">{top.label}</span> at{' '}
          <span className="tnum text-ink">{fmtPct(top.probability)}</span> confidence.
        </figcaption>

        <table className="sr-only">
          <caption>Traffic class probabilities</caption>
          <thead>
            <tr>
              <th scope="col">Class</th>
              <th scope="col">Probability</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((entry) => (
              <tr key={entry.label}>
                <td>{entry.label}</td>
                <td>{fmtPct(entry.probability)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </figure>

      {uncertain ? (
        <div
          role="status"
          data-testid="uncertain-banner"
          className="mt-3 rounded-control border border-warn/40 bg-warn/10 px-3 py-2"
        >
          <p className="flex items-center gap-1.5 text-xs font-semibold text-warn">
            <TriangleAlert size={14} aria-hidden="true" />
            Uncertain classification
          </p>
          <p className="mt-0.5 text-[12px] leading-4 text-muted">
            Uncertain classification. The top prediction is below the confidence threshold; treat the traffic type as
            unknown.
          </p>
          <ul className="mt-1.5 flex flex-wrap gap-2 text-[11px]">
            {sorted.slice(0, 3).map((entry) => (
              <li key={entry.label} className="rounded-full border border-line bg-raised px-2 py-0.5 text-ink">
                {entry.label} <span className="tnum text-muted">{fmtPct(entry.probability)}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </Card>
  )
}
