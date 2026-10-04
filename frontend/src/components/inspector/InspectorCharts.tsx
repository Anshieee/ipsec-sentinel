import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip as ChartTooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { Card, CardHeader } from '@/components/ui/Card'
import { CHART_AXIS, CHART_GRID, CHART_PALETTE, CHART_TOOLTIP } from '@/lib/chartColors'
import type { AnalysisResult } from '@/types/analysis'

/** Packets per 10 s by protocol plus the ESP length histogram (spec 10.2 item 6). */
export function InspectorCharts({ analysis }: { analysis: AnalysisResult }) {
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <Card data-testid="timeseries-chart">
        <CardHeader title="Packets per 10 s" description="Stacked by protocol" />
        <figure className="m-0">
          <div className="h-56 w-full" aria-hidden="true">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={analysis.timeSeries} margin={{ top: 4, right: 8, bottom: 4, left: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={CHART_GRID} />
                <XAxis dataKey="t" tick={{ fontSize: 11, fill: CHART_AXIS }} axisLine={{ stroke: CHART_GRID }} tickLine={{ stroke: CHART_GRID }} />
                <YAxis tick={{ fontSize: 11, fill: CHART_AXIS }} axisLine={{ stroke: CHART_GRID }} tickLine={{ stroke: CHART_GRID }} />
                <ChartTooltip contentStyle={CHART_TOOLTIP} />
                <Area
                  type="monotone"
                  dataKey="ike"
                  stackId="1"
                  stroke={CHART_PALETTE[0]}
                  fill={CHART_PALETTE[0]}
                  isAnimationActive={false}
                />
                <Area
                  type="monotone"
                  dataKey="esp"
                  stackId="1"
                  stroke={CHART_PALETTE[1]}
                  fill={CHART_PALETTE[1]}
                  isAnimationActive={false}
                />
                <Area
                  type="monotone"
                  dataKey="other"
                  stackId="1"
                  stroke={CHART_PALETTE[6]}
                  fill={CHART_PALETTE[6]}
                  isAnimationActive={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <figcaption className="mt-1 text-[11px] text-text-secondary">
            Packets per 10-second bucket for IKE, ESP and other protocols.
          </figcaption>
          <table className="sr-only">
            <caption>Packets per 10 seconds</caption>
            <thead>
              <tr>
                <th scope="col">Bucket (s)</th>
                <th scope="col">IKE</th>
                <th scope="col">ESP</th>
                <th scope="col">Other</th>
              </tr>
            </thead>
            <tbody>
              {analysis.timeSeries.map((point) => (
                <tr key={point.t}>
                  <td>{point.t}</td>
                  <td>{point.ike}</td>
                  <td>{point.esp}</td>
                  <td>{point.other}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </figure>
      </Card>

      <Card data-testid="length-histogram">
        <CardHeader title="ESP length distribution" />
        <figure className="m-0">
          <div className="h-56 w-full" aria-hidden="true">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={analysis.lengthHistogram} margin={{ top: 4, right: 8, bottom: 4, left: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={CHART_GRID} />
                <XAxis dataKey="bin" tick={{ fontSize: 11, fill: CHART_AXIS }} axisLine={{ stroke: CHART_GRID }} tickLine={{ stroke: CHART_GRID }} />
                <YAxis tick={{ fontSize: 11, fill: CHART_AXIS }} axisLine={{ stroke: CHART_GRID }} tickLine={{ stroke: CHART_GRID }} />
                <ChartTooltip contentStyle={CHART_TOOLTIP} />
                <Bar dataKey="count" fill={CHART_PALETTE[0]} isAnimationActive={false} radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
          <figcaption className="mt-1 text-[11px] text-text-secondary">
            ESP length distribution. Overhead and padding patterns support cipher inference.
          </figcaption>
          <table className="sr-only">
            <caption>ESP packet length histogram</caption>
            <thead>
              <tr>
                <th scope="col">Bin</th>
                <th scope="col">Count</th>
              </tr>
            </thead>
            <tbody>
              {analysis.lengthHistogram.map((bin) => (
                <tr key={bin.bin}>
                  <td>{bin.bin}</td>
                  <td>{bin.count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </figure>
      </Card>
    </div>
  )
}
