import { useMemo } from 'react'
import { Line, LineChart, ReferenceLine, ResponsiveContainer, Tooltip as ChartTooltip, XAxis, YAxis } from 'recharts'
import { Card, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { useSentinel } from '@/store/useSentinel'
import { confusionMatrix, reliabilityDiagram, EXPECTED_CALIBRATION_ERROR, TRAFFIC_LABELS } from '@/api/modelEval'
import { CHART_AXIS, CHART_GRID, CHART_INK, CHART_PALETTE, CHART_TOOLTIP, rgbChannels } from '@/lib/chartColors'

/**
 * Heatmap cell: the accent tinted down over the panel surface. The ramp stops
 * at 0.6 alpha on purpose — beyond it no text colour reaches 4.5:1 against the
 * mid-tone background, so the ramp and the ink stay inside the legible band.
 */
function cellStyle(value: number): { backgroundColor: string; color: string } {
  const alpha = 0.08 + (Math.round(value * 100) / 100) * 0.52
  return {
    backgroundColor: `rgba(${rgbChannels(CHART_PALETTE[0])}, ${alpha})`,
    color: CHART_INK,
  }
}

/** Model evaluation: confusion matrix heatmap and reliability diagram (spec 10.3 item 4). */
export function ModelEvaluation() {
  const matrix = useMemo(() => confusionMatrix(), [])
  const points = useMemo(() => reliabilityDiagram(), [])
  const curve = points.map((point) => ({ ...point, ideal: point.predicted }))
  const liveMode = useSentinel((s) => s.settings.dataSource) === 'live'
  const simBadge = liveMode ? (
    <Badge tone="warn" title="Static demonstration figures, not measured from the live backend.">
      SIMULATED
    </Badge>
  ) : null;

  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
      <Card data-testid="confusion-matrix">
        <CardHeader title="Confusion matrix" description="Rows: actual class · Columns: predicted class" actions={simBadge} />
        <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Confusion matrix">
          <div
            className="grid min-w-[420px] gap-1"
            style={{ gridTemplateColumns: `repeat(${TRAFFIC_LABELS.length + 1}, minmax(0, 1fr))` }}
            role="grid"
            aria-label="Confusion matrix heatmap"
          >
            <div className="p-1 text-2xs text-muted" />
            {TRAFFIC_LABELS.map((label) => (
              <div key={label} className="p-1 text-center text-2xs text-muted" title={label}>
                {label}
              </div>
            ))}
            {matrix.rows.map((row, rowIndex) => [
              <div key={`row-${TRAFFIC_LABELS[rowIndex]}`} className="p-1 text-2xs text-muted" title={TRAFFIC_LABELS[rowIndex]}>
                {TRAFFIC_LABELS[rowIndex]}
              </div>,
              ...row.map((value, colIndex) => (
                <div
                  key={`${rowIndex}-${colIndex}`}
                  role="gridcell"
                  aria-label={`Actual ${TRAFFIC_LABELS[rowIndex]}, predicted ${TRAFFIC_LABELS[colIndex]}: ${value.toFixed(3)}`}
                  className="flex h-9 items-center justify-center rounded text-2xs tabular-nums"
                  style={cellStyle(value)}
                >
                  {value.toFixed(2)}
                </div>
              )),
            ])}
          </div>
        </div>
        <p className="mt-2 text-[11px] text-muted">
          Diagonal values are per-class recall; each row sums to 1.
        </p>
      </Card>

      <Card data-testid="reliability-diagram">
        <CardHeader title="Reliability diagram" description="Predicted probability vs observed frequency" actions={simBadge} />
        <figure className="m-0">
          <div className="h-56 w-full" aria-hidden="true">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={curve} margin={{ top: 6, right: 10, bottom: 4, left: 0 }}>
              <XAxis
                dataKey="predicted"
                type="number"
                domain={[0, 1]}
                tick={{ fontSize: 11, fill: CHART_AXIS }}
                axisLine={{ stroke: CHART_GRID }}
                tickLine={{ stroke: CHART_GRID }}
              />
              <YAxis
                type="number"
                domain={[0, 1]}
                tick={{ fontSize: 11, fill: CHART_AXIS }}
                axisLine={{ stroke: CHART_GRID }}
                tickLine={{ stroke: CHART_GRID }}
              />
              <ChartTooltip contentStyle={CHART_TOOLTIP} />
              <ReferenceLine
                segment={[{ x: 0, y: 0 }, { x: 1, y: 1 }]}
                stroke={CHART_GRID}
                strokeDasharray="4 4"
              />
              <Line
                type="monotone"
                dataKey="ideal"
                stroke={CHART_PALETTE[6]}
                strokeDasharray="4 4"
                dot={false}
                isAnimationActive={false}
              />
              <Line
                type="monotone"
                dataKey="observed"
                stroke={CHART_PALETTE[0]}
                strokeWidth={2}
                dot={{ r: 3 }}
                isAnimationActive={false}
              />
              </LineChart>
            </ResponsiveContainer>
          </div>
          <figcaption className="mt-1 text-[11px] text-muted">
            Calibration: Expected Calibration Error {EXPECTED_CALIBRATION_ERROR.toFixed(3)}
          </figcaption>
          <table className="sr-only">
            <caption>Reliability diagram data</caption>
            <thead>
              <tr>
                <th scope="col">Predicted</th>
                <th scope="col">Observed</th>
              </tr>
            </thead>
            <tbody>
              {points.map((point) => (
                <tr key={point.predicted}>
                  <td>{point.predicted.toFixed(1)}</td>
                  <td>{point.observed.toFixed(3)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </figure>
      </Card>
    </div>
  )
}
