import { motion, useReducedMotion } from 'framer-motion'
import { ArrowDownRight, ArrowUpRight, CircleAlert, ShieldCheck, TriangleAlert } from 'lucide-react'
import { cn } from '@/components/ui/cn'
import { RISK_BAND_LABEL, RISK_BAND_TONE } from '@/lib/severity'
import { TONE_TEXT } from '@/lib/severity'
import type { RiskBand } from '@/lib/severity'

const BAND_STROKE: Record<RiskBand, string> = {
  low: 'stroke-safe',
  moderate: 'stroke-warn',
  high: 'stroke-danger',
}

const BAND_ICON: Record<RiskBand, typeof ShieldCheck> = {
  low: ShieldCheck,
  moderate: TriangleAlert,
  high: CircleAlert,
}

export interface RiskGaugeProps {
  score: number
  band: RiskBand
  delta?: number | null
}

/**
 * Custom semicircular risk gauge (spec 10.1 A.1): `role="meter"` with
 * `aria-valuenow` and `aria-valuetext`, animated only without reduced motion.
 */
export function RiskGauge({ score, band, delta }: RiskGaugeProps) {
  const reduceMotion = useReducedMotion()
  const clamped = Math.max(0, Math.min(100, Math.round(score)))
  const BandIcon = BAND_ICON[band]
  const valueText = `${clamped} out of 100, ${band} risk`

  return (
    <div className="flex flex-col items-center">
      <div
        role="meter"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={clamped}
        aria-valuetext={valueText}
        aria-label="Global risk score"
        data-testid="risk-gauge"
        className="w-full"
      >
        <svg viewBox="0 0 200 120" className="w-full" role="img" aria-hidden="true">
          <path
            d="M 20 100 A 80 80 0 0 1 180 100"
            pathLength={100}
            fill="none"
            stroke="currentColor"
            strokeWidth={14}
            strokeLinecap="round"
            className="text-raised"
          />
          <motion.path
            d="M 20 100 A 80 80 0 0 1 180 100"
            pathLength={100}
            fill="none"
            strokeWidth={14}
            strokeLinecap="round"
            className={BAND_STROKE[band]}
            strokeDasharray={`${clamped} 100`}
            initial={reduceMotion ? false : { strokeDasharray: '0 100' }}
            animate={{ strokeDasharray: `${clamped} 100` }}
            transition={{ duration: reduceMotion ? 0 : 0.24, ease: 'easeOut' }}
          />
          <text
            x="100"
            y="86"
            textAnchor="middle"
            className="fill-ink tnum"
            style={{ fontSize: 28, fontWeight: 600 }}
          >
            {clamped}
          </text>
          <text x="100" y="106" textAnchor="middle" className="fill-muted" style={{ fontSize: 12 }}>
            / 100
          </text>
        </svg>
      </div>
      <p className={cn('-mt-1 flex items-center gap-1.5 text-xs font-semibold', TONE_TEXT[RISK_BAND_TONE[band]])}>
        <BandIcon size={14} aria-hidden="true" />
        {RISK_BAND_LABEL[band]}
      </p>
      {typeof delta === 'number' && delta !== 0 ? (
        <p
          className={cn('mt-1 flex items-center gap-1 text-[11px]', delta > 0 ? 'text-danger' : 'text-safe')}
          data-testid="risk-delta"
        >
          {delta > 0 ? <ArrowUpRight size={12} aria-hidden="true" /> : <ArrowDownRight size={12} aria-hidden="true" />}
          <span className="tnum">
            {delta > 0 ? `+${delta}` : delta} since previous analysis
          </span>
        </p>
      ) : null}
    </div>
  )
}
