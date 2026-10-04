import { fmtPct } from '@/lib/format'
import { confidenceTone } from '@/lib/severity'
import type { Tone } from '@/lib/severity'
import { TONE_BG } from '@/lib/severity'
import { cn } from './cn'

export interface ConfidenceBarProps {
  /** 0..1 calibrated probability. */
  value: number
  className?: string
  /** `auto` applies the 0.85 / 0.7 bands. */
  tone?: Tone | 'auto'
  /** Render the numeric label. */
  showValue?: boolean
  ariaLabel?: string
}

/** Thin bar plus `%` text. Confidence is a calibrated probability, never "accuracy". */
export function ConfidenceBar({ value, className, tone = 'auto', showValue = true, ariaLabel }: ConfidenceBarProps) {
  const clamped = Math.max(0, Math.min(1, Number.isFinite(value) ? value : 0))
  const resolved: Tone = tone === 'auto' ? confidenceTone(clamped) : tone
  return (
    <div className={cn('flex h-5 min-w-[80px] items-center gap-2', className)}>
      <div
        role="meter"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={Math.round(clamped * 100)}
        aria-label={ariaLabel ?? `Confidence ${fmtPct(clamped)}`}
        className="h-1.5 flex-1 overflow-hidden rounded-full bg-bg-card"
      >
        <div
          className={cn('h-full rounded-full transition-[width]', TONE_BG[resolved])}
          style={{ width: `${clamped * 100}%` }}
        />
      </div>
      {showValue ? <span className="tnum w-11 text-right text-2xs font-semibold text-text-secondary">{fmtPct(clamped)}</span> : null}
    </div>
  )
}
