import type { HTMLAttributes, ReactNode } from 'react'
import { cn } from './cn'
import { CHIP_CLASS } from './Chip'
import type { Tone } from '@/lib/severity'
import { TONE_BG, TONE_TEXT } from '@/lib/severity'

/** Tone → border/background/text triple. Shared by `Badge` and `SeverityBadge`. */
export const TONE_CLASS: Record<Tone, string> = {
  neutral: 'border-line bg-raised text-ink',
  safe: 'border-safe/40 bg-safe/15 text-safe',
  warn: 'border-warn/40 bg-warn/15 text-warn',
  orange: 'border-orange/40 bg-orange/15 text-orange',
  danger: 'border-danger/40 bg-danger/15 text-danger',
  info: 'border-accent/40 bg-accent/15 text-accent',
  cyan: 'border-highlight/40 bg-highlight/15 text-highlight',
}

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  tone?: Tone
  children: ReactNode
}

export function Badge({ tone = 'neutral', className, children, ...rest }: BadgeProps) {
  return (
    <span className={cn(CHIP_CLASS, TONE_CLASS[tone], className)} {...rest}>
      {children}
    </span>
  )
}

/** Small dot indicator that combines colour with a text label. */
export function ToneDot({ tone, className }: { tone: Tone; className?: string }) {
  return (
    <span className={cn('inline-block h-2 w-2 shrink-0 rounded-full', TONE_BG[tone], className)} aria-hidden="true" />
  )
}

export { TONE_TEXT }
