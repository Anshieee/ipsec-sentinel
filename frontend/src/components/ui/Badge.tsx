import type { HTMLAttributes, ReactNode } from 'react'
import { cn } from './cn'
import { CHIP_CLASS } from './Chip'
import type { Tone } from '@/lib/severity'
import { TONE_BG, TONE_TEXT } from '@/lib/severity'

/** Tone → border/background/text triple (B3 badge spec: tinted bg 8-12%,
 * 1px border 30-40%, bright/accent text). Shared by `Badge` and `SeverityBadge`. */
export const TONE_CLASS: Record<Tone, string> = {
  neutral: 'border-border bg-bg-card text-text-primary',
  safe: 'border-green/40 bg-green/10 text-green-bright',
  warn: 'border-amber/40 bg-amber/10 text-amber',
  orange: 'border-orange/40 bg-orange/10 text-orange',
  danger: 'border-red/40 bg-red/10 text-red',
  info: 'border-blue/40 bg-blue/10 text-blue',
  cyan: 'border-blue/40 bg-blue/10 text-blue',
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
