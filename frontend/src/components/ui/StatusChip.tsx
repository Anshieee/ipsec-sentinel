import { CheckCircle2, CircleHelp, CircleX } from 'lucide-react'
import type { ReactNode } from 'react'
import { cn } from './cn'
import { CHIP_CLASS, CHIP_ICON } from './Chip'

export type StatusKind = 'enabled' | 'disabled' | 'unknown' | 'neutral'

const KIND_CLASS: Record<StatusKind, string> = {
  enabled: 'border-green/40 bg-green/15 text-green',
  disabled: 'border-red/40 bg-red/15 text-red',
  unknown: 'border-border bg-bg-card text-text-secondary',
  neutral: 'border-border bg-bg-card text-text-secondary',
}

const KIND_LABEL: Record<StatusKind, string> = {
  enabled: 'Enabled',
  disabled: 'Disabled',
  unknown: 'Unknown',
  neutral: 'Not observed',
}

export interface StatusChipProps {
  status: StatusKind
  label?: string
  /** Secondary line, for example "ESN on". */
  sub?: string
  className?: string
  children?: ReactNode
}

/** Icon + label for Enabled / Disabled / Unknown states (neutral renders no icon). */
export function StatusChip({ status, label, sub, className, children }: StatusChipProps) {
  const text = label ?? KIND_LABEL[status]
  return (
    <span
      className={cn(
        CHIP_CLASS,
        KIND_CLASS[status],
        className,
      )}
    >
      {status === 'enabled' ? (
        <CheckCircle2 size={CHIP_ICON} aria-hidden="true" />
      ) : status === 'disabled' ? (
        <CircleX size={CHIP_ICON} aria-hidden="true" />
      ) : status === 'unknown' ? (
        <CircleHelp size={CHIP_ICON} aria-hidden="true" />
      ) : null}
      <span>{text}</span>
      {sub ? <span className="font-medium text-text-secondary">{sub}</span> : null}
      {children}
    </span>
  )
}
