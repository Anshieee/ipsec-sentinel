import { CheckCircle2, CircleHelp, CircleX } from 'lucide-react'
import type { ReactNode } from 'react'
import { cn } from './cn'
import { CHIP_CLASS, CHIP_ICON } from './Chip'

export type StatusKind = 'enabled' | 'disabled' | 'unknown'

const KIND_CLASS: Record<StatusKind, string> = {
  enabled: 'border-safe/40 bg-safe/15 text-safe',
  disabled: 'border-danger/40 bg-danger/15 text-danger',
  unknown: 'border-line bg-raised text-muted',
}

const KIND_LABEL: Record<StatusKind, string> = {
  enabled: 'Enabled',
  disabled: 'Disabled',
  unknown: 'Unknown',
}

export interface StatusChipProps {
  status: StatusKind
  label?: string
  /** Secondary line, for example "ESN on". */
  sub?: string
  className?: string
  children?: ReactNode
}

/** Icon + label for Enabled / Disabled / Unknown states. */
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
      ) : (
        <CircleHelp size={CHIP_ICON} aria-hidden="true" />
      )}
      <span>{text}</span>
      {sub ? <span className="font-medium text-muted">{sub}</span> : null}
      {children}
    </span>
  )
}
