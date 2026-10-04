import { CircleAlert, Info, OctagonAlert, TriangleAlert } from 'lucide-react'
import type { Severity } from '@/types/analysis'
import { SEVERITY_LABEL, SEVERITY_TONE } from '@/lib/severity'
import { cn } from './cn'
import { TONE_CLASS } from './Badge'
import { CHIP_CLASS, CHIP_ICON } from './Chip'

const ICON_CLASS: Record<Severity, string> = {
  critical: 'text-red',
  high: 'text-orange',
  medium: 'text-amber',
  low: 'text-blue',
}

export function SeverityIcon({ severity, className }: { severity: Severity; className?: string }) {
  const props = {
    size: CHIP_ICON,
    className: cn('shrink-0', className ?? ICON_CLASS[severity]),
    'aria-hidden': true,
  } as const
  if (severity === 'critical') return <OctagonAlert {...props} />
  if (severity === 'high') return <TriangleAlert {...props} />
  if (severity === 'medium') return <CircleAlert {...props} />
  return <Info {...props} />
}

export interface SeverityBadgeProps {
  severity: Severity
  className?: string
  /** Renders only the icon plus a visually hidden label. */
  compact?: boolean
}

/** Severity always combines colour, icon and text (spec 3.4). */
export function SeverityBadge({ severity, className, compact }: SeverityBadgeProps) {
  const label = SEVERITY_LABEL[severity]
  return (
    <span className={cn(CHIP_CLASS, TONE_CLASS[SEVERITY_TONE[severity]], className)} title={label}>
      <SeverityIcon severity={severity} />
      {compact ? <span className="sr-only">{label}</span> : <span>{label}</span>}
    </span>
  )
}

export { SEVERITY_TONE }
