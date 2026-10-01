import { Eye, Sparkles } from 'lucide-react'
import type { Provenance } from '@/types/analysis'
import { cn } from './cn'
import { CHIP_CLASS, CHIP_ICON } from './Chip'

export const PROVENANCE_TOOLTIP: Record<Provenance, string> = {
  observed: 'Read directly from cleartext protocol fields.',
  inferred:
    'Estimated by an AI model from encrypted-traffic characteristics. Confidence is a calibrated probability.',
}

const LABEL: Record<Provenance, string> = {
  observed: 'Observed',
  inferred: 'Inferred',
}

export interface ProvenanceBadgeProps {
  provenance: Provenance
  className?: string
  /** Hide the text label; the icon and title remain. */
  iconOnly?: boolean
}

/** Observed = solid cyan outline with Eye icon; inferred = dashed violet outline with Sparkles icon. */
export function ProvenanceBadge({ provenance, className, iconOnly }: ProvenanceBadgeProps) {
  const tooltip = PROVENANCE_TOOLTIP[provenance]
  return (
    <span
      title={tooltip}
      className={cn(
        CHIP_CLASS,
        provenance === 'observed' && 'border-solid border-highlight/70 bg-highlight/10 text-highlight',
        provenance === 'inferred' && 'border-dashed border-violet/70 bg-violet/10 text-violet',
        className,
      )}
    >
      {provenance === 'observed' ? (
        <Eye size={CHIP_ICON} aria-hidden="true" />
      ) : (
        <Sparkles size={CHIP_ICON} aria-hidden="true" />
      )}
      <span>{iconOnly ? <span className="sr-only">{LABEL[provenance]}</span> : LABEL[provenance]}</span>
      <span className="sr-only">{tooltip}</span>
    </span>
  )
}
